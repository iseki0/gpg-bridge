use crate::{
    protocol::{MAX_DATA, SigningKey},
    util,
};
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use std::{path::PathBuf, process::Stdio, time::Duration};
use tokio::{io::AsyncWriteExt, process::Command};

#[derive(Clone)]
pub struct Gpg {
    pub program: PathBuf,
    pub homedir: Option<PathBuf>,
    pub timeout: Duration,
}
impl Gpg {
    pub fn command(&self) -> Command {
        let mut cmd = Command::new(&self.program);
        if let Some(home) = &self.homedir {
            cmd.arg("--homedir").arg(home);
        }
        cmd.kill_on_drop(true);
        cmd
    }
    pub async fn run(&self, args: &[String], input: &[u8]) -> Result<std::process::Output> {
        let mut cmd = self.command();
        let mut child = cmd
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .with_context(|| {
                format!(
                    "无法运行 {}，请安装 GnuPG/Gpg4win，或设置 --gpg",
                    self.program.display()
                )
            })?;
        let mut stdin = child.stdin.take().context("gpg stdin unavailable")?;
        let (output, ()) = tokio::time::timeout(self.timeout, async {
            tokio::try_join!(child.wait_with_output(), async {
                // GPG may exit before consuming stdin. Its exit status carries that error.
                match stdin.write_all(input).await {
                    Ok(()) => (),
                    Err(e) if e.kind() == std::io::ErrorKind::BrokenPipe => (),
                    Err(e) => return Err(e),
                }
                drop(stdin);
                Ok(())
            })
        })
        .await
        .context("GnuPG 操作超时（子进程已终止）")??;
        Ok(output)
    }
    pub async fn keys(&self) -> Result<Vec<SigningKey>> {
        let args = [
            "--batch",
            "--with-colons",
            "--fixed-list-mode",
            "--with-fingerprint",
            "--with-subkey-fingerprint",
            "--list-secret-keys",
        ]
        .map(str::to_owned);
        let out = self.run(&args, &[]).await?;
        ensure!(
            out.status.success(),
            "无法列出密钥：{}",
            util::display(&String::from_utf8_lossy(&out.stderr))
        );
        parse_keys(&String::from_utf8_lossy(&out.stdout), util::now())
    }
    pub async fn export_public(&self, keys: &[SigningKey]) -> Result<String> {
        let mut args: Vec<String> = ["--batch", "--armor", "--export"].map(str::to_owned).into();
        args.extend(keys.iter().map(|k| k.primary.clone()));
        let out = self.run(&args, &[]).await?;
        ensure!(
            out.status.success() && !out.stdout.is_empty() && out.stdout.len() <= MAX_DATA,
            "无法导出公钥"
        );
        Ok(String::from_utf8(out.stdout)?)
    }
    pub async fn sign(&self, key: &SigningKey, data: &[u8]) -> Result<(String, String)> {
        ensure!(
            !data.is_empty() && data.len() <= MAX_DATA,
            "待签名内容大小不合法"
        );
        // Recheck revocation, expiry, and secret availability for every request.
        ensure!(
            self.keys()
                .await?
                .iter()
                .any(|k| k.fingerprint == key.fingerprint),
            "签名密钥已失效或不可用"
        );
        let args = vec![
            "--batch".into(),
            "--no-tty".into(),
            "--status-fd=2".into(),
            "--armor".into(),
            "--detach-sign".into(),
            "--local-user".into(),
            format!("{}!", key.fingerprint),
            "--output".into(),
            "-".into(),
        ];
        let out = self.run(&args, data).await?;
        let stderr = String::from_utf8_lossy(&out.stderr);
        ensure!(
            out.status.success(),
            "GnuPG 签名失败：{}",
            util::display(&stderr)
        );
        let status = stderr
            .lines()
            .filter(|l| l.starts_with("[GNUPG:] "))
            .collect::<Vec<_>>()
            .join("\n")
            + "\n";
        // SIG_CREATED: type pk_algo hash_algo class timestamp actual_signing_fingerprint.
        let actual = status
            .lines()
            .find_map(|line| line.strip_prefix("[GNUPG:] SIG_CREATED "))
            .and_then(|s| s.split_whitespace().last())
            .context("GnuPG 没有报告 SIG_CREATED")?;
        ensure!(
            actual.eq_ignore_ascii_case(&key.fingerprint),
            "GnuPG 使用了未授权的签名密钥"
        );
        let sig = String::from_utf8(out.stdout)?;
        ensure!(
            sig.starts_with("-----BEGIN PGP SIGNATURE-----") && sig.len() <= 128 * 1024,
            "无效的 GPG 签名输出"
        );
        Ok((sig, status))
    }
}

#[derive(Default)]
struct Record {
    fpr: String,
    valid: bool,
    usable: bool,
    signs: bool,
    expires: u64,
    created: u64,
    hardware: bool,
}
#[derive(Default)]
struct Group {
    uid: String,
    records: Vec<Record>,
}
fn unescape(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'\\'
            && bytes.get(i + 1) == Some(&b'x')
            && i + 3 < bytes.len()
            && let Ok(hex) = std::str::from_utf8(&bytes[i + 2..i + 4])
            && let Ok(n) = u8::from_str_radix(hex, 16)
        {
            out.push(n);
            i += 4;
            continue;
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}
pub fn valid_fingerprint(s: &str) -> bool {
    matches!(s.len(), 40 | 64) && s.bytes().all(|b| b.is_ascii_hexdigit())
}

pub fn parse_keys(text: &str, now: u64) -> Result<Vec<SigningKey>> {
    let mut groups: Vec<Group> = Vec::new();
    for line in text.lines() {
        let f: Vec<&str> = line.split(':').collect();
        let field = |n: usize| f.get(n).copied().unwrap_or("");
        match field(0) {
            "sec" | "ssb" => {
                if field(0) == "sec" {
                    groups.push(Group::default());
                }
                let Some(group) = groups.last_mut() else {
                    continue;
                };
                let expiry = field(6).parse::<u64>().unwrap_or(0);
                group.records.push(Record {
                    valid: !matches!(field(1), "r" | "e" | "d" | "i")
                        && !field(11).contains('D')
                        && (expiry == 0 || expiry > now),
                    usable: !matches!(field(1), "r" | "e" | "d" | "i")
                        && !field(11).contains('D')
                        && field(14) != "#"
                        && (expiry == 0 || expiry > now),
                    signs: field(11).contains('s'), // Uppercase S is aggregate, NOT primary-key capability.
                    expires: expiry,
                    created: field(5).parse().unwrap_or(0),
                    hardware: !matches!(field(14), "" | "+" | "#"),
                    ..Record::default()
                });
            }
            "fpr" => {
                if let Some(rec) = groups.last_mut().and_then(|g| g.records.last_mut())
                    && rec.fpr.is_empty()
                {
                    rec.fpr = field(9).to_uppercase();
                }
            }
            "uid" => {
                if let Some(g) = groups.last_mut()
                    && g.uid.is_empty()
                    && !matches!(field(1), "r" | "e" | "i")
                {
                    g.uid = unescape(field(9));
                }
            }
            _ => (),
        }
    }
    let mut keys = Vec::new();
    for g in groups {
        let Some(primary) = g.records.first() else {
            continue;
        };
        // An offline primary (#) is normal if a signing subkey exists.
        // Root validity must be checked separately from root secret availability.
        if !primary.valid || !valid_fingerprint(&primary.fpr) {
            continue;
        }
        for rec in &g.records {
            if rec.usable && rec.signs && valid_fingerprint(&rec.fpr) {
                keys.push((
                    rec.created,
                    SigningKey {
                        primary: primary.fpr.clone(),
                        fingerprint: rec.fpr.clone(),
                        uid: g.uid.clone(),
                        expires: if primary.expires == 0 {
                            rec.expires
                        } else if rec.expires == 0 {
                            primary.expires
                        } else {
                            primary.expires.min(rec.expires)
                        },
                        hardware: rec.hardware,
                    },
                ));
            }
        }
    }
    // Newest first within an identity; preserve all eligible leaves for explicit selection.
    keys.sort_by_key(|a| (a.1.fingerprint == a.1.primary, std::cmp::Reverse(a.0)));
    Ok(keys.into_iter().map(|(_, k)| k).collect())
}

#[derive(Serialize, Deserialize)]
struct Preferences {
    primaries: Vec<String>,
}

pub async fn select_keys(
    gpg: &Gpg,
    explicit: &[String],
    remember: bool,
) -> Result<Vec<SigningKey>> {
    let all = gpg.keys().await?;
    ensure!(
        !all.is_empty(),
        "没有可用签名密钥。请检查 Gpg4win 密钥、有效期及硬件设备；不会自动生成新密钥。"
    );
    if !explicit.is_empty() {
        let mut selected = Vec::new();
        for fpr in explicit {
            let fpr = fpr.trim_end_matches('!').to_uppercase();
            ensure!(
                valid_fingerprint(&fpr),
                "--key 需要完整指纹；通常无需此选项"
            );
            let k = all
                .iter()
                .find(|k| k.fingerprint == fpr)
                .or_else(|| all.iter().find(|k| k.primary == fpr))
                .context("指定的签名密钥不可用")?;
            if !selected
                .iter()
                .any(|s: &SigningKey| s.fingerprint == k.fingerprint)
            {
                selected.push(k.clone());
            }
        }
        return Ok(selected);
    }
    let mut identities = Vec::<SigningKey>::new();
    for k in &all {
        if !identities.iter().any(|i| i.primary == k.primary) {
            identities.push(k.clone());
        }
    }
    let pref_path = util::state_dir()?.join("preferences.json");
    let old: Option<Preferences> = std::fs::read(&pref_path)
        .ok()
        .and_then(|b| serde_json::from_slice(&b).ok());
    let hint = Command::new("git")
        .args(["config", "--get", "user.signingkey"])
        .output()
        .await
        .ok()
        .filter(|o| o.status.success())
        .map(|o| {
            String::from_utf8_lossy(&o.stdout)
                .trim()
                .trim_end_matches('!')
                .to_owned()
        });
    let mut defaults = Vec::new();
    if let Some(old) = &old {
        defaults = identities
            .iter()
            .enumerate()
            .filter(|(_, k)| old.primaries.contains(&k.primary))
            .map(|(i, _)| i)
            .collect();
    }
    if defaults.is_empty()
        && let Some(hint) = hint
    {
        let norm = hint.to_uppercase();
        let matches: Vec<_> = identities
            .iter()
            .enumerate()
            .filter(|(_, i)| {
                all.iter().any(|k| {
                    k.primary == i.primary && norm.len() >= 16 && k.fingerprint.ends_with(&norm)
                }) || (norm.len() >= 16 && i.primary.ends_with(&norm))
                    || i.uid == hint
                    || i.uid.contains(&format!("<{hint}>"))
            })
            .map(|(i, _)| i)
            .collect();
        if matches.len() == 1 {
            defaults = matches;
        }
    }
    if defaults.is_empty() && identities.len() == 1 {
        defaults.push(0);
    }
    eprintln!("本机可用的签名身份（硬件记录不代表设备已插入）：");
    for (i, k) in identities.iter().enumerate() {
        let expiry = if k.expires == 0 {
            "永不过期".into()
        } else {
            chrono::DateTime::from_timestamp(k.expires as i64, 0)
                .map(|t| t.format("%Y-%m-%d").to_string())
                .unwrap_or_else(|| "未知".into())
        };
        eprintln!(
            "  {}. {} | …{} | {} | {}{}",
            i + 1,
            util::display(&k.uid),
            &k.fingerprint[k.fingerprint.len() - 16..],
            expiry,
            if k.hardware {
                "硬件钥匙"
            } else {
                "本机密钥"
            },
            if defaults.contains(&i) {
                " [默认]"
            } else {
                ""
            }
        );
    }
    let chosen = if remember && !defaults.is_empty() {
        eprintln!("使用已选择/唯一身份；--choose 可重新选择。");
        defaults
    } else {
        let input = util::prompt("选择编号（逗号分隔；回车使用默认）：")?;
        if input.is_empty() {
            ensure!(!defaults.is_empty(), "存在多个身份，请选择编号");
            defaults
        } else {
            input
                .split(',')
                .map(|v| {
                    let n: usize = v.trim().parse().context("请输入编号")?;
                    ensure!(n > 0 && n <= identities.len(), "编号超出范围");
                    Ok(n - 1)
                })
                .collect::<Result<Vec<_>>>()?
        }
    };
    let mut selected = Vec::new();
    for i in chosen {
        if !selected
            .iter()
            .any(|s: &SigningKey| s.primary == identities[i].primary)
        {
            selected.push(identities[i].clone());
        }
    }
    ensure!(!selected.is_empty(), "没有选择身份");
    // Preferences contain PUBLIC fingerprints only; never credentials.
    std::fs::write(
        pref_path,
        serde_json::to_vec_pretty(&Preferences {
            primaries: selected.iter().map(|k| k.primary.clone()).collect(),
        })?,
    )?;
    Ok(selected)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn line(kind: &str, validity: &str, caps: &str, expiry: u64, secret: &str) -> String {
        let mut f = vec!["".to_owned(); 16];
        f[0] = kind.into();
        f[1] = validity.into();
        f[5] = "100".into();
        f[6] = expiry.to_string();
        f[11] = caps.into();
        f[14] = secret.into();
        f.join(":")
    }
    #[test]
    fn aggregate_capability_is_not_signing_and_offline_primary_is_supported() {
        let p = "A".repeat(40);
        let s = "B".repeat(40);
        let text = format!(
            "{}\nfpr:::::::::{p}:\nuid:u::::::::Alice\\x3a Test <a@example.com>:\n{}\nfpr:::::::::{s}:\n",
            line("sec", "u", "cSC", 0, "#"),
            line("ssb", "u", "s", 0, "+")
        );
        let k = parse_keys(&text, 1000).unwrap();
        assert_eq!(k.len(), 1);
        assert_eq!(k[0].fingerprint, s);
        assert!(k[0].uid.contains("Alice: Test"));
    }
    #[test]
    fn signing_subkey_is_preferred_over_primary_even_with_equal_timestamp() {
        let text = format!(
            "{}\nfpr:::::::::{}:\n{}\nfpr:::::::::{}:\n",
            line("sec", "u", "scSC", 0, "+"),
            "A".repeat(40),
            line("ssb", "u", "s", 0, "+"),
            "B".repeat(40)
        );
        let keys = parse_keys(&text, 1000).unwrap();
        assert_eq!(keys[0].fingerprint, "B".repeat(40));
    }

    #[test]
    fn invalid_primary_invalidates_its_signing_subkeys() {
        for validity in ["r", "e", "d", "i"] {
            let text = format!(
                "{}\nfpr:::::::::{}:\n{}\nfpr:::::::::{}:\n",
                line("sec", validity, "cSC", 0, "#"),
                "A".repeat(40),
                line("ssb", "u", "s", 0, "+"),
                "B".repeat(40)
            );
            assert!(parse_keys(&text, 1000).unwrap().is_empty());
        }
    }

    #[test]
    fn expired_and_missing_subkeys_are_excluded() {
        for (expiry, secret) in [(100, "+"), (0, "#")] {
            let text = format!(
                "{}\nfpr:::::::::{}:\n",
                line("sec", "u", "s", expiry, secret),
                "A".repeat(40)
            );
            assert!(parse_keys(&text, 1000).unwrap().is_empty());
        }
    }
}
