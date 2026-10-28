use crate::{
    gpg::{Gpg, valid_fingerprint},
    protocol::*,
    util,
};
use anyhow::{Context, Result, bail, ensure};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    io::{Read, Write},
    path::{Path, PathBuf},
    process::Stdio,
    time::Duration,
};
use tokio::process::Command;
use zeroize::Zeroizing;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Config {
    ticket: Ticket,
    key: SigningKey,
    gpg_program: PathBuf,
    verify_home: PathBuf,
    previous: BTreeMap<String, Vec<String>>,
    installed: BTreeMap<String, Vec<String>>,
}

pub async fn rpc(ticket: &Ticket, request: &Request) -> Result<Response> {
    ticket.validate()?;
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(Duration::from_secs(15))
        .timeout(Duration::from_secs(300))
        .build()?;
    let endpoint = ticket.endpoint.trim_end_matches('/');
    let mut noise = initiator(ticket)?;
    let mut buf = [0; 4096];
    let n = noise.write_message(&[], &mut buf)?;
    let hello = Hello {
        session: ticket.session.clone(),
        message: encode(&buf[..n]),
    };
    let response = client
        .post(format!("{endpoint}/v1/handshake"))
        .json(&hello)
        .send()
        .await
        .context("无法连接 Windows；检查端点、云端代理、域名白名单及 Tailscale 路由")?;
    let welcome: Welcome = serde_json::from_slice(&bounded(response, 8192).await?)?;
    ensure!(
        welcome.id.len() <= 128
            && welcome
                .id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_'),
        "无效请求 ID"
    );
    noise
        .read_message(&decode(&welcome.message)?, &mut buf)
        .context("服务端身份认证失败")?;
    let mut noise = noise.into_transport_mode()?;
    let wire = seal(&mut noise, &serde_json::to_vec(request)?)?;
    let response = client
        .post(format!("{endpoint}/v1/rpc/{}", welcome.id))
        .header("Content-Type", "application/octet-stream")
        .body(wire)
        .send()
        .await
        .context("签名服务请求失败（不会自动重试）")?;
    let wire = bounded(response, MAX_WIRE).await?;
    response_ok(serde_json::from_slice(&open(&mut noise, &wire)?)?)
}
async fn bounded(mut response: reqwest::Response, limit: usize) -> Result<Vec<u8>> {
    ensure!(
        response.status().is_success(),
        "服务返回 HTTP {}（未自动重试）",
        response.status().as_u16()
    );
    let mut out = Vec::new();
    while let Some(chunk) = response.chunk().await? {
        ensure!(
            chunk.len() <= limit.saturating_sub(out.len()),
            "服务响应超出大小限制"
        );
        out.extend_from_slice(&chunk);
    }
    Ok(out)
}

async fn git(args: &[&str]) -> Result<std::process::Output> {
    let out = Command::new("git")
        .args(args)
        .output()
        .await
        .context("无法启动 git")?;
    Ok(out)
}
async fn git_ok(args: &[&str]) -> Result<String> {
    let out = git(args).await?;
    ensure!(
        out.status.success(),
        "Git 操作失败：{}",
        util::display(&String::from_utf8_lossy(&out.stderr))
    );
    Ok(String::from_utf8(out.stdout)?.trim_end().into())
}
async fn path() -> Result<PathBuf> {
    let dir = git_ok(&["rev-parse", "--absolute-git-dir"]).await?;
    Ok(PathBuf::from(dir).join("gpg-bridge-client.json"))
}
async fn get_config(key: &str) -> Result<Vec<String>> {
    let out = git(&["config", "--local", "--null", "--get-all", key]).await?;
    if out.status.code() == Some(1) {
        return Ok(Vec::new());
    }
    ensure!(out.status.success(), "无法读取 Git 配置");
    let text = String::from_utf8(out.stdout)?;
    Ok(text.split_terminator('\0').map(str::to_owned).collect())
}
async fn set_config(key: &str, values: &[String]) -> Result<()> {
    let out = git(&["config", "--local", "--unset-all", key]).await?;
    ensure!(
        out.status.success() || out.status.code() == Some(5),
        "无法修改 Git 配置"
    );
    for value in values {
        git_ok(&["config", "--local", "--add", key, value]).await?;
    }
    Ok(())
}
fn shell_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}

/// Open once, refuse symlinks, check owner/mode on the actual descriptor, and
/// bound reads. Never check a pathname and then open a different file by race.
#[cfg(unix)]
fn read_config(path: &Path) -> Result<Zeroizing<Vec<u8>>> {
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)?;
    let meta = file.metadata()?;
    // SAFETY: geteuid has no pointer arguments or preconditions.
    let uid = unsafe { libc::geteuid() };
    ensure!(
        meta.is_file() && meta.mode() & 0o077 == 0 && meta.uid() == uid,
        "客户端凭证必须属于当前用户、为普通文件且权限为 600：{}",
        path.display()
    );
    let mut bytes = Zeroizing::new(Vec::new());
    file.take(32 * 1024 + 1).read_to_end(&mut bytes)?;
    ensure!(bytes.len() <= 32 * 1024, "客户端配置过长");
    Ok(bytes)
}
#[cfg(not(unix))]
fn read_config(_path: &Path) -> Result<Zeroizing<Vec<u8>>> {
    bail!("云端客户端暂仅支持 Unix；Windows 请使用 serve")
}
fn load(path: &Path) -> Result<Config> {
    let bytes = read_config(path)?;
    let c: Config = serde_json::from_slice(&bytes).context("无效的客户端配置")?;
    c.ticket.validate()?;
    ensure!(valid_fingerprint(&c.key.fingerprint), "无效密钥指纹");
    Ok(c)
}

struct CreatedDir {
    path: PathBuf,
    keep: bool,
}
impl Drop for CreatedDir {
    fn drop(&mut self) {
        if !self.keep {
            let _ = std::fs::remove_dir_all(&self.path);
        }
    }
}

struct CreatedFile {
    path: PathBuf,
    keep: bool,
}
impl Drop for CreatedFile {
    fn drop(&mut self) {
        if !self.keep {
            let _ = std::fs::remove_file(&self.path);
        }
    }
}

pub async fn connect(ticket_file: Option<PathBuf>, gpg: PathBuf) -> Result<()> {
    ensure!(
        cfg!(unix),
        "客户端目前支持 Linux/macOS；Windows 上请运行 serve"
    );
    let path = path().await?;
    ensure!(
        !path.exists(),
        "本仓库已配置 bridge；请先运行 gpg-bridge disconnect"
    );
    let raw = Zeroizing::new(if let Some(file) = ticket_file {
        let file = std::fs::File::open(file)?;
        let mut s = String::new();
        file.take(8193).read_to_string(&mut s)?;
        s
    } else {
        util::prompt("粘贴 Windows 输出的连接串，然后回车：")?
    });
    let ticket = Ticket::unpack(raw.trim())?;
    let Response::Info {
        session,
        expires,
        keys,
        public_keys,
    } = rpc(&ticket, &Request::Info).await?
    else {
        bail!("服务响应类型错误")
    };
    ensure!(
        session == ticket.session && expires == ticket.expires && !keys.is_empty(),
        "会话信息不匹配"
    );
    let key = keys[0].clone();
    ensure!(
        valid_fingerprint(&key.fingerprint) && valid_fingerprint(&key.primary),
        "服务返回无效密钥指纹"
    );
    ensure!(
        public_keys.starts_with("-----BEGIN PGP PUBLIC KEY BLOCK-----")
            && public_keys.len() <= MAX_DATA,
        "无效公钥"
    );
    let gpg = resolve_program(gpg)?;
    let home = path
        .parent()
        .context("缺少 Git 目录")?
        .join("gpg-bridge-gnupg");
    std::fs::create_dir(&home).context("无法创建独立验签目录（不会使用或覆盖已有目录）")?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&home, std::fs::Permissions::from_mode(0o700))?;
    }
    let mut home_guard = CreatedDir {
        path: home.clone(),
        keep: false,
    };
    let local = Gpg {
        program: gpg.clone(),
        homedir: Some(home.clone()),
        timeout: Duration::from_secs(30),
        passphrase: None,
    };
    let out = local
        .run(
            &[
                "--batch".into(),
                "--no-autostart".into(),
                "--dearmor".into(),
            ],
            public_keys.as_bytes(),
        )
        .await?;
    if !out.status.success() {
        let _ = std::fs::remove_dir_all(&home);
        bail!(
            "导入验签公钥失败：{}",
            util::display(&String::from_utf8_lossy(&out.stderr))
        )
    }
    ensure!(
        !out.stdout.is_empty() && out.stdout.len() <= MAX_DATA,
        "无效公钥数据"
    );
    util::write_new_private(&home.join("pubring.gpg"), &out.stdout)?;
    let exe = std::env::current_exe()?.canonicalize()?;
    let exe_str = exe.to_str().context("可执行文件路径必须是 UTF-8")?;
    let config_str = path.to_str().context("配置路径必须是 UTF-8")?;
    // Git's GPG setting accepts an executable PATH, not a shell command.
    // Use a private generated shim so spaces/quotes in paths work correctly.
    let wrapper_path = path
        .parent()
        .context("缺少 Git 目录")?
        .join("gpg-bridge-wrapper.sh");
    let wrapper = wrapper_path
        .to_str()
        .context("适配器路径必须为 UTF-8")?
        .to_owned();
    let script = format!(
        "#!/bin/sh\n# Generated by gpg-bridge; contains no credentials.\nexec {} gpg --bridge-config {} \"$@\"\n",
        shell_quote(exe_str),
        shell_quote(config_str)
    );
    util::write_new_private(&wrapper_path, script.as_bytes())?;
    let mut wrapper_guard = CreatedFile {
        path: wrapper_path,
        keep: false,
    };
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&wrapper_guard.path, std::fs::Permissions::from_mode(0o700))?;
    }
    let installed: BTreeMap<String, Vec<String>> = BTreeMap::from([
        ("gpg.format".into(), vec!["openpgp".into()]),
        ("gpg.openpgp.program".into(), vec![wrapper.clone()]),
        ("gpg.program".into(), vec![wrapper]),
        (
            "user.signingkey".into(),
            vec![format!("{}!", key.fingerprint)],
        ),
        ("commit.gpgsign".into(), vec!["true".into()]),
    ]);
    let mut previous = BTreeMap::new();
    for key in installed.keys() {
        previous.insert(key.clone(), get_config(key).await?);
    }
    let config = Config {
        ticket,
        key: key.clone(),
        gpg_program: gpg,
        verify_home: home,
        previous,
        installed,
    };
    let data = Zeroizing::new(serde_json::to_vec_pretty(&config)?);
    util::write_new_private(&path, &data)?;
    home_guard.keep = true;
    wrapper_guard.keep = true;
    for (key, values) in &config.installed {
        if let Err(error) = set_config(key, values).await {
            for (k, v) in &config.previous {
                let _ = set_config(k, v).await;
            }
            // Keep credential config so disconnect can restore/clean up explicitly.
            return Err(error.context("Git 配置失败，已尝试恢复；请运行 disconnect 清理"));
        }
    }
    eprintln!(
        "已配置当前仓库：{} / {}",
        util::display(&key.uid),
        key.fingerprint
    );
    eprintln!(
        "{} 个身份获授权；Git 默认使用第一个。需要切换时可设置 user.signingkey 为另一获授权完整指纹加 !。",
        keys.len()
    );
    eprintln!("私钥留在 Windows；验签在本机完成；恢复配置：gpg-bridge disconnect");
    Ok(())
}

pub fn resolve_program(program: PathBuf) -> Result<PathBuf> {
    if program.is_absolute() {
        return Ok(program);
    }
    if program.components().count() > 1 {
        return Ok(std::env::current_dir()?.join(program));
    }
    if let Some(path) = std::env::var_os("PATH") {
        for dir in std::env::split_paths(&path) {
            let candidate = dir.join(&program);
            if candidate.is_file() {
                return Ok(candidate.canonicalize()?);
            }
            #[cfg(windows)]
            {
                let candidate = candidate.with_extension("exe");
                if candidate.is_file() {
                    return Ok(candidate.canonicalize()?);
                }
            }
        }
    }
    bail!(
        "找不到 GnuPG：{}；请安装或通过 --gpg 指定",
        program.display()
    )
}

pub async fn disconnect() -> Result<()> {
    let path = path().await?;
    // Expired tickets must still be removable.
    let bytes = read_config(&path)?;
    let c: Config = serde_json::from_slice(&bytes)?;
    for (key, old) in &c.previous {
        if let Some(installed) = c.installed.get(key)
            && get_config(key).await? == *installed
        {
            set_config(key, old).await?;
        } else {
            eprintln!("保留后来手工修改的 Git 配置：{key}");
        }
    }
    // Never delete a path supplied by a modified config: derive the owned location.
    let home = path
        .parent()
        .context("缺少配置目录")?
        .join("gpg-bridge-gnupg");
    if c.verify_home == home && home.exists() {
        std::fs::remove_dir_all(home)?;
    }
    let wrapper = path
        .parent()
        .context("缺少配置目录")?
        .join("gpg-bridge-wrapper.sh");
    if wrapper.exists() {
        std::fs::remove_file(wrapper)?;
    }
    std::fs::remove_file(path)?;
    eprintln!("已恢复当前仓库配置并删除本地连接凭证。");
    Ok(())
}
pub async fn status() -> Result<()> {
    let c = load(&path().await?)?;
    let Response::Info { keys, expires, .. } = rpc(&c.ticket, &Request::Info).await? else {
        bail!("服务响应类型错误")
    };
    eprintln!(
        "连接正常；剩余 {} 秒；{} 个获授权签名身份",
        expires.saturating_sub(util::now()),
        keys.len()
    );
    for key in keys {
        eprintln!("{} / {}", util::display(&key.uid), key.fingerprint);
    }
    Ok(())
}

pub async fn gpg_wrapper(mut args: Vec<String>) -> Result<i32> {
    ensure!(
        args.len() >= 2 && args[0] == "--bridge-config",
        "内部调用缺少 --bridge-config"
    );
    let path = PathBuf::from(args.remove(1));
    args.remove(0);
    // Verification works locally even AFTER session expiry/offline.
    let bytes = read_config(&path)?;
    let c: Config = serde_json::from_slice(&bytes)?;
    if args.iter().any(|a| a == "--verify") {
        let mut command = Command::new(&c.gpg_program);
        let exit = command
            .arg("--homedir")
            .arg(&c.verify_home)
            .arg("--no-auto-key-retrieve")
            .arg("--no-autostart")
            .args(&args)
            .stdin(Stdio::inherit())
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .status()
            .await?;
        return Ok(exit.code().unwrap_or(1));
    }
    c.ticket.validate()?;
    let fingerprint = parse_sign_args(&args)?.unwrap_or_else(|| c.key.fingerprint.clone());
    ensure!(valid_fingerprint(&fingerprint), "Git 必须使用完整指纹");
    let mut data = Vec::new();
    std::io::stdin()
        .take((MAX_DATA + 1) as u64)
        .read_to_end(&mut data)?;
    ensure!(
        !data.is_empty() && data.len() <= MAX_DATA,
        "待签名内容超过 1 MiB 或为空"
    );
    let response = rpc(
        &c.ticket,
        &Request::Sign {
            fingerprint,
            data: encode(&data),
        },
    )
    .await?;
    match response {
        Response::Signed { signature, status } => {
            ensure!(
                signature.starts_with("-----BEGIN PGP SIGNATURE-----")
                    && status
                        .lines()
                        .any(|l| l.starts_with("[GNUPG:] SIG_CREATED ")),
                "无效签名响应"
            );
            std::io::stdout().write_all(signature.as_bytes())?;
            // Only protocol status lines, never server-provided terminal text.
            for line in status.lines() {
                if line.starts_with("[GNUPG:] ") {
                    eprintln!("{}", util::display(line));
                }
            }
            Ok(0)
        }
        _ => bail!("服务响应类型错误"),
    }
}

fn parse_sign_args(args: &[String]) -> Result<Option<String>> {
    let mut key = None;
    let mut signing = false;
    let mut detach = false;
    let mut armor = false;
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--status-fd=2" | "--batch" | "--no-tty" | "-" => (),
            "--status-fd" => ensure!(
                iter.next().map(String::as_str) == Some("2"),
                "只支持 status-fd=2"
            ),
            "--detach-sign" => {
                signing = true;
                detach = true;
            }
            "--armor" => armor = true,
            "--local-user" | "-u" => {
                key = Some(
                    iter.next()
                        .context("缺少签名钥匙")?
                        .trim_end_matches('!')
                        .to_uppercase(),
                )
            }
            s if s.starts_with('-') && !s.starts_with("--") => {
                for flag in s[1..].chars() {
                    match flag {
                        'b' => {
                            signing = true;
                            detach = true;
                        }
                        's' => signing = true,
                        'a' => armor = true,
                        'u' => {
                            key = Some(
                                iter.next()
                                    .context("缺少签名钥匙")?
                                    .trim_end_matches('!')
                                    .to_uppercase(),
                            )
                        }
                        _ => bail!("不支持的 GPG 签名参数"),
                    }
                }
            }
            _ => bail!("不支持的 GPG 签名参数"),
        }
    }
    ensure!(
        signing && detach && armor,
        "只支持 armored detached signatures"
    );
    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn git_signing_arguments_and_command_rejection() {
        let key = "A".repeat(40);
        let args = vec![
            "--status-fd=2".into(),
            "-bsau".into(),
            format!("{key}!"),
            "-".into(),
        ];
        assert_eq!(parse_sign_args(&args).unwrap(), Some(key));
        for args in [
            vec!["--decrypt".into()],
            vec!["-bsau".into()],
            vec!["--status-fd=1".into(), "-bsa".into()],
        ] {
            assert!(parse_sign_args(&args).is_err());
        }
    }
    #[cfg(unix)]
    #[test]
    fn credentials_refuse_open_permissions_and_symlinks() {
        use std::os::unix::fs::{PermissionsExt, symlink};
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("client.json");
        util::write_new_private(&path, b"{}").unwrap();
        assert!(read_config(&path).is_ok());
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(read_config(&path).is_err());
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        let link = dir.path().join("link.json");
        symlink(&path, &link).unwrap();
        assert!(read_config(&link).is_err());
        assert!(util::write_new_private(&path, b"replacement").is_err());
    }

    #[test]
    fn shell_paths_are_quoted() {
        assert_eq!(shell_quote("a'b"), "'a'\\''b'");
    }
}
