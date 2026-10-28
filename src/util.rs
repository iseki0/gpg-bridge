use anyhow::{Context, Result, bail};
use std::{
    io::{self, Write},
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

pub fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Escape terminal controls (including bidi controls) and bound hostile text.
pub fn display(s: &str) -> String {
    let mut out = String::new();
    for c in s.chars().take(300) {
        if c.is_control()
            || matches!(c, '\u{061c}' | '\u{200e}' | '\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}')
        {
            out.extend(c.escape_unicode());
        } else {
            out.push(c);
        }
    }
    if s.chars().count() > 300 {
        out.push('…');
    }
    out
}

pub fn prompt(label: &str) -> Result<String> {
    eprint!("{label}");
    io::stderr().flush()?;
    let mut input = String::new();
    if io::stdin().read_line(&mut input)? == 0 {
        bail!("输入已关闭 / stdin closed");
    }
    Ok(input.trim().to_owned())
}

pub fn state_dir() -> Result<PathBuf> {
    let p = directories::ProjectDirs::from("dev", "gpg-bridge", "gpg-bridge")
        .context("找不到用户配置目录")?
        .config_dir()
        .to_path_buf();
    std::fs::create_dir_all(&p)?;
    Ok(p)
}

/// Never follow an existing path or overwrite a credential file.
pub fn write_new_private(path: &Path, data: &[u8]) -> Result<()> {
    use std::fs::OpenOptions;
    let mut opts = OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts
        .open(path)
        .with_context(|| format!("无法创建 {}（不覆盖已有文件）", path.display()))?;
    f.write_all(data)?;
    f.sync_all()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn hostile_terminal_text_is_escaped() {
        let s = display("x\x1b[31m\n\u{202e}abc");
        assert!(!s.contains('\x1b'));
        assert!(!s.contains('\n'));
        assert!(!s.contains('\u{202e}'));
    }
}
