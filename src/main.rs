use anyhow::{Context, Result, ensure};
use clap::{Parser, Subcommand};
use gpg_bridge::{
    client,
    gpg::{self, Gpg},
    server,
};
use std::{net::SocketAddr, path::PathBuf, time::Duration};

#[derive(Parser)]
#[command(
    version,
    about = "将 Git 签名请求安全地发送到 Windows 上的 GnuPG agent"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}
#[derive(Subcommand)]
enum Commands {
    /// 在有私钥的电脑上运行；默认每次签名都在本机确认
    Serve {
        /// 监听地址；默认只监听回环，适合 Tailscale Serve/Funnel
        #[arg(long, default_value = "127.0.0.1:17389")]
        bind: SocketAddr,
        /// 云端能访问的 HTTP/HTTPS 根地址；省略时按监听地址或 Tailscale 主机名推导
        #[arg(long)]
        endpoint: Option<String>,
        /// 会话有效期（秒），最大 86400
        #[arg(long, default_value_t = 28800)]
        ttl: u64,
        /// 明确允许本会话自动签名，不逐次确认
        #[arg(long)]
        auto_approve: bool,
        /// 允许签署不符合 Git commit/tag 格式的通用数据
        #[arg(long)]
        allow_data: bool,
        /// 强制重新显示交互式身份选择
        #[arg(long)]
        choose: bool,
        /// 高级选项：完整主钥/子钥指纹，可重复；通常无需指定
        #[arg(long)]
        key: Vec<String>,
        #[arg(long, default_value = "gpg")]
        gpg: PathBuf,
        #[arg(long)]
        homedir: Option<PathBuf>,
        #[arg(long, default_value_t = 120)]
        gpg_timeout: u64,
        /// 日志文件（必须为新文件，不包含配对凭证）
        #[arg(long)]
        log_file: Option<PathBuf>,
        /// 显示待签名原文前 300 字符（转义控制字符）
        #[arg(long)]
        verbose: bool,
    },
    /// 在云端仓库中运行，从 stdin 粘贴连接串并配置当前仓库
    Connect {
        #[arg(long)]
        ticket_file: Option<PathBuf>,
        #[arg(long, default_value = "gpg")]
        gpg: PathBuf,
    },
    /// 验证连接并列出本会话允许的签名身份
    Status,
    /// 恢复当前仓库原有配置，删除本地凭证；过期后也能使用
    Disconnect,
    /// Git 内部调用入口，请勿手工调用
    #[command(hide = true)]
    Gpg {
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },
}

fn main() {
    let runtime = tokio::runtime::Runtime::new().expect("create async runtime");
    let code = match runtime.block_on(run()) {
        Ok(code) => code,
        Err(error) => {
            eprintln!(
                "gpg-bridge: {}",
                gpg_bridge::util::display(&format!("{error:#}"))
            );
            1
        }
    };
    // Returning from the runtime aborts outstanding async signing processes.
    // Never process::exit inside an active runtime: child kill_on_drop must run.
    drop(runtime);
    if code != 0 {
        std::process::exit(code);
    }
}
async fn run() -> Result<i32> {
    match Cli::parse().command {
        Commands::Serve {
            bind,
            endpoint,
            ttl,
            auto_approve,
            allow_data,
            choose,
            key,
            gpg,
            homedir,
            gpg_timeout,
            log_file,
            verbose,
        } => {
            ensure!(
                gpg_timeout > 0 && gpg_timeout <= 600,
                "--gpg-timeout 必须为 1 至 600 秒"
            );
            let gpg = Gpg {
                program: locate_gpg(gpg)?,
                homedir,
                timeout: Duration::from_secs(gpg_timeout),
            };
            let keys = gpg::select_keys(&gpg, &key, !choose).await?;
            let endpoint = match endpoint {
                Some(e) => e,
                None => default_endpoint(bind).await?,
            };
            server::run(server::Options {
                bind,
                endpoint,
                ttl,
                auto_approve,
                allow_data,
                verbose,
                log_file,
                keys,
                gpg,
            })
            .await?;
        }
        Commands::Connect { ticket_file, gpg } => client::connect(ticket_file, gpg).await?,
        Commands::Disconnect => client::disconnect().await?,
        Commands::Status => client::status().await?,
        Commands::Gpg { args } => return client::gpg_wrapper(args).await,
    }
    Ok(0)
}
fn locate_gpg(program: PathBuf) -> Result<PathBuf> {
    if let Ok(path) = client::resolve_program(program.clone()) {
        return Ok(path);
    }
    #[cfg(windows)]
    {
        if program != PathBuf::from("gpg") {
            return client::resolve_program(program);
        }
        for root in ["ProgramFiles(x86)", "ProgramFiles", "LOCALAPPDATA"] {
            if let Some(dir) = std::env::var_os(root) {
                for relative in [
                    "GnuPG/bin/gpg.exe",
                    "Gpg4win/bin/gpg.exe",
                    "Programs/GnuPG/bin/gpg.exe",
                ] {
                    let p = PathBuf::from(&dir).join(relative);
                    if p.is_file() {
                        return Ok(p);
                    }
                }
            }
        }
    }
    client::resolve_program(program)
}
async fn default_endpoint(bind: SocketAddr) -> Result<String> {
    if !bind.ip().is_loopback() && !bind.ip().is_unspecified() {
        return Ok(format!("http://{bind}"));
    }
    let output = tokio::process::Command::new("tailscale")
        .args(["status", "--json"])
        .output()
        .await
        .context("无法自动发现 Tailscale；请用 --endpoint 指定云端能访问的地址")?;
    ensure!(
        output.status.success(),
        "请先连接 Tailscale，或用 --endpoint 指定地址"
    );
    let value: serde_json::Value = serde_json::from_slice(&output.stdout)?;
    let dns = value
        .get("Self")
        .and_then(|v| v.get("DNSName"))
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .context("无法取得 Tailscale DNS 名称；请用 --endpoint 指定")?;
    if bind.ip().is_loopback() {
        eprintln!(
            "使用 Tailscale HTTPS 地址；请另开终端运行 tailscale serve {}。",
            bind.port()
        );
        Ok(format!("https://{}", dns.trim_end_matches('.')))
    } else {
        anyhow::bail!("通配监听需要 --endpoint 明确指定云端地址")
    }
}
