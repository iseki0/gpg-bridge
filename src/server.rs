use crate::{
    gpg::Gpg,
    protocol::{self, *},
    util,
};
use anyhow::{Context, Result, ensure};
use axum::{
    Router,
    body::{Body, Bytes, to_bytes},
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
    routing::post,
};
use sha2::{Digest, Sha256};
use std::{
    collections::HashMap,
    fs::File,
    io::Write,
    net::SocketAddr,
    path::PathBuf,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use tokio::sync::{Semaphore, mpsc, oneshot};
use zeroize::Zeroizing;

pub struct Options {
    pub bind: SocketAddr,
    pub endpoint: String,
    pub ttl: u64,
    pub auto_approve: bool,
    pub allow_data: bool,
    pub verbose: bool,
    pub log_file: Option<PathBuf>,
    pub keys: Vec<SigningKey>,
    pub gpg: Gpg,
}
#[derive(Clone)]
pub struct Audit(Arc<Mutex<Option<File>>>);
impl Audit {
    fn new(path: Option<&PathBuf>) -> Result<Self> {
        let file = if let Some(p) = path {
            Some(
                std::fs::OpenOptions::new()
                    .create_new(true)
                    .write(true)
                    .open(p)
                    .context("日志文件必须为新文件")?,
            )
        } else {
            None
        };
        Ok(Self(Arc::new(Mutex::new(file))))
    }
    pub fn log(&self, text: &str) {
        let line = format!(
            "{} {}",
            chrono::Local::now().format("%Y-%m-%d %H:%M:%S"),
            text
        );
        eprintln!("{line}");
        if let Ok(mut guard) = self.0.lock()
            && let Some(file) = guard.as_mut()
        {
            let _ = writeln!(file, "{line}");
            let _ = file.flush();
        }
    }
}
struct Pending {
    created: Instant,
    noise: snow::TransportState,
}
struct Confirm {
    summary: String,
    deadline: Instant,
    reply: oneshot::Sender<bool>,
}
struct Shared {
    ticket: Ticket,
    private: Zeroizing<Vec<u8>>,
    psk: Zeroizing<Vec<u8>>,
    gpg: Gpg,
    keys: Vec<SigningKey>,
    public_keys: String,
    pending: Mutex<HashMap<String, Pending>>,
    http: Semaphore,
    signing: Semaphore,
    rate: Mutex<(Instant, u32)>,
    confirm: mpsc::Sender<Confirm>,
    audit: Audit,
    auto_approve: bool,
    allow_data: bool,
    verbose: bool,
}
impl Shared {
    fn rate_allowed(&self) -> bool {
        let mut rate = self.rate.lock().unwrap();
        if rate.0.elapsed() >= Duration::from_secs(1) {
            *rate = (Instant::now(), 0);
        }
        rate.1 += 1;
        rate.1 <= 20
    }
}

pub async fn run(opts: Options) -> Result<()> {
    ensure!(
        (1..=24 * 60 * 60).contains(&opts.ttl),
        "会话有效期必须为 1 秒至 24 小时"
    );
    let audit = Audit::new(opts.log_file.as_ref())?;
    let pair = snow::Builder::new(PATTERN.parse()?).generate_keypair()?;
    let psk = Zeroizing::new(protocol::random32().to_vec());
    let ticket = Ticket {
        version: 1,
        endpoint: opts.endpoint.trim_end_matches('/').into(),
        server_public: encode(&pair.public),
        psk: encode(&psk),
        session: encode(&protocol::random32()[..16]),
        expires: util::now() + opts.ttl,
    };
    ticket.validate()?;
    let public_keys = opts.gpg.export_public(&opts.keys).await?;
    let listener = tokio::net::TcpListener::bind(opts.bind)
        .await
        .context("无法监听地址")?;
    let (tx, mut rx) = mpsc::channel::<Confirm>(1);
    // Dedicated OS thread, not a Tokio blocking task: expiry/Ctrl+C can exit even
    // while a terminal read is blocked. Late answers never authorize a new request.
    std::thread::spawn(move || {
        while let Some(c) = rx.blocking_recv() {
            if c.reply.is_closed() || Instant::now() >= c.deadline {
                continue;
            }
            eprintln!("{}", c.summary);
            let answer = util::prompt("允许此签名？[y/N]（120 秒内）：").unwrap_or_default();
            let ok = Instant::now() < c.deadline && answer.eq_ignore_ascii_case("y");
            let _ = c.reply.send(ok);
        }
    });
    let state = Arc::new(Shared {
        ticket: ticket.clone(),
        private: Zeroizing::new(pair.private),
        psk,
        gpg: opts.gpg,
        keys: opts.keys,
        public_keys,
        pending: Mutex::new(HashMap::new()),
        http: Semaphore::new(32),
        signing: Semaphore::new(1),
        rate: Mutex::new((Instant::now(), 0)),
        confirm: tx,
        audit: audit.clone(),
        auto_approve: opts.auto_approve,
        allow_data: opts.allow_data,
        verbose: opts.verbose,
    });
    let app = Router::new()
        .route("/v1/handshake", post(handshake))
        .route("/v1/rpc/{id}", post(rpc))
        .with_state(state);
    audit.log(&format!(
        "服务启动，监听 {}，有效期 {} 秒，模式：{}",
        listener.local_addr()?,
        opts.ttl,
        if opts.auto_approve {
            "自动签名（凭证持有者可请求签名）"
        } else {
            "逐次本机确认"
        }
    ));
    audit.log("下面的连接串是临时签名凭证，请只交给预期的云端任务；停止服务即撤销。");
    println!("{}", ticket.pack()?);
    std::io::stdout().flush()?;
    // No network input is used to select local executables, arguments, or paths.
    tokio::select! {
        result = async { axum::serve(listener, app).await } => { result?; },
        _ = tokio::signal::ctrl_c() => { audit.log("收到停止信号，会话撤销。"); },
        _ = tokio::time::sleep(Duration::from_secs(opts.ttl)) => { audit.log("会话到期，服务停止。"); },
    }
    Ok(())
}
async fn read_body(body: Body, max: usize) -> Result<Bytes, StatusCode> {
    tokio::time::timeout(Duration::from_secs(15), to_bytes(body, max))
        .await
        .map_err(|_| StatusCode::REQUEST_TIMEOUT)?
        .map_err(|_| StatusCode::PAYLOAD_TOO_LARGE)
}
async fn handshake(
    State(s): State<Arc<Shared>>,
    body: Body,
) -> Result<impl IntoResponse, StatusCode> {
    let _permit = s
        .http
        .try_acquire()
        .map_err(|_| StatusCode::TOO_MANY_REQUESTS)?;
    if !s.rate_allowed() {
        return Err(StatusCode::TOO_MANY_REQUESTS);
    }
    if util::now() >= s.ticket.expires {
        return Err(StatusCode::GONE);
    }
    let bytes = read_body(body, 4096).await?;
    let hello: Hello = serde_json::from_slice(&bytes).map_err(|_| StatusCode::BAD_REQUEST)?;
    if hello.session != s.ticket.session {
        s.audit.log("拒绝未知会话连接");
        return Err(StatusCode::UNAUTHORIZED);
    }
    let mut noise = responder(&s.private, &s.psk).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let message = decode(&hello.message).map_err(|_| StatusCode::BAD_REQUEST)?;
    let mut buf = [0; 4096];
    if noise.read_message(&message, &mut buf).is_err() {
        s.audit.log("客户端认证失败");
        return Err(StatusCode::UNAUTHORIZED);
    }
    let n = noise
        .write_message(&[], &mut buf)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let reply = encode(&buf[..n]);
    let noise = noise
        .into_transport_mode()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let mut pending = s.pending.lock().unwrap();
    pending.retain(|_, p| p.created.elapsed() < Duration::from_secs(30));
    if pending.len() >= 64 {
        return Err(StatusCode::TOO_MANY_REQUESTS);
    }
    let id = encode(&protocol::random32()[..16]);
    pending.insert(
        id.clone(),
        Pending {
            created: Instant::now(),
            noise,
        },
    );
    s.audit
        .log(&format!("认证成功，建立一次请求连接 {}", &id[..8]));
    Ok(axum::Json(Welcome { id, message: reply }))
}
async fn rpc(
    State(s): State<Arc<Shared>>,
    Path(id): Path<String>,
    body: Body,
) -> Result<impl IntoResponse, StatusCode> {
    let _permit = s
        .http
        .try_acquire()
        .map_err(|_| StatusCode::TOO_MANY_REQUESTS)?;
    if util::now() >= s.ticket.expires {
        return Err(StatusCode::GONE);
    }
    let mut pending = s
        .pending
        .lock()
        .unwrap()
        .remove(&id)
        .ok_or(StatusCode::UNAUTHORIZED)?;
    if pending.created.elapsed() >= Duration::from_secs(30) {
        return Err(StatusCode::GONE);
    }
    let wire = read_body(body, MAX_WIRE).await?;
    let plain = open(&mut pending.noise, &wire).map_err(|_| StatusCode::UNAUTHORIZED)?;
    let request: Request = serde_json::from_slice(&plain).map_err(|_| StatusCode::BAD_REQUEST)?;
    let response = handle(&s, &id, request).await;
    let wire = seal(
        &mut pending.noise,
        &serde_json::to_vec(&response).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?,
    )
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok((
        [(axum::http::header::CONTENT_TYPE, "application/octet-stream")],
        wire,
    ))
}
async fn handle(s: &Shared, id: &str, request: Request) -> Response {
    match request {
        Request::Info => {
            s.audit.log("客户端读取本会话签名身份与公钥");
            Response::Info {
                session: s.ticket.session.clone(),
                expires: s.ticket.expires,
                keys: s.keys.clone(),
                public_keys: s.public_keys.clone(),
            }
        }
        Request::Sign { fingerprint, data } => {
            let start = Instant::now();
            let result = sign_request(s, id, &fingerprint, &data).await;
            match result {
                Ok((signature, status)) => {
                    s.audit.log(&format!(
                        "请求 {} 签名成功，耗时 {:.2}s",
                        &id[..8],
                        start.elapsed().as_secs_f64()
                    ));
                    Response::Signed { signature, status }
                }
                Err(err) => {
                    s.audit.log(&format!(
                        "请求 {} 被拒绝/失败：{}",
                        &id[..8],
                        util::display(&err.to_string())
                    ));
                    Response::Error {
                        message:
                            "签名被拒绝、服务忙、会话过期或 GnuPG 操作失败；请查看 Windows 日志"
                                .into(),
                    }
                }
            }
        }
    }
}
async fn sign_request(
    s: &Shared,
    id: &str,
    fingerprint: &str,
    data: &str,
) -> Result<(String, String)> {
    let _permit = s.signing.try_acquire().context("已有签名请求进行中")?;
    ensure!(util::now() < s.ticket.expires, "会话已过期");
    let key = s
        .keys
        .iter()
        .find(|k| k.fingerprint == fingerprint)
        .context("请求使用未授权钥匙")?;
    let data = decode(data)?;
    ensure!(
        !data.is_empty() && data.len() <= MAX_DATA,
        "待签名内容必须在 1 字节至 1 MiB 之间"
    );
    let summary = summarize(&data);
    ensure!(
        s.allow_data || summary.is_some(),
        "默认只接受 Git commit/tag 格式；通用数据签名需要 --allow-data"
    );
    let digest = format!("{:x}", Sha256::digest(&data));
    let description = format!(
        "请求 {}：{}；{} 字节；SHA256={}\n签名身份：{} / {}",
        &id[..8],
        summary.unwrap_or_else(|| "通用数据签名".into()),
        data.len(),
        digest,
        util::display(&key.uid),
        key.fingerprint
    );
    s.audit.log(&description);
    if s.verbose {
        s.audit.log(&format!(
            "待签名原文（转义，最多 300 字符）：{}",
            util::display(&String::from_utf8_lossy(&data))
        ));
    }
    if !s.auto_approve {
        let (tx, rx) = oneshot::channel();
        let wait = Duration::from_secs(120.min(s.ticket.expires.saturating_sub(util::now())));
        s.confirm
            .try_send(Confirm {
                summary: format!("本机确认：请求 {}，SHA256={digest}", &id[..8]),
                deadline: Instant::now() + wait,
                reply: tx,
            })
            .context("确认界面忙")?;
        ensure!(
            tokio::time::timeout(wait, rx)
                .await
                .context("等待确认超时")?
                .unwrap_or(false),
            "用户拒绝签名"
        );
    }
    ensure!(util::now() < s.ticket.expires, "会话已过期");
    // A running GPG process must also be killed when this session expires.
    let remaining = Duration::from_secs(s.ticket.expires.saturating_sub(util::now()));
    tokio::time::timeout(remaining, s.gpg.sign(key, &data))
        .await
        .context("会话过期，终止签名")?
}

/// This is a format check and a display aid, NOT proof of repository or consent.
pub fn summarize(data: &[u8]) -> Option<String> {
    let text = std::str::from_utf8(data).ok()?;
    let (headers, message) = text.split_once("\n\n")?;
    let lines: Vec<_> = headers.lines().collect();
    let field = |name: &str| lines.iter().find_map(|l| l.strip_prefix(name));
    let hash = |s: &str| matches!(s.len(), 40 | 64) && s.bytes().all(|b| b.is_ascii_hexdigit());
    let subject = util::display(message.lines().next().unwrap_or(""));
    if field("tree ").is_some_and(hash)
        && field("author ").is_some()
        && field("committer ").is_some()
    {
        return Some(format!(
            "Git commit 格式；作者={}；说明={}",
            util::display(field("author ").unwrap()),
            subject
        ));
    }
    if field("object ").is_some_and(hash)
        && matches!(field("type "), Some("commit" | "tree" | "blob" | "tag"))
        && field("tag ").is_some()
        && field("tagger ").is_some()
    {
        return Some(format!(
            "Git tag 格式；标签={}；说明={}",
            util::display(field("tag ").unwrap()),
            subject
        ));
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn summarize_git_and_escape_hostile_messages() {
        let text = format!(
            "tree {}\nauthor A <a@b> 100 +0000\ncommitter A <a@b> 100 +0000\n\nfix\x1b[31m\n",
            "a".repeat(40)
        );
        let s = summarize(text.as_bytes()).unwrap();
        assert!(s.contains("Git commit"));
        assert!(!s.contains('\x1b'));
        assert!(summarize(b"arbitrary data").is_none());
    }
}
