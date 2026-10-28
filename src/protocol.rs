use anyhow::{Context, Result, bail, ensure};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD as B64};
use serde::{Deserialize, Serialize};
use snow::{Builder, HandshakeState, TransportState};
use zeroize::{Zeroize, ZeroizeOnDrop};

pub const PATTERN: &str = "Noise_NKpsk0_25519_ChaChaPoly_BLAKE2s";
pub const MAX_DATA: usize = 1024 * 1024;
pub const MAX_WIRE: usize = 2 * 1024 * 1024;
const CHUNK: usize = 60_000;
const PROLOGUE: &[u8] = b"gpg-bridge rpc v1";

pub fn encode(data: &[u8]) -> String {
    B64.encode(data)
}
pub fn decode(s: &str) -> Result<Vec<u8>> {
    B64.decode(s).context("无效的 base64url")
}
pub fn random32() -> [u8; 32] {
    rand::random()
}

#[derive(Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(deny_unknown_fields)]
pub struct Ticket {
    pub version: u32,
    pub endpoint: String,
    pub server_public: String,
    pub psk: String,
    pub session: String,
    pub expires: u64,
}
impl Ticket {
    pub fn pack(&self) -> Result<String> {
        Ok(format!(
            "gpgbridge:v1:{}",
            encode(&serde_json::to_vec(self)?)
        ))
    }
    pub fn unpack(s: &str) -> Result<Self> {
        ensure!(s.len() <= 8192, "连接串过长");
        let raw = s
            .strip_prefix("gpgbridge:v1:")
            .context("连接串前缀应为 gpgbridge:v1:")?;
        let ticket: Self = serde_json::from_slice(&decode(raw)?)?;
        ticket.validate()?;
        Ok(ticket)
    }
    pub fn validate(&self) -> Result<()> {
        ensure!(self.version == 1, "不支持的协议版本");
        ensure!(
            self.expires > crate::util::now(),
            "会话已过期，请重新启动 Windows 服务"
        );
        ensure!(
            decode(&self.server_public)?.len() == 32 && decode(&self.psk)?.len() == 32,
            "无效的连接密钥"
        );
        ensure!(
            !self.session.is_empty() && self.session.len() <= 128,
            "无效的会话 ID"
        );
        let url = url::Url::parse(&self.endpoint)?;
        ensure!(
            matches!(url.scheme(), "http" | "https") && url.host_str().is_some(),
            "端点必须是 HTTP/HTTPS 地址"
        );
        ensure!(
            url.username().is_empty()
                && url.password().is_none()
                && url.query().is_none()
                && url.fragment().is_none(),
            "端点不能含凭证、查询或 fragment"
        );
        ensure!(matches!(url.path(), "" | "/"), "端点路径必须为 /");
        Ok(())
    }
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct SigningKey {
    pub primary: String,
    pub fingerprint: String,
    pub uid: String,
    pub expires: u64,
    pub hardware: bool,
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
pub enum Request {
    Info,
    Sign { fingerprint: String, data: String },
}
#[derive(Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "snake_case", deny_unknown_fields)]
pub enum Response {
    Info {
        session: String,
        expires: u64,
        keys: Vec<SigningKey>,
        public_keys: String,
    },
    Signed {
        signature: String,
        status: String,
    },
    Error {
        message: String,
    },
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Hello {
    pub session: String,
    pub message: String,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Welcome {
    pub id: String,
    pub message: String,
}

pub fn initiator(ticket: &Ticket) -> Result<HandshakeState> {
    let remote = decode(&ticket.server_public)?;
    let psk = zeroize::Zeroizing::new(decode(&ticket.psk)?);
    Ok(Builder::new(PATTERN.parse()?)
        .prologue(PROLOGUE)?
        .remote_public_key(&remote)?
        .psk(0, psk.as_slice().try_into()?)?
        .build_initiator()?)
}
pub fn responder(private: &[u8], psk: &[u8]) -> Result<HandshakeState> {
    Ok(Builder::new(PATTERN.parse()?)
        .prologue(PROLOGUE)?
        .local_private_key(private)?
        .psk(0, psk.try_into()?)?
        .build_responder()?)
}

/// Frame authenticated transport messages. Decrypt the WHOLE body before execution.
/// Framing is bounded; request/response is one logical payload with one final parse.
pub fn seal(noise: &mut TransportState, plain: &[u8]) -> Result<Vec<u8>> {
    ensure!(
        !plain.is_empty() && plain.len() <= MAX_WIRE - 4096,
        "消息大小超出限制"
    );
    // Encrypted length prefix prevents an intermediary truncating a valid frame suffix.
    let mut payload = Vec::with_capacity(8 + plain.len());
    payload.extend_from_slice(&(plain.len() as u64).to_be_bytes());
    payload.extend_from_slice(plain);
    let mut out = Vec::new();
    let mut buf = vec![0; 65_535];
    for chunk in payload.chunks(CHUNK) {
        let n = noise.write_message(chunk, &mut buf)?;
        out.extend_from_slice(&(n as u32).to_be_bytes());
        out.extend_from_slice(&buf[..n]);
    }
    ensure!(out.len() <= MAX_WIRE, "消息过长");
    Ok(out)
}
pub fn open(noise: &mut TransportState, mut wire: &[u8]) -> Result<Vec<u8>> {
    ensure!(
        !wire.is_empty() && wire.len() <= MAX_WIRE,
        "消息大小超出限制"
    );
    let mut out = Vec::new();
    let mut buf = vec![0; 65_535];
    while !wire.is_empty() {
        ensure!(wire.len() >= 4, "不完整帧");
        let n = u32::from_be_bytes(wire[..4].try_into()?) as usize;
        wire = &wire[4..];
        ensure!((16..=65_535).contains(&n) && wire.len() >= n, "无效帧长度");
        let len = noise.read_message(&wire[..n], &mut buf)?;
        out.extend_from_slice(&buf[..len]);
        wire = &wire[n..];
    }
    ensure!(out.len() >= 8, "缺少完整消息长度");
    let expected = u64::from_be_bytes(out[..8].try_into()?);
    ensure!(expected == (out.len() - 8) as u64, "消息被截断或追加");
    Ok(out.split_off(8))
}

pub fn response_ok(response: Response) -> Result<Response> {
    match response {
        Response::Error { message } => {
            bail!("Windows 服务拒绝：{}", crate::util::display(&message))
        }
        other => Ok(other),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn pair() -> (TransportState, TransportState) {
        let k = Builder::new(PATTERN.parse().unwrap())
            .generate_keypair()
            .unwrap();
        let psk = random32();
        let ticket = Ticket {
            version: 1,
            endpoint: "http://127.0.0.1:1".into(),
            server_public: encode(&k.public),
            psk: encode(&psk),
            session: "test".into(),
            expires: u64::MAX,
        };
        let mut a = initiator(&ticket).unwrap();
        let mut b = responder(&k.private, &psk).unwrap();
        let mut buf = [0; 1024];
        let n = a.write_message(&[], &mut buf).unwrap();
        b.read_message(&buf[..n], &mut [0; 1024]).unwrap();
        let n = b.write_message(&[], &mut buf).unwrap();
        a.read_message(&buf[..n], &mut [0; 1024]).unwrap();
        (
            a.into_transport_mode().unwrap(),
            b.into_transport_mode().unwrap(),
        )
    }
    #[test]
    fn large_payload_tamper_truncation_and_replay() {
        let (mut a, mut b) = pair();
        let plain = vec![42; MAX_DATA];
        let wire = seal(&mut a, &plain).unwrap();
        assert_eq!(open(&mut b, &wire).unwrap(), plain);
        assert!(open(&mut b, &wire).is_err());
        let (mut a, mut b) = pair();
        let mut wire = seal(&mut a, &plain).unwrap();
        wire[20] ^= 1;
        assert!(open(&mut b, &wire).is_err());
        let (mut a, mut b) = pair();
        let wire = seal(&mut a, &plain).unwrap();
        let first = u32::from_be_bytes(wire[..4].try_into().unwrap()) as usize;
        assert!(open(&mut b, &wire[..4 + first]).is_err());
    }
    #[test]
    fn wrong_psk_and_server_identity_fail() {
        let k = Builder::new(PATTERN.parse().unwrap())
            .generate_keypair()
            .unwrap();
        let t = Ticket {
            version: 1,
            endpoint: "https://example.com".into(),
            server_public: encode(&k.public),
            psk: encode(&random32()),
            session: "test".into(),
            expires: u64::MAX,
        };
        let mut a = initiator(&t).unwrap();
        let mut b = responder(&k.private, &random32()).unwrap();
        let mut buf = [0; 1024];
        let n = a.write_message(&[], &mut buf).unwrap();
        assert!(b.read_message(&buf[..n], &mut [0; 1024]).is_err());
        let other = Builder::new(PATTERN.parse().unwrap())
            .generate_keypair()
            .unwrap();
        let mut a = initiator(&t).unwrap();
        let mut b = responder(&other.private, &decode(&t.psk).unwrap()).unwrap();
        let n = a.write_message(&[], &mut buf).unwrap();
        assert!(b.read_message(&buf[..n], &mut [0; 1024]).is_err());
    }
    #[test]
    fn ticket_rejects_unsafe_endpoints() {
        let mut t = Ticket {
            version: 1,
            endpoint: "https://example.com".into(),
            server_public: encode(&random32()),
            psk: encode(&random32()),
            session: "x".into(),
            expires: u64::MAX,
        };
        assert!(t.validate().is_ok());
        for endpoint in [
            "file:///etc/passwd",
            "https://user:secret@example.com",
            "https://example.com/path",
            "https://example.com?token=x",
        ] {
            t.endpoint = endpoint.into();
            assert!(t.validate().is_err());
        }
    }
}
