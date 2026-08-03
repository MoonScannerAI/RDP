use thiserror::Error;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Error)]
pub enum Error {
    #[error("protocol violation: {0}")]
    Protocol(String),
    #[error("message too large: {got} bytes (limit {limit})")]
    Oversized { got: usize, limit: usize },
    #[error("invalid message: {0}")]
    Invalid(String),
    #[error("unsupported protocol version {0}")]
    Version(u16),
    #[error("authentication failed: {0}")]
    Auth(String),
    #[error("pairing failed: {0}")]
    Pairing(String),
    #[error("transport: {0}")]
    Transport(String),
    #[error("serialization: {0}")]
    Serde(String),
    #[error("crypto: {0}")]
    Crypto(String),
    #[error("capture: {0}")]
    Capture(String),
    #[error("encoder: {0}")]
    Encoder(String),
    #[error("decoder: {0}")]
    Decoder(String),
    #[error("input: {0}")]
    Input(String),
    #[error("service ipc: {0}")]
    SvcIpc(String),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("{0}")]
    Other(String),
}

impl From<postcard::Error> for Error {
    fn from(e: postcard::Error) -> Self {
        Error::Serde(e.to_string())
    }
}
