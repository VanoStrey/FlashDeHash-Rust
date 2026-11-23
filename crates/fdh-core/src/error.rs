use thiserror::Error;

#[derive(Debug, Error)]
pub enum FdhError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("Unknown hash algorithm: {0}")]
    UnknownAlgorithm(String),

    #[error("Invalid alphabet: {0}")]
    InvalidAlphabet(String),

    #[error("Invalid hex hash: {0}")]
    InvalidHex(String),

    #[error("Invalid .fdh file format: {0}")]
    InvalidFormat(String),

    #[error("Legacy dictionary error: {0}")]
    LegacyError(String),

    #[error("Encoding error: {0}")]
    Encoding(String),
}

pub type Result<T> = std::result::Result<T, FdhError>;
