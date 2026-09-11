use serde::Serialize;
use thiserror::Error;

/// Machine-readable failure from decode or argument validation.
#[derive(Debug, Clone, PartialEq, Eq, Error, Serialize)]
#[error("{kind}: {message}")]
pub struct Error {
    #[serde(rename = "error")]
    pub kind: ErrorKind,
    pub message: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorKind {
    #[error("unknown_hrp")]
    UnknownHrp,
    #[error("invalid_argument")]
    InvalidArgument,
    #[error("decode_failed")]
    DecodeFailed,
}

impl Error {
    pub fn new(kind: ErrorKind, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
        }
    }
}
