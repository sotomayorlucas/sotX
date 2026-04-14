//! sotSh error type.

use core::fmt;

#[derive(Debug)]
pub enum Error {
    ParseError(String),
    CapDenied(&'static str),
    UnknownBuiltin(String),
    BadArgs(String),
    Io(std::io::Error),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::ParseError(s) => write!(f, "parse error: {s}"),
            Error::CapDenied(c) => write!(f, "capability denied: {c}"),
            Error::UnknownBuiltin(n) => write!(f, "unknown built-in: {n}"),
            Error::BadArgs(s) => write!(f, "bad arguments: {s}"),
            Error::Io(e) => write!(f, "io: {e}"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Error::Io(e)
    }
}
