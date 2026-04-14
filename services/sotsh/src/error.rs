//! sotSh error type.
//!
//! `Error` is independent of `std::io` — this crate is `no_std`. The `Io`
//! variant carries a raw errno (negative `i32` as returned by sotOS
//! syscalls via `sotos_common::sys`).

use alloc::string::String;
use core::fmt;

#[derive(Debug)]
pub enum Error {
    ParseError(String),
    CapDenied(&'static str),
    UnknownBuiltin(String),
    BadArgs(String),
    /// Raw errno from a `sotos_common::sys` call. Kept as an `i32` so
    /// built-ins can forward whatever the kernel actually returned
    /// without lossy mapping to a bespoke error enum.
    Io(i32),
    Other(&'static str),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::ParseError(s) => write!(f, "parse error: {s}"),
            Error::CapDenied(c) => write!(f, "capability denied: {c}"),
            Error::UnknownBuiltin(n) => write!(f, "unknown built-in: {n}"),
            Error::BadArgs(s) => write!(f, "bad arguments: {s}"),
            Error::Io(e) => write!(f, "io: errno {e}"),
            Error::Other(s) => write!(f, "{s}"),
        }
    }
}
