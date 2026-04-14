//! Built-in: `arm` — list active deception profiles.
//!
//! B2d: replaces the Wave-2 (#116) hardcoded 4-profile stub with a real
//! IPC query to the `"deception"` service hosted by sotos-init (see
//! `services/init/src/deception_service.rs`, landed in Wave B1.5d / PR
//! #124). The profile set still comes from
//! `personality/common/deception/src/profile.rs`, but the *active* flag
//! is now sourced from the runtime `ProfileRegistry` rather than
//! hard-coded.
//!
//! Wire protocol: `sotos_common::sys::deception_query_arms` — issues
//! `DECEPTION_QUERY_ARMS` ops in a loop until the server returns
//! `DECEPTION_EOT`. No heap allocation on the syscall path; the caller
//! provides a fixed `[DeceptionArm; DECEPTION_MAX_ARMS]` buffer.
//!
//! Required capabilities: `deception:read` (see [`super::required_caps`]).

use alloc::string::String;

use sotos_common::sys::{
    deception_query_arms, DeceptionArm, DECEPTION_MAX_ARMS,
};

use crate::context::Context;
use crate::error::Error;
use crate::value::{Row, Value};

pub fn run(_args: &[Value], _ctx: &mut Context) -> Result<Value, Error> {
    let mut buf = [DeceptionArm::empty(); DECEPTION_MAX_ARMS];
    let count = deception_query_arms(&mut buf).map_err(|e| Error::Io(e as i32))?;

    let rows = buf[..count]
        .iter()
        .map(|arm| {
            Row::new()
                .with("name", Value::Str(decode_name(arm.name_bytes())))
                .with("kind", Value::Str("profile".into()))
                .with("active", Value::Bool(arm.active))
        })
        .collect();
    Ok(Value::Table(rows))
}

/// Decode a NUL-padded profile name into an owned `String`. The server
/// already bounds `name_len <= 32` (see `DeceptionArm::name_bytes`), so
/// we only need to strip any trailing NUL bytes that slipped through and
/// fall back to lossy ASCII when the payload is not valid UTF-8.
fn decode_name(bytes: &[u8]) -> String {
    let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    let trimmed = &bytes[..end];
    match core::str::from_utf8(trimmed) {
        Ok(s) => String::from(s),
        Err(_) => trimmed
            .iter()
            .map(|&b| if (0x20..=0x7e).contains(&b) { b as char } else { '?' })
            .collect(),
    }
}
