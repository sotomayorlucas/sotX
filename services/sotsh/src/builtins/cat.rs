//! Built-in: `cat` — concatenate and print file contents.
//!
//! Required capabilities: `fs:read` (see [`super::required_caps`]).
//!
//! B2a: rewritten over `sotos_common::vfs::{vfs_open, vfs_read,
//! vfs_close}`. Paths are resolved against `ctx.cwd` when relative.
//! Reads are looped in 4 KiB chunks up to a 1 MiB safety cap so a
//! runaway file can't exhaust the shell's heap. Only UTF-8 text is
//! supported; binary payloads return [`Error::BadArgs`].

use alloc::string::String;
use alloc::vec::Vec;

use sotos_common::vfs::{vfs_close, vfs_open, vfs_read};

use crate::context::Context;
use crate::error::Error;
use crate::value::Value;

/// Linux `O_RDONLY`.
const O_RDONLY: u64 = 0;

/// Read buffer per `vfs_read` call. `vfs_read` itself loops over 56 B IPC
/// chunks internally; we still batch here to amortise the outer call.
const READ_CHUNK: usize = 4096;

/// Hard cap on accumulated file size. Protects the shell's heap from a
/// pathologically large file; callers wanting more should stream.
const MAX_FILE_BYTES: usize = 1024 * 1024;

pub fn run(args: &[Value], ctx: &mut Context) -> Result<Value, Error> {
    let path = match args.first() {
        Some(Value::Str(s)) => s,
        _ => return Err(Error::BadArgs(String::from("cat requires a path"))),
    };

    // Resolve relative paths against ctx.cwd. Absolute paths pass through.
    let mut resolved: Vec<u8> = Vec::new();
    if path.as_bytes().first().copied() == Some(b'/') {
        resolved.extend_from_slice(path.as_bytes());
    } else {
        resolved.extend_from_slice(ctx.cwd.as_bytes());
        if resolved.last().copied() != Some(b'/') {
            resolved.push(b'/');
        }
        resolved.extend_from_slice(path.as_bytes());
    }

    let open = vfs_open(&resolved, O_RDONLY).map_err(|e| Error::Io(e as i32))?;
    let fd = open.fd;

    let mut data: Vec<u8> = Vec::new();
    let mut chunk = [0u8; READ_CHUNK];
    loop {
        let remaining = MAX_FILE_BYTES.saturating_sub(data.len());
        if remaining == 0 {
            break;
        }
        let want = remaining.min(READ_CHUNK);
        let n = match vfs_read(fd, &mut chunk[..want]) {
            Ok(n) => n,
            Err(e) => {
                let _ = vfs_close(fd);
                return Err(Error::Io(e as i32));
            }
        };
        if n == 0 {
            break;
        }
        data.extend_from_slice(&chunk[..n]);
        if n < want {
            break;
        }
    }

    let _ = vfs_close(fd);

    let text = String::from_utf8(data)
        .map_err(|_| Error::BadArgs(String::from("non-UTF-8 file — cat only supports text")))?;
    Ok(Value::Str(text))
}
