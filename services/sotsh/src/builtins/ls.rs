//! Built-in: `ls` — list directory contents.
//!
//! Required capabilities: `fs:read` (see [`super::required_caps`]).
//!
//! B2a: reimplemented over `sotos_common::vfs`. Opens the target directory
//! with `O_DIRECTORY | O_RDONLY`, loops `vfs_getdents64` until EOF (returns
//! `Ok(None)`), and emits one [`Row`] per entry with `name` / `kind` /
//! `size` cells. The VFS server returns only `oid`/`kind`/`name` per entry
//! (see `libs/sotos-common/src/vfs.rs`), so `size` is left as `Int(0)`.

use alloc::string::{String, ToString};
use alloc::vec::Vec;

use sotos_common::linux_abi::{O_DIRECTORY, O_RDONLY};
use sotos_common::vfs;

use crate::context::Context;
use crate::error::Error;
use crate::value::{Row, Value};

/// Defensive upper bound — no real sotFS directory approaches this, but it
/// prevents a runaway loop if the server ever regresses on EOF.
const MAX_ENTRIES: usize = 4096;

pub fn run(args: &[Value], ctx: &mut Context) -> Result<Value, Error> {
    let path = match args.get(0) {
        None => ctx.cwd.clone(),
        Some(Value::Str(s)) => resolve(&ctx.cwd, s),
        Some(_) => return Err(Error::BadArgs("ls: path must be a string".to_string())),
    };

    let flags = (O_DIRECTORY | O_RDONLY) as u64;
    let opened = vfs::vfs_open(path.as_bytes(), flags).map_err(errno_to_err)?;

    let mut rows: Vec<Row> = Vec::new();
    for _ in 0..MAX_ENTRIES {
        match vfs::vfs_getdents64(opened.fd) {
            Ok(None) => break,
            Ok(Some(entry)) => {
                let name_bytes = &entry.name[..entry.name_len];
                let name_str = match core::str::from_utf8(name_bytes) {
                    Ok(s) => s.to_string(),
                    Err(_) => lossy_ascii(name_bytes),
                };
                rows.push(
                    Row::new()
                        .with("name", Value::Str(name_str))
                        .with("kind", Value::Str(kind_label(entry.kind).to_string()))
                        .with("size", Value::Int(0)),
                );
            }
            Err(e) => {
                let _ = vfs::vfs_close(opened.fd);
                return Err(errno_to_err(e));
            }
        }
    }

    let _ = vfs::vfs_close(opened.fd);
    Ok(Value::Table(rows))
}

/// Join `cwd` and `arg` into an absolute path. Absolute `arg` wins.
fn resolve(cwd: &str, arg: &str) -> String {
    if arg.starts_with('/') {
        return arg.to_string();
    }
    let mut out = String::with_capacity(cwd.len() + 1 + arg.len());
    out.push_str(cwd);
    if !cwd.ends_with('/') {
        out.push('/');
    }
    out.push_str(arg);
    out
}

/// VFS server hands us kind 13 (file) / 14 (dir); anything else is "other".
fn kind_label(kind: u8) -> &'static str {
    match kind {
        13 => "file",
        14 => "dir",
        _ => "other",
    }
}

/// Replace non-ASCII / NUL bytes with `?` — good enough for `ls` display.
fn lossy_ascii(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len());
    for &b in bytes {
        if b.is_ascii() && b != 0 {
            out.push(b as char);
        } else {
            out.push('?');
        }
    }
    out
}

fn errno_to_err(e: i64) -> Error {
    Error::Io(e as i32)
}
