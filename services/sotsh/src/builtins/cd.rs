//! Built-in: `cd` — change the shell's working directory.
//!
//! Required capabilities: none (see [`super::required_caps`]).
//!
//! B2a: implemented over `sotos_common::vfs::vfs_chdir`. The server side
//! (init's vfs_service) holds the authoritative per-client cwd; we mirror
//! the canonical path locally in `ctx.cwd` so relative-path joining and
//! prompt display stay in sync without a `vfs_getcwd` round-trip.

use alloc::string::{String, ToString};
use alloc::vec::Vec;

use sotos_common::vfs::vfs_chdir;

use crate::context::Context;
use crate::error::Error;
use crate::value::Value;

/// Join `cwd` and a relative `rel` path with a single `/` separator.
fn join_rel(cwd: &str, rel: &str) -> String {
    let mut out = String::with_capacity(cwd.len() + rel.len() + 1);
    out.push_str(cwd);
    if !out.ends_with('/') {
        out.push('/');
    }
    out.push_str(rel);
    out
}

/// Collapse `.`/`..`/duplicate slashes in an absolute path. The server
/// does the real canonicalization on chdir; this is only for the local
/// `ctx.cwd` mirror used by prompt/joining.
fn canonicalize_abs(path: &str) -> String {
    let mut stack: Vec<&str> = Vec::new();
    for seg in path.split('/') {
        match seg {
            "" | "." => {}
            ".." => {
                stack.pop();
            }
            s => stack.push(s),
        }
    }
    if stack.is_empty() {
        "/".to_string()
    } else {
        let mut out = String::new();
        for seg in &stack {
            out.push('/');
            out.push_str(seg);
        }
        out
    }
}

pub fn run(args: &[Value], ctx: &mut Context) -> Result<Value, Error> {
    let target_str: String = match args.first() {
        Some(Value::Str(p)) => p.clone(),
        Some(_) => return Err(Error::BadArgs("cd: expected string path".to_string())),
        None => "/".to_string(),
    };

    let absolute = if target_str.starts_with('/') {
        target_str
    } else {
        join_rel(&ctx.cwd, &target_str)
    };

    vfs_chdir(absolute.as_bytes()).map_err(|e| Error::Io(e as i32))?;

    ctx.cwd = canonicalize_abs(&absolute);
    Ok(Value::Str(ctx.cwd.clone()))
}
