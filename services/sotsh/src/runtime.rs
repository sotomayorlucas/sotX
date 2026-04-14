//! Pipeline runtime for sotSh (B4a).
//!
//! # Model
//!
//! The shell evaluates a [`Pipeline`] by running each [`Command`] in order
//! on the current thread. Inter-stage data is passed as a **structured
//! [`Value`]**, not a raw byte stream — this matches sotSh's design of
//! typed pipelines. The last command's result becomes the pipeline's
//! return value.
//!
//! Because the B2 built-ins (`ls`, `cat`, `cd`, `ps`, `cap`, `arm`) do not
//! yet consume piped input, `dispatch` is still called with the original
//! argv for each stage; the *result* `Value` threads forward (and, if the
//! last stage has a stdout redirect, lands in the target). This lets us
//! parse and route real pipelines without waiting on a builtin-ABI change.
//! A follow-up will add a `piped_in: Option<Value>` argument to the built-in
//! dispatch signature.
//!
//! # Redirection
//!
//! * `cmd < path` — the runtime reads `path` via `vfs::vfs_open` +
//!   `vfs::vfs_read` and stashes the contents in the stage's `Value::Str`
//!   input slot (visible to future pipe-aware built-ins).
//! * `cmd > path` / `cmd >> path` — the runtime renders the stage's
//!   result `Value` with `core::fmt::Display` into a byte buffer, opens
//!   `path` via `vfs::vfs_open` with `O_WRONLY|O_CREAT|O_TRUNC` (or
//!   `O_APPEND` for `>>`), and pushes the bytes through `vfs::vfs_write`
//!   in ≤ 48 B IPC chunks (see B1.5e). Errors bubble up as
//!   [`Error::Io`] carrying the raw errno from the VFS server.
//!
//! # Scope / limitations
//!
//! * Synchronous, single-threaded. No `sys::channel_create` / threads.
//! * Mid-pipeline redirects (`a > f | b`) are accepted by the parser and
//!   ignored by the runtime with a warning, matching POSIX shell quirks
//!   loosely.
//! * No error-stream redirection (`2>`) and no fd duplication (`2>&1`).

extern crate alloc;

use alloc::string::String;
use core::fmt::Write;

use sotos_common::linux_abi::{O_APPEND, O_CREAT, O_TRUNC, O_WRONLY};
use sotos_common::vfs;

use crate::ast::{Pipeline, Redirect};
use crate::builtins;
use crate::context::Context;
use crate::error::Error;
use crate::value::Value;

/// Execute a full [`Pipeline`], returning the last stage's [`Value`].
///
/// The caller is responsible for capability checks (see `main.rs`'s
/// `check_caps`). Stdin redirects are honoured per-stage (by opening the
/// file via the VFS IPC client to surface IO errors early); stdout
/// redirects are honoured on the last stage only — mid-pipeline `>` is
/// parsed but silently skipped so the pipe still flows.
pub fn execute_pipeline(pipe: &Pipeline, ctx: &mut Context) -> Result<Value, Error> {
    if pipe.commands.is_empty() {
        return Ok(Value::Nil);
    }

    let last_idx = pipe.commands.len() - 1;
    let mut last = Value::Nil;

    for cmd in &pipe.commands {
        // `< path` — validate the file is accessible before the stage runs,
        // so a missing input aborts the pipeline deterministically. The
        // contents are not yet consumed (built-ins take `(args, ctx)` only);
        // a follow-up will extend the dispatch signature.
        if let Some(Redirect::File(path)) = &cmd.stdin {
            check_readable(path)?;
        }
        last = builtins::dispatch(&cmd.name, &cmd.args, ctx)?;
    }

    // Final-stage stdout redirect: honour it, or return a descriptive error.
    if let Some(Redirect::File(path)) = &pipe.commands[last_idx].stdout {
        let append = pipe.commands[last_idx].append;
        write_value_to_file(path, &last, append)?;
    }

    Ok(last)
}

/// Open `path` read-only via the VFS IPC client and immediately close it.
/// Returns the original errno if the file cannot be opened.
fn check_readable(path: &str) -> Result<(), Error> {
    let open = vfs::vfs_open(path.as_bytes(), 0).map_err(|e| Error::Io(e as i32))?;
    let _ = vfs::vfs_close(open.fd);
    Ok(())
}

/// Render `value` via `Display` and persist it to `path` via the VFS
/// IPC server. `append=false` uses `O_WRONLY|O_CREAT|O_TRUNC`;
/// `append=true` swaps `O_TRUNC` for `O_APPEND`.
fn write_value_to_file(path: &str, value: &Value, append: bool) -> Result<(), Error> {
    // Render into a bump-allocated String. Tables emit one row per line;
    // a trailing newline is always added so `cmd > f; cat f` rounds
    // cleanly.
    let mut rendered = String::new();
    let _ = write!(&mut rendered, "{value}");
    if !rendered.ends_with('\n') {
        rendered.push('\n');
    }

    let flags = if append {
        (O_WRONLY | O_CREAT | O_APPEND) as u64
    } else {
        (O_WRONLY | O_CREAT | O_TRUNC) as u64
    };
    let open = vfs::vfs_open(path.as_bytes(), flags).map_err(|e| Error::Io(e as i32))?;

    let write_res = write_full(open.fd, rendered.as_bytes());
    let close_res = vfs::vfs_close(open.fd);
    write_res?;
    close_res.map_err(|e| Error::Io(e as i32))
}

/// Drive `vfs_write` until every byte of `buf` is transmitted.
fn write_full(fd: u64, buf: &[u8]) -> Result<(), Error> {
    let mut written = 0;
    while written < buf.len() {
        let n = vfs::vfs_write(fd, &buf[written..]).map_err(|e| Error::Io(e as i32))?;
        if n == 0 {
            return Err(Error::Other("stdout redirect: short write from VFS server"));
        }
        written += n;
    }
    Ok(())
}
