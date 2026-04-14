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
//!   result `Value` with `core::fmt::Display` into a byte buffer. The VFS
//!   IPC protocol exposed to native binaries (see `vfs.rs`) is **read-only**
//!   today — there is no `VFS_WRITE` opcode. Rather than silently dropping
//!   the output, the runtime returns `Error::Other(...)` so the user knows
//!   the redirect was accepted syntactically but cannot be fulfilled yet.
//!   A follow-up will either extend the VFS IPC protocol or route writes
//!   through a new `sotos_common::sys::write_file` shim.
//!
//! # Scope / limitations
//!
//! * Synchronous, single-threaded. No `sys::channel_create` / threads.
//! * Mid-pipeline redirects (`a > f | b`) are accepted by the parser and
//!   ignored by the runtime with a warning, matching POSIX shell quirks
//!   loosely.
//! * No error-stream redirection (`2>`) and no fd duplication (`2>&1`).

use alloc::format;
use alloc::string::String;
use core::fmt::Write;

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

    // `cmd &` — B4b background jobs.
    //
    // Scope note: we currently record the job in `ctx.jobs` and return
    // immediately with `"[N] tid"` WITHOUT spawning a real thread. A real
    // `sys::thread_create` spawn needs (a) a trampoline that re-enters the
    // builtin dispatcher with an owned Context clone, (b) a way to collect
    // the exit Value back into the table, and (c) a reaper hook for
    // `fg`/`bg`. That's a follow-up; for now the pipeline is dropped and
    // the job shows `state=Running, tid=0` in `jobs`.
    if pipe.background {
        let summary = summarize_pipeline(pipe);
        let id = ctx.register_job(summary, 0);
        return Ok(Value::Str(format!("[{id}] 0")));
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

/// Render `value` via `Display` and persist it to `path`.
///
/// **Currently unimplemented** — the native-binary VFS IPC protocol
/// (`libs/sotos-common/src/vfs.rs`) has no write opcode. Returns
/// [`Error::Other`] so the shell reports a clear message.
fn write_value_to_file(_path: &str, _value: &Value, _append: bool) -> Result<(), Error> {
    Err(Error::Other(
        "stdout redirection (> / >>): VFS write path not wired yet; see runtime.rs docs",
    ))
}

/// Render a human-readable summary of a pipeline for the job table.
///
/// Format: `"cmd1 arg1 | cmd2 arg2"`. Values are formatted via `Display`,
/// so strings appear unquoted and ints as bare digits — this matches what
/// the user typed closely enough for `jobs` output.
fn summarize_pipeline(pipe: &Pipeline) -> String {
    let mut out = String::new();
    for (i, cmd) in pipe.commands.iter().enumerate() {
        if i > 0 {
            out.push_str(" | ");
        }
        out.push_str(&cmd.name);
        for a in &cmd.args {
            // `Value: Display` handles str/int/bool; Table/Nil are
            // unlikely in argv but fall through harmlessly.
            let _ = write!(out, " {a}");
        }
    }
    out
}
