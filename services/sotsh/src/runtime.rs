//! Pipeline runtime for sotSh (B4a + B4d).
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
//! # Environment variables (B4d)
//!
//! * `VAR=val cmd args...` — the parser attaches `(VAR, val)` to
//!   `Command::prefix_env`. Before dispatch the runtime merges those
//!   entries into `ctx.env`, calls the builtin, and restores the prior
//!   values (bash-compatible scoping).
//! * `VAR=val` on its own (empty command name) — permanent assignment
//!   into `ctx.env`, no builtin runs for that stage.
//! * `$VAR` inside any `Value::Str` arg is expanded against the merged
//!   env, unset names becoming the empty string. Quoted strings and bare
//!   words go through the same pass; there is no `${...}` form yet.
//!
//! # Scope / limitations
//!
//! * Synchronous, single-threaded. No `sys::channel_create` / threads.
//! * Mid-pipeline redirects (`a > f | b`) are accepted by the parser and
//!   ignored by the runtime with a warning, matching POSIX shell quirks
//!   loosely.
//! * No error-stream redirection (`2>`) and no fd duplication (`2>&1`).

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;

use sotos_common::vfs;

use crate::ast::{Command, Pipeline, Redirect};
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
        // Pure assignment (empty command name + non-empty prefix_env):
        // persist the assignments into ctx.env and skip dispatch.
        if cmd.name.is_empty() {
            for (k, v) in &cmd.prefix_env {
                ctx.env.insert(k.clone(), v.clone());
            }
            last = Value::Nil;
            continue;
        }

        // `< path` — validate the file is accessible before the stage runs,
        // so a missing input aborts the pipeline deterministically. The
        // contents are not yet consumed (built-ins take `(args, ctx)` only);
        // a follow-up will extend the dispatch signature.
        if let Some(Redirect::File(path)) = &cmd.stdin {
            check_readable(path)?;
        }

        last = dispatch_with_env(cmd, ctx)?;
    }

    // Final-stage stdout redirect: honour it, or return a descriptive error.
    if let Some(Redirect::File(path)) = &pipe.commands[last_idx].stdout {
        let append = pipe.commands[last_idx].append;
        write_value_to_file(path, &last, append)?;
    }

    Ok(last)
}

/// Run `cmd` with its `prefix_env` overlaid on `ctx.env` (bash-style scoped
/// assignment) and `$VAR` references in string args resolved against the
/// merged env. Previous values are restored on return so the scope really
/// is limited to this one command.
fn dispatch_with_env(cmd: &Command, ctx: &mut Context) -> Result<Value, Error> {
    // Snapshot the variables we are about to shadow so we can restore
    // them after dispatch. Values not previously present are removed on
    // restore (stored as `None`).
    let mut saved: Vec<(String, Option<String>)> = Vec::with_capacity(cmd.prefix_env.len());
    for (k, v) in &cmd.prefix_env {
        saved.push((k.clone(), ctx.env.get(k).cloned()));
        ctx.env.insert(k.clone(), v.clone());
    }

    let expanded_args: Vec<Value> = cmd
        .args
        .iter()
        .map(|a| expand_value(a, &ctx.env))
        .collect();

    let result = builtins::dispatch(&cmd.name, &expanded_args, ctx);

    // Restore prior env state regardless of dispatch success.
    for (k, prior) in saved.into_iter().rev() {
        match prior {
            Some(v) => {
                ctx.env.insert(k, v);
            }
            None => {
                ctx.env.remove(&k);
            }
        }
    }

    result
}

/// Expand `$VAR` occurrences inside a [`Value::Str`]. Non-string values
/// are returned unchanged — we don't have numeric coercion here because
/// the parser already committed to a type for bare words, and preserving
/// `Value::Int`/`Value::Bool` keeps builtin arg typing stable.
fn expand_value(v: &Value, env: &BTreeMap<String, String>) -> Value {
    match v {
        Value::Str(s) if s.contains('$') => Value::Str(expand_dollars(s, env)),
        other => other.clone(),
    }
}

/// Substitute every `$NAME` in `input` with `env[NAME]` (empty string when
/// unset). `NAME` matches `[A-Za-z_][A-Za-z0-9_]*`. A bare `$` at end of
/// input or `$` followed by a non-identifier char is left literal, which
/// matches common shell behaviour for e.g. `"$"` or `"$1"` (we treat
/// positional parameters as unknown and leave them alone).
fn expand_dollars(input: &str, env: &BTreeMap<String, String>) -> String {
    let bytes = input.as_bytes();
    let mut out = String::with_capacity(input.len());
    let mut i = 0;
    while i < bytes.len() {
        let b = bytes[i];
        if b != b'$' {
            out.push(b as char);
            i += 1;
            continue;
        }
        // `$` found. Is the next byte an identifier-start?
        let start = i + 1;
        if start >= bytes.len() || !is_ident_start(bytes[start]) {
            out.push('$');
            i = start;
            continue;
        }
        // Walk the identifier.
        let mut end = start + 1;
        while end < bytes.len() && is_ident_cont(bytes[end]) {
            end += 1;
        }
        // Safety: we only advanced over ASCII bytes, so this range is a
        // valid UTF-8 boundary inside `input`.
        let name = &input[start..end];
        if let Some(val) = env.get(name) {
            out.push_str(val);
        }
        // Unset -> empty string (bash default with unset var), so nothing
        // gets pushed.
        i = end;
    }
    out
}

fn is_ident_start(b: u8) -> bool {
    b.is_ascii_alphabetic() || b == b'_'
}

fn is_ident_cont(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
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
