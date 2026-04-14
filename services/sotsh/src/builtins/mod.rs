//! Built-in command registry and dispatch.
//!
//! # Contract for Wave-2 workers
//!
//! Each Wave-2 worker fills in exactly ONE of the modules below by
//! replacing the body of `pub fn run(...)` in its stub. Do not touch
//! anything else in this crate from a Wave-2 PR.
//!
//! Adding a new built-in after Wave-2 requires three edits here:
//! 1. a `pub mod <name>;` line,
//! 2. a match arm in [`required_caps`],
//! 3. a match arm in [`dispatch`].

pub mod arm;
pub mod cap;
pub mod cat;
pub mod cd;
pub mod export;
pub mod ls;
pub mod lua;
pub mod ps;
pub mod jobs;
pub mod fg;
pub mod bg;

use alloc::string::ToString;

use crate::context::Context;
use crate::error::Error;
use crate::value::Value;

/// Shared `fg`/`bg` argv parser: returns the vector index into `ctx.jobs`
/// for the target job. With no arg, picks the most recently registered
/// job; with an `Int`/`Str` arg, looks up by user-visible id.
///
/// `name` is the builtin's own name ("fg" or "bg") — used only to select
/// the right `&'static str` error so `Error::Other` can carry it.
pub(crate) fn resolve_job_target(
    name: &'static str,
    args: &[Value],
    ctx: &Context,
) -> Result<usize, Error> {
    let (no_jobs, no_such, bad_int) = match name {
        "fg" => (
            "fg: no background jobs",
            "fg: no such job",
            "fg: job id must be an integer",
        ),
        _ => (
            "bg: no background jobs",
            "bg: no such job",
            "bg: job id must be an integer",
        ),
    };
    if ctx.jobs.is_empty() {
        return Err(Error::Other(no_jobs));
    }
    let id: u32 = match args.get(0) {
        None => return Ok(ctx.jobs.len() - 1),
        Some(Value::Int(n)) => *n as u32,
        Some(Value::Str(s)) => s.parse().map_err(|_| Error::BadArgs(bad_int.to_string()))?,
        Some(_) => return Err(Error::BadArgs(bad_int.to_string())),
    };
    ctx.job_index_by_id(id).ok_or(Error::Other(no_such))
}

/// Capabilities a built-in must hold before it is allowed to run.
///
/// Returned strings are capability *names* (e.g. `"fs:read"`). The real
/// capability check is performed by the dispatcher against the active
/// [`Context`] — this function is just the advertised requirement.
pub fn required_caps(name: &str) -> &'static [&'static str] {
    match name {
        "ls" => &["fs:read"],
        "cat" => &["fs:read"],
        "cd" => &[],
        "ps" => &["proc:list"],
        "cap" => &[],
        "arm" => &["deception:read"],
        "export" => &[],
        "eval" | "lua" => &[],
        "jobs" => &[],
        "fg" => &[],
        "bg" => &[],
        _ => &[],
    }
}

/// Dispatch a single command to its built-in implementation.
///
/// The ls/cat/cd bodies are stubbed pending B2a (they will be rewritten
/// over `sotos_common::sys` syscalls); ps/cap/arm remain as the hardcoded
/// placeholders from Wave-2.
pub fn dispatch(name: &str, args: &[Value], ctx: &mut Context) -> Result<Value, Error> {
    match name {
        "ls" => ls::run(args, ctx),
        "cat" => cat::run(args, ctx),
        "cd" => cd::run(args, ctx),
        "ps" => ps::run(args, ctx),
        "cap" => cap::run(args, ctx),
        "arm" => arm::run(args, ctx),
        "export" => export::run(args, ctx),
        "eval" | "lua" => lua::run(args, ctx),
        "jobs" => jobs::run(args, ctx),
        "fg" => fg::run(args, ctx),
        "bg" => bg::run(args, ctx),
        other => Err(Error::UnknownBuiltin(other.to_string())),
    }
}
