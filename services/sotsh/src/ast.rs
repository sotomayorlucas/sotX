//! Abstract syntax tree for sotSh.
//!
//! A parsed command line is a [`Pipeline`] of one or more [`Command`]s. Each
//! `Command` is a name, evaluated [`Value`] args, plus optional stdin/stdout
//! redirects attached to its ends.
//!
//! Future work: extend `Ast` with `Let`, `Assign`, `If`, `Graph(DagId)`, etc.

use alloc::string::String;
use alloc::vec::Vec;

use crate::value::Value;

/// Top-level parsed form.
#[derive(Debug, Clone)]
pub enum Ast {
    /// One or more commands joined by `|`. Always non-empty for valid input.
    Pipeline(Pipeline),
}

/// A pipeline: `cmd1 | cmd2 | ... | cmdN`.
///
/// `commands` is guaranteed non-empty by the parser. Stdin redirects are
/// only meaningful on `commands[0]`; stdout redirects only on the last
/// command. The parser accepts them anywhere syntactically but the runtime
/// may warn / error if placed mid-pipeline.
#[derive(Debug, Clone)]
pub struct Pipeline {
    pub commands: Vec<Command>,
}

/// A single invocation: `name arg1 arg2 ...` plus optional redirections.
#[derive(Debug, Clone)]
pub struct Command {
    pub name: String,
    pub args: Vec<Value>,
    /// `< path` — read input from `path` before the command runs.
    pub stdin: Option<Redirect>,
    /// `> path` or `>> path` — send rendered output to `path`.
    pub stdout: Option<Redirect>,
    /// `true` when the stdout redirect was `>>` (append), `false` for `>`.
    pub append: bool,
    /// Command-scoped `VAR=val` prefixes (à la bash). Parsed before the
    /// command name; merged into the runtime env for this command only.
    /// When the command name is empty, these are set as permanent
    /// assignments in `ctx.env` instead (handled by the runtime).
    pub prefix_env: Vec<(String, String)>,
}

/// Where a redirection sources / sinks data.
///
/// Only file redirection is supported today. Future variants: `Fd(u64)`
/// (dup an existing fd), `Null` (for `2>/dev/null`), `Cap(CapRef)` (native
/// sotOS capability handle).
#[derive(Debug, Clone)]
pub enum Redirect {
    File(String),
}
