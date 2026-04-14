//! Abstract syntax tree for sotSh.
//!
//! A parsed command line is a [`Pipeline`](Ast::Pipeline) of one or more
//! [`Command`]s. Each `Command` is a name plus evaluated [`Value`] args.
//!
//! Future work: extend `Ast` with `Let`, `Assign`, `If`, `Graph(DagId)`, etc.

use crate::value::Value;

/// Top-level parsed form.
#[derive(Debug, Clone)]
pub enum Ast {
    /// One or more commands joined by `|`. Always non-empty for valid input.
    Pipeline(Vec<Command>),
}

/// A single invocation: `name arg1 arg2 ...`.
#[derive(Debug, Clone)]
pub struct Command {
    pub name: String,
    pub args: Vec<Value>,
}
