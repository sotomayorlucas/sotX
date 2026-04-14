//! Built-in: `ps` — list active processes.
//!
//! TODO: replace stub with real listing once sotsh runs under sotOS — will
//! use `sys::thread_info` (syscall 140) + `sys::thread_count` (syscall 142)
//! to enumerate threads from `sotos-common::sys`.
//!
//! Required capabilities: `proc:list` (see [`super::required_caps`]).

use alloc::vec;

use crate::context::Context;
use crate::error::Error;
use crate::value::{Row, Value};

pub fn run(_args: &[Value], _ctx: &mut Context) -> Result<Value, Error> {
    let rows = vec![
        Row {
            cells: vec![
                ("pid".into(), Value::Int(1)),
                ("name".into(), Value::Str("init".into())),
                ("state".into(), Value::Str("R".into())),
            ],
        },
        Row {
            cells: vec![
                ("pid".into(), Value::Int(0)),
                ("name".into(), Value::Str("(stub)".into())),
                ("state".into(), Value::Str("S".into())),
            ],
        },
    ];
    Ok(Value::Table(rows))
}
