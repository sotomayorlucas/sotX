//! Built-in: `ps` — list active processes.
//!
//! TODO: replace stub with real listing once sotsh runs under sotOS — will
//! use `sys::thread_info` (syscall 140) + `sys::thread_count` (syscall 142)
//! to enumerate threads from `sotos-common::sys`. Host-std build cannot
//! reach these.
//!
//! Required capabilities: `proc:list` (see [`super::required_caps`]).

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn returns_table_with_two_rows() {
        let mut ctx = Context::new().unwrap();
        let v = run(&[], &mut ctx).unwrap();
        let Value::Table(rows) = v else {
            panic!("expected Table");
        };
        assert_eq!(rows.len(), 2);
    }

    #[test]
    fn first_row_has_pid_1_init() {
        let mut ctx = Context::new().unwrap();
        let v = run(&[], &mut ctx).unwrap();
        let Value::Table(rows) = v else {
            panic!("expected Table");
        };
        let first = &rows[0];
        let pid = &first.cells.iter().find(|(k, _)| k == "pid").unwrap().1;
        let name = &first.cells.iter().find(|(k, _)| k == "name").unwrap().1;
        assert!(matches!(pid, Value::Int(1)));
        match name {
            Value::Str(s) => assert_eq!(s, "init"),
            _ => panic!("expected Str"),
        }
    }
}
