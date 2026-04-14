//! Built-in: `cap` — inspect the current process's capability set.
//!
//! TODO: replace stub once sotsh runs under sotOS. Will enumerate the
//! per-thread capability table via a syscall (TBD — candidates:
//! `sotos-common::sys` inventory of cap-related calls). Host-std build
//! has no access to sotOS caps.
//!
//! Future row schema (once real):
//!   `[("cap_id", Value::Int), ("type", Value::Str), ("rights", Value::Str)]`
//!
//! Required capabilities: none (see [`super::required_caps`]).

use crate::context::Context;
use crate::error::Error;
use crate::value::Value;

pub fn run(_args: &[Value], _ctx: &mut Context) -> Result<Value, Error> {
    Ok(Value::Table(Vec::new()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn returns_empty_table_on_host() {
        let mut ctx = Context::new().unwrap();
        let v = run(&[], &mut ctx).unwrap();
        if let Value::Table(rows) = v {
            assert!(rows.is_empty());
        } else {
            panic!("expected Table");
        }
    }

    #[test]
    fn returns_ok_not_error() {
        let mut ctx = Context::new().unwrap();
        assert!(run(&[], &mut ctx).is_ok());
    }
}
