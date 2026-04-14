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
pub mod ls;
pub mod ps;

use crate::context::Context;
use crate::error::Error;
use crate::value::Value;

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
        _ => &[],
    }
}

/// Dispatch a single command to its built-in implementation.
///
/// Wave-1 (this PR) wires up the routing only — each stub returns
/// `Value::Str("not implemented")`. Wave-2 workers replace those bodies.
pub fn dispatch(name: &str, args: &[Value], ctx: &mut Context) -> Result<Value, Error> {
    match name {
        "ls" => ls::run(args, ctx),
        "cat" => cat::run(args, ctx),
        "cd" => cd::run(args, ctx),
        "ps" => ps::run(args, ctx),
        "cap" => cap::run(args, ctx),
        "arm" => arm::run(args, ctx),
        other => Err(Error::UnknownBuiltin(other.into())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn required_caps_known_builtins() {
        assert_eq!(required_caps("ls"), &["fs:read"]);
        assert_eq!(required_caps("cat"), &["fs:read"]);
        assert_eq!(required_caps("cd"), &[] as &[&str]);
        assert_eq!(required_caps("ps"), &["proc:list"]);
        assert_eq!(required_caps("cap"), &[] as &[&str]);
        assert_eq!(required_caps("arm"), &["deception:read"]);
    }

    #[test]
    fn required_caps_unknown_returns_empty() {
        assert_eq!(required_caps("nope"), &[] as &[&str]);
    }

    #[test]
    fn dispatch_unknown_errors() {
        let mut ctx = Context::new().unwrap();
        let err = dispatch("nope", &[], &mut ctx).unwrap_err();
        matches!(err, Error::UnknownBuiltin(_));
    }
}
