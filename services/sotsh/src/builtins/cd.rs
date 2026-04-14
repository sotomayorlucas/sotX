//! Built-in: `cd` — change the shell's working directory.
//!
//! Wave-2 seam. Replace the body of [`run`] with the real implementation.
//! Required capabilities: none (see [`super::required_caps`]).

use crate::context::Context;
use crate::error::Error;
use crate::value::Value;

pub fn run(_args: &[Value], _ctx: &mut Context) -> Result<Value, Error> {
    Ok(Value::Str("not implemented".into()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stub_returns_not_implemented() {
        let mut ctx = Context::new().unwrap();
        let v = run(&[], &mut ctx).unwrap();
        if let Value::Str(s) = v {
            assert_eq!(s, "not implemented");
        } else {
            panic!("expected Str");
        }
    }
}
