//! Built-in: `cat` — concatenate and print file contents.
//!
//! Required capabilities: `fs:read` (see [`super::required_caps`]).

use crate::context::Context;
use crate::error::Error;
use crate::value::Value;

pub fn run(args: &[Value], ctx: &mut Context) -> Result<Value, Error> {
    let path = match args.get(0) {
        Some(Value::Str(p)) => p,
        _ => return Err(Error::BadArgs("cat requires a path argument".into())),
    };

    // `PathBuf::join` returns the argument unchanged when it is absolute,
    // so this handles both absolute and relative inputs.
    let contents = std::fs::read_to_string(ctx.cwd.join(path))?;
    Ok(Value::Str(contents))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_cargo_toml() {
        let mut ctx = Context::new().unwrap();
        let v = run(&[Value::Str("Cargo.toml".into())], &mut ctx).unwrap();
        let Value::Str(s) = v else { panic!("expected Str") };
        assert!(s.contains("[package]"));
    }

    #[test]
    fn returns_bad_args_without_path() {
        let mut ctx = Context::new().unwrap();
        let err = run(&[], &mut ctx).unwrap_err();
        assert!(matches!(err, Error::BadArgs(_)));
    }

    #[test]
    fn returns_io_error_for_missing_file() {
        let mut ctx = Context::new().unwrap();
        let err = run(
            &[Value::Str("/definitely/does/not/exist/12345".into())],
            &mut ctx,
        )
        .unwrap_err();
        assert!(matches!(err, Error::Io(_)));
    }
}
