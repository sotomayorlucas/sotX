//! Built-in: `cd` — change the shell's working directory.
//!
//! Resolves the target path (absolute or relative to `ctx.cwd`), canonicalizes
//! it (which verifies existence and resolves symlinks), and mutates `ctx.cwd`.
//! Required capabilities: none (see [`super::required_caps`]).

use std::path::PathBuf;

use crate::context::Context;
use crate::error::Error;
use crate::value::Value;

pub fn run(args: &[Value], ctx: &mut Context) -> Result<Value, Error> {
    let target: PathBuf = match args.get(0) {
        Some(Value::Str(path)) => PathBuf::from(path),
        _ => PathBuf::from("/"),
    };

    let resolved = if target.is_absolute() {
        target
    } else {
        ctx.cwd.join(target)
    };

    let canonical = resolved.canonicalize()?;
    ctx.cwd = canonical;
    Ok(Value::Str(ctx.cwd.display().to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cd_to_src_updates_cwd() {
        let mut ctx = Context::new().unwrap();
        ctx.cwd = std::env::current_dir().unwrap();
        run(&[Value::Str("src".into())], &mut ctx).unwrap();
        assert!(ctx.cwd.display().to_string().ends_with("src"));
    }

    #[test]
    fn cd_dotdot_goes_up() {
        let mut ctx = Context::new().unwrap();
        ctx.cwd = std::env::current_dir().unwrap();
        run(&[Value::Str("..".into())], &mut ctx).unwrap();
        assert!(ctx.cwd.display().to_string().ends_with("services"));
    }

    #[test]
    fn cd_missing_returns_io_error() {
        let mut ctx = Context::new().unwrap();
        let r = run(
            &[Value::Str("/definitely/does/not/exist".into())],
            &mut ctx,
        );
        assert!(matches!(r, Err(Error::Io(_))));
    }
}
