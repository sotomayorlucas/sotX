//! Built-in: `ls` — list directory contents.
//!
//! Lists entries of a directory as a [`Value::Table`] with columns
//! `name`, `kind`, `size`. Required capabilities: `fs:read` (see
//! [`super::required_caps`]).

use crate::context::Context;
use crate::error::Error;
use crate::value::{Row, Value};

/// List the contents of a directory.
///
/// The first argument (if a [`Value::Str`]) names the directory; otherwise
/// `"."` is used. Relative paths are anchored at [`Context::cwd`];
/// absolute paths are used as-is (this is how [`std::path::PathBuf::join`]
/// behaves).
pub fn run(args: &[Value], ctx: &mut Context) -> Result<Value, Error> {
    let raw = match args.get(0) {
        Some(Value::Str(s)) => s.as_str(),
        _ => ".",
    };
    let path = ctx.cwd.join(raw);

    let mut rows = Vec::new();
    for entry in std::fs::read_dir(&path)? {
        let entry = entry?;
        let name = entry.file_name().to_string_lossy().into_owned();
        let ft = entry.file_type()?;
        let kind = if ft.is_dir() {
            "dir"
        } else if ft.is_file() {
            "file"
        } else if ft.is_symlink() {
            "symlink"
        } else {
            "other"
        };
        let size = entry.metadata()?.len() as i64;
        rows.push(
            Row::new()
                .with("name", Value::Str(name))
                .with("kind", Value::Str(kind.into()))
                .with("size", Value::Int(size)),
        );
    }

    Ok(Value::Table(rows))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row_name(row: &Row) -> Option<&str> {
        for (k, v) in &row.cells {
            if k == "name" {
                if let Value::Str(s) = v {
                    return Some(s.as_str());
                }
            }
        }
        None
    }

    fn table_names(v: &Value) -> Vec<String> {
        match v {
            Value::Table(rows) => rows
                .iter()
                .filter_map(|r| row_name(r).map(str::to_owned))
                .collect(),
            _ => Vec::new(),
        }
    }

    #[test]
    fn lists_current_dir_contains_cargo_toml() {
        let mut ctx = Context::new().unwrap();
        let v = run(&[], &mut ctx).expect("ls . should succeed");
        let names = table_names(&v);
        assert!(
            names.iter().any(|n| n == "Cargo.toml"),
            "expected Cargo.toml in {names:?}"
        );
    }

    #[test]
    fn lists_specified_path_arg() {
        let mut ctx = Context::new().unwrap();
        let v = run(&[Value::Str("src".into())], &mut ctx).expect("ls src should succeed");
        let names = table_names(&v);
        for expected in ["main.rs", "lib.rs", "parser.rs"] {
            assert!(
                names.iter().any(|n| n == expected),
                "expected {expected} in {names:?}"
            );
        }
    }

    #[test]
    fn returns_io_error_for_missing_dir() {
        let mut ctx = Context::new().unwrap();
        let err = run(
            &[Value::Str("/definitely/does/not/exist/12345".into())],
            &mut ctx,
        )
        .expect_err("missing dir must error");
        assert!(
            matches!(err, Error::Io(_)),
            "expected Error::Io, got {err:?}"
        );
    }
}
