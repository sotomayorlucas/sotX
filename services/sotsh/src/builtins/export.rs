//! Built-in: `export` — manage shell environment variables.
//!
//! Required capabilities: none.
//!
//! Behaviour:
//! - `export`               — list all env vars as a `Value::Table` with
//!                            columns `name:str` and `value:str`. Rows are
//!                            in the BTreeMap's natural (sorted) order.
//! - `export VAR=val ...`   — assign each `VAR=val` pair into `ctx.env`.
//!                            Returns `Value::Nil`.
//! - `export VAR`           — shorthand for "keep whatever value is in
//!                            `ctx.env[VAR]`"; no-op today because the
//!                            sotSh env is already the only env. Kept
//!                            quiet for bash muscle memory.
//!
//! Arguments arrive as already-evaluated [`Value`]s, so `FOO=42` in the
//! prompt arrives as `Value::Int(42)` *unless* quoted. We accept both and
//! stringify numbers so the stored value is always text.

use alloc::string::{String, ToString};
use alloc::vec::Vec;

use crate::context::Context;
use crate::error::Error;
use crate::value::{Row, Value};

pub fn run(args: &[Value], ctx: &mut Context) -> Result<Value, Error> {
    if args.is_empty() {
        return Ok(list_env(ctx));
    }

    for a in args {
        let s = value_to_string(a)?;
        let Some(eq) = s.find('=') else {
            // Bare `export VAR` — no-op, tolerated for compatibility.
            continue;
        };
        let (k, v) = s.split_at(eq);
        // Strip the leading `=` from the value side.
        let v = &v[1..];
        if k.is_empty() {
            return Err(Error::BadArgs(
                "export: VAR=val requires a non-empty VAR".to_string(),
            ));
        }
        ctx.env.insert(k.to_string(), v.to_string());
    }
    Ok(Value::Nil)
}

fn list_env(ctx: &Context) -> Value {
    let mut rows: Vec<Row> = Vec::with_capacity(ctx.env.len());
    for (k, v) in &ctx.env {
        rows.push(
            Row::new()
                .with("name", Value::Str(k.clone()))
                .with("value", Value::Str(v.clone())),
        );
    }
    Value::Table(rows)
}

/// Coerce an arg `Value` to its env-var textual form. `Value` already
/// implements `Display`, so we defer to `ToString` and only special-case
/// the disallowed `Table` input.
fn value_to_string(v: &Value) -> Result<String, Error> {
    match v {
        Value::Table(_) => Err(Error::BadArgs(
            "export: cannot assign a table to an env var".to_string(),
        )),
        other => Ok(other.to_string()),
    }
}
