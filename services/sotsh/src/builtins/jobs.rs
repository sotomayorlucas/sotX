//! Built-in: `jobs` — list background jobs (B4b).
//!
//! Emits one [`Row`] per entry in [`Context::jobs`] with `id`, `state`,
//! and `pipeline` cells. Empty table when no jobs are registered.
//!
//! Required capabilities: none.

use alloc::vec::Vec;

use crate::context::Context;
use crate::error::Error;
use crate::value::{Row, Value};

pub fn run(_args: &[Value], ctx: &mut Context) -> Result<Value, Error> {
    let mut rows: Vec<Row> = Vec::new();
    for job in &ctx.jobs {
        rows.push(
            Row::new()
                .with("id", Value::Int(job.id as i64))
                .with("state", Value::Str(job.state.as_str().into()))
                .with("pipeline", Value::Str(job.pipeline.clone())),
        );
    }
    Ok(Value::Table(rows))
}
