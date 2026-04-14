//! Built-in: `bg` — resume a stopped job in the background (B4b).
//!
//! Arg: job id (integer). With no arg, picks the most recently registered
//! job. Currently a **stub** — requires `sys::thread_resume` + the job to
//! have actually been backgrounded (`tid != 0`). See `fg.rs` for the
//! shared rationale.
//!
//! Required capabilities: none.

use crate::context::{Context, JobState};
use crate::error::Error;
use crate::value::Value;

pub fn run(args: &[Value], ctx: &mut Context) -> Result<Value, Error> {
    let target = resolve_target(args, ctx)?;
    let job = &mut ctx.jobs[target];

    if job.tid == 0 {
        return Err(Error::Other(
            "bg: job was registered as a stub (tid=0); real backgrounding not wired yet",
        ));
    }

    // Placeholder: a real implementation would call `sys::thread_resume`.
    // Flip the state optimistically so `jobs` reflects the user intent
    // once the syscall wiring lands.
    job.state = JobState::Running;
    Err(Error::Other(
        "bg: sys::thread_resume not exposed to userspace yet",
    ))
}

fn resolve_target(args: &[Value], ctx: &Context) -> Result<usize, Error> {
    super::resolve_job_target("bg", args, ctx)
}
