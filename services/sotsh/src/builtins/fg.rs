//! Built-in: `fg` — bring a background job to the foreground (B4b).
//!
//! Arg: job id (integer). With no arg, picks the most recently registered
//! job. Currently a **stub** — real foregrounding requires
//! `sys::thread_suspend` / `thread_resume` plus a join path to collect the
//! backgrounded pipeline's exit value, neither of which is wired through
//! the native shell yet. Returns [`Error::Other`] when invoked on a
//! tid=0 (stub) job so the user sees a clear diagnostic.
//!
//! Required capabilities: none.

use crate::context::Context;
use crate::error::Error;
use crate::value::Value;

pub fn run(args: &[Value], ctx: &mut Context) -> Result<Value, Error> {
    let target = resolve_target(args, ctx)?;
    let job = &mut ctx.jobs[target];

    if job.tid == 0 {
        return Err(Error::Other(
            "fg: job was registered as a stub (tid=0); real backgrounding not wired yet",
        ));
    }

    // Placeholder: a real implementation would
    //   sys::thread_resume(job.tid);
    //   wait for the thread to exit;
    //   remove the entry from ctx.jobs.
    Err(Error::Other(
        "fg: sys::thread_suspend/resume not exposed to userspace yet",
    ))
}

fn resolve_target(args: &[Value], ctx: &Context) -> Result<usize, Error> {
    super::resolve_job_target("fg", args, ctx)
}
