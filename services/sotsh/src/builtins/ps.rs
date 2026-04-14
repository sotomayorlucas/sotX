//! Built-in: `ps` — list active kernel threads.
//!
//! Enumerates threads via `sys::thread_count` (syscall 142) +
//! `sys::thread_info` (syscall 140). Replaces the Wave-2 hardcoded stub
//! (PR #115) now that the B1.5b wrapper fix (PR #121) makes
//! `thread_info` return real data (tid, state, priority, cpu_ticks,
//! mem_pages, is_user) via inline-asm register capture.
//!
//! Required capabilities: `proc:list` (see [`super::required_caps`]).

use alloc::vec::Vec;

use sotos_common::sys;

use crate::context::Context;
use crate::error::Error;
use crate::value::{Row, Value};



/// Safety cap: never iterate more than this many thread slots, regardless
/// of what `thread_count()` returns. Guards against a misbehaving kernel.
const MAX_THREADS: usize = 128;

/// Map kernel `ThreadState` discriminant to a short display string.
///
/// Values match `kernel/src/sched/mod.rs::thread_info`:
/// 0=Ready, 1=Running, 2=Blocked, 3=Faulted, 4=Dead.
fn state_name(state: u64) -> &'static str {
    match state {
        0 => "R",  // Ready
        1 => "X",  // Running (eXecuting)
        2 => "B",  // Blocked
        3 => "F",  // Faulted
        4 => "D",  // Dead
        _ => "?",
    }
}

pub fn run(_args: &[Value], _ctx: &mut Context) -> Result<Value, Error> {
    let total = (sys::thread_count() as usize).min(MAX_THREADS);
    let mut rows: Vec<Row> = Vec::new();

    for idx in 0..total {
        let (tid, state, priority, ticks, mem, user) = match sys::thread_info(idx as u64) {
            Ok(info) => info,
            Err(_) => continue,
        };
        // Skip empty slots (kernel sentinel).
        if tid == 0 {
            continue;
        }
        rows.push(
            Row::new()
                .with("pid", Value::Int(tid as i64))
                .with("state", Value::Str(state_name(state).into()))
                .with("priority", Value::Int(priority as i64))
                .with("ticks", Value::Int(ticks as i64))
                .with("mem_pages", Value::Int(mem as i64))
                .with(
                    "user",
                    Value::Str(if user != 0 { "user".into() } else { "kernel".into() }),
                ),
        );
    }

    Ok(Value::Table(rows))
}
