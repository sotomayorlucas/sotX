//! Per-session execution context.
//!
//! Holds mutable shell state that built-ins may read or update (e.g. `cd`
//! mutates `cwd`; `jobs`/`fg`/`bg` read and mutate the job table).
//!
//! `no_std`: the host-std prototype used `std::path::PathBuf` and
//! `std::env::current_dir()`. sotOS has no per-process CWD exposed via a
//! syscall today, so we default to `"/"`; `cd` will mutate this once B2a
//! rewrites it over `sotos_common::sys`.

use alloc::collections::BTreeMap;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

/// A single entry in the shell's background-job table (B4b).
///
/// Populated when a pipeline is terminated with `&`. `tid` is the raw
/// thread id returned by `sys::thread_create`; `0` means "no thread was
/// spawned" (stub mode — the pipeline was recorded but not actually
/// backgrounded because `sys::thread_create` integration is a follow-up).
#[derive(Debug, Clone)]
pub struct Job {
    /// User-visible id, 1-indexed in insertion order.
    pub id: u32,
    /// Human-readable summary of the pipeline (`"sleep 1 | grep foo"`).
    pub pipeline: String,
    /// Raw tid from `sys::thread_create`, or `0` if not backgrounded yet.
    pub tid: u64,
    /// Current lifecycle state.
    pub state: JobState,
}

/// Coarse job lifecycle. Mirrors the POSIX `jobs(1)` output column.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JobState {
    Running,
    Stopped,
    Done,
}

impl JobState {
    pub fn as_str(&self) -> &'static str {
        match self {
            JobState::Running => "Running",
            JobState::Stopped => "Stopped",
            JobState::Done => "Done",
        }
    }
}

pub struct Context {
    /// Current working directory as a UTF-8 path string. `cd` mutates this;
    /// other built-ins treat relative paths as being anchored here.
    pub cwd: String,
    /// Shell environment variables. `$VAR` expansion in the parser-emitted
    /// args is resolved against this map at runtime. `export` mutates it;
    /// a bare `VAR=val` line (no command) also writes here. Per-command
    /// `VAR=val prefix cmd args` overlays on top for the duration of that
    /// one dispatch without persisting.
    pub env: BTreeMap<String, String>,
    /// Background jobs spawned via `cmd &` (B4b). Kept as a `Vec` because
    /// the table is small (O(10s) at most in practice) and insertion order
    /// is meaningful for the default `fg`/`bg` target.
    pub jobs: Vec<Job>,
    /// Next id to hand out. Monotonically increasing; never reused even
    /// after a job is removed, to keep `fg %N` references unambiguous.
    pub next_job_id: u32,
    // Future:
    //   pub caps: CapSet,
    //   pub graph: DagBuilder,
    //   pub deception: Option<ProfileId>,
}

impl Context {
    /// Create a fresh context rooted at `"/"`. Infallible under `no_std`.
    pub fn new() -> Self {
        Self {
            cwd: "/".to_string(),
            env: BTreeMap::new(),
            jobs: Vec::new(),
            next_job_id: 1,
        }
    }

    /// Record a new background job and return its user-visible id.
    ///
    /// `tid = 0` is accepted and means "stub — actual thread not spawned"
    /// (see B4b runtime docs). Callers print `"[N] tid"` to the user.
    pub fn register_job(&mut self, pipeline: String, tid: u64) -> u32 {
        let id = self.next_job_id;
        self.next_job_id = self.next_job_id.saturating_add(1);
        self.jobs.push(Job {
            id,
            pipeline,
            tid,
            state: JobState::Running,
        });
        id
    }

    /// Look up a job by its user-visible id; `Some(index)` into `self.jobs`.
    pub fn job_index_by_id(&self, id: u32) -> Option<usize> {
        self.jobs.iter().position(|j| j.id == id)
    }
}

impl Default for Context {
    fn default() -> Self {
        Self::new()
    }
}
