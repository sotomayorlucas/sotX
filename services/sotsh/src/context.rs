//! Per-session execution context.
//!
//! Holds mutable shell state that built-ins may read or update (e.g. `cd`
//! mutates `cwd`). Future additions: capability set, DAG builder handle,
//! active deception-profile binding.
//!
//! `no_std`: the host-std prototype used `std::path::PathBuf` and
//! `std::env::current_dir()`. sotOS has no per-process CWD exposed via a
//! syscall today, so we default to `"/"`; `cd` will mutate this once B2a
//! rewrites it over `sotos_common::sys`.

use alloc::collections::BTreeMap;
use alloc::string::{String, ToString};

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
        }
    }
}

impl Default for Context {
    fn default() -> Self {
        Self::new()
    }
}
