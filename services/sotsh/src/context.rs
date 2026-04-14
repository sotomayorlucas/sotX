//! Per-session execution context.
//!
//! Holds mutable shell state that built-ins may read or update (e.g. `cd`
//! mutates `cwd`). Future additions: capability set, DAG builder handle,
//! active deception-profile binding.

use std::path::PathBuf;

pub struct Context {
    /// Current working directory. `cd` mutates this; other built-ins treat
    /// relative paths as being anchored here.
    pub cwd: PathBuf,
    // Future:
    //   pub caps: CapSet,
    //   pub graph: DagBuilder,
    //   pub deception: Option<ProfileId>,
}

impl Context {
    pub fn new() -> std::io::Result<Self> {
        Ok(Self {
            cwd: std::env::current_dir()?,
        })
    }
}
