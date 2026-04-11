//! # sotfs-fuse — FUSE binding for sotFS
//!
//! Exposes the sotFS type graph as a mountable POSIX filesystem.
//!
//! Usage:
//!   sotfs-fuse <mountpoint>                    # in-memory (ephemeral)
//!   sotfs-fuse <mountpoint> --db <path.redb>   # persistent via redb

#[cfg(unix)]
mod fs;

fn main() {
    #[cfg(unix)]
    {
        env_logger::init();
        fs::run();
    }

    #[cfg(not(unix))]
    {
        eprintln!("sotfs-fuse requires Linux or macOS with FUSE support.");
        eprintln!("The core libraries (sotfs-graph, sotfs-ops, sotfs-tx) work on all platforms.");
        std::process::exit(1);
    }
}
