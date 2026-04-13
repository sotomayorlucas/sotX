//! POSIX conformance tests for sotX personality layers.
//!
//! These tests verify that the BSD (rump) and Linux (LKL/LUCAS) personality
//! layers correctly implement POSIX/SUS semantics. The test categories
//! follow the Linux Test Project (LTP) organization.
//!
//! Tests are host-side runners that boot sotX in QEMU and execute
//! test binaries via the personality layer, checking results via serial.

mod file_ops;
mod process_control;
mod signals;
mod pipes;
mod sockets;

// ---------------------------------------------------------------------------
// Test infrastructure
// ---------------------------------------------------------------------------

/// Markers for LTP test categories.
///
/// These tags map to LTP test suites and are used to track coverage
/// against the LTP test matrix.
pub mod ltp {
    /// LTP syscalls/ test category: individual syscall conformance.
    pub const SYSCALLS: &str = "ltp:syscalls";

    /// LTP fs/ test category: filesystem operations.
    pub const FS: &str = "ltp:fs";

    /// LTP ipc/ test category: inter-process communication.
    pub const IPC: &str = "ltp:ipc";

    /// LTP net/ test category: networking.
    pub const NET: &str = "ltp:net";

    /// LTP mm/ test category: memory management.
    pub const MM: &str = "ltp:mm";

    /// LTP sched/ test category: scheduler conformance.
    pub const SCHED: &str = "ltp:sched";
}

/// Expected result of a POSIX test.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PosixResult {
    /// Syscall returned successfully with the given value.
    Ok(i64),
    /// Syscall returned -1 with the given errno.
    Errno(i32),
}

/// Standard errno values for test assertions.
pub mod errno {
    pub const ENOENT: i32 = 2;
    pub const EACCES: i32 = 13;
    pub const EEXIST: i32 = 17;
    pub const ENOTDIR: i32 = 20;
    pub const EISDIR: i32 = 21;
    pub const EINVAL: i32 = 22;
    pub const ENOSPC: i32 = 28;
    pub const EPIPE: i32 = 32;
    pub const EAGAIN: i32 = 11;
    pub const EBADF: i32 = 9;
    pub const ENOMEM: i32 = 12;
    pub const EFAULT: i32 = 14;
    pub const ESPIPE: i32 = 29;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn errno_values_match_linux() {
        // Sanity: verify our errno constants match Linux ABI.
        assert_eq!(errno::ENOENT, 2);
        assert_eq!(errno::EACCES, 13);
        assert_eq!(errno::EINVAL, 22);
    }

    #[test]
    fn posix_result_comparison() {
        assert_eq!(PosixResult::Ok(0), PosixResult::Ok(0));
        assert_ne!(PosixResult::Ok(0), PosixResult::Errno(0));
        assert_eq!(PosixResult::Errno(errno::ENOENT), PosixResult::Errno(2));
    }
}
