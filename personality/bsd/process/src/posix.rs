//! POSIX-to-SOT translation table.
//!
//! Each POSIX operation maps to one or more SOT microkernel primitives.
//! The kernel has no notion of "processes" or "files" -- only domains,
//! capabilities, shared objects, and IPC channels.

use alloc::vec::Vec;

/// A capability handle in the SOT kernel.
pub type Cap = u64;

/// Permissions that can be granted on a capability.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CapPerms(pub u32);

impl CapPerms {
    pub const READ: Self = Self(1 << 0);
    pub const WRITE: Self = Self(1 << 1);
    pub const EXEC: Self = Self(1 << 2);
    pub const GRANT: Self = Self(1 << 3);

    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    pub const fn contains(self, other: Self) -> bool {
        (self.0 & other.0) == other.0
    }
}

/// SOT kernel operations that POSIX calls translate into.
#[derive(Debug, Clone)]
pub enum SotOp {
    /// Create a new domain with CoW memory and attenuated parent caps.
    DomainCreate { flags: DomainCreateFlags },
    /// Destroy a domain, revoking all its caps.
    DomainDestroy { domain: Cap },
    /// Create an IPC channel (byte-stream or message).
    ChannelCreate { mode: ChannelMode },
    /// Send a message on a channel.
    ChannelSend { channel: Cap, data: Vec<u8> },
    /// Receive a message from a channel (blocking).
    ChannelRecv { channel: Cap },
    /// Duplicate a capability (possibly with restricted perms).
    CapDuplicate { cap: Cap, perms: Option<CapPerms> },
    /// Revoke a capability.
    CapRevoke { cap: Cap },
    /// Restrict a VFS cap's namespace (chroot).
    CapRestrictNamespace { vfs_cap: Cap, new_root: Cap },
    /// Invoke a shared object operation.
    SoInvoke { cap: Cap, op: SoOperation, args: Vec<u64> },
    /// Create a shared object (memory region).
    SoCreate { kind: SoKind },
    /// Grant a shared-object cap to a domain.
    SoGrant { cap: Cap, domain: Cap, perms: CapPerms },
    /// Begin a transaction (for atomic exec).
    TxBegin,
    /// Commit a transaction.
    TxCommit,
    /// Abort a transaction.
    TxAbort,
    /// Reset caps to match an exec policy.
    CapsReset { policy: Cap },
}

/// Flags for domain_create.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DomainCreateFlags(pub u32);

impl DomainCreateFlags {
    pub const COPY_CAPS: Self = Self(1 << 0);
    pub const COW_MEMORY: Self = Self(1 << 1);

    /// Standard fork: CoW memory + attenuated parent caps.
    pub const FORK: Self = Self(Self::COPY_CAPS.0 | Self::COW_MEMORY.0);

    pub const fn contains(self, other: Self) -> bool {
        (self.0 & other.0) == other.0
    }
}

/// Channel modes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChannelMode {
    /// Unstructured byte stream (pipe semantics).
    ByteStream,
    /// Structured messages (datagram semantics).
    Message,
}

/// Shared-object operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SoOperation {
    Read,
    Write,
    Replace,
}

/// Shared-object kinds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SoKind {
    Memory,
    Code,
}

/// `fork()` -- Create a child domain with CoW memory and attenuated parent caps.
///
/// POSIX: creates a child process sharing the parent's address space (CoW).
/// SOT:   `domain_create(COPY_CAPS | COW_MEMORY)` -- new domain gets a
///        snapshot of the parent's memory and a restricted copy of its caps.
pub fn translate_fork() -> SotOp {
    SotOp::DomainCreate {
        flags: DomainCreateFlags::FORK,
    }
}

/// `exec(path, argv, envp)` -- Atomically replace the current domain's code.
///
/// POSIX: replaces the calling process's image with a new program.
/// SOT:   transactional domain reset:
///   1. `tx_begin()`
///   2. `so_invoke(code_cap, REPLACE)` -- load new binary
///   3. `caps_reset(policy)` -- apply binary's cap policy
///   4. `tx_commit()`
///
/// If any step fails, `tx_abort()` restores the previous state.
/// See `exec.rs` for the full implementation.
pub fn translate_exec(code_cap: Cap, policy_cap: Cap) -> Vec<SotOp> {
    alloc::vec![
        SotOp::TxBegin,
        SotOp::SoInvoke {
            cap: code_cap,
            op: SoOperation::Replace,
            args: alloc::vec![],
        },
        SotOp::CapsReset { policy: policy_cap },
        SotOp::TxCommit,
    ]
}

/// `exit(status)` -- Destroy the current domain, revoking all caps.
///
/// POSIX: terminates the calling process.
/// SOT:   `domain_destroy(current)` -- revokes all caps held by this domain,
///        which implicitly closes all channels and frees resources.
pub fn translate_exit(domain: Cap) -> SotOp {
    SotOp::DomainDestroy { domain }
}

/// `pipe()` -- Create a byte-stream channel, returning (read_cap, write_cap).
///
/// POSIX: creates a unidirectional data channel.
/// SOT:   `channel_create(BYTE_STREAM)` returns two caps, one for each end.
pub fn translate_pipe() -> SotOp {
    SotOp::ChannelCreate {
        mode: ChannelMode::ByteStream,
    }
}

/// `dup(fd)` / `dup2(old, new)` -- Duplicate a capability.
///
/// POSIX: creates a copy of a file descriptor.
/// SOT:   `cap_duplicate(fd_cap)` -- new cap referencing the same object.
pub fn translate_dup(fd_cap: Cap) -> SotOp {
    SotOp::CapDuplicate {
        cap: fd_cap,
        perms: None,
    }
}

/// `open(path, flags)` -- Send OPEN request to VFS, receive file cap.
///
/// POSIX: opens a file and returns a file descriptor.
/// SOT:   `vfs_channel.send(OPEN, path, flags)` -- VFS server validates
///        the request against the caller's caps and returns a file cap.
pub fn translate_open(vfs_channel: Cap, path: &[u8]) -> SotOp {
    SotOp::ChannelSend {
        channel: vfs_channel,
        data: path.to_vec(),
    }
}

/// `read(fd, buf, len)` / `write(fd, buf, len)` -- Invoke on fd cap.
///
/// POSIX: reads from or writes to a file descriptor.
/// SOT:   `so_invoke(fd_cap, READ/WRITE, buf, len)`.
pub fn translate_io(fd_cap: Cap, op: SoOperation, len: u64) -> SotOp {
    SotOp::SoInvoke {
        cap: fd_cap,
        op,
        args: alloc::vec![len],
    }
}

pub fn translate_read(fd_cap: Cap, len: u64) -> SotOp {
    translate_io(fd_cap, SoOperation::Read, len)
}

pub fn translate_write(fd_cap: Cap, len: u64) -> SotOp {
    translate_io(fd_cap, SoOperation::Write, len)
}

/// `close(fd)` -- Revoke the file capability.
///
/// POSIX: closes a file descriptor.
/// SOT:   `so_revoke(fd_cap)` -- the capability is destroyed; if it was the
///        last reference the kernel reclaims the underlying resource.
pub fn translate_close(fd_cap: Cap) -> SotOp {
    SotOp::CapRevoke { cap: fd_cap }
}

/// `kill(pid, sig)` -- Send a signal as an IPC message (requires SIGNAL cap).
///
/// POSIX: sends a signal to a process or process group.
/// SOT:   `signal_channel.send(signal)` -- the target's signal channel
///        delivers the signal as an IPC message. Requires the caller to
///        hold a SIGNAL cap for the target domain.
pub fn translate_kill(signal_channel: Cap, signum: u8) -> SotOp {
    SotOp::ChannelSend {
        channel: signal_channel,
        data: alloc::vec![signum],
    }
}

/// `wait()/waitpid()` -- Receive on the child's exit channel.
///
/// POSIX: waits for a child process to change state.
/// SOT:   `channel_recv(child_exit_channel)` -- blocks until the child
///        domain sends its exit status (or is destroyed by the kernel).
pub fn translate_wait(child_exit_channel: Cap) -> SotOp {
    SotOp::ChannelRecv {
        channel: child_exit_channel,
    }
}

/// `mmap(addr, len, prot, flags, fd, offset)` -- Create a memory object + grant.
///
/// POSIX: maps memory into the process address space.
/// SOT:   `so_create(MEMORY)` to create the backing object, then
///        `so_grant(mem_cap, domain, perms)` to map it with the right perms.
pub fn translate_mmap(domain: Cap, perms: CapPerms) -> Vec<SotOp> {
    alloc::vec![
        SotOp::SoCreate {
            kind: SoKind::Memory,
        },
        SotOp::SoGrant {
            cap: 0, // placeholder: filled by so_create result
            domain,
            perms,
        },
    ]
}

/// `chroot(path)` -- Restrict the VFS cap's namespace.
///
/// POSIX: changes the apparent root directory.
/// SOT:   `cap_restrict_namespace(vfs_cap, new_root)` -- the VFS cap is
///        attenuated so it can only resolve paths under `new_root`.
///        No privilege escalation possible: the new cap is strictly weaker.
pub fn translate_chroot(vfs_cap: Cap, new_root: Cap) -> SotOp {
    SotOp::CapRestrictNamespace { vfs_cap, new_root }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fork_produces_domain_create_with_fork_flags() {
        match translate_fork() {
            SotOp::DomainCreate { flags } => {
                assert!(flags.contains(DomainCreateFlags::COPY_CAPS));
                assert!(flags.contains(DomainCreateFlags::COW_MEMORY));
            }
            _ => panic!("expected DomainCreate"),
        }
    }

    #[test]
    fn exec_is_transactional() {
        let ops = translate_exec(1, 2);
        assert_eq!(ops.len(), 4);
        assert!(matches!(ops[0], SotOp::TxBegin));
        assert!(matches!(ops[1], SotOp::SoInvoke { .. }));
        assert!(matches!(ops[2], SotOp::CapsReset { .. }));
        assert!(matches!(ops[3], SotOp::TxCommit));
    }

    #[test]
    fn exit_destroys_domain() {
        assert!(matches!(translate_exit(42), SotOp::DomainDestroy { domain: 42 }));
    }

    #[test]
    fn pipe_creates_byte_stream_channel() {
        match translate_pipe() {
            SotOp::ChannelCreate { mode } => {
                assert_eq!(mode, ChannelMode::ByteStream);
            }
            _ => panic!("expected ChannelCreate"),
        }
    }

    #[test]
    fn dup_duplicates_cap_with_same_perms() {
        match translate_dup(7) {
            SotOp::CapDuplicate { cap: 7, perms: None } => {}
            _ => panic!("expected CapDuplicate with no perm restriction"),
        }
    }

    #[test]
    fn mmap_creates_then_grants() {
        let ops = translate_mmap(1, CapPerms::READ.union(CapPerms::WRITE));
        assert_eq!(ops.len(), 2);
        assert!(matches!(ops[0], SotOp::SoCreate { kind: SoKind::Memory }));
        assert!(matches!(ops[1], SotOp::SoGrant { .. }));
    }
}
