//! Shared value types for the `LinuxBackend` trait.
//!
//! Kept intentionally tiny: the existing child_handler already has its own
//! in-tree representations for these concepts, so the trait boundary should
//! stay friction-free for the follow-up wave that actually moves dispatch.

/// Linux-style process id (tgid). Matches `getpid(2)` semantics.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct LinuxPid(pub u32);

/// POSIX signal number (e.g. `SIGTERM` = 15). Wrapped for type safety.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Signal(pub u32);

/// Raw Linux errno-style return value (positive = ok, negative = -errno).
///
/// Matches the convention used by `child_handler` today: handlers return
/// `i64` where `-38` means `-ENOSYS`, `0` means success, etc.
pub type SyscallResult = i64;

/// Capability bundle handed to a new process at exec time.
///
/// TODO: wire to the real sotos capability subsystem once the trait
/// replaces the child_handler's static-mut global state. For now this is a
/// placeholder so the trait signature stays stable across the migration.
#[derive(Copy, Clone, Debug, Default)]
pub struct CapSet {
    // Intentionally empty. See TODO above.
}

/// Describes an ELF image plus its launch environment.
///
/// Borrowed from the caller because the legacy path loads bytes from the
/// initrd into a fixed scratch region and does not want a heap copy.
#[derive(Copy, Clone)]
pub struct ProcessImage<'a> {
    pub elf_bytes: &'a [u8],
    pub argv: &'a [&'a str],
    pub envp: &'a [&'a str],
}

/// Linux file descriptor wrapper. Negative values denote errors.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Fd(pub i32);
