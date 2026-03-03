//! Shared types and constants between the sotOS kernel and userspace services.
//!
//! This crate defines the ABI contract: syscall numbers, capability types,
//! IPC message formats, and error codes. Both the kernel and userspace
//! link against this crate to ensure type-safe communication.

#![no_std]

/// Syscall numbers. The kernel exposes exactly these operations.
#[repr(u64)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Syscall {
    /// Yield the current thread's remaining timeslice.
    Yield = 0,
    /// Send a message to an IPC endpoint.
    Send = 1,
    /// Receive a message from an IPC endpoint.
    Recv = 2,
    /// Combined send+receive (call semantics).
    Call = 3,
    /// Create a new async IPC channel.
    ChannelCreate = 4,
    /// Send a message on an async channel.
    ChannelSend = 5,
    /// Receive a message from an async channel.
    ChannelRecv = 6,
    /// Close an async channel.
    ChannelClose = 7,
    /// Create a new IPC endpoint.
    EndpointCreate = 10,
    /// Allocate a physical frame.
    FrameAlloc = 20,
    /// Free a physical frame.
    FrameFree = 21,
    /// Map a frame into a virtual address space (delegated to VMM).
    Map = 22,
    /// Unmap a virtual page.
    Unmap = 23,
    /// Delegate a capability (with optional rights restriction).
    CapGrant = 30,
    /// Revoke a capability and all its derivatives.
    CapRevoke = 31,
    /// Create a new thread.
    ThreadCreate = 40,
    /// Destroy a thread.
    ThreadDestroy = 41,
    /// Exit the current thread.
    ThreadExit = 42,
    /// Resume a faulted thread (used by VMM server).
    ThreadResume = 43,
    /// Register an IRQ handler (userspace driver).
    IrqRegister = 50,
    /// Acknowledge an IRQ.
    IrqAck = 51,
    /// Read a byte from an I/O port.
    PortIn = 60,
    /// Write a byte to an I/O port.
    PortOut = 61,
    /// Create a notification object (binary semaphore).
    NotifyCreate = 70,
    /// Wait on a notification (blocks if not pending).
    NotifyWait = 71,
    /// Signal a notification (wakes waiter or sets pending).
    NotifySignal = 72,
    /// Register a notification for page fault delivery (VMM).
    FaultRegister = 80,
    /// Receive the next pending page fault (VMM).
    FaultRecv = 81,
    /// Write a single byte to serial (temporary debug aid).
    DebugPrint = 255,
}

/// Error codes returned by syscalls.
#[repr(i64)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SysError {
    /// Operation succeeded.
    Ok = 0,
    /// Invalid capability.
    InvalidCap = -1,
    /// Insufficient rights on capability.
    NoRights = -2,
    /// Resource exhausted (no frames, no endpoint slots, etc.).
    OutOfResources = -3,
    /// Invalid argument.
    InvalidArg = -4,
    /// Operation would block (for non-blocking variants).
    WouldBlock = -5,
    /// Object not found.
    NotFound = -6,
}

/// Raw syscall wrappers for userspace programs.
///
/// These issue the `syscall` instruction directly. Only usable from
/// Ring 3 code compiled for `x86_64-unknown-none`.
pub mod sys {
    #[inline(always)]
    pub fn syscall0(nr: u64) -> u64 {
        let ret: u64;
        unsafe {
            core::arch::asm!(
                "syscall",
                inlateout("rax") nr => ret,
                lateout("rcx") _,
                lateout("r11") _,
                options(nostack),
            );
        }
        ret
    }

    #[inline(always)]
    pub fn syscall1(nr: u64, a1: u64) -> u64 {
        let ret: u64;
        unsafe {
            core::arch::asm!(
                "syscall",
                inlateout("rax") nr => ret,
                in("rdi") a1,
                lateout("rcx") _,
                lateout("r11") _,
                options(nostack),
            );
        }
        ret
    }

    /// Write a single byte to the kernel debug serial port.
    #[inline(always)]
    pub fn debug_print(byte: u8) {
        syscall1(super::Syscall::DebugPrint as u64, byte as u64);
    }

    /// Terminate the current thread (never returns).
    #[inline(always)]
    pub fn thread_exit() -> ! {
        syscall0(super::Syscall::ThreadExit as u64);
        // Safety: the kernel destroys the thread, so this is unreachable.
        unsafe { core::hint::unreachable_unchecked() }
    }

    /// Yield the remainder of the current timeslice.
    #[inline(always)]
    pub fn yield_now() {
        syscall0(super::Syscall::Yield as u64);
    }
}
