//! Shared types and constants between the sotOS kernel and userspace services.
//!
//! This crate defines the ABI contract: syscall numbers, capability types,
//! IPC message formats, and error codes. Both the kernel and userspace
//! link against this crate to ensure type-safe communication.

#![no_std]

pub mod spsc;
pub mod typed_channel;

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
    /// Create a scheduling domain (budget-enforced thread group).
    DomainCreate = 90,
    /// Attach a thread to a scheduling domain.
    DomainAttach = 91,
    /// Detach a thread from a scheduling domain.
    DomainDetach = 92,
    /// Adjust a domain's quantum (time budget per period).
    DomainAdjust = 93,
    /// Query domain budget info (quantum, consumed, period).
    DomainInfo = 94,
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

/// Well-known virtual address of the BootInfo page (mapped read-only for init).
pub const BOOT_INFO_ADDR: u64 = 0xB00000;

/// Boot info magic number ("SOTOS" in ASCII, zero-extended).
pub const BOOT_INFO_MAGIC: u64 = 0x534F544F53;

/// Maximum capabilities passed to init.
pub const BOOT_INFO_MAX_CAPS: usize = 32;

/// Boot information struct passed from kernel to the init process.
/// Located at BOOT_INFO_ADDR, mapped read-only into the init address space.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct BootInfo {
    pub magic: u64,
    pub cap_count: u64,
    pub caps: [u64; BOOT_INFO_MAX_CAPS],
}

impl BootInfo {
    pub const fn empty() -> Self {
        Self {
            magic: 0,
            cap_count: 0,
            caps: [0; BOOT_INFO_MAX_CAPS],
        }
    }

    /// Check if this BootInfo is valid.
    pub fn is_valid(&self) -> bool {
        self.magic == BOOT_INFO_MAGIC
    }
}

/// IPC message for synchronous endpoint operations.
///
/// `tag` lower 32 bits = message tag, upper 32 bits = optional cap transfer ID.
/// `regs[0..8]` map to rdx/r8/r9/r10/r12/r13/r14/r15 in the syscall ABI.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct IpcMsg {
    pub tag: u64,
    pub regs: [u64; 8],
}

impl IpcMsg {
    pub const fn empty() -> Self {
        Self { tag: 0, regs: [0; 8] }
    }
}

/// Fault information returned by `sys::fault_recv()`.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct FaultInfo {
    pub addr: u64,
    pub code: u64,
    pub tid: u32,
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

    #[inline(always)]
    pub fn syscall2(nr: u64, a1: u64, a2: u64) -> u64 {
        let ret: u64;
        unsafe {
            core::arch::asm!(
                "syscall",
                inlateout("rax") nr => ret,
                in("rdi") a1,
                in("rsi") a2,
                lateout("rcx") _,
                lateout("r11") _,
                options(nostack),
            );
        }
        ret
    }

    #[inline(always)]
    pub fn syscall3(nr: u64, a1: u64, a2: u64, a3: u64) -> u64 {
        let ret: u64;
        unsafe {
            core::arch::asm!(
                "syscall",
                inlateout("rax") nr => ret,
                in("rdi") a1,
                in("rsi") a2,
                in("rdx") a3,
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

    /// Allocate a physical frame. Returns the frame capability ID.
    #[inline(always)]
    pub fn frame_alloc() -> Result<u64, i64> {
        let ret = syscall0(super::Syscall::FrameAlloc as u64);
        if (ret as i64) < 0 { Err(ret as i64) } else { Ok(ret) }
    }

    /// Map a frame into the caller's address space.
    /// `flags`: bit 1 = WRITABLE, bit 63 = NO_EXECUTE.
    #[inline(always)]
    pub fn map(vaddr: u64, frame_cap: u64, flags: u64) -> Result<(), i64> {
        let ret = syscall3(super::Syscall::Map as u64, vaddr, frame_cap, flags);
        if (ret as i64) < 0 { Err(ret as i64) } else { Ok(()) }
    }

    /// Create a notification object. Returns the notification capability ID.
    #[inline(always)]
    pub fn notify_create() -> Result<u64, i64> {
        let ret = syscall0(super::Syscall::NotifyCreate as u64);
        if (ret as i64) < 0 { Err(ret as i64) } else { Ok(ret) }
    }

    /// Wait on a notification (blocks if not pending).
    #[inline(always)]
    pub fn notify_wait(cap: u64) {
        syscall1(super::Syscall::NotifyWait as u64, cap);
    }

    /// Signal a notification (wakes waiter or sets pending).
    #[inline(always)]
    pub fn notify_signal(cap: u64) {
        syscall1(super::Syscall::NotifySignal as u64, cap);
    }

    /// Create a new thread. Returns the thread capability ID.
    #[inline(always)]
    pub fn thread_create(rip: u64, rsp: u64) -> Result<u64, i64> {
        let ret = syscall2(super::Syscall::ThreadCreate as u64, rip, rsp);
        if (ret as i64) < 0 { Err(ret as i64) } else { Ok(ret) }
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

    /// Read a byte from an I/O port.
    #[inline(always)]
    pub fn port_in(cap: u64, port: u64) -> Result<u8, i64> {
        let ret = syscall2(super::Syscall::PortIn as u64, cap, port);
        if (ret as i64) < 0 { Err(ret as i64) } else { Ok(ret as u8) }
    }

    /// Write a byte to an I/O port.
    #[inline(always)]
    pub fn port_out(cap: u64, port: u64, value: u8) -> Result<(), i64> {
        let ret = syscall3(super::Syscall::PortOut as u64, cap, port, value as u64);
        if (ret as i64) < 0 { Err(ret as i64) } else { Ok(()) }
    }

    /// Read the CPU timestamp counter (rdtsc).
    #[inline(always)]
    pub fn rdtsc() -> u64 {
        let lo: u32;
        let hi: u32;
        unsafe {
            core::arch::asm!("rdtsc", out("eax") lo, out("edx") hi, options(nomem, nostack));
        }
        ((hi as u64) << 32) | lo as u64
    }

    // ---------------------------------------------------------------
    // IPC — synchronous endpoints (full register ABI)
    // ---------------------------------------------------------------

    /// Send a message on a synchronous IPC endpoint.
    #[inline(always)]
    pub fn send(ep_cap: u64, msg: &super::IpcMsg) -> Result<(), i64> {
        let ret: u64;
        unsafe {
            core::arch::asm!(
                "syscall",
                inlateout("rax") super::Syscall::Send as u64 => ret,
                in("rdi") ep_cap,
                in("rsi") msg.tag,
                in("rdx") msg.regs[0],
                in("r8") msg.regs[1],
                in("r9") msg.regs[2],
                in("r10") msg.regs[3],
                in("r12") msg.regs[4],
                in("r13") msg.regs[5],
                in("r14") msg.regs[6],
                in("r15") msg.regs[7],
                lateout("rcx") _,
                lateout("r11") _,
                options(nostack),
            );
        }
        if (ret as i64) < 0 { Err(ret as i64) } else { Ok(()) }
    }

    /// Receive a message from a synchronous IPC endpoint.
    #[inline(always)]
    pub fn recv(ep_cap: u64) -> Result<super::IpcMsg, i64> {
        let ret: u64;
        let tag: u64;
        let r0: u64; let r1: u64; let r2: u64; let r3: u64;
        let r4: u64; let r5: u64; let r6: u64; let r7: u64;
        unsafe {
            core::arch::asm!(
                "syscall",
                inlateout("rax") super::Syscall::Recv as u64 => ret,
                in("rdi") ep_cap,
                lateout("rsi") tag,
                lateout("rdx") r0,
                lateout("r8") r1,
                lateout("r9") r2,
                lateout("r10") r3,
                lateout("r12") r4,
                lateout("r13") r5,
                lateout("r14") r6,
                lateout("r15") r7,
                lateout("rcx") _,
                lateout("r11") _,
                options(nostack),
            );
        }
        if (ret as i64) < 0 {
            Err(ret as i64)
        } else {
            Ok(super::IpcMsg { tag, regs: [r0, r1, r2, r3, r4, r5, r6, r7] })
        }
    }

    /// Combined send+receive (call semantics) on a synchronous IPC endpoint.
    #[inline(always)]
    pub fn call(ep_cap: u64, msg: &super::IpcMsg) -> Result<super::IpcMsg, i64> {
        let ret: u64;
        let tag: u64;
        let r0: u64; let r1: u64; let r2: u64; let r3: u64;
        let r4: u64; let r5: u64; let r6: u64; let r7: u64;
        unsafe {
            core::arch::asm!(
                "syscall",
                inlateout("rax") super::Syscall::Call as u64 => ret,
                in("rdi") ep_cap,
                inlateout("rsi") msg.tag => tag,
                inlateout("rdx") msg.regs[0] => r0,
                inlateout("r8") msg.regs[1] => r1,
                inlateout("r9") msg.regs[2] => r2,
                inlateout("r10") msg.regs[3] => r3,
                inlateout("r12") msg.regs[4] => r4,
                inlateout("r13") msg.regs[5] => r5,
                inlateout("r14") msg.regs[6] => r6,
                inlateout("r15") msg.regs[7] => r7,
                lateout("rcx") _,
                lateout("r11") _,
                options(nostack),
            );
        }
        if (ret as i64) < 0 {
            Err(ret as i64)
        } else {
            Ok(super::IpcMsg { tag, regs: [r0, r1, r2, r3, r4, r5, r6, r7] })
        }
    }

    // ---------------------------------------------------------------
    // IPC — async channels
    // ---------------------------------------------------------------

    /// Create a new async IPC channel. Returns the channel capability ID.
    #[inline(always)]
    pub fn channel_create() -> Result<u64, i64> {
        let ret = syscall0(super::Syscall::ChannelCreate as u64);
        if (ret as i64) < 0 { Err(ret as i64) } else { Ok(ret) }
    }

    /// Send a tag on an async channel.
    #[inline(always)]
    pub fn channel_send(cap: u64, tag: u64) -> Result<(), i64> {
        let ret = syscall2(super::Syscall::ChannelSend as u64, cap, tag);
        if (ret as i64) < 0 { Err(ret as i64) } else { Ok(()) }
    }

    /// Receive a tag from an async channel.
    #[inline(always)]
    pub fn channel_recv(cap: u64) -> Result<u64, i64> {
        let ret: u64;
        let tag: u64;
        unsafe {
            core::arch::asm!(
                "syscall",
                inlateout("rax") super::Syscall::ChannelRecv as u64 => ret,
                in("rdi") cap,
                lateout("rsi") tag,
                lateout("rcx") _,
                lateout("r11") _,
                lateout("rdx") _,
                lateout("r8") _,
                lateout("r9") _,
                lateout("r10") _,
                lateout("r12") _,
                lateout("r13") _,
                lateout("r14") _,
                lateout("r15") _,
                options(nostack),
            );
        }
        if (ret as i64) < 0 { Err(ret as i64) } else { Ok(tag) }
    }

    /// Close an async channel.
    #[inline(always)]
    pub fn channel_close(cap: u64) -> Result<(), i64> {
        let ret = syscall1(super::Syscall::ChannelClose as u64, cap);
        if (ret as i64) < 0 { Err(ret as i64) } else { Ok(()) }
    }

    // ---------------------------------------------------------------
    // Endpoints
    // ---------------------------------------------------------------

    /// Create a new IPC endpoint. Returns the endpoint capability ID.
    #[inline(always)]
    pub fn endpoint_create() -> Result<u64, i64> {
        let ret = syscall0(super::Syscall::EndpointCreate as u64);
        if (ret as i64) < 0 { Err(ret as i64) } else { Ok(ret) }
    }

    // ---------------------------------------------------------------
    // Capabilities
    // ---------------------------------------------------------------

    /// Grant (delegate) a capability with restricted rights.
    #[inline(always)]
    pub fn cap_grant(source: u64, rights_mask: u64) -> Result<u64, i64> {
        let ret = syscall2(super::Syscall::CapGrant as u64, source, rights_mask);
        if (ret as i64) < 0 { Err(ret as i64) } else { Ok(ret) }
    }

    /// Revoke a capability and all its derivatives.
    #[inline(always)]
    pub fn cap_revoke(cap: u64) -> Result<(), i64> {
        let ret = syscall1(super::Syscall::CapRevoke as u64, cap);
        if (ret as i64) < 0 { Err(ret as i64) } else { Ok(()) }
    }

    // ---------------------------------------------------------------
    // Memory
    // ---------------------------------------------------------------

    /// Free a physical frame capability.
    #[inline(always)]
    pub fn frame_free(cap: u64) -> Result<(), i64> {
        let ret = syscall1(super::Syscall::FrameFree as u64, cap);
        if (ret as i64) < 0 { Err(ret as i64) } else { Ok(()) }
    }

    /// Unmap a virtual page.
    #[inline(always)]
    pub fn unmap(vaddr: u64) -> Result<(), i64> {
        let ret = syscall1(super::Syscall::Unmap as u64, vaddr);
        if (ret as i64) < 0 { Err(ret as i64) } else { Ok(()) }
    }

    // ---------------------------------------------------------------
    // Threads
    // ---------------------------------------------------------------

    /// Resume a faulted thread.
    #[inline(always)]
    pub fn thread_resume(tid: u64) -> Result<(), i64> {
        let ret = syscall1(super::Syscall::ThreadResume as u64, tid);
        if (ret as i64) < 0 { Err(ret as i64) } else { Ok(()) }
    }

    // ---------------------------------------------------------------
    // IRQ
    // ---------------------------------------------------------------

    /// Register an IRQ handler notification.
    #[inline(always)]
    pub fn irq_register(irq_cap: u64, notify_cap: u64) -> Result<(), i64> {
        let ret = syscall2(super::Syscall::IrqRegister as u64, irq_cap, notify_cap);
        if (ret as i64) < 0 { Err(ret as i64) } else { Ok(()) }
    }

    /// Acknowledge an IRQ (unmask the line).
    #[inline(always)]
    pub fn irq_ack(cap: u64) -> Result<(), i64> {
        let ret = syscall1(super::Syscall::IrqAck as u64, cap);
        if (ret as i64) < 0 { Err(ret as i64) } else { Ok(()) }
    }

    // ---------------------------------------------------------------
    // Faults (VMM)
    // ---------------------------------------------------------------

    /// Register a notification for page fault delivery.
    #[inline(always)]
    pub fn fault_register(notify_cap: u64) -> Result<(), i64> {
        let ret = syscall1(super::Syscall::FaultRegister as u64, notify_cap);
        if (ret as i64) < 0 { Err(ret as i64) } else { Ok(()) }
    }

    /// Receive the next pending page fault.
    #[inline(always)]
    pub fn fault_recv() -> Result<super::FaultInfo, i64> {
        let ret: u64;
        let addr: u64;
        let code: u64;
        let tid: u64;
        unsafe {
            core::arch::asm!(
                "syscall",
                inlateout("rax") super::Syscall::FaultRecv as u64 => ret,
                lateout("rdi") addr,
                lateout("rsi") code,
                lateout("rdx") tid,
                lateout("rcx") _,
                lateout("r11") _,
                options(nostack),
            );
        }
        if (ret as i64) < 0 {
            Err(ret as i64)
        } else {
            Ok(super::FaultInfo { addr, code, tid: tid as u32 })
        }
    }

    // ---------------------------------------------------------------
    // Scheduling Domains
    // ---------------------------------------------------------------

    /// Create a scheduling domain with the given quantum and period (in ms).
    /// Returns the domain capability ID.
    #[inline(always)]
    pub fn domain_create(quantum_ms: u64, period_ms: u64) -> Result<u64, i64> {
        let ret = syscall2(super::Syscall::DomainCreate as u64, quantum_ms, period_ms);
        if (ret as i64) < 0 { Err(ret as i64) } else { Ok(ret) }
    }

    /// Attach a thread to a scheduling domain.
    #[inline(always)]
    pub fn domain_attach(domain_cap: u64, thread_cap: u64) -> Result<(), i64> {
        let ret = syscall2(super::Syscall::DomainAttach as u64, domain_cap, thread_cap);
        if (ret as i64) < 0 { Err(ret as i64) } else { Ok(()) }
    }

    /// Detach a thread from a scheduling domain.
    #[inline(always)]
    pub fn domain_detach(domain_cap: u64, thread_cap: u64) -> Result<(), i64> {
        let ret = syscall2(super::Syscall::DomainDetach as u64, domain_cap, thread_cap);
        if (ret as i64) < 0 { Err(ret as i64) } else { Ok(()) }
    }

    /// Adjust a domain's quantum (in ms).
    #[inline(always)]
    pub fn domain_adjust(domain_cap: u64, new_quantum_ms: u64) -> Result<(), i64> {
        let ret = syscall2(super::Syscall::DomainAdjust as u64, domain_cap, new_quantum_ms);
        if (ret as i64) < 0 { Err(ret as i64) } else { Ok(()) }
    }

    /// Query domain info. Returns (quantum_ticks, consumed_ticks, period_ticks).
    #[inline(always)]
    pub fn domain_info(domain_cap: u64) -> Result<(u64, u64, u64), i64> {
        let ret: u64;
        let quantum: u64;
        let consumed: u64;
        let period: u64;
        unsafe {
            core::arch::asm!(
                "syscall",
                inlateout("rax") super::Syscall::DomainInfo as u64 => ret,
                inlateout("rdi") domain_cap => quantum,
                lateout("rsi") consumed,
                lateout("rdx") period,
                lateout("rcx") _,
                lateout("r11") _,
                options(nostack),
            );
        }
        if (ret as i64) < 0 {
            Err(ret as i64)
        } else {
            Ok((quantum, consumed, period))
        }
    }
}
