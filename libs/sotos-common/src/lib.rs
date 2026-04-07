//! Shared types and constants between the sotOS kernel and userspace services.
//!
//! This crate defines the ABI contract: syscall numbers, capability types,
//! IPC message formats, and error codes. Both the kernel and userspace
//! link against this crate to ensure type-safe communication.

#![no_std]

pub mod elf;
pub mod linux_abi;
pub mod spsc;
pub mod trace;
pub mod typed_channel;

// ---------------------------------------------------------------
// SyncUnsafeCell — Rust 2024-safe replacement for `static mut`
// ---------------------------------------------------------------

/// A wrapper around `UnsafeCell` that implements `Sync`, allowing it to be
/// used in `static` items without `static mut` (which is UB in Rust 2024).
///
/// Safety: The caller must ensure exclusive access when mutating, just like
/// `static mut`. This is semantically equivalent but avoids the Rust 2024
/// `static_mut_refs` lint and future UB.
#[repr(transparent)]
pub struct SyncUnsafeCell<T>(core::cell::UnsafeCell<T>);

unsafe impl<T> Sync for SyncUnsafeCell<T> {}

impl<T> SyncUnsafeCell<T> {
    /// Create a new `SyncUnsafeCell` with the given value.
    pub const fn new(value: T) -> Self {
        Self(core::cell::UnsafeCell::new(value))
    }

    /// Get a raw pointer to the inner value.
    pub const fn get(&self) -> *mut T {
        self.0.get()
    }
}

// ---------------------------------------------------------------
// Stack canary support for userspace processes
// ---------------------------------------------------------------
// Only compiled for userspace (not kernel, which has its own definitions).

#[cfg(not(feature = "kernel"))]
mod stack_canary {
    /// Stack canary value. Initialized with RDTSC entropy.
    #[used]
    #[no_mangle]
    pub static mut __stack_chk_guard: u64 = 0x00000aff0a0d0000;

    /// Called by LLVM when a stack buffer overflow is detected.
    #[no_mangle]
    pub extern "C" fn __stack_chk_fail() -> ! {
        // Write directly to serial via syscall — don't trust the stack.
        let msg = b"!!! STACK SMASH DETECTED !!!\n";
        for &b in msg {
            super::sys::debug_print(b);
        }
        super::sys::thread_exit();
    }
}


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
    /// Unmap a virtual page and free the underlying physical frame.
    UnmapFree = 24,
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
    /// Query physical address of a frame capability.
    FramePhys = 100,
    /// Create an I/O port capability dynamically.
    IoPortCreate = 101,
    /// Allocate N contiguous physical frames.
    FrameAllocContig = 102,
    /// Create an IRQ capability dynamically.
    IrqCreate = 103,
    /// Map page from multi-page Memory cap at offset.
    MapOffset = 104,
    /// Set syscall redirect endpoint on a thread (LUCAS).
    RedirectSet = 110,
    /// Create a new empty user address space, return AS cap.
    AddrSpaceCreate = 120,
    /// Map a frame into a target address space (not caller's).
    MapInto = 121,
    /// Create a thread in a target address space.
    ThreadCreateIn = 122,
    /// Unmap a page from a target address space.
    UnmapFrom = 123,
    /// Clone an address space with Copy-on-Write semantics.
    AddrSpaceClone = 125,
    /// Copy 4KiB from a page in src AS to a frame cap (via kernel HHDM).
    FrameCopy = 126,
    /// Read PTE (phys + flags) for a vaddr in an AS.
    PteRead = 127,
    /// Read bytes from a target address space into caller's buffer.
    VmRead = 128,
    /// Write bytes from caller's buffer into a target address space.
    /// Handles CoW: if the target page is read-only (CoW), allocates a new frame.
    VmWrite = 129,
    /// Register a service name → endpoint mapping.
    SvcRegister = 130,
    /// Look up a service by name, returns a derived endpoint cap.
    SvcLookup = 131,
    /// Read a file from the initrd CPIO archive into a userspace buffer.
    InitrdRead = 132,
    /// Write a BootInfo page into a target address space.
    BootInfoWrite = 133,
    /// Change page permissions (mprotect-like, W^X enforced).
    Protect = 134,
    /// Change page permissions in a target address space.
    ProtectIn = 175,
    /// Set FS_BASE MSR for current thread (TLS support).
    SetFsBase = 160,
    /// Get FS_BASE MSR of current thread.
    GetFsBase = 161,
    /// Change file permissions (chmod).
    Chmod = 150,
    /// Change file ownership (chown).
    Chown = 151,
    /// Get thread info by pool index.
    ThreadInfo = 140,
    /// Set resource limits on current thread.
    ResourceLimit = 141,
    /// Get total live thread count.
    ThreadCount = 142,
    /// Combined send+receive with timeout (ticks in extra reg).
    CallTimeout = 135,
    /// Receive with timeout (ep_cap in rdi[31:0], timeout in rdi[63:32]).
    RecvTimeout = 136,
    /// Create a shared memory region (N pages).
    ShmCreate = 180,
    /// Map shared memory into an address space.
    ShmMap = 181,
    /// Unmap shared memory from an address space.
    ShmUnmap = 182,
    /// Destroy shared memory, free frames when refcount=0.
    ShmDestroy = 183,
    /// Write a single byte to serial (COM1).
    DebugPrint = 255,
    /// Non-blocking serial read (returns byte or u64::MAX if none).
    DebugRead = 253,
    /// Create a new SOT object.
    SoCreate = 300,
    /// Invoke a method on a SOT object.
    SoInvoke = 301,
    /// Grant a SOT capability to another domain.
    SoGrant = 302,
    /// Revoke a SOT capability.
    SoRevoke = 303,
    /// Observe a SOT object (read-only inspection).
    SoObserve = 304,
    /// Create a new SOT scheduling/isolation domain.
    SotDomainCreate = 305,
    /// Enter (switch to) a SOT domain.
    SotDomainEnter = 306,
    /// Create a new SOT typed channel.
    SotChannelCreate = 307,
    /// Begin a transaction.
    TxBegin = 308,
    /// Commit current transaction.
    TxCommit = 309,
    /// Abort current transaction, rollback changes.
    TxAbort = 310,
    /// Tier 2 (MultiObject) two-phase commit: PREPARE phase.
    TxPrepare = 311,
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
    /// IPC call timed out.
    Timeout = -7,
}

// ---------------------------------------------------------------
// Platform constants (centralized to avoid duplication)
// ---------------------------------------------------------------

/// Maximum supported CPUs (used by kernel scheduler, IPC, slab, watchdog).
pub const MAX_CPUS: usize = 16;

/// Keyboard scancode ring buffer virtual address (shared: kernel, kbd, init, xhci).
pub const KB_RING_ADDR: u64 = 0x510000;
/// Mouse event ring buffer virtual address (shared: kernel, kbd, init).
pub const MOUSE_RING_ADDR: u64 = 0x520000;

// ---------------------------------------------------------------
// Address layout constants (kernel + userspace)
// ---------------------------------------------------------------

/// User process stack base address (before ASLR jitter).
pub const PROCESS_STACK_BASE: u64 = 0x900000;
/// ASLR jitter range for stack placement (pages).
pub const ASLR_JITTER_PAGES: u64 = 16;
/// Virtio/device BAR0 MMIO mapping base.
pub const BAR0_VIRT_BASE: u64 = 0xC00000;
/// Framebuffer user-accessible mapping base.
pub const FB_USER_BASE: u64 = 0x4000000;
/// Heap (brk) base address for init child processes.
pub const BRK_BASE: u64 = 0x2000000;
/// Maximum heap size (1 MiB).
pub const BRK_LIMIT: u64 = 0x100000;
/// Anonymous mmap region base for init child processes.
pub const MMAP_BASE: u64 = 0x3000000;
/// Dynamic interpreter (ld.so) load base address.
pub const INTERP_LOAD_BASE: u64 = 0x6000000;
/// Buffer for loading interpreter ELF data.
pub const INTERP_BUF_BASE: u64 = 0xA000000;
/// Spawn buffer base (temp for process creation).
pub const SPAWN_BUF_BASE: u64 = 0x5000000;
/// Exec buffer base (temp for execve ELF loading).
pub const EXEC_BUF_BASE: u64 = 0x5400000;
/// vDSO page base address.
pub const VDSO_BASE: u64 = 0xB80000;
/// Child process heap base (above Wine PE region).
pub const CHILD_BRK_BASE: u64 = 0x200000000;
/// Child region size (256 MiB per child).
pub const CHILD_REGION_SIZE: u64 = 0x20000000;
/// Child mmap offset from brk base.
pub const CHILD_MMAP_OFFSET: u64 = 0x8000000;
/// Pre-TLS canary location (below vDSO).
pub const PRE_TLS_ADDR: u64 = 0xB70000;

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
    /// Entry point of the LUCAS guest binary (0 = none).
    pub guest_entry: u64,
    /// Framebuffer virtual address (0x4000000), 0 = no framebuffer.
    pub fb_addr: u64,
    /// Framebuffer width in pixels.
    pub fb_width: u32,
    /// Framebuffer height in pixels.
    pub fb_height: u32,
    /// Framebuffer pitch (bytes per row).
    pub fb_pitch: u32,
    /// Framebuffer bits per pixel (typically 32).
    pub fb_bpp: u32,
    /// Randomized stack top address (0 = default 0x904000).
    pub stack_top: u64,
    /// Capability ID for init's own address space (for CoW fork cloning).
    /// 0 = not available.
    pub self_as_cap: u64,
}

impl BootInfo {
    pub const fn empty() -> Self {
        Self {
            magic: 0,
            cap_count: 0,
            caps: [0; BOOT_INFO_MAX_CAPS],
            guest_entry: 0,
            fb_addr: 0,
            fb_width: 0,
            fb_height: 0,
            fb_pitch: 0,
            fb_bpp: 0,
            stack_top: 0,
            self_as_cap: 0,
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
    /// CR3 of the faulting address space (0 if not provided).
    pub cr3: u64,
    /// AS capability ID for the faulting address space (0 = unknown).
    /// Used by VMM to call map_into for CoW faults on child address spaces.
    pub as_cap_id: u64,
}

// ---------------------------------------------------------------
// Signal delivery (true async signals)
// ---------------------------------------------------------------

/// Magic tag in IPC reply that tells the kernel to redirect the child
/// thread to a signal handler instead of returning normally from the syscall.
pub const SIG_REDIRECT_TAG: u64 = 0x5349_4700; // "SIG\0"

/// Magic tag in IPC reply that tells the kernel to yield and re-send
/// the syscall to init. Used for non-blocking pipe reads: init can't
/// block in a spin-wait (it would stall all children), so it tells the
/// kernel to retry after yielding, giving other children a chance to
/// write data into the pipe.
pub const PIPE_RETRY_TAG: u64 = 0x5049_5045; // "PIPE"

/// Signal frame pushed onto the user stack during signal delivery.
/// Both the kernel (rt_sigreturn) and LUCAS (frame construction) use
/// this layout. 22 × 8 = 176 bytes.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct SignalFrame {
    /// Return address: sa_restorer (which calls rt_sigreturn).
    pub restorer: u64,
    /// Signal number being delivered.
    pub signo: u64,
    /// Saved general-purpose registers (for rt_sigreturn restoration).
    pub rax: u64,
    pub rbx: u64,
    pub rcx: u64,
    pub rdx: u64,
    pub rsi: u64,
    pub rdi: u64,
    pub rbp: u64,
    pub r8: u64,
    pub r9: u64,
    pub r10: u64,
    pub r11: u64,
    pub r12: u64,
    pub r13: u64,
    pub r14: u64,
    pub r15: u64,
    /// Saved user RIP (instruction pointer before signal).
    pub rip: u64,
    /// Saved user RSP (stack pointer before signal).
    pub rsp: u64,
    /// Saved RFLAGS.
    pub rflags: u64,
    /// Saved FS_BASE (TLS pointer).
    pub fs_base: u64,
    /// Signal mask to restore on rt_sigreturn.
    pub old_sigmask: u64,
    /// Pointer to ucontext_t on the user stack (0 if not SA_SIGINFO).
    /// rt_sigreturn reads modified RIP/RSP from here if non-zero.
    pub ucontext_ptr: u64,
}

/// Size of SignalFrame in bytes.
pub const SIGNAL_FRAME_SIZE: usize = core::mem::size_of::<SignalFrame>();

/// Syscall number for reading a blocked thread's saved registers.
/// Called by LUCAS: rdi = thread_id → writes 18 u64s to rsi buffer.
pub const SYS_GET_THREAD_REGS: u64 = 172;

/// Syscall number for setting a thread's async signal trampoline address.
/// Called by LUCAS: rdi = thread_id, rsi = trampoline_addr.
pub const SYS_SIGNAL_ENTRY: u64 = 173;

/// Syscall number for injecting an async signal into a thread.
/// Called by LUCAS: rdi = thread_id, rsi = signal_number.
pub const SYS_SIGNAL_INJECT: u64 = 174;

/// Get fault info (CR2, error code) for a thread's last kernel-generated signal.
/// rdi = thread_id, returns: rax = fault_addr (CR2), rdx = fault_code (error code).
pub const SYS_GET_FAULT_INFO: u64 = 176;

/// Enable/disable W^X relaxation for an address space.
/// rdi = as_cap (WRITE), rsi = 1 (relax) / 0 (enforce).
pub const SYS_WX_RELAX: u64 = 177;

/// Create a shared memory region.
pub const SYS_SHM_CREATE: u64 = 180;
/// Map shared memory into an address space.
pub const SYS_SHM_MAP: u64 = 181;
/// Unmap shared memory from an address space.
pub const SYS_SHM_UNMAP: u64 = 182;
/// Destroy shared memory, free frames when refcount=0.
pub const SYS_SHM_DESTROY: u64 = 183;

/// Special syscall number used by the async signal trampoline.
/// When the kernel redirects a user thread to the signal trampoline (from
/// timer interrupt), the trampoline calls this syscall which gets redirected
/// to LUCAS for signal frame construction.
pub const SYS_SIGNAL_TRAMPOLINE: u64 = 0x7F00;

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

    #[inline(always)]
    pub fn syscall4(nr: u64, a1: u64, a2: u64, a3: u64, a4: u64) -> u64 {
        let ret: u64;
        unsafe {
            core::arch::asm!(
                "syscall",
                inlateout("rax") nr => ret,
                in("rdi") a1,
                in("rsi") a2,
                in("rdx") a3,
                in("r8") a4,
                lateout("rcx") _,
                lateout("r11") _,
                options(nostack),
            );
        }
        ret
    }

    /// Raw syscall with 5 arguments (nr, rdi, rsi, rdx, r8, r10).
    #[inline(always)]
    pub fn syscall5(nr: u64, a1: u64, a2: u64, a3: u64, a4: u64, a5: u64) -> u64 {
        let ret: u64;
        unsafe {
            core::arch::asm!(
                "syscall",
                inlateout("rax") nr => ret,
                in("rdi") a1,
                in("rsi") a2,
                in("rdx") a3,
                in("r8") a4,
                in("r10") a5,
                lateout("rcx") _,
                lateout("r11") _,
                options(nostack),
            );
        }
        ret
    }

    /// Check a raw syscall return: negative → Err, otherwise Ok(value).
    #[inline(always)]
    fn check_val(ret: u64) -> Result<u64, i64> {
        if (ret as i64) < 0 { Err(ret as i64) } else { Ok(ret) }
    }

    /// Check a raw syscall return: negative → Err, otherwise Ok(()).
    #[inline(always)]
    fn check_unit(ret: u64) -> Result<(), i64> {
        if (ret as i64) < 0 { Err(ret as i64) } else { Ok(()) }
    }

    /// Write a single byte to the kernel debug serial port.
    #[inline(always)]
    pub fn debug_print(byte: u8) {
        syscall1(super::Syscall::DebugPrint as u64, byte as u64);
    }

    /// Query the number of free physical frames (debug).
    #[inline(always)]
    pub fn debug_free_frames() -> u64 {
        syscall0(252)
    }

    /// Drain up to `max` provenance entries from `cpu_id`'s ring into the
    /// caller-provided buffer at `dest`. Each slot is 48 bytes (matching
    /// kernel `ProvenanceEntry`). Returns the number of entries written.
    /// SAFETY: caller must ensure `dest` points at writable storage of at
    /// least `max * 48` bytes.
    #[inline(always)]
    pub unsafe fn provenance_drain(dest: *mut u8, max: u64, cpu_id: u64) -> u64 {
        syscall3(260, dest as u64, max, cpu_id)
    }

    /// Inject a synthetic provenance entry into the current CPU's ring.
    /// `operation` matches `sotos_provenance::Operation` (u16),
    /// `so_type` matches `sotos_provenance::SoType` (u8). Used by the
    /// Tier 3 deception demo's attacker simulator to drive the kernel
    /// ring with semantically meaningful events.
    #[inline(always)]
    pub fn provenance_emit(operation: u16, so_type: u8, so_id: u64, owner_domain: u32) {
        let _ = syscall4(
            261,
            operation as u64,
            so_type as u64,
            so_id,
            owner_domain as u64,
        );
    }

    /// Non-blocking read one byte from serial. Returns Some(byte) or None.
    #[inline(always)]
    pub fn debug_read() -> Option<u8> {
        let ret = syscall0(super::Syscall::DebugRead as u64);
        if ret == u64::MAX { None } else { Some(ret as u8) }
    }

    /// Allocate a physical frame. Returns the frame capability ID.
    #[inline(always)]
    pub fn frame_alloc() -> Result<u64, i64> {
        check_val(syscall0(super::Syscall::FrameAlloc as u64))
    }

    /// Map a frame into the caller's address space.
    /// `flags`: bit 1 = WRITABLE, bit 63 = NO_EXECUTE.
    #[inline(always)]
    pub fn map(vaddr: u64, frame_cap: u64, flags: u64) -> Result<(), i64> {
        check_unit(syscall3(super::Syscall::Map as u64, vaddr, frame_cap, flags))
    }

    /// Create a notification object. Returns the notification capability ID.
    #[inline(always)]
    pub fn notify_create() -> Result<u64, i64> {
        check_val(syscall0(super::Syscall::NotifyCreate as u64))
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
        check_val(syscall3(super::Syscall::ThreadCreate as u64, rip, rsp, 0))
    }

    /// Create a new thread with a pre-set syscall redirect endpoint (for LUCAS).
    /// The redirect is set atomically before the thread is scheduled.
    #[inline(always)]
    pub fn thread_create_redirected(rip: u64, rsp: u64, ep_cap: u64) -> Result<u64, i64> {
        check_val(syscall3(super::Syscall::ThreadCreate as u64, rip, rsp, ep_cap))
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

    macro_rules! port_in_fn {
        ($name:ident, $width:expr, $ty:ty) => {
            #[inline(always)]
            pub fn $name(cap: u64, port: u64) -> Result<$ty, i64> {
                check_val(syscall3(super::Syscall::PortIn as u64, cap, port, $width)).map(|v| v as $ty)
            }
        };
    }
    macro_rules! port_out_fn {
        ($name:ident, $width:expr, $ty:ty) => {
            #[inline(always)]
            pub fn $name(cap: u64, port: u64, value: $ty) -> Result<(), i64> {
                check_unit(syscall4(super::Syscall::PortOut as u64, cap, port, value as u64, $width))
            }
        };
    }

    port_in_fn!(port_in, 1, u8);
    port_in_fn!(port_in16, 2, u16);
    port_in_fn!(port_in32, 4, u32);
    port_out_fn!(port_out, 1, u8);
    port_out_fn!(port_out16, 2, u16);
    port_out_fn!(port_out32, 4, u32);

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
        check_unit(ret)
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
        check_val(ret).map(|_| super::IpcMsg { tag, regs: [r0, r1, r2, r3, r4, r5, r6, r7] })
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
        check_val(ret).map(|_| super::IpcMsg { tag, regs: [r0, r1, r2, r3, r4, r5, r6, r7] })
    }

    /// Combined send+receive with timeout on a synchronous IPC endpoint.
    /// `timeout_ticks` is relative (number of scheduler ticks; 100 ticks ≈ 1s at 100Hz).
    /// Returns `Err(-7)` on timeout (SysError::Timeout).
    #[inline(always)]
    pub fn call_timeout(ep_cap: u64, msg: &super::IpcMsg, timeout_ticks: u32) -> Result<super::IpcMsg, i64> {
        // Encode timeout in upper 32 bits of rdi.
        let rdi_val = (ep_cap & 0xFFFFFFFF) | ((timeout_ticks as u64) << 32);
        let ret: u64;
        let tag: u64;
        let r0: u64; let r1: u64; let r2: u64; let r3: u64;
        let r4: u64; let r5: u64; let r6: u64; let r7: u64;
        unsafe {
            core::arch::asm!(
                "syscall",
                inlateout("rax") super::Syscall::CallTimeout as u64 => ret,
                in("rdi") rdi_val,
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
        check_val(ret).map(|_| super::IpcMsg { tag, regs: [r0, r1, r2, r3, r4, r5, r6, r7] })
    }

    /// Receive with timeout on a synchronous IPC endpoint.
    /// `timeout_ticks` is relative (number of scheduler ticks; 100 ticks ~= 1s at 100Hz).
    /// Returns `Err(-7)` on timeout (SysError::Timeout).
    #[inline(always)]
    pub fn recv_timeout(ep_cap: u64, timeout_ticks: u32) -> Result<super::IpcMsg, i64> {
        let rdi_val = (ep_cap & 0xFFFFFFFF) | ((timeout_ticks as u64) << 32);
        let ret: u64;
        let tag: u64;
        let r0: u64; let r1: u64; let r2: u64; let r3: u64;
        let r4: u64; let r5: u64; let r6: u64; let r7: u64;
        unsafe {
            core::arch::asm!(
                "syscall",
                inlateout("rax") super::Syscall::RecvTimeout as u64 => ret,
                in("rdi") rdi_val,
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
        check_val(ret).map(|_| super::IpcMsg { tag, regs: [r0, r1, r2, r3, r4, r5, r6, r7] })
    }

    // ---------------------------------------------------------------
    // IPC — async channels
    // ---------------------------------------------------------------

    /// Create a new async IPC channel. Returns the channel capability ID.
    #[inline(always)]
    pub fn channel_create() -> Result<u64, i64> {
        check_val(syscall0(super::Syscall::ChannelCreate as u64))
    }

    /// Send a tag on an async channel.
    #[inline(always)]
    pub fn channel_send(cap: u64, tag: u64) -> Result<(), i64> {
        check_unit(syscall2(super::Syscall::ChannelSend as u64, cap, tag))
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
        check_val(ret).map(|_| tag)
    }

    /// Close an async channel.
    #[inline(always)]
    pub fn channel_close(cap: u64) -> Result<(), i64> {
        check_unit(syscall1(super::Syscall::ChannelClose as u64, cap))
    }

    // ---------------------------------------------------------------
    // Endpoints
    // ---------------------------------------------------------------

    /// Create a new IPC endpoint. Returns the endpoint capability ID.
    #[inline(always)]
    pub fn endpoint_create() -> Result<u64, i64> {
        check_val(syscall0(super::Syscall::EndpointCreate as u64))
    }

    // ---------------------------------------------------------------
    // Capabilities
    // ---------------------------------------------------------------

    /// Grant (delegate) a capability with restricted rights.
    #[inline(always)]
    pub fn cap_grant(source: u64, rights_mask: u64) -> Result<u64, i64> {
        check_val(syscall2(super::Syscall::CapGrant as u64, source, rights_mask))
    }

    /// Revoke a capability and all its derivatives.
    #[inline(always)]
    pub fn cap_revoke(cap: u64) -> Result<(), i64> {
        check_unit(syscall1(super::Syscall::CapRevoke as u64, cap))
    }

    // ---------------------------------------------------------------
    // Memory
    // ---------------------------------------------------------------

    /// Free a physical frame capability.
    #[inline(always)]
    pub fn frame_free(cap: u64) -> Result<(), i64> {
        check_unit(syscall1(super::Syscall::FrameFree as u64, cap))
    }

    /// Unmap a virtual page.
    #[inline(always)]
    pub fn unmap(vaddr: u64) -> Result<(), i64> {
        check_unit(syscall1(super::Syscall::Unmap as u64, vaddr))
    }

    /// Unmap a virtual page and free the underlying physical frame.
    #[inline(always)]
    pub fn unmap_free(vaddr: u64) -> Result<(), i64> {
        check_unit(syscall1(super::Syscall::UnmapFree as u64, vaddr))
    }

    // ---------------------------------------------------------------
    // Threads
    // ---------------------------------------------------------------

    /// Resume a faulted thread.
    #[inline(always)]
    pub fn thread_resume(tid: u64) -> Result<(), i64> {
        check_unit(syscall1(super::Syscall::ThreadResume as u64, tid))
    }

    // ---------------------------------------------------------------
    // IRQ
    // ---------------------------------------------------------------

    /// Register an IRQ handler notification.
    #[inline(always)]
    pub fn irq_register(irq_cap: u64, notify_cap: u64) -> Result<(), i64> {
        check_unit(syscall2(super::Syscall::IrqRegister as u64, irq_cap, notify_cap))
    }

    /// Acknowledge an IRQ (unmask the line).
    #[inline(always)]
    pub fn irq_ack(cap: u64) -> Result<(), i64> {
        check_unit(syscall1(super::Syscall::IrqAck as u64, cap))
    }

    // ---------------------------------------------------------------
    // Faults (VMM)
    // ---------------------------------------------------------------

    /// Register a notification for page fault delivery (caller's own AS).
    #[inline(always)]
    pub fn fault_register(notify_cap: u64) -> Result<(), i64> {
        check_unit(syscall2(super::Syscall::FaultRegister as u64, notify_cap, 0))
    }

    /// Register a notification for page fault delivery in a specific address space.
    #[inline(always)]
    pub fn fault_register_as(notify_cap: u64, as_cap: u64) -> Result<(), i64> {
        check_unit(syscall2(super::Syscall::FaultRegister as u64, notify_cap, as_cap))
    }

    /// Receive the next pending page fault.
    #[inline(always)]
    pub fn fault_recv() -> Result<super::FaultInfo, i64> {
        let ret: u64;
        let addr: u64;
        let code: u64;
        let tid: u64;
        let cr3: u64;
        let as_cap_id: u64;
        unsafe {
            core::arch::asm!(
                "syscall",
                inlateout("rax") super::Syscall::FaultRecv as u64 => ret,
                lateout("rdi") addr,
                lateout("rsi") code,
                lateout("rdx") tid,
                lateout("r8") cr3,
                lateout("r9") as_cap_id,
                lateout("rcx") _,
                lateout("r11") _,
                options(nostack),
            );
        }
        check_val(ret).map(|_| super::FaultInfo { addr, code, tid: tid as u32, cr3, as_cap_id })
    }

    // ---------------------------------------------------------------
    // Scheduling Domains
    // ---------------------------------------------------------------

    /// Create a scheduling domain with the given quantum and period (in ms).
    /// Returns the domain capability ID.
    #[inline(always)]
    pub fn domain_create(quantum_ms: u64, period_ms: u64) -> Result<u64, i64> {
        check_val(syscall2(super::Syscall::DomainCreate as u64, quantum_ms, period_ms))
    }

    /// Attach a thread to a scheduling domain.
    #[inline(always)]
    pub fn domain_attach(domain_cap: u64, thread_cap: u64) -> Result<(), i64> {
        check_unit(syscall2(super::Syscall::DomainAttach as u64, domain_cap, thread_cap))
    }

    /// Detach a thread from a scheduling domain.
    #[inline(always)]
    pub fn domain_detach(domain_cap: u64, thread_cap: u64) -> Result<(), i64> {
        check_unit(syscall2(super::Syscall::DomainDetach as u64, domain_cap, thread_cap))
    }

    /// Adjust a domain's quantum (in ms).
    #[inline(always)]
    pub fn domain_adjust(domain_cap: u64, new_quantum_ms: u64) -> Result<(), i64> {
        check_unit(syscall2(super::Syscall::DomainAdjust as u64, domain_cap, new_quantum_ms))
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
        check_val(ret).map(|_| (quantum, consumed, period))
    }

    // ---------------------------------------------------------------
    // Device infrastructure (virtio, PCI)
    // ---------------------------------------------------------------

    /// Query the physical address of a frame capability.
    #[inline(always)]
    pub fn frame_phys(frame_cap: u64) -> Result<u64, i64> {
        check_val(syscall1(super::Syscall::FramePhys as u64, frame_cap))
    }

    /// Create an I/O port capability dynamically. Returns cap_id.
    #[inline(always)]
    pub fn ioport_create(base: u16, count: u16) -> Result<u64, i64> {
        check_val(syscall2(super::Syscall::IoPortCreate as u64, base as u64, count as u64))
    }

    /// Allocate N contiguous physical frames (1–16). Returns Memory cap_id.
    #[inline(always)]
    pub fn frame_alloc_contiguous(count: u64) -> Result<u64, i64> {
        check_val(syscall1(super::Syscall::FrameAllocContig as u64, count))
    }

    /// Create an IRQ capability dynamically (irq_line 0–15). Returns cap_id.
    #[inline(always)]
    pub fn irq_create(irq_line: u64) -> Result<u64, i64> {
        check_val(syscall1(super::Syscall::IrqCreate as u64, irq_line))
    }

    /// Map a page from a multi-page Memory capability at the given offset.
    /// `flags`: bit 1 = WRITABLE, bit 63 = NO_EXECUTE.
    #[inline(always)]
    pub fn map_offset(vaddr: u64, mem_cap: u64, offset: u64, flags: u64) -> Result<(), i64> {
        check_unit(syscall4(super::Syscall::MapOffset as u64, vaddr, mem_cap, offset, flags))
    }

    /// Set syscall redirect endpoint on a thread (LUCAS).
    /// All syscalls from the target thread will be forwarded as IPC messages
    /// to the specified endpoint.
    #[inline(always)]
    pub fn redirect_set(thread_cap: u64, ep_cap: u64) -> Result<(), i64> {
        check_unit(syscall2(super::Syscall::RedirectSet as u64, thread_cap, ep_cap))
    }

    // ---------------------------------------------------------------
    // Multi-address-space
    // ---------------------------------------------------------------

    /// Create a new empty user address space. Returns AS cap ID.
    #[inline(always)]
    pub fn addr_space_create() -> Result<u64, i64> {
        check_val(syscall0(super::Syscall::AddrSpaceCreate as u64))
    }

    /// Map a frame into a target address space (not the caller's).
    #[inline(always)]
    pub fn map_into(as_cap: u64, vaddr: u64, frame_cap: u64, flags: u64) -> Result<(), i64> {
        check_unit(syscall4(super::Syscall::MapInto as u64, as_cap, vaddr, frame_cap, flags))
    }

    /// Create a thread in a target address space. Returns thread cap ID.
    /// `redirect_ep_cap` = 0 means no redirect; non-zero = endpoint cap for syscall redirect.
    #[inline(always)]
    pub fn thread_create_in(as_cap: u64, rip: u64, rsp: u64, redirect_ep_cap: u64) -> Result<u64, i64> {
        thread_create_in_sig(as_cap, rip, rsp, redirect_ep_cap, 0)
    }

    /// Create a thread in a target AS with signal trampoline set atomically.
    /// Prevents the race where the thread faults before signal_entry() is called.
    pub fn thread_create_in_sig(as_cap: u64, rip: u64, rsp: u64, redirect_ep_cap: u64, signal_tramp: u64) -> Result<u64, i64> {
        check_val(syscall5(super::Syscall::ThreadCreateIn as u64, as_cap, rip, rsp, redirect_ep_cap, signal_tramp))
    }

    /// Unmap a page from a target address space.
    #[inline(always)]
    pub fn unmap_from(as_cap: u64, vaddr: u64) -> Result<(), i64> {
        check_unit(syscall2(super::Syscall::UnmapFrom as u64, as_cap, vaddr))
    }

    /// Clone an address space with Copy-on-Write semantics.
    /// Returns the new AS cap ID.
    #[inline(always)]
    pub fn addr_space_clone(src_as_cap: u64) -> Result<u64, i64> {
        check_val(syscall1(super::Syscall::AddrSpaceClone as u64, src_as_cap))
    }

    /// Set FS_BASE on a target thread (by thread cap). For CoW fork child init.
    #[inline(always)]
    pub fn set_thread_fs_base(thread_cap: u64, fs_base: u64) -> Result<(), i64> {
        check_unit(syscall2(162, thread_cap, fs_base))
    }

    /// Copy 4KiB from a page in src AS to a frame cap (via kernel HHDM).
    #[inline(always)]
    pub fn frame_copy(dst_frame_cap: u64, src_as_cap: u64, vaddr: u64) -> Result<(), i64> {
        check_unit(syscall3(super::Syscall::FrameCopy as u64, dst_frame_cap, src_as_cap, vaddr))
    }

    /// Read PTE (phys + flags) for a vaddr in an AS.
    /// Returns (phys_addr, flags) on success.
    /// Kernel returns: rax = phys, rdi = flags.
    #[inline(always)]
    pub fn pte_read(as_cap: u64, vaddr: u64) -> Result<(u64, u64), i64> {
        let phys_or_err: u64;
        let flags: u64;
        unsafe {
            core::arch::asm!(
                "syscall",
                inlateout("rax") super::Syscall::PteRead as u64 => phys_or_err,
                inlateout("rdi") as_cap => flags,
                in("rsi") vaddr,
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
        if (phys_or_err as i64) < 0 { Err(phys_or_err as i64) } else { Ok((phys_or_err, flags)) }
    }

    // ---------------------------------------------------------------
    // Cross-AS memory access (for CoW fork handler)
    // ---------------------------------------------------------------

    /// Read bytes from a target address space into caller's buffer.
    /// as_cap: AddrSpace capability for the target AS.
    /// remote_vaddr: virtual address in the target AS to read from.
    /// local_buf: pointer in caller's AS to write into.
    /// len: number of bytes to read (max 4096).
    #[inline(always)]
    pub fn vm_read(as_cap: u64, remote_vaddr: u64, local_buf: u64, len: u64) -> Result<(), i64> {
        check_unit(syscall4(super::Syscall::VmRead as u64, as_cap, remote_vaddr, local_buf, len))
    }

    /// Write bytes from caller's buffer into a target address space.
    /// Handles CoW: if the target page is read-only, allocates a new frame,
    /// copies old content, updates PTE, then writes the data.
    /// as_cap: AddrSpace capability for the target AS.
    /// remote_vaddr: virtual address in the target AS to write to.
    /// local_buf: pointer in caller's AS to read from.
    /// len: number of bytes to write (max 4096).
    #[inline(always)]
    pub fn vm_write(as_cap: u64, remote_vaddr: u64, local_buf: u64, len: u64) -> Result<(), i64> {
        check_unit(syscall4(super::Syscall::VmWrite as u64, as_cap, remote_vaddr, local_buf, len))
    }

    // ---------------------------------------------------------------
    // Service registry
    // ---------------------------------------------------------------

    /// Register a service name → endpoint mapping.
    /// `ep_cap` must be an Endpoint capability.
    #[inline(always)]
    pub fn svc_register(name_ptr: u64, name_len: u64, ep_cap: u64) -> Result<(), i64> {
        check_unit(syscall3(super::Syscall::SvcRegister as u64, name_ptr, name_len, ep_cap))
    }

    /// Look up a service by name. Returns a derived endpoint cap ID.
    #[inline(always)]
    pub fn svc_lookup(name_ptr: u64, name_len: u64) -> Result<u64, i64> {
        check_val(syscall2(super::Syscall::SvcLookup as u64, name_ptr, name_len))
    }

    // ---------------------------------------------------------------
    // Userspace process spawning
    // ---------------------------------------------------------------

    /// Read a file from the initrd CPIO archive into a userspace buffer.
    /// Returns the file size on success.
    #[inline(always)]
    pub fn initrd_read(name_ptr: u64, name_len: u64, buf_ptr: u64, buf_len: u64) -> Result<u64, i64> {
        check_val(syscall4(super::Syscall::InitrdRead as u64, name_ptr, name_len, buf_ptr, buf_len))
    }

    /// Write a BootInfo page into a target address space at 0xB00000.
    /// `caps_ptr` points to an array of cap IDs, `cap_count` is the number.
    #[inline(always)]
    pub fn bootinfo_write(as_cap: u64, caps_ptr: u64, cap_count: u64) -> Result<(), i64> {
        check_unit(syscall3(super::Syscall::BootInfoWrite as u64, as_cap, caps_ptr, cap_count))
    }

    /// Change page permissions (mprotect-like). W^X enforced by kernel.
    /// `flags`: bit 1 = WRITABLE, bit 63 = NO_EXECUTE.
    #[inline(always)]
    pub fn protect(vaddr: u64, flags: u64) -> Result<(), i64> {
        check_unit(syscall2(super::Syscall::Protect as u64, vaddr, flags))
    }

    /// Change page permissions in a target address space.
    #[inline(always)]
    pub fn protect_in(as_cap: u64, vaddr: u64, flags: u64) -> Result<(), i64> {
        check_unit(syscall3(super::Syscall::ProtectIn as u64, as_cap, vaddr, flags))
    }

    /// Enable/disable W^X relaxation for an address space.
    /// `as_cap`: address space capability (WRITE). `enable`: 1=relax, 0=enforce.
    #[inline(always)]
    pub fn wx_relax(as_cap: u64, enable: u64) -> Result<(), i64> {
        check_unit(syscall2(super::SYS_WX_RELAX, as_cap, enable))
    }

    /// Create a shared memory region with `num_pages` physical frames.
    /// Returns the handle (index) on success.
    #[inline(always)]
    pub fn shm_create(num_pages: u64) -> Result<u64, i64> {
        check_val(syscall1(super::SYS_SHM_CREATE, num_pages))
    }

    /// Map a shared memory region into an address space.
    /// `flags`: bit 0 = writable.
    #[inline(always)]
    pub fn shm_map(handle: u64, as_cap: u64, vaddr: u64, flags: u64) -> Result<(), i64> {
        check_unit(syscall4(super::SYS_SHM_MAP, handle, as_cap, vaddr, flags))
    }

    /// Unmap a shared memory region from an address space.
    #[inline(always)]
    pub fn shm_unmap(handle: u64, as_cap: u64, vaddr: u64) -> Result<(), i64> {
        check_unit(syscall3(super::SYS_SHM_UNMAP, handle, as_cap, vaddr))
    }

    /// Destroy a shared memory region, freeing frames when refcount=0.
    #[inline(always)]
    pub fn shm_destroy(handle: u64) -> Result<(), i64> {
        check_unit(syscall1(super::SYS_SHM_DESTROY, handle))
    }

    /// Change file permissions (chmod).
    /// `path_ptr`/`path_len`: path string in userspace memory.
    /// `mode`: Unix permission bits (e.g. 0o755).
    #[inline(always)]
    pub fn chmod(path_ptr: u64, path_len: u64, mode: u64) -> Result<(), i64> {
        check_unit(syscall3(super::Syscall::Chmod as u64, path_ptr, path_len, mode))
    }

    /// Change file ownership (chown).
    /// `path_ptr`/`path_len`: path string in userspace memory.
    /// `uid`: new owner user ID. `gid`: new owner group ID.
    #[inline(always)]
    pub fn chown(path_ptr: u64, path_len: u64, uid: u64, gid: u64) -> Result<(), i64> {
        check_unit(syscall4(super::Syscall::Chown as u64, path_ptr, path_len, uid, gid))
    }

    /// Get thread info by pool index.
    /// Returns (tid, state, priority, cpu_ticks, mem_pages, is_user) or error.
    #[inline(always)]
    pub fn thread_info(idx: u64) -> Result<(u64, u64, u64, u64, u64, u64), i64> {
        check_val(syscall1(super::Syscall::ThreadInfo as u64, idx)).map(|_| (0, 0, 0, 0, 0, 0))
    }

    /// Get total live thread count.
    #[inline(always)]
    pub fn thread_count() -> u64 {
        syscall0(super::Syscall::ThreadCount as u64)
    }

    /// Set the FS_BASE MSR for the current thread (TLS support).
    #[inline(always)]
    pub fn set_fs_base(addr: u64) -> Result<(), i64> {
        check_unit(syscall1(super::Syscall::SetFsBase as u64, addr))
    }

    /// Get the FS_BASE MSR of the current thread.
    #[inline(always)]
    pub fn get_fs_base() -> u64 {
        syscall0(super::Syscall::GetFsBase as u64)
    }

    /// Debug: read u64 from physical address via kernel HHDM.
    #[inline(always)]
    pub fn debug_phys_read(phys_addr: u64) -> u64 {
        syscall1(254, phys_addr)
    }

    // ---------------------------------------------------------------
    // Signal delivery support
    // ---------------------------------------------------------------

    /// Read saved user-mode registers of a blocked thread (for signal frame construction).
    /// Writes 20 u64s to `out_buf`:
    ///   [0..14]=GPRs (rax,rbx,rcx,rdx,rsi,rdi,rbp,r8..r15),
    ///   [15]=RSP, [16]=fs_base, [17]=kernel_signal,
    ///   [18]=real_rip, [19]=real_rflags (non-zero when from interrupt/fault context).
    /// When [18]/[19] are 0, use rcx/r11 as rip/rflags (SYSCALL convention).
    #[inline(always)]
    pub fn get_thread_regs(tid: u64, out_buf: &mut [u64; 20]) -> Result<(), i64> {
        check_unit(syscall2(super::SYS_GET_THREAD_REGS, tid, out_buf.as_mut_ptr() as u64))
    }

    /// Get fault info (CR2 and error code) for a thread's last kernel signal.
    /// Returns (fault_addr, fault_code).
    #[inline(always)]
    pub fn get_fault_info(tid: u64) -> (u64, u64) {
        let addr: u64;
        let code: u64;
        unsafe {
            core::arch::asm!(
                "syscall",
                inlateout("rax") super::SYS_GET_FAULT_INFO => addr,
                in("rdi") tid,
                lateout("rdx") code,
                lateout("rcx") _,
                lateout("r11") _,
                options(nostack),
            );
        }
        (addr, code)
    }

    /// Set the async signal trampoline address for a thread.
    #[inline(always)]
    pub fn signal_entry(tid: u64, trampoline_addr: u64) -> Result<(), i64> {
        check_unit(syscall2(super::SYS_SIGNAL_ENTRY, tid, trampoline_addr))
    }

    /// Inject an async signal into a thread (sets pending bit).
    #[inline(always)]
    pub fn signal_inject(tid: u64, sig: u64) -> Result<(), i64> {
        check_unit(syscall2(super::SYS_SIGNAL_INJECT, tid, sig))
    }

    // ---- SOT Exokernel Primitives (syscalls 300-310) ----

    #[inline(always)]
    pub fn so_create(type_id: u64, policy: u64) -> Result<u64, i64> {
        check_val(syscall2(super::Syscall::SoCreate as u64, type_id, policy))
    }
    /// Same as `so_create` but also sets the owner_domain field used by
    /// the kernel provenance recorder. Lets userspace tag activity it
    /// produces with a domain id so the GraphHunter can group operations.
    #[inline(always)]
    pub fn so_create_owned(type_id: u64, policy: u64, owner_domain: u64) -> Result<u64, i64> {
        check_val(syscall3(super::Syscall::SoCreate as u64, type_id, policy, owner_domain))
    }
    #[inline(always)]
    pub fn so_invoke(cap: u64, method: u64, arg0: u64, arg1: u64) -> Result<u64, i64> {
        check_val(syscall4(super::Syscall::SoInvoke as u64, cap, method, arg0, arg1))
    }
    #[inline(always)]
    pub fn so_grant(cap: u64, target_domain: u64, rights_mask: u64) -> Result<u64, i64> {
        check_val(syscall3(super::Syscall::SoGrant as u64, cap, target_domain, rights_mask))
    }
    #[inline(always)]
    pub fn so_revoke(cap: u64) -> Result<(), i64> {
        check_unit(syscall1(super::Syscall::SoRevoke as u64, cap))
    }
    #[inline(always)]
    pub fn so_observe(cap: u64, observer_cap: u64) -> Result<(), i64> {
        check_unit(syscall2(super::Syscall::SoObserve as u64, cap, observer_cap))
    }
    #[inline(always)]
    pub fn sot_domain_create(policy: u64, cr3: u64) -> Result<u64, i64> {
        check_val(syscall2(super::Syscall::SotDomainCreate as u64, policy, cr3))
    }
    #[inline(always)]
    pub fn sot_domain_enter(domain_cap: u64, entry_cap: u64) -> Result<(), i64> {
        check_unit(syscall2(super::Syscall::SotDomainEnter as u64, domain_cap, entry_cap))
    }
    #[inline(always)]
    pub fn sot_channel_create(protocol: u64) -> Result<u64, i64> {
        check_val(syscall1(super::Syscall::SotChannelCreate as u64, protocol))
    }
    #[inline(always)]
    pub fn tx_begin(tier: u64) -> Result<u64, i64> {
        // Pass domain_cap=0 (root) explicitly so kernel sees a clean rdi/rsi.
        // Use syscall2 to ensure tier lands in rsi instead of leaving it uninitialized.
        check_val(syscall2(super::Syscall::TxBegin as u64, 0, tier))
    }
    #[inline(always)]
    pub fn tx_commit(tx_id: u64) -> Result<(), i64> {
        check_unit(syscall1(super::Syscall::TxCommit as u64, tx_id))
    }
    #[inline(always)]
    pub fn tx_abort(tx_id: u64) -> Result<(), i64> {
        check_unit(syscall1(super::Syscall::TxAbort as u64, tx_id))
    }
    /// Tier 2 (MultiObject) two-phase commit: PREPARE phase.
    /// Active -> Preparing. Must be followed by `tx_commit` or `tx_abort`.
    #[inline(always)]
    pub fn tx_prepare(tx_id: u64) -> Result<(), i64> {
        check_unit(syscall1(super::Syscall::TxPrepare as u64, tx_id))
    }
}
