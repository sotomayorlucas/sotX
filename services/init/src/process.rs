// ---------------------------------------------------------------------------
// Process management: process table, signals, thread groups, futex
// ---------------------------------------------------------------------------

use sotos_common::sys;
use sotos_common::{IpcMsg, SIG_REDIRECT_TAG, SIGNAL_FRAME_SIZE};
use sotos_common::linux_abi;
use core::sync::atomic::{AtomicU64, Ordering};
use crate::exec::BufWriter;
use ufmt::uwrite;
use crate::fd::fd_grp_init;

// ---------------------------------------------------------------------------
// Process table constants
// ---------------------------------------------------------------------------

pub(crate) const MAX_PROCS: usize = 64;

// ---------------------------------------------------------------------------
// ProcessState: all per-process metadata in one struct.
// Uses AtomicU64 fields for lock-free concurrent access.
// ---------------------------------------------------------------------------

pub(crate) struct ProcessState {
    // Core process info
    pub state: AtomicU64,       // 0=Free, 1=Running, 2=Zombie
    pub exit_code: AtomicU64,   // exit status (valid when Zombie)
    pub parent: AtomicU64,      // parent PID (0=none)
    pub kernel_tid: AtomicU64,  // raw kernel thread ID (for async signal injection)

    // Thread group / resource sharing
    pub tgid: AtomicU64,        // thread group ID
    pub fd_group: AtomicU64,    // FD group index (into THREAD_GROUPS)
    pub mem_group: AtomicU64,   // memory group index (into THREAD_GROUPS)
    pub sig_group: AtomicU64,   // signal handler group index
    pub clear_tid: AtomicU64,   // CLONE_CHILD_CLEARTID pointer

    // Stack tracking
    pub stack_base: AtomicU64,
    pub stack_pages: AtomicU64,

    // ELF load range (page-aligned)
    pub elf_lo: AtomicU64,
    pub elf_hi: AtomicU64,
    pub has_interp: AtomicU64,

    // brk/mmap per-process tracking (for cleanup on exit)
    pub brk_base: AtomicU64,
    pub brk_current: AtomicU64,
    pub mmap_base: AtomicU64,
    pub mmap_next: AtomicU64,

    // Signals
    pub sig_pending: AtomicU64,         // pending signals bitmask
    pub sig_blocked: AtomicU64,         // blocked signals bitmask
    pub sig_handler: [AtomicU64; 32],   // handler addr per signal (0=SIG_DFL, 1=SIG_IGN)
    pub sig_flags: [AtomicU64; 32],     // SA_* flags per signal
    pub sig_restorer: [AtomicU64; 32],  // sa_restorer per signal

    // Alternate signal stack (sigaltstack)
    pub sig_alt_sp: AtomicU64,          // ss_sp (stack base pointer)
    pub sig_alt_size: AtomicU64,        // ss_size (stack size in bytes)
    pub sig_alt_flags: AtomicU64,       // ss_flags (0=enabled, SS_ONSTACK=1, SS_DISABLE=2)
    /// Set to 1 when SIGSEGV handler is active. If raise(SIGSEGV) fires
    /// while this is set, force SIG_DFL (like Linux's force_sig_fault).
    pub sig_in_handler: AtomicU64,

    // Robust futex list (set_robust_list/get_robust_list)
    pub robust_list_head: AtomicU64,    // pointer to robust_list_head struct
    pub robust_list_len: AtomicU64,     // length argument from set_robust_list

    // Process name (prctl PR_SET_NAME, 16 bytes max including NUL)
    pub proc_name: [AtomicU64; 2],      // 16 bytes stored as 2×u64

    // Executable path for /proc/self/exe (set at exec time)
    pub exe_path: [AtomicU64; 4],       // up to 32 bytes (NUL-terminated)

    // Personality (0=default/musl, 1=glibc) — controls library resolution
    pub personality: core::sync::atomic::AtomicU8,
}

impl ProcessState {
    pub(crate) const fn new() -> Self {
        Self {
            state: AtomicU64::new(0),
            exit_code: AtomicU64::new(0),
            parent: AtomicU64::new(0),
            kernel_tid: AtomicU64::new(0),
            tgid: AtomicU64::new(0),
            fd_group: AtomicU64::new(0),
            mem_group: AtomicU64::new(0),
            sig_group: AtomicU64::new(0),
            clear_tid: AtomicU64::new(0),
            stack_base: AtomicU64::new(0),
            stack_pages: AtomicU64::new(0),
            elf_lo: AtomicU64::new(0),
            elf_hi: AtomicU64::new(0),
            has_interp: AtomicU64::new(0),
            brk_base: AtomicU64::new(0),
            brk_current: AtomicU64::new(0),
            mmap_base: AtomicU64::new(0),
            mmap_next: AtomicU64::new(0),
            sig_pending: AtomicU64::new(0),
            sig_blocked: AtomicU64::new(0),
            sig_handler: [const { AtomicU64::new(0) }; 32],
            sig_flags: [const { AtomicU64::new(0) }; 32],
            sig_restorer: [const { AtomicU64::new(0) }; 32],
            sig_alt_sp: AtomicU64::new(0),
            sig_alt_size: AtomicU64::new(0),
            sig_alt_flags: AtomicU64::new(2), // SS_DISABLE
            sig_in_handler: AtomicU64::new(0),
            robust_list_head: AtomicU64::new(0),
            robust_list_len: AtomicU64::new(0),
            proc_name: [const { AtomicU64::new(0) }; 2],
            exe_path: [const { AtomicU64::new(0) }; 4],
            personality: core::sync::atomic::AtomicU8::new(0),
        }
    }
}

/// Consolidated per-process state. Indexed by pid-1 (0-based).
pub(crate) static PROCESSES: [ProcessState; MAX_PROCS] =
    [const { ProcessState::new() }; MAX_PROCS];

/// Init's own address space capability (from BootInfo.self_as_cap).
/// Set once at startup, read by child_handler for CoW fork.
pub(crate) static INIT_SELF_AS_CAP: AtomicU64 = AtomicU64::new(0);

// ---------------------------------------------------------------------------
// Personality: controls library resolution (initrd skip for glibc processes)
// ---------------------------------------------------------------------------
#[allow(dead_code)]
pub(crate) const PERS_DEFAULT: u8 = 0;
pub(crate) const PERS_GLIBC: u8 = 1;

/// Read the personality byte for a given pid (0 if invalid pid).
pub(crate) fn get_personality(pid: usize) -> u8 {
    if pid == 0 || pid > MAX_PROCS { return 0; }
    PROCESSES[pid - 1].personality.load(core::sync::atomic::Ordering::Acquire)
}

pub(crate) fn set_personality(pid: usize, val: u8) {
    if pid > 0 && pid <= MAX_PROCS {
        PROCESSES[pid - 1].personality.store(val, core::sync::atomic::Ordering::Release);
    }
}

// Signal constants
pub(crate) const _SA_NOCLDSTOP: u64 = 1;
pub(crate) const _SA_NOCLDWAIT: u64 = 2;

/// Boot TSC value for uptime calculation.
pub(crate) static BOOT_TSC: AtomicU64 = AtomicU64::new(0);

/// Next PID to allocate (monotonically increasing, starts at 1).
pub(crate) static NEXT_PID: AtomicU64 = AtomicU64::new(1);
/// Next vaddr for child stacks (guest + handler interleaved, 0x2000 apart).
pub(crate) static NEXT_CHILD_STACK: AtomicU64 = AtomicU64::new(0x100000000); // 4 GiB — safely above all loaded binaries and Wine PE region

// Handshake statics for passing setup info to child handler thread.
pub(crate) static CHILD_SETUP_EP: AtomicU64 = AtomicU64::new(0);
pub(crate) static CHILD_SETUP_PID: AtomicU64 = AtomicU64::new(0);
pub(crate) static CHILD_SETUP_READY: AtomicU64 = AtomicU64::new(0);
pub(crate) static CHILD_SETUP_FLAGS: AtomicU64 = AtomicU64::new(0);
/// AS cap for fork-children (0 for same-AS children).
pub(crate) static CHILD_SETUP_AS_CAP: AtomicU64 = AtomicU64::new(0);

// ---------------------------------------------------------------------------
// Phase 4: Thread groups, shared FD tables, and futex
// ---------------------------------------------------------------------------

// Clone flag constants — sourced from linux_abi (linux-raw-sys)
pub(crate) use linux_abi::{CLONE_VM, CLONE_FILES, CLONE_SIGHAND, CLONE_THREAD,
                           CLONE_SETTLS, CLONE_PARENT_SETTID, CLONE_CHILD_SETTID,
                           CLONE_CHILD_CLEARTID};

// ---------------------------------------------------------------------------
// Futex wait queue (Phase 4)
// ---------------------------------------------------------------------------
pub(crate) const MAX_FUTEX_WAITERS: usize = 128;
/// Address being waited on (0 = free slot).
pub(crate) static FUTEX_ADDR: [AtomicU64; MAX_FUTEX_WAITERS] = {
    const INIT: AtomicU64 = AtomicU64::new(0);
    [INIT; MAX_FUTEX_WAITERS]
};
/// Wake flag: 1 = woken. Waiter spins until this is set.
pub(crate) static FUTEX_WOKEN: [AtomicU64; MAX_FUTEX_WAITERS] = {
    const INIT: AtomicU64 = AtomicU64::new(0);
    [INIT; MAX_FUTEX_WAITERS]
};

// ---------------------------------------------------------------------------
// Signal functions
// ---------------------------------------------------------------------------

/// Default action for a signal: 0=terminate, 1=ignore, 2=stop, 3=continue.
pub(crate) fn sig_default_action(sig: u64) -> u8 {
    match sig {
        1 => 0,  // SIGHUP -> terminate
        2 => 0,  // SIGINT -> terminate
        3 => 0,  // SIGQUIT -> terminate (core)
        4 => 0,  // SIGILL -> terminate (core)
        5 => 0,  // SIGTRAP -> terminate (core)
        6 => 1,  // SIGABRT -> ignore (Wine survives server_protocol_error + abort)
        7 => 0,  // SIGBUS -> terminate (core)
        8 => 0,  // SIGFPE -> terminate (core)
        9 => 0,  // SIGKILL -> terminate (uncatchable)
        10 => 0, // SIGUSR1 -> terminate
        11 => 0, // SIGSEGV -> terminate (core)
        12 => 0, // SIGUSR2 -> terminate
        13 => 0, // SIGPIPE -> terminate
        14 => 0, // SIGALRM -> terminate
        15 => 0, // SIGTERM -> terminate
        17 => 1, // SIGCHLD -> ignore
        18 => 3, // SIGCONT -> continue
        19 => 2, // SIGSTOP -> stop (uncatchable)
        20 => 2, // SIGTSTP -> stop
        21 => 2, // SIGTTIN -> stop
        22 => 2, // SIGTTOU -> stop
        23 => 0, // SIGURG -> ignore (treat as terminate for simplicity)
        _ => 0,  // default: terminate
    }
}

/// Deliver a signal to a process. Sets the pending bit.
pub(crate) fn sig_send(pid: usize, sig: u64) {
    if sig == 0 || sig >= 32 || pid == 0 || pid > MAX_PROCS { return; }
    let p = &PROCESSES[pid - 1];
    p.sig_pending.fetch_or(1 << sig, Ordering::Release);
    // SIGKILL always terminates immediately
    if sig == linux_abi::SIGKILL as u64 {
        p.exit_code.store(128 + sig, Ordering::Release);
        p.state.store(2, Ordering::Release);
    }
    // Inject into kernel for async delivery
    let tc = p.kernel_tid.load(Ordering::Acquire);
    if tc != 0 {
        let _ = sys::signal_inject(tc, sig);
    }
}

/// Check pending unblocked signals. Returns the lowest signal number that
/// should be acted on, or 0 if none. Clears the signal from pending.
pub(crate) fn sig_dequeue(pid: usize) -> u64 {
    if pid == 0 || pid > MAX_PROCS { return 0; }
    let p = &PROCESSES[pid - 1];
    let pending = p.sig_pending.load(Ordering::Acquire);
    let blocked = p.sig_blocked.load(Ordering::Acquire);
    let actionable = pending & !blocked;
    if actionable == 0 { return 0; }
    let sig = actionable.trailing_zeros() as u64;
    p.sig_pending.fetch_and(!(1 << sig), Ordering::AcqRel);
    sig
}

/// Process a dequeued signal for a process. Returns:
/// - 0: signal ignored (continue normally)
/// - 1: process should be terminated
/// - 2: return -EINTR to current syscall
/// - 3: signal has a user handler -> caller should call signal_deliver()
pub(crate) fn sig_dispatch(pid: usize, sig: u64) -> u8 {
    if sig == 0 || sig >= 32 || pid == 0 || pid > MAX_PROCS { return 0; }
    let p = &PROCESSES[pid - 1];

    // SIGKILL/SIGSTOP cannot be caught or ignored
    if sig == linux_abi::SIGKILL as u64 {
        p.exit_code.store(128 + sig, Ordering::Release);
        p.state.store(2, Ordering::Release);
        return 1;
    }

    let handler = p.sig_handler[sig as usize].load(Ordering::Acquire);

    match handler {
        linux_abi::SIG_DFL => {
            match sig_default_action(sig) {
                0 => {
                    p.exit_code.store(128 + sig, Ordering::Release);
                    p.state.store(2, Ordering::Release);
                    1
                }
                1 => 0,
                2 => 0,
                3 => 0,
                _ => 0,
            }
        }
        linux_abi::SIG_IGN => 0,
        _handler_addr => 3,
    }
}

/// Write data into the child's address space. If child_as_cap==0, direct write;
/// otherwise uses kernel vm_write to target the child's page tables.
fn child_write(child_as_cap: u64, addr: u64, data: &[u8]) {
    if child_as_cap == 0 {
        unsafe { core::ptr::copy_nonoverlapping(data.as_ptr(), addr as *mut u8, data.len()); }
    } else {
        let mut done = 0;
        while done < data.len() {
            let chunk = (data.len() - done).min(4096);
            let _ = sys::vm_write(child_as_cap, addr + done as u64,
                                  data[done..].as_ptr() as u64, chunk as u64);
            done += chunk;
        }
    }
}

/// Deliver a signal to a child process by building a SignalFrame on the
/// child's user stack and replying with SIG_REDIRECT_TAG.
/// Supports SA_ONSTACK (alternate signal stack) and SA_SIGINFO (3-arg handler
/// with siginfo_t + ucontext_t).
/// fault_addr/fault_code: from kernel #PF (CR2 and error code). Used for siginfo.si_addr
/// and ucontext gregs[19] (ERR) / gregs[22] (CR2).
/// child_as_cap: the child's address-space capability (0 = shared with init).
pub(crate) fn signal_deliver(ep_cap: u64, pid: usize, sig: u64, child_tid: u64, syscall_ret: i64, is_async: bool, fault_addr: u64, fault_code: u64, child_as_cap: u64) -> bool {
    if sig == 0 || sig >= 32 || pid == 0 || pid > MAX_PROCS { return false; }
    let p = &PROCESSES[pid - 1];

    // force_sig_fault: if SIGSEGV is re-raised while handler is active,
    // the handler failed to fix the fault → force SIG_DFL (kill).
    if sig == 11 && p.sig_in_handler.load(Ordering::Acquire) != 0 {
        crate::framebuffer::print(b"SIGSEGV-FORCE-DFL P");
        crate::framebuffer::print_u64(pid as u64);
        crate::framebuffer::print(b" kill (handler re-raised SIGSEGV)\n");
        return false; // fall through to default action (terminate)
    }

    let handler = p.sig_handler[sig as usize].load(Ordering::Acquire);
    let restorer = p.sig_restorer[sig as usize].load(Ordering::Acquire);
    let sig_fl = p.sig_flags[sig as usize].load(Ordering::Acquire);

    if handler <= 1 { return false; }

    let restorer_addr = if restorer != 0 {
        restorer
    } else {
        return false;
    };

    let mut saved_regs = [0u64; 20];
    if sys::get_thread_regs(child_tid, &mut saved_regs).is_err() {
        return false;
    }

    let saved_rax = saved_regs[0];
    let saved_rbx = saved_regs[1];
    let saved_rcx = saved_regs[2];
    let saved_rdx = saved_regs[3];
    let saved_rsi = saved_regs[4];
    let saved_rdi = saved_regs[5];
    let saved_rbp = saved_regs[6];
    let saved_r8  = saved_regs[7];
    let saved_r9  = saved_regs[8];
    let saved_r10 = saved_regs[9];
    let saved_r11 = saved_regs[10];
    let saved_r12 = saved_regs[11];
    let saved_r13 = saved_regs[12];
    let saved_r14 = saved_regs[13];
    let saved_r15 = saved_regs[14];
    let saved_rsp = saved_regs[15];
    let saved_fsbase = saved_regs[16];

    // [18]/[19] are non-zero when the context comes from an interrupt (#PF/timer),
    // where RCX/R11 contain the ORIGINAL user values (not clobbered by SYSCALL).
    // When zero, fall back to SYSCALL convention: rcx=rip, r11=rflags.
    let saved_rip = if saved_regs[18] != 0 { saved_regs[18] } else { saved_rcx };
    let saved_rflags = if saved_regs[19] != 0 { saved_regs[19] } else { saved_r11 };
    let frame_rax = if is_async { saved_rax } else { syscall_ret as u64 };

    // ── Determine base RSP: use alt stack if SA_ONSTACK + alt stack enabled ──
    let use_altstack = {
        let has_sa_onstack = sig_fl & linux_abi::SA_ONSTACK != 0;
        let alt_flags = p.sig_alt_flags.load(Ordering::Acquire);
        let alt_enabled = alt_flags != linux_abi::SS_DISABLE;
        if has_sa_onstack && alt_enabled {
            let alt_sp = p.sig_alt_sp.load(Ordering::Acquire);
            let alt_size = p.sig_alt_size.load(Ordering::Acquire);
            // Don't switch if already on the alt stack (RSP within [sp, sp+size))
            let already_on = saved_rsp >= alt_sp && saved_rsp < alt_sp + alt_size;
            !already_on && alt_sp != 0 && alt_size != 0
        } else {
            false
        }
    };

    let base_rsp = if use_altstack {
        let alt_sp = p.sig_alt_sp.load(Ordering::Acquire);
        let alt_size = p.sig_alt_size.load(Ordering::Acquire);
        // Top of alt stack (stack grows down)
        alt_sp + alt_size
    } else {
        saved_rsp
    };

    // ── SA_SIGINFO: allocate siginfo_t + ucontext_t on stack ──
    let has_siginfo = sig_fl & linux_abi::SA_SIGINFO != 0;

    // siginfo_t is 128 bytes, ucontext_t is 936 bytes on x86_64
    const SIGINFO_SIZE: u64 = 128;
    const UCONTEXT_SIZE: u64 = 936;
    // gregset starts at offset 40 in ucontext_t (uc_flags=8, uc_link=8, uc_stack=24 → 40)
    const UC_MCONTEXT_GREGS_OFF: u64 = 40;

    let (siginfo_ptr, ucontext_ptr, stack_after_extras) = if has_siginfo {
        // Layout on stack (growing down from base_rsp):
        //   [ucontext_t] [siginfo_t] [SignalFrame] [return addr]
        let uc_rsp = (base_rsp - UCONTEXT_SIZE) & !0xF;
        let si_rsp = (uc_rsp - SIGINFO_SIZE) & !0xF;

        // Build siginfo_t in local buffer, then write to child AS
        let mut si_buf = [0u8; SIGINFO_SIZE as usize];
        // si_signo at offset 0 (i32)
        si_buf[0..4].copy_from_slice(&(sig as i32).to_le_bytes());
        if sig == 11 && fault_addr != 0 {
            let si_code: i32 = if fault_code & 0x01 != 0 { 2 } else { 1 };
            si_buf[8..12].copy_from_slice(&si_code.to_le_bytes());
            si_buf[16..24].copy_from_slice(&fault_addr.to_le_bytes());
        }
        child_write(child_as_cap, si_rsp, &si_buf);

        // Build ucontext_t in local buffer, then write to child AS
        let mut uc_buf = [0u8; UCONTEXT_SIZE as usize];
        if use_altstack {
            let alt_sp = p.sig_alt_sp.load(Ordering::Acquire);
            let alt_size = p.sig_alt_size.load(Ordering::Acquire);
            uc_buf[16..24].copy_from_slice(&alt_sp.to_le_bytes());        // ss_sp
            uc_buf[24..32].copy_from_slice(&(linux_abi::SS_ONSTACK).to_le_bytes()); // ss_flags
            uc_buf[32..40].copy_from_slice(&alt_size.to_le_bytes());       // ss_size
        }
        // uc_mcontext.gregs at offset 40 (23 entries × 8 bytes)
        let go = UC_MCONTEXT_GREGS_OFF as usize;
        let gregs: [u64; 23] = [
            saved_r8, saved_r9, saved_r10, saved_r11,
            saved_r12, saved_r13, saved_r14, saved_r15,
            saved_rdi, saved_rsi, saved_rbp, saved_rbx,
            saved_rdx, frame_rax, saved_rcx, saved_rsp,
            saved_rip, saved_rflags, 0x33, fault_code,
            if sig == 11 { 14 } else { 0 }, 0, fault_addr,
        ];
        for (i, &val) in gregs.iter().enumerate() {
            let off = go + i * 8;
            uc_buf[off..off + 8].copy_from_slice(&val.to_le_bytes());
        }
        child_write(child_as_cap, uc_rsp, &uc_buf);

        (si_rsp, uc_rsp, si_rsp)
    } else {
        (0u64, 0u64, base_rsp)
    };

    // ── Build SignalFrame below the extras (or directly below base_rsp) ──
    let frame_size = SIGNAL_FRAME_SIZE as u64;
    let frame_rsp = (stack_after_extras - frame_size) & !0xF;
    let entry_rsp = frame_rsp - 8;

    // Write restorer return address at entry_rsp
    child_write(child_as_cap, entry_rsp, &restorer_addr.to_le_bytes());

    // Build SignalFrame in local buffer, then write to child AS
    let old_mask = p.sig_blocked.load(Ordering::Acquire);
    let frame_data: [u64; 23] = [
        restorer_addr, sig, frame_rax, saved_rbx,
        saved_rcx, saved_rdx, saved_rsi, saved_rdi,
        saved_rbp, saved_r8, saved_r9, saved_r10,
        saved_r11, saved_r12, saved_r13, saved_r14,
        saved_r15, saved_rip, saved_rsp, saved_rflags,
        saved_fsbase, old_mask, ucontext_ptr,
    ];
    let frame_bytes: &[u8] = unsafe {
        core::slice::from_raw_parts(frame_data.as_ptr() as *const u8, frame_data.len() * 8)
    };
    child_write(child_as_cap, frame_rsp, frame_bytes);

    // NOTE: We do NOT block the signal during handler execution because
    // sotOS rt_sigreturn (kernel-only) cannot restore sig_blocked from
    // the saved old_mask. Blocking without unblocking would permanently
    // block the signal. Wine specifically needs SIGSEGV re-entrant delivery.
    // The old_mask is still saved in the SignalFrame for future use.

    // Mark SIGSEGV as "in handler" so re-raised SIGSEGV triggers force_sig_fault.
    if sig == 11 {
        p.sig_in_handler.store(1, Ordering::Release);
    }

    // ── SIG_REDIRECT_TAG reply ──
    let reply = IpcMsg {
        tag: SIG_REDIRECT_TAG,
        regs: [
            handler,
            sig,
            siginfo_ptr,
            ucontext_ptr,
            entry_rsp,
            0, 0, 0,
        ],
    };
    let _ = sys::send(ep_cap, &reply);
    true
}

// ---------------------------------------------------------------------------
// Process group initialization
// ---------------------------------------------------------------------------

/// Initialize process group state for a new process (leader).
pub(crate) fn proc_group_init(pid: usize) {
    let idx = pid - 1;
    let p = &PROCESSES[idx];
    p.tgid.store(pid as u64, Ordering::Release);
    p.fd_group.store(idx as u64, Ordering::Release);
    p.mem_group.store(idx as u64, Ordering::Release);
    p.sig_group.store(idx as u64, Ordering::Release);
    p.clear_tid.store(0, Ordering::Release);
    // Clear stale signal state from previous use of this process slot
    p.sig_pending.store(0, Ordering::Release);
    p.sig_blocked.store(0, Ordering::Release);
    fd_grp_init(idx);
}

/// Initialize process group state for a thread (CLONE_THREAD).
/// Shares parent's groups based on clone flags.
pub(crate) fn proc_thread_init(child_pid: usize, parent_pid: usize, flags: u64) {
    let cidx = child_pid - 1;
    let pidx = parent_pid - 1;
    let child = &PROCESSES[cidx];
    let parent = &PROCESSES[pidx];

    // Thread group: if CLONE_THREAD, share parent's tgid
    if flags & CLONE_THREAD != 0 {
        let parent_tgid = parent.tgid.load(Ordering::Acquire);
        child.tgid.store(parent_tgid, Ordering::Release);
    } else {
        child.tgid.store(child_pid as u64, Ordering::Release);
    }

    // FD group: if CLONE_FILES, share parent's FD table
    if flags & CLONE_FILES != 0 {
        let parent_fdg = parent.fd_group.load(Ordering::Acquire);
        child.fd_group.store(parent_fdg, Ordering::Release);
    } else {
        child.fd_group.store(cidx as u64, Ordering::Release);
        fd_grp_init(cidx);
    }

    // Memory group: if CLONE_VM, share parent's brk/mmap state
    if flags & CLONE_VM != 0 {
        let parent_memg = parent.mem_group.load(Ordering::Acquire);
        child.mem_group.store(parent_memg, Ordering::Release);
    } else {
        child.mem_group.store(cidx as u64, Ordering::Release);
    }

    // Signal handler group: if CLONE_SIGHAND, share parent's signal handlers
    if flags & CLONE_SIGHAND != 0 {
        let parent_sigg = parent.sig_group.load(Ordering::Acquire);
        child.sig_group.store(parent_sigg, Ordering::Release);
    } else {
        child.sig_group.store(cidx as u64, Ordering::Release);
    }

    child.clear_tid.store(0, Ordering::Release);
}

// ---------------------------------------------------------------------------
// Futex operations
// ---------------------------------------------------------------------------

/// FUTEX_WAIT: if *addr == expected, block until woken.
pub(crate) fn futex_wait(addr: u64, expected: u32) -> i64 {
    let mut slot = usize::MAX;
    for i in 0..MAX_FUTEX_WAITERS {
        if FUTEX_ADDR[i].compare_exchange(0, addr, Ordering::AcqRel, Ordering::Relaxed).is_ok() {
            FUTEX_WOKEN[i].store(0, Ordering::Release);
            slot = i;
            break;
        }
    }
    if slot == usize::MAX {
        return -(linux_abi::ENOMEM);
    }

    // NOTE: the value check (current == expected) is done by the CALLER
    // using ctx.guest_read (correct for separate-AS children). We skip
    // the redundant direct-read check here because `addr` may now be a
    // physical address key (for shared futex matching across processes).

    let mut spins = 0u64;
    while FUTEX_WOKEN[slot].load(Ordering::Acquire) == 0 {
        sys::yield_now();
        spins += 1;
        if spins > 500_000 {
            FUTEX_ADDR[slot].store(0, Ordering::Release);
            return -(linux_abi::ETIMEDOUT);
        }
    }

    FUTEX_ADDR[slot].store(0, Ordering::Release);
    0
}

/// FUTEX_WAKE: wake up to `count` waiters on addr.
pub(crate) fn futex_wake(addr: u64, count: u32) -> i64 {
    let mut woken = 0u32;
    for i in 0..MAX_FUTEX_WAITERS {
        if woken >= count { break; }
        if FUTEX_ADDR[i].load(Ordering::Acquire) == addr {
            FUTEX_WOKEN[i].store(1, Ordering::Release);
            woken += 1;
        }
    }
    woken as i64
}

// ---------------------------------------------------------------------------
// Utility functions
// ---------------------------------------------------------------------------

/// Parse a decimal u64 from a byte slice. Returns (value, bytes_consumed).
pub(crate) fn parse_u64_from(s: &[u8]) -> (u64, usize) {
    let mut val: u64 = 0;
    let mut i = 0;
    while i < s.len() && s[i] >= b'0' && s[i] <= b'9' {
        val = val * 10 + (s[i] - b'0') as u64;
        i += 1;
    }
    (val, i)
}

/// Format /proc/N/status content into buf. Returns bytes written.
pub(crate) fn format_proc_status(buf: &mut [u8], pid: usize) -> usize {
    let mut w = BufWriter::new(buf);
    let p = &PROCESSES[pid - 1];
    let state_str = match p.state.load(Ordering::Acquire) {
        1 => "R", 2 => "Z", _ => "?",
    };
    let ppid = p.parent.load(Ordering::Acquire);
    let _ = uwrite!(w, "Name:\tprocess_{}\nState:\t{}\nPid:\t{}\nPPid:\t{}\n",
                    pid, state_str, pid, ppid);
    w.pos()
}

// clone_child_trampoline is defined in child_handler.rs
