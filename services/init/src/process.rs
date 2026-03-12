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
        }
    }
}

/// Consolidated per-process state. Indexed by pid-1 (0-based).
pub(crate) static PROCESSES: [ProcessState; MAX_PROCS] =
    [const { ProcessState::new() }; MAX_PROCS];

/// Init's own address space capability (from BootInfo.self_as_cap).
/// Set once at startup, read by child_handler for CoW fork.
pub(crate) static INIT_SELF_AS_CAP: AtomicU64 = AtomicU64::new(0);

// Signal constants
pub(crate) const _SA_NOCLDSTOP: u64 = 1;
pub(crate) const _SA_NOCLDWAIT: u64 = 2;

/// Boot TSC value for uptime calculation.
pub(crate) static BOOT_TSC: AtomicU64 = AtomicU64::new(0);

/// Next PID to allocate (monotonically increasing, starts at 1).
pub(crate) static NEXT_PID: AtomicU64 = AtomicU64::new(1);
/// Next vaddr for child stacks (guest + handler interleaved, 0x2000 apart).
pub(crate) static NEXT_CHILD_STACK: AtomicU64 = AtomicU64::new(0xE80000);

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
                           CLONE_SETTLS, CLONE_PARENT_SETTID, CLONE_CHILD_CLEARTID};

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
        6 => 0,  // SIGABRT -> terminate (core)
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

/// Deliver a signal to a child process by building a SignalFrame on the
/// child's user stack and replying with SIG_REDIRECT_TAG.
pub(crate) fn signal_deliver(ep_cap: u64, pid: usize, sig: u64, child_tid: u64, syscall_ret: i64, is_async: bool) -> bool {
    if sig == 0 || sig >= 32 || pid == 0 || pid > MAX_PROCS { return false; }
    let p = &PROCESSES[pid - 1];

    let handler = p.sig_handler[sig as usize].load(Ordering::Acquire);
    let restorer = p.sig_restorer[sig as usize].load(Ordering::Acquire);

    if handler <= 1 { return false; }

    let restorer_addr = if restorer != 0 {
        restorer
    } else {
        return false;
    };

    let mut saved_regs = [0u64; 18];
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

    let saved_rip = saved_rcx;
    let saved_rflags = saved_r11;
    let frame_rax = if is_async { saved_rax } else { syscall_ret as u64 };

    let frame_size = SIGNAL_FRAME_SIZE as u64;
    let frame_rsp = (saved_rsp - frame_size) & !0xF;
    let entry_rsp = frame_rsp - 8;

    unsafe {
        core::ptr::write_volatile(entry_rsp as *mut u64, restorer_addr);
    }

    let frame_ptr = frame_rsp as *mut u64;
    unsafe {
        core::ptr::write_volatile(frame_ptr.add(0),  restorer_addr);
        core::ptr::write_volatile(frame_ptr.add(1),  sig);
        core::ptr::write_volatile(frame_ptr.add(2),  frame_rax);
        core::ptr::write_volatile(frame_ptr.add(3),  saved_rbx);
        core::ptr::write_volatile(frame_ptr.add(4),  saved_rcx);
        core::ptr::write_volatile(frame_ptr.add(5),  saved_rdx);
        core::ptr::write_volatile(frame_ptr.add(6),  saved_rsi);
        core::ptr::write_volatile(frame_ptr.add(7),  saved_rdi);
        core::ptr::write_volatile(frame_ptr.add(8),  saved_rbp);
        core::ptr::write_volatile(frame_ptr.add(9),  saved_r8);
        core::ptr::write_volatile(frame_ptr.add(10), saved_r9);
        core::ptr::write_volatile(frame_ptr.add(11), saved_r10);
        core::ptr::write_volatile(frame_ptr.add(12), saved_r11);
        core::ptr::write_volatile(frame_ptr.add(13), saved_r12);
        core::ptr::write_volatile(frame_ptr.add(14), saved_r13);
        core::ptr::write_volatile(frame_ptr.add(15), saved_r14);
        core::ptr::write_volatile(frame_ptr.add(16), saved_r15);
        core::ptr::write_volatile(frame_ptr.add(17), saved_rip);
        core::ptr::write_volatile(frame_ptr.add(18), saved_rsp);
        core::ptr::write_volatile(frame_ptr.add(19), saved_rflags);
        core::ptr::write_volatile(frame_ptr.add(20), saved_fsbase);
        let old_mask = p.sig_blocked.load(Ordering::Acquire);
        core::ptr::write_volatile(frame_ptr.add(21), old_mask);
    }

    // Block the signal during handler execution
    let cur_mask = p.sig_blocked.load(Ordering::Acquire);
    p.sig_blocked.store(cur_mask | (1 << sig), Ordering::Release);

    let reply = IpcMsg {
        tag: SIG_REDIRECT_TAG,
        regs: [
            handler,
            sig,
            0,
            0,
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

    let current = unsafe { core::ptr::read_volatile(addr as *const u32) };
    if current != expected {
        FUTEX_ADDR[slot].store(0, Ordering::Release);
        return -(linux_abi::EAGAIN);
    }

    let mut spins = 0u64;
    while FUTEX_WOKEN[slot].load(Ordering::Acquire) == 0 {
        sys::yield_now();
        spins += 1;
        if spins > 10_000 {
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
