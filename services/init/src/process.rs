// ---------------------------------------------------------------------------
// Process management: process table, signals, thread groups, futex
// ---------------------------------------------------------------------------

use sotos_common::sys;
use sotos_common::{IpcMsg, SIG_REDIRECT_TAG, SIGNAL_FRAME_SIZE};
use sotos_common::linux_abi;
use core::sync::atomic::{AtomicU64, Ordering};
use crate::exec::format_u64_into;
use crate::fd::fd_grp_init;

// ---------------------------------------------------------------------------
// LUCAS process table (Phase 10.5) -- shared between handler threads
// ---------------------------------------------------------------------------

pub(crate) const MAX_PROCS: usize = 16;

/// Process state: 0=Free, 1=Running, 2=Zombie.
pub(crate) static PROC_STATE: [AtomicU64; MAX_PROCS] = {
    const INIT: AtomicU64 = AtomicU64::new(0);
    [INIT; MAX_PROCS]
};
/// Exit status (valid when Zombie).
pub(crate) static PROC_EXIT: [AtomicU64; MAX_PROCS] = {
    const INIT: AtomicU64 = AtomicU64::new(0);
    [INIT; MAX_PROCS]
};
/// Parent PID (0=none).
pub(crate) static PROC_PARENT: [AtomicU64; MAX_PROCS] = {
    const INIT: AtomicU64 = AtomicU64::new(0);
    [INIT; MAX_PROCS]
};
/// Kernel thread ID (raw) for each LUCAS pid (for async signal injection).
pub(crate) static PROC_KERNEL_TID: [AtomicU64; MAX_PROCS] = {
    const INIT: AtomicU64 = AtomicU64::new(0);
    [INIT; MAX_PROCS]
};
/// Pending signals bitmask per process (bit N = signal N pending).
pub(crate) static SIG_PENDING: [AtomicU64; MAX_PROCS] = {
    const INIT: AtomicU64 = AtomicU64::new(0);
    [INIT; MAX_PROCS]
};
/// Blocked signals bitmask per process (bit N = signal N blocked).
pub(crate) static SIG_BLOCKED: [AtomicU64; MAX_PROCS] = {
    const INIT: AtomicU64 = AtomicU64::new(0);
    [INIT; MAX_PROCS]
};
/// Signal handler addresses per process, 32 signals each.
/// 0 = SIG_DFL, 1 = SIG_IGN, else = user handler address.
pub(crate) static SIG_HANDLER: [[AtomicU64; 32]; MAX_PROCS] = {
    const H: AtomicU64 = AtomicU64::new(0);
    const ROW: [AtomicU64; 32] = [H; 32];
    [ROW; MAX_PROCS]
};
/// Signal flags (SA_RESTART etc.) per process per signal.
pub(crate) static SIG_FLAGS: [[AtomicU64; 32]; MAX_PROCS] = {
    const H: AtomicU64 = AtomicU64::new(0);
    const ROW: [AtomicU64; 32] = [H; 32];
    [ROW; MAX_PROCS]
};
/// Signal handler masks per process per signal (blocked during handler).
pub(crate) static SIG_RESTORER: [[AtomicU64; 32]; MAX_PROCS] = {
    const H: AtomicU64 = AtomicU64::new(0);
    const ROW: [AtomicU64; 32] = [H; 32];
    [ROW; MAX_PROCS]
};

// Signal constants
// Signal/sigaction constants — sourced from linux_abi (linux-raw-sys)
pub(crate) const _SA_NOCLDSTOP: u64 = 1;
pub(crate) const _SA_NOCLDWAIT: u64 = 2;

/// Boot TSC value for uptime calculation.
pub(crate) static BOOT_TSC: AtomicU64 = AtomicU64::new(0);

/// Next PID to allocate (monotonically increasing, starts at 1).
pub(crate) static NEXT_PID: AtomicU64 = AtomicU64::new(1);
/// Next vaddr for child stacks (guest + handler interleaved, 0x2000 apart).
/// Range: 0xE30000..0x2000000 (safe: BRK_BASE is at 0x2000000).
pub(crate) static NEXT_CHILD_STACK: AtomicU64 = AtomicU64::new(0xE30000);

// Handshake statics for passing setup info to child handler thread.
pub(crate) static CHILD_SETUP_EP: AtomicU64 = AtomicU64::new(0);
pub(crate) static CHILD_SETUP_PID: AtomicU64 = AtomicU64::new(0);
pub(crate) static CHILD_SETUP_READY: AtomicU64 = AtomicU64::new(0);
pub(crate) static CHILD_SETUP_FLAGS: AtomicU64 = AtomicU64::new(0);

// ---------------------------------------------------------------------------
// Phase 4: Thread groups, shared FD tables, and futex
// ---------------------------------------------------------------------------

// Clone flag constants — sourced from linux_abi (linux-raw-sys)
pub(crate) use linux_abi::{CLONE_VM, CLONE_FILES, CLONE_SIGHAND, CLONE_THREAD,
                           CLONE_SETTLS, CLONE_PARENT_SETTID, CLONE_CHILD_CLEARTID};

/// Thread group ID per process slot. tgid = pid for leaders, tgid = leader's pid for threads.
pub(crate) static PROC_TGID: [AtomicU64; MAX_PROCS] = {
    const INIT: AtomicU64 = AtomicU64::new(0);
    [INIT; MAX_PROCS]
};
/// FD group index for each process (threads with CLONE_FILES share the same group).
pub(crate) static PROC_FD_GROUP: [AtomicU64; MAX_PROCS] = {
    const INIT: AtomicU64 = AtomicU64::new(0);
    [INIT; MAX_PROCS]
};
/// Memory group index (threads with CLONE_VM share brk/mmap state).
pub(crate) static PROC_MEM_GROUP: [AtomicU64; MAX_PROCS] = {
    const INIT: AtomicU64 = AtomicU64::new(0);
    [INIT; MAX_PROCS]
};
/// Signal handler group (threads with CLONE_SIGHAND share signal handlers).
pub(crate) static PROC_SIG_GROUP: [AtomicU64; MAX_PROCS] = {
    const INIT: AtomicU64 = AtomicU64::new(0);
    [INIT; MAX_PROCS]
};
/// clear_child_tid pointer (CLONE_CHILD_CLEARTID): on exit, *ptr = 0 + futex_wake.
pub(crate) static PROC_CLEAR_TID: [AtomicU64; MAX_PROCS] = {
    const INIT: AtomicU64 = AtomicU64::new(0);
    [INIT; MAX_PROCS]
};

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
    SIG_PENDING[pid - 1].fetch_or(1 << sig, Ordering::Release);
    // SIGKILL always terminates immediately
    if sig == linux_abi::SIGKILL as u64 {
        PROC_EXIT[pid - 1].store(128 + sig, Ordering::Release);
        PROC_STATE[pid - 1].store(2, Ordering::Release);
    }
    // Inject into kernel for async delivery (timer interrupt will redirect to trampoline)
    let tc = PROC_KERNEL_TID[pid - 1].load(Ordering::Acquire);
    if tc != 0 {
        let _ = sys::signal_inject(tc, sig);
    }
}

/// Check pending unblocked signals. Returns the lowest signal number that
/// should be acted on, or 0 if none. Clears the signal from pending.
pub(crate) fn sig_dequeue(pid: usize) -> u64 {
    if pid == 0 || pid > MAX_PROCS { return 0; }
    let idx = pid - 1;
    let pending = SIG_PENDING[idx].load(Ordering::Acquire);
    let blocked = SIG_BLOCKED[idx].load(Ordering::Acquire);
    let actionable = pending & !blocked;
    if actionable == 0 { return 0; }
    // Find lowest set bit
    let sig = actionable.trailing_zeros() as u64;
    // Clear it
    SIG_PENDING[idx].fetch_and(!(1 << sig), Ordering::AcqRel);
    sig
}

/// Process a dequeued signal for a process. Returns:
/// - 0: signal ignored (continue normally)
/// - 1: process should be terminated
/// - 2: return -EINTR to current syscall
/// - 3: signal has a user handler -> caller should call signal_deliver()
pub(crate) fn sig_dispatch(pid: usize, sig: u64) -> u8 {
    if sig == 0 || sig >= 32 || pid == 0 || pid > MAX_PROCS { return 0; }
    let idx = pid - 1;

    // SIGKILL/SIGSTOP cannot be caught or ignored
    if sig == linux_abi::SIGKILL as u64 {
        PROC_EXIT[idx].store(128 + sig, Ordering::Release);
        PROC_STATE[idx].store(2, Ordering::Release);
        return 1;
    }

    let handler = SIG_HANDLER[idx][sig as usize].load(Ordering::Acquire);

    match handler {
        linux_abi::SIG_DFL => {
            // Apply default action
            match sig_default_action(sig) {
                0 => {
                    // Terminate
                    PROC_EXIT[idx].store(128 + sig, Ordering::Release);
                    PROC_STATE[idx].store(2, Ordering::Release);
                    1
                }
                1 => 0, // Ignore
                2 => 0, // Stop (not implemented, treat as ignore)
                3 => 0, // Continue (not implemented, treat as ignore)
                _ => 0,
            }
        }
        linux_abi::SIG_IGN => 0, // Explicitly ignored
        _handler_addr => {
            // User handler registered -- deliver via signal frame injection
            3
        }
    }
}

/// Deliver a signal to a child process by building a SignalFrame on the
/// child's user stack and replying with SIG_REDIRECT_TAG.
///
/// `ep_cap`: the IPC endpoint to reply on
/// `pid`: process slot (1-based)
/// `sig`: signal number to deliver
/// `child_tid`: kernel thread ID of the child
/// `syscall_ret`: the original syscall return value (saved in signal frame)
///
/// Returns true if delivery succeeded (caller should NOT send another reply).
pub(crate) fn signal_deliver(ep_cap: u64, pid: usize, sig: u64, child_tid: u64, syscall_ret: i64, is_async: bool) -> bool {
    if sig == 0 || sig >= 32 || pid == 0 || pid > MAX_PROCS { return false; }
    let idx = pid - 1;

    let handler = SIG_HANDLER[idx][sig as usize].load(Ordering::Acquire);
    let restorer = SIG_RESTORER[idx][sig as usize].load(Ordering::Acquire);

    if handler <= 1 { return false; } // SIG_DFL or SIG_IGN -- can't deliver

    // Need a restorer (sa_restorer) -- musl always sets one via SA_RESTORER.
    // If not set, we can't return from the handler. Use a fallback that just
    // calls rt_sigreturn directly.
    let restorer_addr = if restorer != 0 {
        restorer
    } else {
        // No restorer -- the handler can't return cleanly. Skip delivery.
        return false;
    };

    // Read the child's saved register state from the kernel
    let mut saved_regs = [0u64; 18];
    if sys::get_thread_regs(child_tid, &mut saved_regs).is_err() {
        return false;
    }

    // saved_regs layout: [rax,rbx,rcx,rdx,rsi,rdi,rbp,r8..r15,rsp,fs_base,rflags_or_0]
    let saved_rax = saved_regs[0];
    let saved_rbx = saved_regs[1];
    let saved_rcx = saved_regs[2]; // user RIP (from SYSCALL: rcx = rip)
    let saved_rdx = saved_regs[3];
    let saved_rsi = saved_regs[4];
    let saved_rdi = saved_regs[5];
    let saved_rbp = saved_regs[6];
    let saved_r8  = saved_regs[7];
    let saved_r9  = saved_regs[8];
    let saved_r10 = saved_regs[9];
    let saved_r11 = saved_regs[10]; // user RFLAGS (from SYSCALL: r11 = rflags)
    let saved_r12 = saved_regs[11];
    let saved_r13 = saved_regs[12];
    let saved_r14 = saved_regs[13];
    let saved_r15 = saved_regs[14];
    let saved_rsp = saved_regs[15];
    let saved_fsbase = saved_regs[16];
    // saved_regs[17] may hold rflags for async signals

    // For the signal frame, rip and rflags:
    let saved_rip = saved_rcx;    // rcx holds user RIP for SYSCALL
    let saved_rflags = saved_r11; // r11 holds user RFLAGS for SYSCALL

    // For sync signals: use the syscall return value (what rax would have been).
    // For async signals: use the actual user rax at interrupt time.
    let frame_rax = if is_async { saved_rax } else { syscall_ret as u64 };

    // Compute new RSP for signal frame (below current user RSP, 16-byte aligned - 8)
    let frame_size = SIGNAL_FRAME_SIZE as u64;
    let new_rsp = ((saved_rsp - frame_size) & !0xF) - 8;

    // Write the SignalFrame onto the child's user stack
    // (LUCAS has access to child's pages at the same virtual addresses)
    let frame_ptr = new_rsp as *mut u64;
    unsafe {
        core::ptr::write_volatile(frame_ptr.add(0),  restorer_addr);  // restorer
        core::ptr::write_volatile(frame_ptr.add(1),  sig);            // signo
        core::ptr::write_volatile(frame_ptr.add(2),  frame_rax);      // rax (syscall return)
        core::ptr::write_volatile(frame_ptr.add(3),  saved_rbx);      // rbx
        core::ptr::write_volatile(frame_ptr.add(4),  saved_rcx);      // rcx
        core::ptr::write_volatile(frame_ptr.add(5),  saved_rdx);      // rdx
        core::ptr::write_volatile(frame_ptr.add(6),  saved_rsi);      // rsi
        core::ptr::write_volatile(frame_ptr.add(7),  saved_rdi);      // rdi
        core::ptr::write_volatile(frame_ptr.add(8),  saved_rbp);      // rbp
        core::ptr::write_volatile(frame_ptr.add(9),  saved_r8);       // r8
        core::ptr::write_volatile(frame_ptr.add(10), saved_r9);       // r9
        core::ptr::write_volatile(frame_ptr.add(11), saved_r10);      // r10
        core::ptr::write_volatile(frame_ptr.add(12), saved_r11);      // r11
        core::ptr::write_volatile(frame_ptr.add(13), saved_r12);      // r12
        core::ptr::write_volatile(frame_ptr.add(14), saved_r13);      // r13
        core::ptr::write_volatile(frame_ptr.add(15), saved_r14);      // r14
        core::ptr::write_volatile(frame_ptr.add(16), saved_r15);      // r15
        core::ptr::write_volatile(frame_ptr.add(17), saved_rip);      // rip
        core::ptr::write_volatile(frame_ptr.add(18), saved_rsp);      // rsp
        core::ptr::write_volatile(frame_ptr.add(19), saved_rflags);   // rflags
        core::ptr::write_volatile(frame_ptr.add(20), saved_fsbase);   // fs_base
        // old_sigmask: save current mask, then apply sa_mask
        let old_mask = SIG_BLOCKED[idx].load(Ordering::Acquire);
        core::ptr::write_volatile(frame_ptr.add(21), old_mask);       // old_sigmask
    }

    // Block the signal during handler execution (add to blocked mask)
    let cur_mask = SIG_BLOCKED[idx].load(Ordering::Acquire);
    SIG_BLOCKED[idx].store(cur_mask | (1 << sig), Ordering::Release);

    // Reply with SIG_REDIRECT_TAG to redirect the child to the handler
    let reply = IpcMsg {
        tag: SIG_REDIRECT_TAG,
        regs: [
            handler,      // regs[0] = new RIP (handler address)
            sig,          // regs[1] = signal number (RDI = arg0)
            0,            // regs[2] = &siginfo (RSI = arg1, 0 for now)
            0,            // regs[3] = &ucontext (RDX = arg2, 0 for now)
            new_rsp,      // regs[4] = new RSP (below signal frame)
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
    PROC_TGID[idx].store(pid as u64, Ordering::Release);
    PROC_FD_GROUP[idx].store(idx as u64, Ordering::Release);
    PROC_MEM_GROUP[idx].store(idx as u64, Ordering::Release);
    PROC_SIG_GROUP[idx].store(idx as u64, Ordering::Release);
    PROC_CLEAR_TID[idx].store(0, Ordering::Release);
    fd_grp_init(idx);
}

/// Initialize process group state for a thread (CLONE_THREAD).
/// Shares parent's groups based on clone flags.
pub(crate) fn proc_thread_init(child_pid: usize, parent_pid: usize, flags: u64) {
    let cidx = child_pid - 1;
    let pidx = parent_pid - 1;

    // Thread group: if CLONE_THREAD, share parent's tgid
    if flags & CLONE_THREAD != 0 {
        let parent_tgid = PROC_TGID[pidx].load(Ordering::Acquire);
        PROC_TGID[cidx].store(parent_tgid, Ordering::Release);
    } else {
        PROC_TGID[cidx].store(child_pid as u64, Ordering::Release);
    }

    // FD group: if CLONE_FILES, share parent's FD table
    if flags & CLONE_FILES != 0 {
        let parent_fdg = PROC_FD_GROUP[pidx].load(Ordering::Acquire);
        PROC_FD_GROUP[cidx].store(parent_fdg, Ordering::Release);
    } else {
        PROC_FD_GROUP[cidx].store(cidx as u64, Ordering::Release);
        fd_grp_init(cidx);
    }

    // Memory group: if CLONE_VM, share parent's brk/mmap state
    if flags & CLONE_VM != 0 {
        let parent_memg = PROC_MEM_GROUP[pidx].load(Ordering::Acquire);
        PROC_MEM_GROUP[cidx].store(parent_memg, Ordering::Release);
    } else {
        PROC_MEM_GROUP[cidx].store(cidx as u64, Ordering::Release);
    }

    // Signal handler group: if CLONE_SIGHAND, share parent's signal handlers
    if flags & CLONE_SIGHAND != 0 {
        let parent_sigg = PROC_SIG_GROUP[pidx].load(Ordering::Acquire);
        PROC_SIG_GROUP[cidx].store(parent_sigg, Ordering::Release);
    } else {
        PROC_SIG_GROUP[cidx].store(cidx as u64, Ordering::Release);
    }

    PROC_CLEAR_TID[cidx].store(0, Ordering::Release);
}

// ---------------------------------------------------------------------------
// Futex operations
// ---------------------------------------------------------------------------

/// FUTEX_WAIT: if *addr == expected, block until woken. Returns 0 on wake, -EAGAIN if mismatch.
pub(crate) fn futex_wait(addr: u64, expected: u32) -> i64 {
    // Find a free slot and register
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

    // Check the value AFTER registering (to avoid missing a wake between check and register)
    let current = unsafe { core::ptr::read_volatile(addr as *const u32) };
    if current != expected {
        FUTEX_ADDR[slot].store(0, Ordering::Release);
        return -(linux_abi::EAGAIN);
    }

    // Spin-wait until woken (with yield to avoid burning CPU)
    let mut spins = 0u64;
    while FUTEX_WOKEN[slot].load(Ordering::Acquire) == 0 {
        sys::yield_now();
        spins += 1;
        // Safety timeout: ~10 seconds at 100Hz scheduler
        if spins > 10_000 {
            FUTEX_ADDR[slot].store(0, Ordering::Release);
            return -(linux_abi::ETIMEDOUT);
        }
    }

    // Clean up slot
    FUTEX_ADDR[slot].store(0, Ordering::Release);
    0
}

/// FUTEX_WAKE: wake up to `count` waiters on addr. Returns number actually woken.
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
    let mut pos: usize = 0;
    // Name:\tprocess_N
    let prefix = b"Name:\tprocess_";
    buf[pos..pos + prefix.len()].copy_from_slice(prefix);
    pos += prefix.len();
    pos += format_u64_into(&mut buf[pos..], pid as u64);
    buf[pos] = b'\n';
    pos += 1;
    // State:\tR or Z
    let sp = b"State:\t";
    buf[pos..pos + sp.len()].copy_from_slice(sp);
    pos += sp.len();
    let state = PROC_STATE[pid - 1].load(Ordering::Acquire);
    buf[pos] = match state {
        1 => b'R',
        2 => b'Z',
        _ => b'?',
    };
    pos += 1;
    buf[pos] = b'\n';
    pos += 1;
    // Pid:\tN
    let pp = b"Pid:\t";
    buf[pos..pos + pp.len()].copy_from_slice(pp);
    pos += pp.len();
    pos += format_u64_into(&mut buf[pos..], pid as u64);
    buf[pos] = b'\n';
    pos += 1;
    // PPid:\tP
    let ppp = b"PPid:\t";
    buf[pos..pos + ppp.len()].copy_from_slice(ppp);
    pos += ppp.len();
    let ppid = PROC_PARENT[pid - 1].load(Ordering::Acquire);
    pos += format_u64_into(&mut buf[pos..], ppid);
    buf[pos] = b'\n';
    pos += 1;
    pos
}

// clone_child_trampoline is defined in child_handler.rs
