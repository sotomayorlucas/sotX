// ---------------------------------------------------------------------------
// child_handler: Full-featured handler for child processes.
// Extracted from main.rs.
// Fork/clone helpers live in crate::fork.
// Virtual file emulation lives in crate::virtual_files.
// ---------------------------------------------------------------------------

use sotos_common::sys;
use sotos_common::{BootInfo, BOOT_INFO_ADDR};
use sotos_common::linux_abi::*;
use core::sync::atomic::Ordering;
use crate::framebuffer::{print, print_u64, fb_putchar};
use crate::exec::{reply_val, rdtsc, exec_from_initrd, exec_from_initrd_argv,
                  exec_from_initrd_into, exec_from_initrd_argv_into,
                  EXEC_LOCK, MAX_EXEC_ARG_LEN, MAX_EXEC_ARGS, MAX_EXEC_ENVS,
                  copy_guest_path, starts_with};
use crate::process::*;
use crate::fd::*;
use crate::syscall_log::syscall_log_record;
use crate::vdso;
use crate::syscalls::context::SyscallContext;
use crate::syscalls::mm as syscalls_mm;
use crate::syscalls::fs as syscalls_fs;
use crate::syscalls::net as syscalls_net;
use crate::syscalls::signal as syscalls_signal;
use crate::syscalls::info as syscalls_info;
use crate::syscalls::task as syscalls_task;
use crate::lkl;

// Re-export from submodules so external `use crate::child_handler::X` still works.
pub(crate) use crate::fork::clone_child_trampoline;
pub(crate) use crate::virtual_files::{open_virtual_file, fill_random};

const MAP_WRITABLE: u64 = 2;

// ── LKL FD ownership tracking ──
// Bitset per process: bit N set ⇒ guest fd N is managed by LKL, not LUCAS.
// 128 fds per process (2 × u64).
use crate::process::MAX_PROCS;
static mut LKL_FDS: [[u64; 2]; MAX_PROCS] = [[0u64; 2]; MAX_PROCS];

#[inline]
fn lkl_fd_set(pid: usize, fd: i64) {
    if fd >= 0 && (fd as usize) < 128 && pid > 0 && pid <= MAX_PROCS {
        let i = pid - 1;
        unsafe { LKL_FDS[i][(fd as usize) / 64] |= 1u64 << ((fd as usize) % 64); }
    }
}
#[inline]
fn lkl_fd_clear(pid: usize, fd: i64) {
    if fd >= 0 && (fd as usize) < 128 && pid > 0 && pid <= MAX_PROCS {
        let i = pid - 1;
        unsafe { LKL_FDS[i][(fd as usize) / 64] &= !(1u64 << ((fd as usize) % 64)); }
    }
}
#[inline]
fn lkl_fd_is_set(pid: usize, fd: u64) -> bool {
    if (fd as usize) >= 128 || pid == 0 || pid > MAX_PROCS { return false; }
    let i = pid - 1;
    unsafe { LKL_FDS[i][(fd as usize) / 64] & (1u64 << ((fd as usize) % 64)) != 0 }
}

/// Forward a syscall to LKL, return the result (caller decides when to reply).
#[inline]
fn forward_to_lkl_ret(syscall_nr: u64,
                      msg: &sotos_common::IpcMsg, pid: usize, child_as_cap: u64) -> i64
{
    let args = [msg.regs[0], msg.regs[1], msg.regs[2],
                msg.regs[3], msg.regs[4], msg.regs[5]];
    lkl::syscall(syscall_nr, &args, child_as_cap, pid)
}

/// Forward a syscall directly to LKL and reply immediately.
fn forward_to_lkl(ep_cap: u64, syscall_nr: u64,
                  msg: &sotos_common::IpcMsg, pid: usize, child_as_cap: u64)
{
    let ret = forward_to_lkl_ret(syscall_nr, msg, pid, child_as_cap);
    reply_val(ep_cap, ret);
}

/// Per-pid retry counters to suppress repeated pipe-retry log lines.
/// Index by pid (0..MAX_PROCS). Incremented when PIPE_RETRY_TAG sent,
/// cleared when a non-retry syscall is processed for that pid.
pub(crate) static mut RETRY_COUNT: [u64; 16] = [0; 16];
/// Cumulative pipe stall counter per-pid. Only cleared on successful pipe I/O.
pub(crate) static mut PIPE_STALL: [u64; 16] = [0; 16];
/// Which pipe each process is currently stalling on (0xFF = none).
pub(crate) static mut PIPE_STALL_ID: [u8; 16] = [0xFF; 16];
/// Processes that received EOF from the deadlock detector.
/// If they exit with non-zero status shortly after, treat it as clean exit.
pub(crate) static mut DEADLOCK_EOF: [bool; 16] = [false; 16];

pub(crate) fn mark_pipe_retry_on(pid: usize, pipe_id: usize) {
    if pid < 16 { unsafe { RETRY_COUNT[pid] += 1; PIPE_STALL[pid] += 1; PIPE_STALL_ID[pid] = pipe_id as u8; } }
}
pub(crate) fn clear_pipe_retry(pid: usize) {
    if pid < 16 { unsafe { RETRY_COUNT[pid] = 0; } }
}
pub(crate) fn clear_pipe_stall(pid: usize) {
    if pid < 16 { unsafe { PIPE_STALL[pid] = 0; PIPE_STALL_ID[pid] = 0xFF; } }
}

/// Format a u64 as decimal into buf, return bytes written.
pub(crate) fn fmt_u64(val: u64, buf: &mut [u8]) -> usize {
    if val == 0 { buf[0] = b'0'; return 1; }
    let mut tmp = [0u8; 20];
    let mut n = 0;
    let mut v = val;
    while v > 0 { tmp[n] = b'0' + (v % 10) as u8; n += 1; v /= 10; }
    for j in 0..n { buf[j] = tmp[n - 1 - j]; }
    n
}

/// Child process handler — full-featured handler for child processes.
/// Supports brk, mmap, munmap, FD table (shared via GRP_ tables),
/// file I/O, all musl-libc init syscalls, execve, clone(CLONE_THREAD), and futex.
pub(crate) extern "C" fn child_handler() -> ! {
    // Wait for parent to provide setup info
    while CHILD_SETUP_READY.load(Ordering::Acquire) != 1 {
        sys::yield_now();
    }
    let mut ep_cap = CHILD_SETUP_EP.load(Ordering::Acquire);
    let pid = CHILD_SETUP_PID.load(Ordering::Acquire) as usize;
    print(b"CHILD-HANDLER pid="); print_u64(pid as u64);
    print(b" ep="); print_u64(ep_cap);
    print(b"\n");
    let clone_flags = CHILD_SETUP_FLAGS.load(Ordering::Acquire);
    let mut child_as_cap = CHILD_SETUP_AS_CAP.load(Ordering::Acquire);
    // Signal that we consumed the setup
    CHILD_SETUP_READY.store(0, Ordering::Release);

    // Resolve group indices for this thread
    let fdg = PROCESSES[pid - 1].fd_group.load(Ordering::Acquire) as usize;
    let memg = PROCESSES[pid - 1].mem_group.load(Ordering::Acquire) as usize;
    let _sigg = PROCESSES[pid - 1].sig_group.load(Ordering::Acquire) as usize;

    // Per-child brk/mmap state. Each memory group gets its own region.
    const CHILD_REGION_SIZE: u64 = 0x20000000; // 512 MiB per child (brk + mmap)
    const CHILD_BRK_BASE: u64 = 0x200000000; // 8 GiB — above Wine PE region
    const CHILD_MMAP_OFFSET: u64 = 0x8000000; // mmap starts 128 MiB into the region
    // Initrd file buffers: separate region well above brk/mmap
    // 16 children × 512 MiB = 8 GiB → ends at 0x400000000.
    const INITRD_BUF_REGION: u64 = 0x500000000; // 20 GiB (above child regions)
    const INITRD_BUF_PER_GROUP: u64 = 0x300000000; // 12 GiB per group (64 slots × 192 MiB)

    // Initialize memory group state: check if parent set inherited brk/mmap
    // (CoW fork children inherit the parent's VA layout, not a fresh region).
    let inherited_brk = PROCESSES[pid - 1].brk_base.load(Ordering::Acquire);
    let (my_brk_base, my_mmap_base) = if inherited_brk != 0 && (clone_flags & CLONE_VM == 0) {
        // Fork child: use state inherited from parent (set in fork path)
        let brk_cur = PROCESSES[pid - 1].brk_current.load(Ordering::Acquire);
        let mmap_base = PROCESSES[pid - 1].mmap_base.load(Ordering::Acquire);
        let mmap_next = PROCESSES[pid - 1].mmap_next.load(Ordering::Acquire);
        unsafe {
            THREAD_GROUPS[memg].brk = brk_cur;
            THREAD_GROUPS[memg].mmap_next = mmap_next;
            THREAD_GROUPS[memg].initrd_buf_base = INITRD_BUF_REGION + ((memg as u64) % MAX_PROCS as u64) * INITRD_BUF_PER_GROUP;
        }
        (inherited_brk, mmap_base)
    } else {
        // New process (not fork) or CLONE_VM thread: fresh region
        let base = CHILD_BRK_BASE + ((memg as u64) % MAX_PROCS as u64) * CHILD_REGION_SIZE;
        let mmap = base + CHILD_MMAP_OFFSET;
        unsafe {
            if clone_flags & CLONE_VM == 0 || THREAD_GROUPS[memg].brk == 0 {
                THREAD_GROUPS[memg].brk = base;
                THREAD_GROUPS[memg].mmap_next = mmap;
                THREAD_GROUPS[memg].initrd_buf_base = INITRD_BUF_REGION + ((memg as u64) % MAX_PROCS as u64) * INITRD_BUF_PER_GROUP;
            }
        }
        // Record fresh brk/mmap base for this process
        if pid > 0 && pid <= MAX_PROCS {
            PROCESSES[pid - 1].brk_base.store(base, Ordering::Release);
            PROCESSES[pid - 1].brk_current.store(base, Ordering::Release);
            PROCESSES[pid - 1].mmap_base.store(mmap, Ordering::Release);
            PROCESSES[pid - 1].mmap_next.store(mmap, Ordering::Release);
        }
        (base, mmap)
    };

    // If this child was created via fork, copy parent's socket metadata
    // into this child's THREAD_GROUPS slot.
    if FORK_SOCK_READY.load(Ordering::Acquire) != 0 {
        unsafe {
            THREAD_GROUPS[fdg].fd_flags = FORK_FD_FLAGS;
            THREAD_GROUPS[fdg].sock_conn_id = FORK_SOCK_CONN;
            THREAD_GROUPS[fdg].sock_udp_local_port = FORK_SOCK_UDP_LPORT;
            THREAD_GROUPS[fdg].sock_udp_remote_ip = FORK_SOCK_UDP_RIP;
            THREAD_GROUPS[fdg].sock_udp_remote_port = FORK_SOCK_UDP_RPORT;
        }
        FORK_SOCK_READY.store(0, Ordering::Release);
    }

    // Helper macro: create a SyscallContext from THREAD_GROUPS state.
    // Acquires per-group FD lock (ρ_repl). Lock is released automatically
    // when SyscallContext is dropped (RAII via Drop impl).
    macro_rules! make_ctx {
        () => {{
            fd_grp_lock(fdg);
            unsafe {
                let tg = &mut THREAD_GROUPS[fdg];
                let initrd_buf_base = THREAD_GROUPS[memg].initrd_buf_base;
                SyscallContext {
                    pid, ep_cap, child_as_cap,
                    guard_fdg: fdg,
                    current_brk: &mut THREAD_GROUPS[memg].brk,
                    mmap_next: &mut THREAD_GROUPS[memg].mmap_next,
                    my_brk_base, my_mmap_base, memg,
                    child_fds: &mut tg.fds,
                    fd_cloexec: &mut tg.fd_cloexec,
                    initrd_files: &mut tg.initrd,
                    initrd_file_buf_base: initrd_buf_base,
                    vfs_files: &mut tg.vfs,
                    dir_buf: &mut tg.dir_buf,
                    dir_len: &mut tg.dir_len,
                    dir_pos: &mut tg.dir_pos,
                    cwd: &mut tg.cwd,
                    fd_flags: &mut tg.fd_flags,
                    sock_conn_id: &mut tg.sock_conn_id,
                    sock_udp_local_port: &mut tg.sock_udp_local_port,
                    sock_udp_remote_ip: &mut tg.sock_udp_remote_ip,
                    sock_udp_remote_port: &mut tg.sock_udp_remote_port,
                    eventfd_counter: &mut tg.eventfd_counter,
                    eventfd_flags: &mut tg.eventfd_flags,
                    eventfd_slot_fd: &mut tg.eventfd_slot_fd,
                    timerfd_interval_ns: &mut tg.timerfd_interval_ns,
                    timerfd_expiry_tsc: &mut tg.timerfd_expiry_tsc,
                    timerfd_slot_fd: &mut tg.timerfd_slot_fd,
                    memfd_base: &mut tg.memfd_base,
                    memfd_size: &mut tg.memfd_size,
                    memfd_cap: &mut tg.memfd_cap,
                    memfd_slot_fd: &mut tg.memfd_slot_fd,
                    epoll_reg_fd: &mut tg.epoll_reg_fd,
                    epoll_reg_events: &mut tg.epoll_reg_events,
                    epoll_reg_data: &mut tg.epoll_reg_data,
                }
            }
        }}
    }

    // Activate LAPIC RIP profiler for P7+ (Wine grandchild processes).
    // This lets the kernel sample the user-mode RIP via timer interrupt
    // so we can see where P7 is stuck if it stops making syscalls.
    if pid >= 7 && child_as_cap != 0 {
        print(b"PROF-ENABLE P"); print_u64(pid as u64);
        print(b" as_cap="); print_u64(child_as_cap);
        print(b"\n");
        // syscall 256 = SYS_DEBUG_PROFILE_CR3, arg = as_cap
        let _ = sys::syscall1(256, child_as_cap);
    }

    // All processes use the same generous timeout.
    // Short timeouts cause a race: recv_timeout expiry coincides with the
    // child's endpoint::call(), consuming the message and leaving the child
    // blocked forever waiting for a reply that was discarded.
    let recv_ticks: u32 = 50000;
    let mut recv_fails: u32 = 0;

    loop {
        let msg = match sys::recv_timeout(ep_cap, recv_ticks) {
            Ok(m) => { recv_fails = 0; m },
            Err(e) => {
                recv_fails += 1;
                // Log timeout but keep waiting — short timeouts race with
                // CoW faults and cause the handler to miss the child's syscall
                if recv_fails <= 5 || recv_fails % 100 == 0 {
                    print(b"HANDLER-WAIT P"); print_u64(pid as u64);
                    print(b" #"); print_u64(recv_fails as u64);
                    print(b"\n");
                }
                if recv_fails < 1000 { continue; }
                print(b"HANDLER-ERR P"); print_u64(pid as u64);
                print(b" e="); print_u64(e as u64);
                print(b" fails="); print_u64(recv_fails as u64);
                print(b"\n");
                break;
            },
        };

        // Poll LKL readiness (no-op once already ready)
        lkl::poll_ready();

        // Cache the kernel thread ID for async signal injection
        let kernel_tid = msg.regs[6];
        if kernel_tid != 0 {
            PROCESSES[pid - 1].kernel_tid.store(kernel_tid, Ordering::Release);
        }

        // Check for pending unblocked signals
        if let Some(action) = syscalls_signal::check_pending_signals(ep_cap, pid, kernel_tid, child_as_cap) {
            if action.is_break() { break; }
            continue;
        }

        let syscall_nr = msg.tag;

        // === PWC watchpoint: detect spurious pipe close (should not fire after deadlock fix) ===
        if pid >= 3 && pid <= 5 {
            use core::sync::atomic::Ordering as Ord;
            let pwc1 = PIPE_WRITE_CLOSED[1].load(Ord::Relaxed);
            let wref1 = PIPE_WRITE_REFS[1].load(Ord::Relaxed);
            let act1 = PIPE_ACTIVE[1].load(Ord::Relaxed);
            if pwc1 != 0 && wref1 > 0 && act1 != 0 {
                static mut PWC_FIRED: bool = false;
                if !unsafe { PWC_FIRED } {
                    unsafe { PWC_FIRED = true; }
                    print(b"!! PWC-ANOM P"); print_u64(pid as u64);
                    print(b" S"); print_u64(syscall_nr);
                    print(b" pwc1="); print_u64(pwc1);
                    print(b" wref1="); print_u64(wref1);
                    print(b"\n");
                }
            }
        }

        // Phase 5: Syscall shadow logging (record every child syscall)
        syscall_log_record(pid as u16, syscall_nr as u16, msg.regs[0], 0);
        // Wine PE loader diagnostics: log every syscall for Wine PIDs
        crate::wine_diag::log_syscall(pid, syscall_nr, &msg.regs);
        // Clear retry state before dispatch. If the handler sends
        // PIPE_RETRY_TAG it will re-increment via mark_pipe_retry().
        clear_pipe_retry(pid);
        // Detect symlink/symlinkat calls from ANY process (Wine dosdevices debug)
        if syscall_nr == 88 || syscall_nr == 266 {
            print(b"!! SYMLINK-CALL P"); print_u64(pid as u64);
            print(b" nr="); print_u64(syscall_nr);
            print(b"\n");
        }

        // Trace syscalls for separate-AS child processes (P6+)
        if pid >= 6 {
            static mut AS_TRACE_N: [u32; 16] = [0; 16];
            let tn = if pid < 16 { unsafe { &mut AS_TRACE_N[pid] } } else { unsafe { &mut AS_TRACE_N[0] } };
            *tn += 1;
            if *tn <= 20 || *tn % 200 == 0 {
                print(b"AS-SYS P"); print_u64(pid as u64);
                print(b" #"); print_u64(syscall_nr);
                if syscall_nr == 0 || syscall_nr == 1 || syscall_nr == 3 || syscall_nr == 7 {
                    print(b" fd="); print_u64(msg.regs[0]);
                }
                print(b"\n");
            }
        }
        // Log P5 (wineserver) key syscalls
        if pid == 5 && (syscall_nr == 0 || syscall_nr == 1 || syscall_nr == 20
           || syscall_nr == 47 || syscall_nr == 46 || syscall_nr == 232) {
            print(b"WS5 #"); print_u64(syscall_nr);
            print(b" fd="); print_u64(msg.regs[0]);
            print(b"\n");
        }

        // ── LKL forwarding (direct in-process call, no IPC) ──
        // LKL handles: FS, networking, time, sync, uname, random.
        // LUCAS keeps: process mgmt (fork/exec/exit/wait), memory (brk/mmap),
        //              signals, thread mgmt, stdin/stdout/stderr.
        //
        // Category A: Always forward (no fd arg, or creates new fd).
        // Category B: Route based on FD ownership (LKL vs LUCAS bitset).
        if lkl::LKL_READY.load(Ordering::Acquire) {
            let forwarded = match syscall_nr {
                // ── Category A: path-only syscalls (always LKL) ──
                SYS_STAT | SYS_LSTAT | SYS_ACCESS | SYS_GETCWD | SYS_CHDIR |
                SYS_MKDIR | SYS_RMDIR | SYS_UNLINK | SYS_RENAME |
                SYS_CHMOD | SYS_FSTATAT | SYS_READLINKAT |
                SYS_FACCESSAT | SYS_MKDIRAT | SYS_UNLINKAT => {
                    forward_to_lkl(ep_cap, syscall_nr, &msg, pid, child_as_cap);
                    true
                }
                // ── Category A: info/time syscalls (always LKL) ──
                // Note: SYS_FUTEX stays in LUCAS — bridge_lock would deadlock on FUTEX_WAIT.
                SYS_UNAME | SYS_SYSINFO | SYS_GETRANDOM |
                SYS_GETTIMEOFDAY | SYS_CLOCK_GETTIME | SYS_CLOCK_GETRES |
                SYS_NANOSLEEP | SYS_CLOCK_NANOSLEEP => {
                    forward_to_lkl(ep_cap, syscall_nr, &msg, pid, child_as_cap);
                    true
                }
                // ── Category A: fd-creating syscalls → forward + mark fd ──
                SYS_OPEN | SYS_OPENAT => {
                    let ret = forward_to_lkl_ret(syscall_nr, &msg, pid, child_as_cap);
                    if ret >= 0 { lkl_fd_set(pid, ret); }
                    reply_val(ep_cap, ret);
                    true
                }
                SYS_SOCKET | SYS_EPOLL_CREATE | SYS_EPOLL_CREATE1 |
                SYS_EVENTFD | SYS_EVENTFD2 |
                SYS_TIMERFD_CREATE | SYS_MEMFD_CREATE |
                SYS_INOTIFY_INIT1 => {
                    let ret = forward_to_lkl_ret(syscall_nr, &msg, pid, child_as_cap);
                    if ret >= 0 { lkl_fd_set(pid, ret); }
                    reply_val(ep_cap, ret);
                    true
                }
                SYS_ACCEPT | SYS_ACCEPT4 => {
                    let ret = forward_to_lkl_ret(syscall_nr, &msg, pid, child_as_cap);
                    if ret >= 0 { lkl_fd_set(pid, ret); }
                    reply_val(ep_cap, ret);
                    true
                }
                SYS_PIPE | SYS_PIPE2 => {
                    let ret = forward_to_lkl_ret(syscall_nr, &msg, pid, child_as_cap);
                    if ret == 0 {
                        // Read back the two fds written to guest memory
                        let ptr = msg.regs[0] as *const [i32; 2];
                        let fds = unsafe { *ptr };
                        lkl_fd_set(pid, fds[0] as i64);
                        lkl_fd_set(pid, fds[1] as i64);
                    }
                    reply_val(ep_cap, ret);
                    true
                }
                SYS_SOCKETPAIR => {
                    let ret = forward_to_lkl_ret(syscall_nr, &msg, pid, child_as_cap);
                    if ret == 0 {
                        let ptr = msg.regs[3] as *const [i32; 2];
                        let fds = unsafe { *ptr };
                        lkl_fd_set(pid, fds[0] as i64);
                        lkl_fd_set(pid, fds[1] as i64);
                    }
                    reply_val(ep_cap, ret);
                    true
                }
                // ── Category B: fd-bearing syscalls → route by ownership ──
                SYS_READ | SYS_WRITE | SYS_LSEEK | SYS_FSTAT |
                SYS_PREAD64 | SYS_PWRITE64 | SYS_READV | SYS_WRITEV |
                SYS_FTRUNCATE | SYS_FSYNC | SYS_FDATASYNC |
                SYS_GETDENTS64 | SYS_FCNTL | SYS_IOCTL |
                SYS_CONNECT | SYS_BIND | SYS_LISTEN | SYS_SHUTDOWN |
                SYS_SENDTO | SYS_SENDMSG | SYS_RECVFROM | SYS_RECVMSG |
                SYS_GETSOCKOPT | SYS_SETSOCKOPT |
                SYS_GETSOCKNAME | SYS_GETPEERNAME |
                SYS_EPOLL_CTL |
                SYS_TIMERFD_SETTIME | SYS_TIMERFD_GETTIME |
                SYS_INOTIFY_ADD_WATCH | SYS_INOTIFY_RM_WATCH
                if lkl_fd_is_set(pid, msg.regs[0]) => {
                    forward_to_lkl(ep_cap, syscall_nr, &msg, pid, child_as_cap);
                    true
                }
                // epoll_wait/pwait: epfd is regs[0]
                SYS_EPOLL_WAIT | SYS_EPOLL_PWAIT
                if lkl_fd_is_set(pid, msg.regs[0]) => {
                    forward_to_lkl(ep_cap, syscall_nr, &msg, pid, child_as_cap);
                    true
                }
                // poll/ppoll/select/pselect6: mixed fds, too complex to route
                // per-fd — forward only if LKL has ANY fds (best effort)
                SYS_POLL | SYS_PPOLL | SYS_SELECT | SYS_PSELECT6
                if pid > 0 && pid <= MAX_PROCS &&
                   unsafe { LKL_FDS[pid-1][0] | LKL_FDS[pid-1][1] } != 0 => {
                    forward_to_lkl(ep_cap, syscall_nr, &msg, pid, child_as_cap);
                    true
                }
                SYS_CLOSE if lkl_fd_is_set(pid, msg.regs[0]) => {
                    let ret = forward_to_lkl_ret(syscall_nr, &msg, pid, child_as_cap);
                    if ret == 0 { lkl_fd_clear(pid, msg.regs[0] as i64); }
                    reply_val(ep_cap, ret);
                    true
                }
                SYS_DUP if lkl_fd_is_set(pid, msg.regs[0]) => {
                    let ret = forward_to_lkl_ret(syscall_nr, &msg, pid, child_as_cap);
                    if ret >= 0 { lkl_fd_set(pid, ret); }
                    reply_val(ep_cap, ret);
                    true
                }
                SYS_DUP2 | SYS_DUP3 if lkl_fd_is_set(pid, msg.regs[0]) => {
                    let ret = forward_to_lkl_ret(syscall_nr, &msg, pid, child_as_cap);
                    if ret >= 0 { lkl_fd_set(pid, ret); }
                    reply_val(ep_cap, ret);
                    true
                }
                _ => false,
            };
            if forwarded { continue; }
        }

        match syscall_nr {
            // SYS_read(fd, buf, len)
            SYS_READ => {
                let mut ctx = make_ctx!();
                syscalls_fs::sys_read(&mut ctx, &msg);
            }

            // SYS_write(fd, buf, len)
            SYS_WRITE => {
                // Trace P4 writes to pipe fds (wineserver reply pipe)
                if pid == 4 && (msg.regs[0] as usize) < 128 {
                    let wfd = msg.regs[0] as usize;
                    let wlen = msg.regs[2];
                    unsafe {
                        let k = THREAD_GROUPS[fdg].fds[wfd];
                        if k == 11 { // pipe write
                            print(b"WS4-WRITE fd="); print_u64(wfd as u64);
                            print(b" len="); print_u64(wlen);
                            print(b" pipe="); print_u64(THREAD_GROUPS[fdg].sock_conn_id[wfd] as u64);
                            print(b"\n");
                        }
                    }
                }
                let mut ctx = make_ctx!();
                syscalls_fs::sys_write(&mut ctx, &msg);
            }

            // SYS_close(fd)
            SYS_CLOSE => {
                let mut ctx = make_ctx!();
                syscalls_fs::sys_close(&mut ctx, &msg);
            }

            // SYS_open(path, flags, mode) — used by musl dynamic linker + busybox
            SYS_OPEN => {
                print(b"CH-OPEN P"); crate::framebuffer::print_u64(pid as u64);
                print(b" ptr="); crate::framebuffer::print_hex64(msg.regs[0]);
                print(b"\n");
                let mut ctx = make_ctx!();
                syscalls_fs::sys_open(&mut ctx, &msg);
            }

            // SYS_fstat(fd, stat_buf)
            SYS_FSTAT => {
                let mut ctx = make_ctx!();
                syscalls_fs::sys_fstat(&mut ctx, &msg);
            }

            // SYS_stat(path, statbuf) — check if path exists (for terminfo etc.)
            SYS_STAT | SYS_LSTAT => {
                let mut ctx = make_ctx!();
                syscalls_fs::sys_stat(&mut ctx, &msg);
            }

            // SYS_poll(fds, nfds, timeout)
            SYS_POLL => {
                let mut ctx = make_ctx!();
                syscalls_net::sys_poll(&mut ctx, &msg);
            }

            // SYS_lseek(fd, offset, whence)
            SYS_LSEEK => {
                let mut ctx = make_ctx!();
                syscalls_fs::sys_lseek(&mut ctx, &msg);
            }

            // SYS_mmap — delegated to syscalls::mm
            SYS_MMAP => {
                let mut ctx = make_ctx!();
                syscalls_mm::sys_mmap(&mut ctx, &msg);
            }

            // SYS_mprotect — delegated to syscalls::mm
            SYS_MPROTECT => {
                // Trace mprotect for Wine debug
                if pid == 2 {
                    static mut MP_COUNT: u32 = 0;
                    let c = unsafe { &mut MP_COUNT };
                    if *c < 5 || *c % 100 == 0 {
                        print(b"MPROT P2 addr=");
                        crate::framebuffer::print_hex64(msg.regs[0]);
                        print(b" len=");
                        print_u64(msg.regs[1]);
                        print(b" prot=");
                        print_u64(msg.regs[2]);
                        print(b"\n");
                    }
                    *c += 1;
                }
                let mut ctx = make_ctx!();
                syscalls_mm::sys_mprotect(&mut ctx, &msg);
            }

            // SYS_pread64(fd, buf, count, offset)
            SYS_PREAD64 => {
                let mut ctx = make_ctx!();
                syscalls_fs::sys_pread64(&mut ctx, &msg);
            }

            // SYS_munmap — delegated to syscalls::mm
            SYS_MUNMAP => {
                let mut ctx = make_ctx!();
                syscalls_mm::sys_munmap(&mut ctx, &msg);
            }

            // SYS_brk(addr) — delegated to syscalls::mm
            SYS_BRK => {
                let mut ctx = make_ctx!();
                syscalls_mm::sys_brk(&mut ctx, &msg);
            }

            // SYS_rt_sigaction(sig, act, oldact, sigsetsize)
            SYS_RT_SIGACTION => {
                let mut ctx = make_ctx!();
                syscalls_signal::sys_rt_sigaction(&mut ctx, &msg);
            }

            // SYS_rt_sigprocmask(how, set, oldset, sigsetsize)
            SYS_RT_SIGPROCMASK => {
                let mut ctx = make_ctx!();
                syscalls_signal::sys_rt_sigprocmask(&mut ctx, &msg);
            }

            // SYS_ioctl — terminal emulation
            SYS_IOCTL => {
                let mut ctx = make_ctx!();
                syscalls_fs::sys_ioctl(&mut ctx, &msg);
            }

            // SYS_readv(fd, iov, iovcnt) — scatter read
            SYS_READV => {
                let mut ctx = make_ctx!();
                syscalls_fs::sys_readv(&mut ctx, &msg);
            }

            // SYS_writev
            SYS_WRITEV => {
                let mut ctx = make_ctx!();
                syscalls_fs::sys_writev(&mut ctx, &msg);
            }

            // SYS_access / SYS_faccessat — check file accessibility
            SYS_ACCESS | SYS_FACCESSAT => {
                let mut ctx = make_ctx!();
                syscalls_fs::sys_access(&mut ctx, &msg, syscall_nr);
            }

            // SYS_pipe
            SYS_PIPE => {
                let mut ctx = make_ctx!();
                syscalls_fs::sys_pipe(&mut ctx, &msg);
            }

            // SYS_nanosleep
            SYS_NANOSLEEP => { let mut ctx = make_ctx!(); syscalls_info::sys_nanosleep(&mut ctx, &msg); }

            SYS_GETPID => {
                let mut ctx = make_ctx!();
                syscalls_task::sys_getpid(&mut ctx, &msg);
            }

            SYS_GETTID => {
                let mut ctx = make_ctx!();
                syscalls_task::sys_gettid(&mut ctx, &msg);
            }

            // SYS_dup(oldfd) — copies fd kind + socket/VFS metadata
            SYS_DUP => {
                let mut ctx = make_ctx!();
                syscalls_fs::sys_dup(&mut ctx, &msg);
            }

            SYS_DUP2 => {
                let mut ctx = make_ctx!();
                syscalls_fs::sys_dup2(&mut ctx, &msg);
            }

            // SYS_execve(path, argv, envp) — generic: loads any ELF from initrd
            SYS_EXECVE => {
                print(b"EXEC P"); print_u64(pid as u64); print(b"\n");
                let path_ptr = msg.regs[0];
                let argv_ptr = msg.regs[1];
                let envp_ptr = msg.regs[2];

                // For CoW fork children, privatize pages before vm_read to avoid
                // reading stale/corrupted data from shared frames the parent may
                // have written to. Dedup tracker prevents double-privatizing.
                // Stack pages were already eagerly copied at fork time so they
                // are already private; privatizing them again is harmless.
                let mut priv_pages = [0u64; 32];
                let mut priv_count = 0usize;
                let privatize = |as_cap: u64, addr: u64, pages: &mut [u64; 32], count: &mut usize| {
                    if as_cap == 0 || addr == 0 { return; }
                    let pg = addr & !0xFFF;
                    // Dedup: don't privatize the same page twice
                    for i in 0..*count { if pages[i] == pg { return; } }
                    if *count >= 32 { return; }
                    if let Ok(nf) = sys::frame_alloc() {
                        if sys::frame_copy(nf, as_cap, pg).is_ok() {
                            let _ = sys::unmap_from(as_cap, pg);
                            let _ = sys::map_into(as_cap, pg, nf, 2);
                            pages[*count] = pg;
                            *count += 1;
                        }
                    }
                };

                // Privatize path page before reading
                privatize(child_as_cap, path_ptr, &mut priv_pages, &mut priv_count);

                let mut path = [0u8; 48];
                let path_len = if child_as_cap != 0 {
                    let mut tmp = [0u8; 48];
                    match sys::vm_read(child_as_cap, path_ptr, tmp.as_mut_ptr() as u64, 48) {
                        Ok(()) => {}
                        Err(e) => {
                            print(b"EXECVE-VM-READ-FAIL path_ptr="); print_u64(path_ptr);
                            print(b" err="); print_u64((-e) as u64);
                            print(b"\n");
                        }
                    }
                    let slen = tmp.iter().position(|&b| b == 0).unwrap_or(47);
                    path[..slen].copy_from_slice(&tmp[..slen]);
                    path[slen] = 0;
                    slen
                } else {
                    copy_guest_path(path_ptr, &mut path)
                };
                let name = &path[..path_len];
                let bin_name = if path_len > 5 && starts_with(name, b"/bin/") { &name[5..] } else { name };

                let is_shell = bin_name == b"shell" || bin_name == b"sh";
                if is_shell {
                    let boot_info = unsafe { &*(BOOT_INFO_ADDR as *const BootInfo) };
                    let entry = boot_info.guest_entry;
                    if entry == 0 { reply_val(ep_cap, -ENOENT); continue; }
                    let stack_addr = NEXT_CHILD_STACK.fetch_add(0x2000, Ordering::SeqCst);
                    let guest_frame = match sys::frame_alloc() { Ok(f) => f, Err(_) => { reply_val(ep_cap, -ENOMEM); continue; } };
                    if sys::map(stack_addr, guest_frame, MAP_WRITABLE).is_err() { reply_val(ep_cap, -ENOMEM); continue; }
                    let new_ep = match sys::endpoint_create() { Ok(e) => e, Err(_) => { reply_val(ep_cap, -ENOMEM); continue; } };
                    let new_thread = match sys::thread_create_redirected(entry, stack_addr + 0x1000, new_ep) { Ok(t) => t, Err(_) => { reply_val(ep_cap, -ENOMEM); continue; } };
                    let _ = sys::signal_entry(new_thread, vdso::SIGNAL_TRAMPOLINE_ADDR);
                    ep_cap = new_ep;
                    continue;
                }

                // Read argv from guest memory.
                // For CoW fork children (child_as_cap != 0), use vm_read
                // since the child's stack pages are in a separate address space.
                let mut exec_argv = [[0u8; MAX_EXEC_ARG_LEN]; MAX_EXEC_ARGS];
                let mut exec_argc: usize = 0;
                if argv_ptr != 0 {
                    privatize(child_as_cap, argv_ptr, &mut priv_pages, &mut priv_count);
                    let mut ap = argv_ptr;
                    while exec_argc < MAX_EXEC_ARGS {
                        privatize(child_as_cap, ap, &mut priv_pages, &mut priv_count);
                        let str_ptr = if child_as_cap != 0 {
                            let mut buf = [0u8; 8];
                            let _ = sys::vm_read(child_as_cap, ap, buf.as_mut_ptr() as u64, 8);
                            u64::from_le_bytes(buf)
                        } else {
                            unsafe { *(ap as *const u64) }
                        };
                        if str_ptr == 0 { break; }
                        privatize(child_as_cap, str_ptr, &mut priv_pages, &mut priv_count);
                        if child_as_cap != 0 {
                            // Read string from child AS
                            let mut tmp = [0u8; MAX_EXEC_ARG_LEN];
                            let _ = sys::vm_read(child_as_cap, str_ptr, tmp.as_mut_ptr() as u64, MAX_EXEC_ARG_LEN as u64);
                            // Find NUL terminator
                            let slen = tmp.iter().position(|&b| b == 0).unwrap_or(MAX_EXEC_ARG_LEN - 1);
                            exec_argv[exec_argc][..slen].copy_from_slice(&tmp[..slen]);
                            exec_argv[exec_argc][slen] = 0;
                        } else {
                            copy_guest_path(str_ptr, &mut exec_argv[exec_argc]);
                        }
                        exec_argc += 1;
                        ap += 8;
                    }
                }

                // Read envp from guest memory
                let mut exec_envp = [[0u8; MAX_EXEC_ARG_LEN]; MAX_EXEC_ENVS];
                let mut exec_envc: usize = 0;
                if envp_ptr != 0 {
                    privatize(child_as_cap, envp_ptr, &mut priv_pages, &mut priv_count);
                    let mut ep = envp_ptr;
                    while exec_envc < MAX_EXEC_ENVS {
                        privatize(child_as_cap, ep, &mut priv_pages, &mut priv_count);
                        let str_ptr = if child_as_cap != 0 {
                            let mut buf = [0u8; 8];
                            let _ = sys::vm_read(child_as_cap, ep, buf.as_mut_ptr() as u64, 8);
                            u64::from_le_bytes(buf)
                        } else {
                            unsafe { *(ep as *const u64) }
                        };
                        if str_ptr == 0 { break; }
                        privatize(child_as_cap, str_ptr, &mut priv_pages, &mut priv_count);
                        if child_as_cap != 0 {
                            let mut tmp = [0u8; MAX_EXEC_ARG_LEN];
                            let _ = sys::vm_read(child_as_cap, str_ptr, tmp.as_mut_ptr() as u64, MAX_EXEC_ARG_LEN as u64);
                            let slen = tmp.iter().position(|&b| b == 0).unwrap_or(MAX_EXEC_ARG_LEN - 1);
                            exec_envp[exec_envc][..slen].copy_from_slice(&tmp[..slen]);
                            exec_envp[exec_envc][slen] = 0;
                        } else {
                            copy_guest_path(str_ptr, &mut exec_envp[exec_envc]);
                        }
                        exec_envc += 1;
                        ep += 8;
                    }
                }

                // Strip WINESERVERSOCKET env var: the inherited fd is CLOEXEC-closed
                // during exec. Without this, Wine tries to reuse the dead fd instead
                // of connecting to the existing wineserver via socket path.
                {
                    let mut dst = 0usize;
                    for i in 0..exec_envc {
                        if !exec_envp[i].starts_with(b"WINESERVERSOCKET=") {
                            if dst != i { exec_envp[dst] = exec_envp[i]; }
                            dst += 1;
                        }
                    }
                    exec_envc = dst;
                }

                while EXEC_LOCK.compare_exchange(0, 1, Ordering::AcqRel, Ordering::Relaxed).is_err() { sys::yield_now(); }

                // ALWAYS create a fresh AS for exec so that fork/clone_cow
                // never operates on init's shared AS (which would corrupt
                // pages for all threads sharing it).
                let exec_target_as = match sys::addr_space_create() {
                    Ok(as_cap) => {
                        // Relax W^X for child AS (Wine PE needs RWX pages)
                        let _ = sys::wx_relax(as_cap, 1);
                        as_cap
                    }
                    Err(_) => {
                        EXEC_LOCK.store(0, Ordering::Release);
                        reply_val(ep_cap, -12);
                        continue;
                    }
                };

                // Try initrd first (by full path, then by basename), then VFS
                let envp_slice = &exec_envp[..exec_envc];
                let result = if exec_target_as != 0 {
                    if exec_argc > 0 || exec_envc > 0 {
                        exec_from_initrd_argv_into(bin_name, &exec_argv[..exec_argc], envp_slice, exec_target_as)
                    } else {
                        exec_from_initrd_into(bin_name, exec_target_as)
                    }
                } else {
                    if exec_argc > 0 || exec_envc > 0 {
                        exec_from_initrd_argv(bin_name, &exec_argv[..exec_argc], envp_slice)
                    } else {
                        exec_from_initrd(bin_name)
                    }
                };
                // If initrd failed with full path, try basename (e.g. /usr/libexec/git-core/git → git)
                let result = match result {
                    Ok(r) => Ok(r),
                    Err(_) => {
                        let basename = {
                            let mut last_slash = 0;
                            let mut i = 0;
                            while i < bin_name.len() {
                                if bin_name[i] == b'/' { last_slash = i + 1; }
                                i += 1;
                            }
                            if last_slash > 0 && last_slash < bin_name.len() {
                                &bin_name[last_slash..]
                            } else {
                                bin_name
                            }
                        };
                        if basename != bin_name {
                            if exec_target_as != 0 {
                                if exec_argc > 0 || exec_envc > 0 {
                                    exec_from_initrd_argv_into(basename, &exec_argv[..exec_argc], envp_slice, exec_target_as)
                                } else {
                                    exec_from_initrd_into(basename, exec_target_as)
                                }
                            } else {
                                if exec_argc > 0 || exec_envc > 0 {
                                    exec_from_initrd_argv(basename, &exec_argv[..exec_argc], envp_slice)
                                } else {
                                    exec_from_initrd(basename)
                                }
                            }
                        } else {
                            Err(-2)
                        }
                    }
                };
                let result = match result {
                    Ok(r) => Ok(r),
                    Err(_) => {
                        // Initrd failed — try VFS with full path
                        // Use bin_name if it's an absolute path (avoids /bin/ prefix duplication)
                        let vfs_path = if !bin_name.is_empty() && bin_name[0] == b'/' { bin_name } else { name };
                        if exec_target_as != 0 {
                            if exec_argc > 0 || exec_envc > 0 {
                                crate::exec::exec_from_vfs_argv_into(vfs_path, &exec_argv[..exec_argc], envp_slice, exec_target_as)
                            } else {
                                crate::exec::exec_from_vfs_into(vfs_path, exec_target_as)
                            }
                        } else {
                            if exec_argc > 0 || exec_envc > 0 {
                                crate::exec::exec_from_vfs_argv(vfs_path, &exec_argv[..exec_argc], envp_slice)
                            } else {
                                crate::exec::exec_from_vfs(vfs_path)
                            }
                        }
                    }
                };
                match result {
                    Ok((new_ep, _tc)) => {
                        // Close all fds marked close-on-exec
                        {
                            let mut ctx = make_ctx!();
                            ctx.ep_cap = new_ep; // use new endpoint
                            crate::syscalls::fs::close_cloexec_fds(&mut ctx);
                        }
                        // Record page info for cleanup on exit
                        if pid > 0 && pid <= MAX_PROCS {
                            use crate::exec::{LAST_EXEC_STACK_BASE, LAST_EXEC_STACK_PAGES,
                                              LAST_EXEC_ELF_LO, LAST_EXEC_ELF_HI, LAST_EXEC_HAS_INTERP,
                                              LAST_EXEC_PERSONALITY};
                            PROCESSES[pid - 1].stack_base.store(LAST_EXEC_STACK_BASE.load(Ordering::Acquire), Ordering::Release);
                            PROCESSES[pid - 1].stack_pages.store(LAST_EXEC_STACK_PAGES.load(Ordering::Acquire), Ordering::Release);
                            PROCESSES[pid - 1].elf_lo.store(LAST_EXEC_ELF_LO.load(Ordering::Acquire), Ordering::Release);
                            PROCESSES[pid - 1].elf_hi.store(LAST_EXEC_ELF_HI.load(Ordering::Acquire), Ordering::Release);
                            PROCESSES[pid - 1].has_interp.store(LAST_EXEC_HAS_INTERP.load(Ordering::Acquire), Ordering::Release);
                            PROCESSES[pid - 1].personality.store(LAST_EXEC_PERSONALITY.load(Ordering::Acquire), Ordering::Release);
                            // Seed VMAs for /proc/self/maps
                            {
                                use crate::vma::{VMA_LISTS, VmaLabel};
                                let elo = LAST_EXEC_ELF_LO.load(Ordering::Acquire);
                                let ehi = LAST_EXEC_ELF_HI.load(Ordering::Acquire);
                                let sb = LAST_EXEC_STACK_BASE.load(Ordering::Acquire);
                                let sp = LAST_EXEC_STACK_PAGES.load(Ordering::Acquire);
                                let vl = unsafe { &mut VMA_LISTS[memg] };
                                vl.count = 0; // clear previous VMAs
                                if ehi > elo {
                                    vl.insert(elo, ehi, 5, 0x02, VmaLabel::Text); // r-xp
                                }
                                if sp > 0 && sb >= sp * 0x1000 {
                                    let stack_lo = sb - sp * 0x1000;
                                    vl.insert(stack_lo, sb, 3, 0x02, VmaLabel::Stack); // rw-p
                                }
                                // vDSO
                                vl.insert(0xB80000, 0xB81000, 5, 0x02, VmaLabel::Vdso);
                                // Heap (starts empty, grows via brk)
                                vl.insert(my_brk_base, my_brk_base, 3, 0x22, VmaLabel::Heap);
                            }
                            // Store exe_path for /proc/self/exe
                            {
                                let mut path_buf = [0u8; 32];
                                let src = if !bin_name.is_empty() && bin_name[0] == b'/' {
                                    bin_name
                                } else {
                                    name
                                };
                                let n = src.len().min(31);
                                path_buf[..n].copy_from_slice(&src[..n]);
                                let w0 = u64::from_le_bytes(path_buf[0..8].try_into().unwrap());
                                let w1 = u64::from_le_bytes(path_buf[8..16].try_into().unwrap());
                                let w2 = u64::from_le_bytes(path_buf[16..24].try_into().unwrap());
                                let w3 = u64::from_le_bytes(path_buf[24..32].try_into().unwrap());
                                PROCESSES[pid - 1].exe_path[0].store(w0, Ordering::Release);
                                PROCESSES[pid - 1].exe_path[1].store(w1, Ordering::Release);
                                PROCESSES[pid - 1].exe_path[2].store(w2, Ordering::Release);
                                PROCESSES[pid - 1].exe_path[3].store(w3, Ordering::Release);
                            }
                        }
                        // Reset brk/mmap for the fresh address space.
                        // exec creates a new AS — must use FRESH bases from this
                        // child's memory group, NOT inherited parent values.
                        // Parent's mmap_base can collide with newly loaded ELF segments.
                        let fresh_brk = CHILD_BRK_BASE + ((memg as u64) % MAX_PROCS as u64) * CHILD_REGION_SIZE;
                        let fresh_mmap = fresh_brk + CHILD_MMAP_OFFSET;
                        unsafe {
                            THREAD_GROUPS[memg].brk = fresh_brk;
                            THREAD_GROUPS[memg].mmap_next = fresh_mmap;
                        }
                        PROCESSES[pid - 1].brk_base.store(fresh_brk, Ordering::Release);
                        PROCESSES[pid - 1].brk_current.store(fresh_brk, Ordering::Release);
                        PROCESSES[pid - 1].mmap_base.store(fresh_mmap, Ordering::Release);
                        PROCESSES[pid - 1].mmap_next.store(fresh_mmap, Ordering::Release);

                        // For glibc (Wine) processes: map a sentinel page at 0x10000
                        // to force Wine's low-address reservation to fail → re-exec
                        // via preloader path (avoids dlopen dual-libc assertion).
                        if crate::exec::LAST_EXEC_PERSONALITY.load(Ordering::Acquire)
                            == crate::process::PERS_GLIBC
                        {
                            if let Ok(f) = sys::frame_alloc() {
                                let _ = sys::map_into(exec_target_as, 0x10000, f, 0);
                            }
                        }
                        // For Wine (glibc) children: set CWD to drive_c so Wine
                        // can find DOS drive mapping (fixes "could not find DOS drive" stall)
                        if crate::exec::LAST_EXEC_PERSONALITY.load(Ordering::Acquire)
                            == crate::process::PERS_GLIBC
                        {
                            let drive_c = b"/root/.wine/drive_c";
                            unsafe {
                                let grp = &mut crate::fd::THREAD_GROUPS[fdg];
                                grp.cwd[..drive_c.len()].copy_from_slice(drive_c);
                                grp.cwd[drive_c.len()] = 0;
                            }
                        }
                        EXEC_LOCK.store(0, Ordering::Release);
                        print(b"EXEC-OK P"); print_u64(pid as u64);
                        print(b" new_ep="); print_u64(new_ep);
                        print(b" as="); print_u64(exec_target_as);
                        print(b"\n");
                        // Reply to old thread → it resumes in child_exec_main,
                        // calls linux_exit(1), which terminates the process cleanly.
                        reply_val(ep_cap, 0);
                        ep_cap = new_ep;
                        // Exec always creates its own AS now — use vm_read/vm_write
                        child_as_cap = exec_target_as;
                        continue;
                    }
                    Err(errno) => {
                        EXEC_LOCK.store(0, Ordering::Release); reply_val(ep_cap, errno); continue;
                    }
                }
            }

            // SYS_exit(status)
            SYS_EXIT => {
                let mut ctx = make_ctx!();
                if syscalls_task::sys_exit(&mut ctx, &msg).is_break() {
                    break;
                }
            }

            // SYS_kill(pid, sig)
            SYS_KILL => {
                let mut ctx = make_ctx!();
                syscalls_task::sys_kill(&mut ctx, &msg);
            }

            // SYS_clone(flags, child_stack, ptid, ctid, newtls) — create a thread
            SYS_CLONE => {
                let flags = msg.regs[0];
                let child_stack = msg.regs[1];

                // Fork-style clone: no CLONE_VM means fork, not thread creation.
                // musl's fork() calls clone(SIGCHLD, 0, ...).
                // Real CoW fork via addr_space_clone (same as SYS_FORK).
                if flags & CLONE_VM == 0 {
                    // CoW fork via clone(SIGCHLD, 0) — same as SYS_FORK
                    let fork_cpid = NEXT_PID.fetch_add(1, Ordering::SeqCst) as usize;
                    if fork_cpid > MAX_PROCS {
                        reply_val(ep_cap, -ENOMEM);
                        continue;
                    }

                    // Determine source AS: parent's separate AS if non-zero, else init's AS
                    let parent_as = child_as_cap; // outer scope: parent's own AS (0 = init's AS)
                    let clone_source = if parent_as != 0 {
                        parent_as
                    } else {
                        let cap = INIT_SELF_AS_CAP.load(Ordering::Acquire);
                        if cap == 0 { reply_val(ep_cap, -ENOSYS); continue; }
                        cap
                    };

                    let parent_tid = msg.regs[6];
                    let fork_rsp = msg.regs[7];
                    let mut saved_regs = [0u64; 20];
                    let _ = sys::get_thread_regs(parent_tid, &mut saved_regs);
                    let fork_rip = saved_regs[2];
                    let fork_rbx = saved_regs[1];
                    let fork_rbp = saved_regs[6];
                    let fork_r12 = saved_regs[11];
                    let fork_r13 = saved_regs[12];
                    let fork_r14 = saved_regs[13];
                    let fork_r15 = saved_regs[14];
                    let fork_fsbase = saved_regs[16];
                    let fork_gsbase = saved_regs[17];

                    // Diagnostic: show fork context for Wine child processes
                    if fork_cpid >= 6 {
                        print(b"FK-CTX cpid="); print_u64(fork_cpid as u64);
                        print(b" rip="); crate::framebuffer::print_hex64(fork_rip);
                        print(b" fs="); crate::framebuffer::print_hex64(fork_fsbase);
                        print(b"\n");
                    }
                    let frame_rsp = fork_rsp - 56;
                    // Write fork frame (callee-saved regs) to stack.
                    // For parent_as != 0: defer to AFTER clone_cow (write to child_as_cap).
                    // vm_write before clone triggers CoW on the parent page, so the child
                    // inherits the ORIGINAL page without the fork frame.
                    if parent_as == 0 {
                        unsafe {
                            *((frame_rsp) as *mut u64) = fork_rbx;
                            *((frame_rsp + 8) as *mut u64) = fork_rbp;
                            *((frame_rsp + 16) as *mut u64) = fork_r12;
                            *((frame_rsp + 24) as *mut u64) = fork_r13;
                            *((frame_rsp + 32) as *mut u64) = fork_r14;
                            *((frame_rsp + 40) as *mut u64) = fork_r15;
                            *((frame_rsp + 48) as *mut u64) = fork_rip;
                        }
                    }

                    // Determine child entry point (trampoline needed if TLS/GS is set)
                    let need_trampoline = fork_fsbase != 0 || fork_gsbase != 0;
                    let child_entry = if need_trampoline {
                        vdso::FORK_TLS_TRAMPOLINE_ADDR
                    } else {
                        vdso::COW_FORK_RESTORE_ADDR
                    };

                    // Write TLS/GS trampoline to parent BEFORE cloning ONLY for
                    // init's own AS (parent_as == 0) where there is no CoW sharing.
                    // For separate AS (parent_as != 0), we write to the CHILD's AS
                    // after clone_cow to avoid corrupting shared CoW frames.
                    if need_trampoline && parent_as == 0 {
                        vdso::write_fork_tls_trampoline(fork_fsbase, fork_gsbase);
                    }

                    print(b"FK1 P"); print_u64(pid as u64); print(b"\n");
                    let child_as_cap = match sys::addr_space_clone(clone_source) {
                        Ok(cap) => cap,
                        Err(_) => { reply_val(ep_cap, -ENOMEM); continue; }
                    };
                    print(b"FK2 P"); print_u64(pid as u64); print(b"\n");

                    // For separate AS: write TLS trampoline to the CHILD's private
                    // vDSO page (CoW-safe: allocates new frame, copies, writes).
                    if need_trampoline && parent_as != 0 {
                        vdso::write_fork_tls_trampoline_in(child_as_cap, fork_fsbase, fork_gsbase);
                    }
                    // Fix glibc fork linked list spin: glibc's fork handler iterates
                    // the atfork handler list (linked list at RBX+0x1088). After CoW fork,
                    // a node has next=NULL. The VMM demand-pages address 0 (zero page),
                    // so reading *(NULL) returns 0 instead of faulting. The list traversal
                    // loops forever because 0 != sentinel. Fix: write the sentinel value
                    // to address 0 in the child's AS so the traversal terminates.
                    // Make the list head self-referencing (empty circular list).
                    if fork_rbx != 0 {
                        let head_addr = fork_rbx.wrapping_add(0x1088);
                        // Patch NULL page so *(NULL) returns sentinel (stops infinite loop)
                        let _ = sys::vm_write(child_as_cap, 0,
                            &head_addr as *const u64 as u64, 8);
                        // Make list head point to itself (empty list → skip traversal)
                        if head_addr > 0x10000 && head_addr < 0x0000_8000_0000_0000 {
                            let _ = sys::vm_write(child_as_cap, head_addr,
                                &head_addr as *const u64 as u64, 8);
                            let _ = sys::vm_write(child_as_cap, head_addr + 8,
                                &head_addr as *const u64 as u64, 8);
                        }
                    }

                    // Eagerly copy stack pages for child BEFORE writing fork frame.
                    // This matches SYS_FORK's approach: make pages private+writable
                    // first, then vm_write the fork frame into the writable pages.
                    // Without this, vm_write triggers kernel CoW (allocates frame A),
                    // then eager copy replaces with frame B — but if frame_copy or
                    // map_into fails, the fork frame data can be lost, causing the
                    // child to ret into garbage (e.g. PRE_TLS canary at 0xB7002C).
                    {
                        let base_page = frame_rsp & !0xFFF;
                        for i in 0..8u64 {
                            let pg = base_page + i * 0x1000;
                            if let Ok(nf) = sys::frame_alloc() {
                                if sys::frame_copy(nf, child_as_cap, pg).is_ok() {
                                    let _ = sys::unmap_from(child_as_cap, pg);
                                    let _ = sys::map_into(child_as_cap, pg, nf, 2);
                                }
                            }
                        }
                    }

                    // Write fork frame AFTER eager stack copy so it goes into the
                    // child's now-private writable stack pages (no CoW needed).
                    // (frame_copy copied the original pre-fork content; vm_write then
                    // writes the fork frame into the child's private stack page.)
                    if parent_as != 0 {
                        let mut frame_data = [0u8; 56];
                        frame_data[0..8].copy_from_slice(&fork_rbx.to_le_bytes());
                        frame_data[8..16].copy_from_slice(&fork_rbp.to_le_bytes());
                        frame_data[16..24].copy_from_slice(&fork_r12.to_le_bytes());
                        frame_data[24..32].copy_from_slice(&fork_r13.to_le_bytes());
                        frame_data[32..40].copy_from_slice(&fork_r14.to_le_bytes());
                        frame_data[40..48].copy_from_slice(&fork_r15.to_le_bytes());
                        frame_data[48..56].copy_from_slice(&fork_rip.to_le_bytes());
                        if sys::vm_write(child_as_cap, frame_rsp, frame_data.as_ptr() as u64, 56).is_err() {
                            print(b"FORK-FATAL: vm_write failed\n");
                            reply_val(ep_cap, -ENOMEM);
                            continue;
                        }
                    }

                    // Eagerly copy TLS page and patch TID fields.
                    if fork_fsbase != 0 {
                        let tls_vaddr = fork_fsbase & !0xFFF;
                        if let Ok(nf) = sys::frame_alloc() {
                            if sys::frame_copy(nf, child_as_cap, tls_vaddr).is_ok() {
                                let _ = sys::unmap_from(child_as_cap, tls_vaddr);
                                let _ = sys::map_into(child_as_cap, tls_vaddr, nf, 2);
                                // Page is now private+writable. Patch via vm_write.
                                let tid_val = fork_cpid as u32;
                                let one: u32 = 1;
                                let _ = sys::vm_write(child_as_cap, fork_fsbase + 0x2D0,
                                    &tid_val as *const u32 as u64, 4);
                                let _ = sys::vm_write(child_as_cap, fork_fsbase + 0x2D4,
                                    &tid_val as *const u32 as u64, 4);
                                let _ = sys::vm_write(child_as_cap, fork_fsbase + 0x2E0,
                                    &one as *const u32 as u64, 4);
                                print(b"TLS-PATCHED cpid="); print_u64(fork_cpid as u64);
                                print(b"\n");
                            }
                        }
                        // Also copy TLS+0x1000 (second page of TLS block)
                        let tls_vaddr2 = tls_vaddr + 0x1000;
                        if let Ok(nf2) = sys::frame_alloc() {
                            if sys::frame_copy(nf2, child_as_cap, tls_vaddr2).is_ok() {
                                let _ = sys::unmap_from(child_as_cap, tls_vaddr2);
                                let _ = sys::map_into(child_as_cap, tls_vaddr2, nf2, 2);
                            }
                        }
                    }
                    print(b"FK3 P"); print_u64(pid as u64); print(b"\n");

                    let child_ep = match sys::endpoint_create() {
                        Ok(e) => e,
                        Err(_) => { reply_val(ep_cap, -ENOMEM); continue; }
                    };

                    let child_thread = match sys::thread_create_in(
                        child_as_cap, child_entry, frame_rsp, child_ep,
                    ) {
                        Ok(t) => t,
                        Err(_) => { reply_val(ep_cap, -ENOMEM); continue; }
                    };
                    let _ = sys::signal_entry(child_thread, vdso::SIGNAL_TRAMPOLINE_ADDR);

                    // CLONE_CHILD_SETTID: write the child's TID to *ctid in the child's AS.
                    // glibc passes ctid = &pthread.tid (in TLS). Without this, the child's
                    // TID field stays 0 (or parent's TID), causing glibc's atfork handlers
                    // to spin waiting for the TID to be set.
                    let ctid_ptr = msg.regs[3];
                    if flags & CLONE_CHILD_SETTID != 0 && ctid_ptr != 0 {
                        let tid_val = fork_cpid as u32;
                        let _ = sys::vm_write(child_as_cap, ctid_ptr,
                            &tid_val as *const u32 as u64, 4);
                    }
                    // CLONE_CHILD_CLEARTID: store ctid for exit cleanup
                    if flags & CLONE_CHILD_CLEARTID != 0 && ctid_ptr != 0 {
                        PROCESSES[fork_cpid - 1].clear_tid.store(ctid_ptr, Ordering::Release);
                    }
                    // CLONE_PARENT_SETTID: write child TID to *ptid in parent's AS
                    let ptid_ptr = msg.regs[2];
                    if flags & CLONE_PARENT_SETTID != 0 && ptid_ptr != 0 {
                        if parent_as != 0 {
                            let tid_val = fork_cpid as u32;
                            let _ = sys::vm_write(parent_as, ptid_ptr,
                                &tid_val as *const u32 as u64, 4);
                        } else {
                            unsafe { core::ptr::write_volatile(ptid_ptr as *mut u32, fork_cpid as u32); }
                        }
                    }

                    print(b"FK4 P"); print_u64(pid as u64); print(b"\n");

                    let cidx = fork_cpid - 1;
                    let pidx = pid - 1;
                    PROCESSES[cidx].parent.store(pid as u64, Ordering::Release);
                    proc_group_init(fork_cpid);

                    // Inherit personality from parent
                    PROCESSES[cidx].personality.store(
                        PROCESSES[pidx].personality.load(Ordering::Acquire),
                        Ordering::Release,
                    );

                    // Inherit brk/mmap state from parent (CoW fork shares same VA layout)
                    {
                        let pb = PROCESSES[pidx].brk_base.load(Ordering::Acquire);
                        let pc = PROCESSES[pidx].brk_current.load(Ordering::Acquire);
                        let pmb = PROCESSES[pidx].mmap_base.load(Ordering::Acquire);
                        let pmn = PROCESSES[pidx].mmap_next.load(Ordering::Acquire);
                        PROCESSES[cidx].brk_base.store(pb, Ordering::Release);
                        PROCESSES[cidx].brk_current.store(pc, Ordering::Release);
                        PROCESSES[cidx].mmap_base.store(pmb, Ordering::Release);
                        PROCESSES[cidx].mmap_next.store(pmn, Ordering::Release);
                    }

                    // Copy parent's VMA list to child (CoW fork inherits VA layout).
                    // Without this, child's find_free/overlaps checks see empty list
                    // and allocate over parent's existing mappings.
                    unsafe {
                        let src = &crate::vma::VMA_LISTS[memg];
                        let dst = &mut crate::vma::VMA_LISTS[cidx];
                        dst.count = src.count;
                        for i in 0..src.count {
                            dst.entries[i] = src.entries[i];
                        }
                    }

                    unsafe {
                        let parent = &THREAD_GROUPS[fdg];
                        THREAD_GROUPS[cidx].fds = parent.fds;
                        THREAD_GROUPS[cidx].fd_cloexec = parent.fd_cloexec;
                        THREAD_GROUPS[cidx].vfs = parent.vfs;
                        THREAD_GROUPS[cidx].initrd = parent.initrd;
                        THREAD_GROUPS[cidx].cwd = parent.cwd;
                        THREAD_GROUPS[cidx].sock_conn_id = parent.sock_conn_id;
                        THREAD_GROUPS[cidx].fd_flags = parent.fd_flags;
                    }

                    // Copy DIR_FD_PATHS from parent to child (inherited dir fds need paths for fchdir)
                    {
                        let parent_base = (pid - 1) * 8;
                        let child_base = cidx * 8;
                        for s in 0..8usize {
                            let ps = parent_base + s;
                            let cs = child_base + s;
                            if ps < MAX_DIR_SLOTS && cs < MAX_DIR_SLOTS {
                                unsafe { DIR_FD_PATHS[cs] = DIR_FD_PATHS[ps]; }
                            }
                        }
                    }

                    for cfd in 0..GRP_MAX_FDS {
                        let k = unsafe { THREAD_GROUPS[cidx].fds[cfd] };
                        let p = unsafe { THREAD_GROUPS[cidx].sock_conn_id[cfd] } as usize;
                        if k == 11 && p < MAX_PIPES { PIPE_WRITE_REFS[p].fetch_add(1, Ordering::AcqRel); }
                        else if k == 10 && p < MAX_PIPES { PIPE_READ_REFS[p].fetch_add(1, Ordering::AcqRel); }
                        if (k == 27 || k == 28) && p < crate::fd::MAX_UNIX_CONNS {
                            crate::fd::UNIX_CONN_REFS[p].fetch_add(1, Ordering::AcqRel);
                        }
                    }

                    unsafe {
                        FORK_FD_FLAGS = THREAD_GROUPS[fdg].fd_flags;
                        FORK_SOCK_CONN = THREAD_GROUPS[fdg].sock_conn_id;
                        FORK_SOCK_UDP_LPORT = THREAD_GROUPS[fdg].sock_udp_local_port;
                        FORK_SOCK_UDP_RIP = THREAD_GROUPS[fdg].sock_udp_remote_ip;
                        FORK_SOCK_UDP_RPORT = THREAD_GROUPS[fdg].sock_udp_remote_port;
                    }

                    print(b"FK5 P"); print_u64(pid as u64);
                    print(b" NCS="); crate::framebuffer::print_hex64(NEXT_CHILD_STACK.load(Ordering::Relaxed));
                    print(b"\n");
                    let handler_stack_base = NEXT_CHILD_STACK.fetch_add(0x20000, Ordering::SeqCst);
                    for hp in 0..32u64 {
                        if let Ok(f) = sys::frame_alloc() {
                            let _ = sys::map(handler_stack_base + hp * 0x1000, f, MAP_WRITABLE);
                        }
                    }
                    print(b"FK6 P"); print_u64(pid as u64); print(b"\n");

                    while CHILD_SETUP_READY.load(Ordering::Acquire) != 0 { sys::yield_now(); }
                    CHILD_SETUP_EP.store(child_ep, Ordering::Release);
                    CHILD_SETUP_PID.store(fork_cpid as u64, Ordering::Release);
                    CHILD_SETUP_FLAGS.store(0, Ordering::Release);
                    CHILD_SETUP_AS_CAP.store(child_as_cap, Ordering::Release);
                    FORK_SOCK_READY.store(1, Ordering::Release);
                    CHILD_SETUP_READY.store(1, Ordering::Release);
                    print(b"FK7 P"); print_u64(pid as u64); print(b"\n");

                    let _ = sys::thread_create(
                        child_handler as *const () as u64,
                        handler_stack_base + 0x20000,
                    );
                    print(b"FK8 P"); print_u64(pid as u64); print(b"\n");

                    while CHILD_SETUP_READY.load(Ordering::Acquire) != 0 { sys::yield_now(); }
                    print(b"FK9 P"); print_u64(pid as u64); print(b"\n");

                    PROCESSES[cidx].state.store(1, Ordering::Release);

                    print(b"FORK-REPLY P"); print_u64(pid as u64);
                    print(b" tid="); print_u64(parent_tid);
                    print(b" cpid="); print_u64(fork_cpid as u64);
                    print(b"\n");
                    reply_val(ep_cap, fork_cpid as i64);
                    continue;
                }

                let ptid_ptr = msg.regs[2];
                let ctid_ptr = msg.regs[3];
                let newtls = msg.regs[4];
                let fn_ptr = msg.regs[5]; // r9 = fn (from musl's __clone)

                // Allocate child PID
                let child_pid = NEXT_PID.fetch_add(1, Ordering::SeqCst) as usize;
                if child_pid > MAX_PROCS {
                    reply_val(ep_cap, -ENOMEM); // -ENOMEM
                    continue;
                }

                // Initialize thread group state based on clone flags
                PROCESSES[child_pid - 1].parent.store(pid as u64, Ordering::Release);
                proc_thread_init(child_pid, pid, flags);

                // CLONE_PARENT_SETTID: write child TID to *ptid
                if flags & CLONE_PARENT_SETTID != 0 && ptid_ptr != 0 {
                    unsafe { core::ptr::write_volatile(ptid_ptr as *mut u32, child_pid as u32); }
                }

                // CLONE_CHILD_CLEARTID: store ctid pointer for exit cleanup
                if flags & CLONE_CHILD_CLEARTID != 0 && ctid_ptr != 0 {
                    PROCESSES[child_pid - 1].clear_tid.store(ctid_ptr, Ordering::Release);
                }

                // Set up the child's stack for clone_child_trampoline:
                // Layout: [fn_ptr, arg, tls_ptr] (popped in order by trampoline)
                // musl __clone pushed arg at [child_stack], so read it first
                let arg = if child_stack != 0 {
                    unsafe { core::ptr::read_volatile(child_stack as *const u64) }
                } else {
                    0
                };
                let tls = if flags & CLONE_SETTLS != 0 { newtls } else { 0 };

                // Write trampoline setup below child_stack (stack grows down)
                let child_sp = child_stack - 24;
                unsafe {
                    core::ptr::write_volatile((child_sp) as *mut u64, fn_ptr);        // [rsp+0] → fn
                    core::ptr::write_volatile((child_sp + 8) as *mut u64, arg);       // [rsp+8] → arg
                    core::ptr::write_volatile((child_sp + 16) as *mut u64, tls);      // [rsp+16] → tls
                }

                // Allocate handler stack (32 pages = 128KB)
                let handler_stack_base = NEXT_CHILD_STACK.fetch_add(0x20000, Ordering::SeqCst);
                let mut hok = true;
                for hp in 0..32u64 {
                    let hf = match sys::frame_alloc() {
                        Ok(f) => f,
                        Err(_) => { hok = false; break; }
                    };
                    if sys::map(handler_stack_base + hp * 0x1000, hf, MAP_WRITABLE).is_err() {
                        hok = false; break;
                    }
                }
                if !hok {
                    reply_val(ep_cap, -ENOMEM);
                    continue;
                }

                // Create child endpoint
                let child_ep = match sys::endpoint_create() {
                    Ok(e) => e,
                    Err(_) => { reply_val(ep_cap, -ENOMEM); continue; }
                };

                // Pass setup info to child handler
                while CHILD_SETUP_READY.load(Ordering::Acquire) != 0 { sys::yield_now(); }
                CHILD_SETUP_EP.store(child_ep, Ordering::Release);
                CHILD_SETUP_PID.store(child_pid as u64, Ordering::Release);
                CHILD_SETUP_FLAGS.store(flags, Ordering::Release);
                CHILD_SETUP_AS_CAP.store(0, Ordering::Release);
                CHILD_SETUP_READY.store(1, Ordering::Release);

                // Spawn child handler thread
                if sys::thread_create(
                    child_handler as *const () as u64,
                    handler_stack_base + 0x20000,
                ).is_err() {
                    CHILD_SETUP_READY.store(0, Ordering::Release);
                    reply_val(ep_cap, -ENOMEM);
                    continue;
                }

                // Wait for child handler to consume setup
                while CHILD_SETUP_READY.load(Ordering::Acquire) != 0 {
                    sys::yield_now();
                }

                // Spawn child guest thread at clone_child_trampoline, redirected to child handler
                let child_thread = match sys::thread_create_redirected(
                    clone_child_trampoline as *const () as u64,
                    child_sp,
                    child_ep,
                ) {
                    Ok(t) => t,
                    Err(_) => { reply_val(ep_cap, -ENOMEM); continue; }
                };
                let _ = sys::signal_entry(child_thread, vdso::SIGNAL_TRAMPOLINE_ADDR);

                // Mark child as running
                PROCESSES[child_pid - 1].state.store(1, Ordering::Release);

                // Reply to parent with child TID
                reply_val(ep_cap, child_pid as i64);
            }

            // SYS_fork(57) / SYS_vfork(58) — real CoW fork via addr_space_clone
            // 1. Clone AS (all pages CoW)
            // 2. Build restore frame below fork_rsp (before clone, so child has it)
            // 3. Create child thread in cloned AS at COW_FORK_RESTORE trampoline
            // 4. Reply to parent with child_pid
            SYS_FORK | SYS_VFORK => {
                let fork_cpid = NEXT_PID.fetch_add(1, Ordering::SeqCst) as usize;
                if fork_cpid > MAX_PROCS {
                    reply_val(ep_cap, -ENOMEM);
                    continue;
                }

                // Determine source AS: parent's separate AS if non-zero, else init's AS
                let parent_as = child_as_cap; // outer scope: parent's own AS (0 = init's AS)
                let clone_source = if parent_as != 0 {
                    parent_as
                } else {
                    let cap = INIT_SELF_AS_CAP.load(Ordering::Acquire);
                    if cap == 0 {
                        print(b"FORK: no self_as_cap!\n");
                        reply_val(ep_cap, -ENOSYS);
                        continue;
                    }
                    cap
                };

                // Get parent's register state
                let parent_tid = msg.regs[6];
                let fork_rsp = msg.regs[7];
                let mut saved_regs = [0u64; 20];
                let _ = sys::get_thread_regs(parent_tid, &mut saved_regs);
                let fork_rip = saved_regs[2];   // RCX = user RIP after SYSCALL
                let fork_rbx = saved_regs[1];
                let fork_rbp = saved_regs[6];
                let fork_r12 = saved_regs[11];
                let fork_r13 = saved_regs[12];
                let fork_r14 = saved_regs[13];
                let fork_r15 = saved_regs[14];
                let fork_fsbase = saved_regs[16];
                let fork_gsbase = saved_regs[17];

                let frame_rsp = fork_rsp - 56;
                // Write fork frame (callee-saved regs) to parent's stack
                // NOTE: For parent_as != 0, the vm_write is deferred until AFTER
                // the eager stack page copy to avoid the copy overwriting the frame.
                if parent_as == 0 {
                    unsafe {
                        *((frame_rsp) as *mut u64) = fork_rbx;
                        *((frame_rsp + 8) as *mut u64) = fork_rbp;
                        *((frame_rsp + 16) as *mut u64) = fork_r12;
                        *((frame_rsp + 24) as *mut u64) = fork_r13;
                        *((frame_rsp + 32) as *mut u64) = fork_r14;
                        *((frame_rsp + 40) as *mut u64) = fork_r15;
                        *((frame_rsp + 48) as *mut u64) = fork_rip;
                    }
                }

                // Determine child entry point (trampoline needed if TLS/GS is set)
                let need_trampoline = fork_fsbase != 0 || fork_gsbase != 0;
                let child_entry = if need_trampoline {
                    vdso::FORK_TLS_TRAMPOLINE_ADDR
                } else {
                    vdso::COW_FORK_RESTORE_ADDR
                };

                // Write TLS/GS trampoline to parent BEFORE cloning ONLY for
                // init's own AS (parent_as == 0) where there is no CoW sharing.
                // For separate AS, we write to the CHILD's AS after clone_cow.
                if need_trampoline && parent_as == 0 {
                    vdso::write_fork_tls_trampoline(fork_fsbase, fork_gsbase);
                }

                // Clone the address space with CoW semantics
                let child_as_cap = match sys::addr_space_clone(clone_source) {
                    Ok(cap) => cap,
                    Err(_) => {
                        reply_val(ep_cap, -ENOMEM);
                        continue;
                    }
                };

                // For separate AS: write TLS trampoline to the CHILD's private
                // vDSO page (CoW-safe: allocates new frame, copies, writes).
                if need_trampoline && parent_as != 0 {
                    vdso::write_fork_tls_trampoline_in(child_as_cap, fork_fsbase, fork_gsbase);
                }

                // Fix glibc fork atfork list (same as SYS_CLONE path).
                if fork_rbx != 0 {
                    let head_addr = fork_rbx.wrapping_add(0x1088);
                    let _ = sys::vm_write(child_as_cap, 0,
                        &head_addr as *const u64 as u64, 8);
                    if head_addr > 0x10000 && head_addr < 0x0000_8000_0000_0000 {
                        let _ = sys::vm_write(child_as_cap, head_addr,
                            &head_addr as *const u64 as u64, 8);
                        let _ = sys::vm_write(child_as_cap, head_addr + 8,
                            &head_addr as *const u64 as u64, 8);
                    }
                }

                // Eagerly copy stack pages for the child.
                {
                    let base_page = frame_rsp & !0xFFF;
                    for i in 0..8u64 {
                        let pg = base_page + i * 0x1000;
                        if let Ok(nf) = sys::frame_alloc() {
                            if sys::frame_copy(nf, child_as_cap, pg).is_ok() {
                                let _ = sys::unmap_from(child_as_cap, pg);
                                let _ = sys::map_into(child_as_cap, pg, nf, 2);
                            }
                        }
                    }
                }

                // Write fork frame AFTER eager stack copy so it isn't overwritten.
                // (frame_copy copies the original pre-write content; vm_write then
                // writes the fork frame into the child's now-private stack page.)
                if parent_as != 0 {
                    let mut frame_data = [0u8; 56];
                    frame_data[0..8].copy_from_slice(&fork_rbx.to_le_bytes());
                    frame_data[8..16].copy_from_slice(&fork_rbp.to_le_bytes());
                    frame_data[16..24].copy_from_slice(&fork_r12.to_le_bytes());
                    frame_data[24..32].copy_from_slice(&fork_r13.to_le_bytes());
                    frame_data[32..40].copy_from_slice(&fork_r14.to_le_bytes());
                    frame_data[40..48].copy_from_slice(&fork_r15.to_le_bytes());
                    frame_data[48..56].copy_from_slice(&fork_rip.to_le_bytes());
                    let _ = sys::vm_write(child_as_cap, frame_rsp, frame_data.as_ptr() as u64, 56);
                }

                // Fix glibc fork spin: eagerly copy TLS page and patch TID.
                if fork_fsbase != 0 {
                    let tls_vaddr = fork_fsbase & !0xFFF;
                    if let Ok(nf) = sys::frame_alloc() {
                        if sys::frame_copy(nf, child_as_cap, tls_vaddr).is_ok() {
                            let _ = sys::unmap_from(child_as_cap, tls_vaddr);
                            let _ = sys::map_into(child_as_cap, tls_vaddr, nf, 2);
                            let tid_val = fork_cpid as u32;
                            let one: u32 = 1;
                            let _ = sys::vm_write(child_as_cap, fork_fsbase + 0x2D0,
                                &tid_val as *const u32 as u64, 4);
                            let _ = sys::vm_write(child_as_cap, fork_fsbase + 0x2D4,
                                &tid_val as *const u32 as u64, 4);
                            let _ = sys::vm_write(child_as_cap, fork_fsbase + 0x2E0,
                                &one as *const u32 as u64, 4);
                            print(b"TLS-FIX2 cpid="); print_u64(fork_cpid as u64); print(b"\n");
                        }
                    }
                    let tls_vaddr2 = (fork_fsbase & !0xFFF) + 0x1000;
                    if let Ok(nf2) = sys::frame_alloc() {
                        if sys::frame_copy(nf2, child_as_cap, tls_vaddr2).is_ok() {
                            let _ = sys::unmap_from(child_as_cap, tls_vaddr2);
                            let _ = sys::map_into(child_as_cap, tls_vaddr2, nf2, 2);
                        }
                    }
                }

                // Create endpoint for child process
                let child_ep = match sys::endpoint_create() {
                    Ok(e) => e,
                    Err(_) => { reply_val(ep_cap, -ENOMEM); continue; }
                };

                // Create child thread in the cloned AS at the TLS trampoline.
                let child_thread = match sys::thread_create_in(
                    child_as_cap,
                    child_entry,
                    frame_rsp,
                    child_ep,
                ) {
                    Ok(t) => t,
                    Err(_) => {
                        reply_val(ep_cap, -ENOMEM);
                        continue;
                    }
                };
                // Set signal trampoline for the child thread
                let _ = sys::signal_entry(child_thread, vdso::SIGNAL_TRAMPOLINE_ADDR);

                // Set up child process metadata
                let cidx = fork_cpid - 1;
                let pidx = pid - 1;
                PROCESSES[cidx].parent.store(pid as u64, Ordering::Release);
                PROCESSES[cidx].kernel_tid.store(0, Ordering::Release);
                proc_group_init(fork_cpid);

                // Inherit personality from parent
                PROCESSES[cidx].personality.store(
                    PROCESSES[pidx].personality.load(Ordering::Acquire),
                    Ordering::Release,
                );

                // Inherit brk/mmap state from parent (CoW fork shares same VA layout)
                {
                    let pb = PROCESSES[pidx].brk_base.load(Ordering::Acquire);
                    let pc = PROCESSES[pidx].brk_current.load(Ordering::Acquire);
                    let pmb = PROCESSES[pidx].mmap_base.load(Ordering::Acquire);
                    let pmn = PROCESSES[pidx].mmap_next.load(Ordering::Acquire);
                    PROCESSES[cidx].brk_base.store(pb, Ordering::Release);
                    PROCESSES[cidx].brk_current.store(pc, Ordering::Release);
                    PROCESSES[cidx].mmap_base.store(pmb, Ordering::Release);
                    PROCESSES[cidx].mmap_next.store(pmn, Ordering::Release);
                }

                // Copy parent's VMA list to child (CoW fork inherits VA layout).
                unsafe {
                    let src = &crate::vma::VMA_LISTS[memg];
                    let dst = &mut crate::vma::VMA_LISTS[cidx];
                    dst.count = src.count;
                    for i in 0..src.count {
                        dst.entries[i] = src.entries[i];
                    }
                }

                // Copy parent's FD state to child
                unsafe {
                    let parent = &THREAD_GROUPS[fdg];
                    THREAD_GROUPS[cidx].fds = parent.fds;
                    THREAD_GROUPS[cidx].fd_cloexec = parent.fd_cloexec;
                    THREAD_GROUPS[cidx].vfs = parent.vfs;
                    THREAD_GROUPS[cidx].initrd = parent.initrd;
                    THREAD_GROUPS[cidx].cwd = parent.cwd;
                    THREAD_GROUPS[cidx].sock_conn_id = parent.sock_conn_id;
                    THREAD_GROUPS[cidx].fd_flags = parent.fd_flags;
                }

                // Copy DIR_FD_PATHS from parent to child (inherited dir fds need paths for fchdir)
                {
                    let parent_base = pidx * 8;
                    let child_base = cidx * 8;
                    for s in 0..8usize {
                        let ps = parent_base + s;
                        let cs = child_base + s;
                        if ps < MAX_DIR_SLOTS && cs < MAX_DIR_SLOTS {
                            unsafe { DIR_FD_PATHS[cs] = DIR_FD_PATHS[ps]; }
                        }
                    }
                }

                // Increment pipe refcounts for fds inherited by child
                for cfd in 0..GRP_MAX_FDS {
                    let k = unsafe { THREAD_GROUPS[cidx].fds[cfd] };
                    let p = unsafe { THREAD_GROUPS[cidx].sock_conn_id[cfd] } as usize;
                    if k == 11 && p < MAX_PIPES {
                        PIPE_WRITE_REFS[p].fetch_add(1, Ordering::AcqRel);
                    } else if k == 10 && p < MAX_PIPES {
                        PIPE_READ_REFS[p].fetch_add(1, Ordering::AcqRel);
                    }
                }

                // Copy socket state for child handler
                unsafe {
                    FORK_FD_FLAGS = THREAD_GROUPS[fdg].fd_flags;
                    FORK_SOCK_CONN = THREAD_GROUPS[fdg].sock_conn_id;
                    FORK_SOCK_UDP_LPORT = THREAD_GROUPS[fdg].sock_udp_local_port;
                    FORK_SOCK_UDP_RIP = THREAD_GROUPS[fdg].sock_udp_remote_ip;
                    FORK_SOCK_UDP_RPORT = THREAD_GROUPS[fdg].sock_udp_remote_port;
                }

                // Allocate handler stack (32 pages = 128KB) for child handler thread
                let handler_stack_base = NEXT_CHILD_STACK.fetch_add(0x20000, Ordering::SeqCst);
                for hp in 0..32u64 {
                    if let Ok(f) = sys::frame_alloc() {
                        let _ = sys::map(handler_stack_base + hp * 0x1000, f, MAP_WRITABLE);
                    }
                }

                // Pass setup info to child handler
                while CHILD_SETUP_READY.load(Ordering::Acquire) != 0 { sys::yield_now(); }
                CHILD_SETUP_EP.store(child_ep, Ordering::Release);
                CHILD_SETUP_PID.store(fork_cpid as u64, Ordering::Release);
                CHILD_SETUP_FLAGS.store(0, Ordering::Release);
                CHILD_SETUP_AS_CAP.store(child_as_cap, Ordering::Release);
                FORK_SOCK_READY.store(1, Ordering::Release);
                CHILD_SETUP_READY.store(1, Ordering::Release);

                let _ = sys::thread_create(
                    child_handler as *const () as u64,
                    handler_stack_base + 0x20000,
                );

                while CHILD_SETUP_READY.load(Ordering::Acquire) != 0 { sys::yield_now(); }

                PROCESSES[cidx].state.store(1, Ordering::Release);

                // Reply to parent with child_pid (parent's RAX = child_pid)
                reply_val(ep_cap, fork_cpid as i64);
            }

            // SYS_wait4(61) — wait for child process
            SYS_WAIT4 => {
                let mut ctx = make_ctx!();
                syscalls_task::sys_wait4(&mut ctx, &msg);
            }

            // SYS_uname
            SYS_UNAME => {
                let mut ctx = make_ctx!();
                let buf_ptr = msg.regs[0];
                if buf_ptr != 0 && buf_ptr < 0x0000_8000_0000_0000 {
                    let mut buf = [0u8; 390];
                    let fields: [&[u8]; 5] = [b"Linux", b"sotos", b"6.1.0-sotOS", b"#1 SMP sotOS 0.1.0", b"x86_64"];
                    for (i, field) in fields.iter().enumerate() {
                        let off = i * 65;
                        let len = field.len().min(64);
                        buf[off..off + len].copy_from_slice(&field[..len]);
                    }
                    ctx.guest_write(buf_ptr, &buf);
                }
                reply_val(ep_cap, 0);
            }

            // SYS_fcntl
            SYS_FCNTL => {
                let mut ctx = make_ctx!();
                syscalls_fs::sys_fcntl(&mut ctx, &msg);
            }

            // SYS_getcwd
            SYS_GETCWD => {
                let mut ctx = make_ctx!();
                syscalls_fs::sys_getcwd(&mut ctx, &msg);
            }

            // SYS_fsync / SYS_fdatasync — flush (no-op, data is already persistent)
            SYS_FSYNC | SYS_FDATASYNC => {
                let mut ctx = make_ctx!();
                syscalls_fs::sys_fsync(&mut ctx, &msg);
            }

            // SYS_ftruncate(fd, length)
            SYS_FTRUNCATE => {
                let mut ctx = make_ctx!();
                syscalls_fs::sys_ftruncate(&mut ctx, &msg);
            }

            // SYS_rename(oldpath, newpath)
            SYS_RENAME => {
                let mut ctx = make_ctx!();
                syscalls_fs::sys_rename(&mut ctx, &msg);
            }

            // SYS_gettimeofday
            SYS_GETTIMEOFDAY => {
                let mut ctx = make_ctx!();
                syscalls_info::sys_gettimeofday(&mut ctx, &msg);
            }

            // SYS_sysinfo
            SYS_SYSINFO => {
                let mut ctx = make_ctx!();
                syscalls_info::sys_sysinfo(&mut ctx, &msg);
            }

            SYS_GETUID | SYS_GETGID | SYS_GETEUID | SYS_GETEGID => {
                let mut ctx = make_ctx!();
                syscalls_task::sys_getuid_family(&mut ctx, &msg);
            }

            // SYS_setpgid
            SYS_SETPGID => {
                let mut ctx = make_ctx!();
                syscalls_task::sys_setpgid(&mut ctx, &msg);
            }

            SYS_GETPPID => {
                let mut ctx = make_ctx!();
                syscalls_task::sys_getppid(&mut ctx, &msg);
            }

            // SYS_getpgrp
            SYS_GETPGRP => {
                let mut ctx = make_ctx!();
                syscalls_task::sys_getpgrp(&mut ctx, &msg);
            }

            // SYS_setsid
            SYS_SETSID => {
                let mut ctx = make_ctx!();
                syscalls_task::sys_setsid(&mut ctx, &msg);
            }

            // SYS_setfsuid / SYS_setfsgid — return previous (0)
            SYS_SETFSUID | SYS_SETFSGID => {
                let mut ctx = make_ctx!();
                syscalls_task::sys_setfsuid_family(&mut ctx, &msg);
            }

            // SYS_sigaltstack — stub
            SYS_SIGALTSTACK => {
                let mut ctx = make_ctx!();
                syscalls_signal::sys_sigaltstack(&mut ctx, &msg);
            }

            // SYS_openat — /dev files + initrd files + VFS files
            SYS_OPENAT => {
                if pid >= 6 {
                    print(b"CH-OA P"); crate::framebuffer::print_u64(pid as u64);
                    print(b" ptr="); crate::framebuffer::print_hex64(msg.regs[1]);
                    print(b"\n");
                }
                let mut ctx = make_ctx!();
                syscalls_fs::sys_openat(&mut ctx, &msg);
            }

            // SYS_set_tid_address — store clear_child_tid pointer, return TID
            SYS_SET_TID_ADDRESS => {
                let mut ctx = make_ctx!();
                syscalls_task::sys_set_tid_address(&mut ctx, &msg);
            }

            // SYS_clock_gettime
            SYS_CLOCK_GETTIME => {
                let mut ctx = make_ctx!();
                syscalls_info::sys_clock_gettime(&mut ctx, &msg);
            }

            // SYS_time(201)
            SYS_TIME => {
                let mut ctx = make_ctx!();
                syscalls_info::sys_time(&mut ctx, &msg);
            }

            // SYS_exit_group
            SYS_EXIT_GROUP => {
                let mut ctx = make_ctx!();
                if syscalls_task::sys_exit_group(&mut ctx, &msg).is_break() {
                    break;
                }
            }

            // SYS_fstatat(dirfd, path, statbuf, flags)
            SYS_FSTATAT => {
                let mut ctx = make_ctx!();
                syscalls_fs::sys_fstatat(&mut ctx, &msg);
            }

            // SYS_readlinkat(dirfd, path, buf, bufsiz)
            SYS_READLINKAT => {
                let mut ctx = make_ctx!();
                syscalls_fs::sys_readlinkat(&mut ctx, &msg);
            }

            // SYS_prlimit64
            SYS_PRLIMIT64 => {
                let mut ctx = make_ctx!();
                syscalls_info::sys_prlimit64(&mut ctx, &msg);
            }

            // SYS_getrandom
            SYS_GETRANDOM => {
                let mut ctx = make_ctx!();
                syscalls_info::sys_getrandom(&mut ctx, &msg);
            }

            // SYS_futex
            SYS_FUTEX => {
                let mut ctx = make_ctx!();
                syscalls_info::sys_futex(&mut ctx, &msg);
            }

            // SYS_sched_getaffinity
            SYS_SCHED_GETAFFINITY => {
                let mut ctx = make_ctx!();
                syscalls_info::sys_sched_getaffinity(&mut ctx, &msg);
            }

            // SYS_getdents64(fd, dirp, count)
            SYS_GETDENTS64 => {
                let mut ctx = make_ctx!();
                syscalls_fs::sys_getdents64(&mut ctx, &msg);
            }

            // SYS_fadvise64 — stub
            SYS_FADVISE64 => {
                let mut ctx = make_ctx!();
                syscalls_fs::sys_fadvise64(&mut ctx, &msg);
            }

            // SYS_ppoll — like poll but with signal mask
            SYS_PPOLL => {
                let mut ctx = make_ctx!();
                syscalls_net::sys_ppoll(&mut ctx, &msg);
            }

            // SYS_statx — musl 1.2.5+ uses this exclusively (no fstatat fallback)
            SYS_STATX => {
                let mut ctx = make_ctx!();
                syscalls_fs::sys_statx(&mut ctx, &msg);
            }

            // SYS_rseq — restartable sequences (musl may use)
            SYS_RSEQ => reply_val(ep_cap, -ENOSYS), // -ENOSYS is fine

            // SYS_SIGNAL_TRAMPOLINE (0x7F00) — async signal delivery
            0x7F00 => {
                let mut ctx = make_ctx!();
                if syscalls_signal::sys_signal_trampoline(&mut ctx, &msg).is_break() {
                    break;
                }
            }

            SYS_SOCKET => {
                let mut ctx = make_ctx!();
                syscalls_net::sys_socket(&mut ctx, &msg);
            }

            SYS_CONNECT => {
                let mut ctx = make_ctx!();
                syscalls_net::sys_connect(&mut ctx, &msg);
            }

            SYS_SENDTO => {
                let mut ctx = make_ctx!();
                syscalls_net::sys_sendto(&mut ctx, &msg);
            }

            SYS_SENDMSG => {
                let mut ctx = make_ctx!();
                syscalls_net::sys_sendmsg(&mut ctx, &msg);
            }

            SYS_RECVFROM => {
                let mut ctx = make_ctx!();
                syscalls_net::sys_recvfrom(&mut ctx, &msg);
            }

            SYS_RECVMSG => {
                let mut ctx = make_ctx!();
                syscalls_net::sys_recvmsg(&mut ctx, &msg);
            }

            SYS_BIND => {
                let mut ctx = make_ctx!();
                syscalls_net::sys_bind(&mut ctx, &msg);
            }
            SYS_LISTEN => {
                let mut ctx = make_ctx!();
                syscalls_net::sys_listen(&mut ctx, &msg);
            }
            SYS_SETSOCKOPT => {
                let mut ctx = make_ctx!();
                syscalls_net::sys_setsockopt(&mut ctx, &msg);
            }

            SYS_GETSOCKNAME | SYS_GETPEERNAME => {
                let mut ctx = make_ctx!();
                syscalls_net::sys_getsockname(&mut ctx, &msg, syscall_nr);
            }

            SYS_GETSOCKOPT => {
                let mut ctx = make_ctx!();
                syscalls_net::sys_getsockopt(&mut ctx, &msg);
            }

            SYS_SHUTDOWN => {
                let mut ctx = make_ctx!();
                syscalls_net::sys_shutdown(&mut ctx, &msg);
            }

            // SYS_chmod(90) — stub
            SYS_CHMOD => { let mut ctx = make_ctx!(); syscalls_info::sys_identity_stubs(&mut ctx, &msg); }

            // SYS_mkdir(83) — create directory in VFS
            SYS_MKDIR => {
                let mut ctx = make_ctx!();
                syscalls_fs::sys_mkdir(&mut ctx, &msg);
            }

            // SYS_select(23) / SYS_pselect6(270) — check readability/writability
            SYS_SELECT | SYS_PSELECT6 => {
                let mut ctx = make_ctx!();
                syscalls_net::sys_select(&mut ctx, &msg, syscall_nr);
            }

            // SYS_epoll_create1(291) — stub: return a fake FD
            SYS_EPOLL_CREATE1 => {
                let mut ctx = make_ctx!();
                syscalls_net::sys_epoll_create(&mut ctx, &msg);
            }

            // SYS_epoll_ctl(233) — stub: always succeed
            SYS_EPOLL_CTL => {
                let mut ctx = make_ctx!();
                syscalls_net::sys_epoll_ctl(&mut ctx, &msg);
            }

            // SYS_epoll_wait(232), SYS_epoll_pwait(281) — real fd tracking
            SYS_EPOLL_WAIT | SYS_EPOLL_PWAIT => {
                let mut ctx = make_ctx!();
                syscalls_net::sys_epoll_wait(&mut ctx, &msg);
            }

            // SYS_epoll_create(213) — old API, same as epoll_create1
            SYS_EPOLL_CREATE => {
                let mut ctx = make_ctx!();
                syscalls_net::sys_epoll_create(&mut ctx, &msg);
            }

            // SYS_pidfd_open(293) — stub: not supported
            SYS_PIPE2 => {
                let mut ctx = make_ctx!();
                syscalls_fs::sys_pipe2(&mut ctx, &msg);
            }

            // --- glibc compatibility stubs ---

            // SYS_set_robust_list(273) — glibc pthread robust mutex tracking
            SYS_SET_ROBUST_LIST => {
                let mut ctx = make_ctx!();
                syscalls_task::sys_set_robust_list(&mut ctx, &msg);
            }

            // SYS_get_robust_list(274)
            SYS_GET_ROBUST_LIST => {
                let mut ctx = make_ctx!();
                syscalls_task::sys_get_robust_list(&mut ctx, &msg);
            }

            // SYS_madvise(28) — memory advisory (MADV_DONTNEED zeros pages)
            SYS_MADVISE => { let mut ctx = make_ctx!(); syscalls_mm::sys_madvise(&mut ctx, &msg); }

            // SYS_sched_setaffinity(203) — stub
            SYS_SCHED_SETAFFINITY => { let mut ctx = make_ctx!(); syscalls_info::sys_identity_stubs(&mut ctx, &msg); }

            // SYS_sysinfo(99) — already handled above but add memory info
            // (already in match)

            // SYS_getrlimit(97) / SYS_setrlimit(160)
            SYS_GETRLIMIT => {
                let mut ctx = make_ctx!();
                syscalls_info::sys_getrlimit(&mut ctx, &msg);
            }
            SYS_SETRLIMIT => { let mut ctx = make_ctx!(); syscalls_info::sys_identity_stubs(&mut ctx, &msg); }


            // SYS_prctl(157)
            SYS_PRCTL => {
                let mut ctx = make_ctx!();
                syscalls_info::sys_prctl(&mut ctx, &msg);
            }


            // SYS_mremap(25) — delegated to syscalls::mm
            SYS_MREMAP => {
                let mut ctx = make_ctx!();
                syscalls_mm::sys_mremap(&mut ctx, &msg);
            }

            // ═══════════════════════════════════════════════════════════
            // Phase A–C: comprehensive Linux ABI for distro binaries + Wine
            // ═══════════════════════════════════════════════════════════

            // ─── Phase A: File operations ────────────────────────────

            // SYS_pwrite64(18) — write at offset (VFS)
            SYS_PWRITE64 => {
                let mut ctx = make_ctx!();
                syscalls_fs::sys_pwrite64(&mut ctx, &msg);
            }

            // SYS_readlink(89) — /proc/self/exe → /bin/program
            SYS_READLINK => {
                let mut ctx = make_ctx!();
                syscalls_fs::sys_readlink(&mut ctx, &msg);
            }

            // SYS_dup3(292) — dup with O_CLOEXEC
            SYS_DUP3 => {
                let mut ctx = make_ctx!();
                syscalls_fs::sys_dup3(&mut ctx, &msg);
            }

            // SYS_statfs(137) / SYS_fstatfs(138) — filesystem info
            SYS_STATFS | SYS_FSTATFS => {
                let mut ctx = make_ctx!();
                syscalls_fs::sys_statfs(&mut ctx, &msg, syscall_nr);
            }

            // SYS_creat(85) — redirect to open with O_CREAT|O_WRONLY|O_TRUNC
            SYS_CREAT => {
                let mut ctx = make_ctx!();
                syscalls_fs::sys_creat(&mut ctx, &msg);
            }

            // SYS_rmdir(84) — remove directory
            SYS_RMDIR => {
                let mut ctx = make_ctx!();
                syscalls_fs::sys_rmdir(&mut ctx, &msg);
            }

            // SYS_unlinkat(263) — unlink with dirfd
            // SYS_unlink(87) — delete file from VFS
            SYS_UNLINK => {
                let mut ctx = make_ctx!();
                syscalls_fs::sys_unlink(&mut ctx, &msg);
            }

            SYS_UNLINKAT => {
                let mut ctx = make_ctx!();
                syscalls_fs::sys_unlinkat(&mut ctx, &msg);
            }

            // SYS_renameat(264) / SYS_renameat2(316) — rename with dirfd
            SYS_RENAMEAT | SYS_RENAMEAT2 => {
                let mut ctx = make_ctx!();
                syscalls_fs::sys_renameat(&mut ctx, &msg);
            }

            // SYS_mkdirat(258) — mkdir with dirfd
            SYS_MKDIRAT => {
                let mut ctx = make_ctx!();
                syscalls_fs::sys_mkdirat(&mut ctx, &msg);
            }

            // SYS_preadv(295) — scatter read at offset
            SYS_PREADV => {
                let mut ctx = make_ctx!();
                syscalls_fs::sys_preadv(&mut ctx, &msg);
            }

            // SYS_pwritev(296) — scatter write at offset
            SYS_PWRITEV => {
                let mut ctx = make_ctx!();
                syscalls_fs::sys_pwritev(&mut ctx, &msg);
            }

            // SYS_copy_file_range(326) — copy between file descriptors
            SYS_COPY_FILE_RANGE => {
                let mut ctx = make_ctx!();
                syscalls_fs::sys_copy_file_range(&mut ctx, &msg);
            }

            // SYS_sendfile(40) — send file data to socket/fd
            SYS_SENDFILE => {
                let mut ctx = make_ctx!();
                syscalls_fs::sys_sendfile(&mut ctx, &msg);
            }

            // link/linkat — return -EPERM so callers (git) fall back to rename()
            SYS_LINK | SYS_LINKAT => {
                reply_val(ep_cap, -EPERM);
            }

            // SYS_SYMLINK(88) / SYS_SYMLINKAT(266): create symlink
            SYS_SYMLINK | SYS_SYMLINKAT => {
                let mut ctx = make_ctx!();
                // Read target and linkpath from guest memory
                let (target_ptr, linkpath_ptr) = if syscall_nr == SYS_SYMLINKAT {
                    (msg.regs[0], msg.regs[2]) // symlinkat(target, newdirfd, linkpath)
                } else {
                    (msg.regs[0], msg.regs[1]) // symlink(target, linkpath)
                };
                let mut target = [0u8; 128];
                let mut linkpath = [0u8; 128];
                if child_as_cap != 0 {
                    let _ = sys::vm_read(child_as_cap, target_ptr, target.as_mut_ptr() as u64, 128);
                    let _ = sys::vm_read(child_as_cap, linkpath_ptr, linkpath.as_mut_ptr() as u64, 128);
                } else {
                    unsafe {
                        core::ptr::copy_nonoverlapping(target_ptr as *const u8, target.as_mut_ptr(), 128);
                        core::ptr::copy_nonoverlapping(linkpath_ptr as *const u8, linkpath.as_mut_ptr(), 128);
                    }
                }
                let tlen = target.iter().position(|&b| b == 0).unwrap_or(127);
                let llen = linkpath.iter().position(|&b| b == 0).unwrap_or(127);
                // Resolve linkpath with CWD if relative
                let mut resolved = [0u8; 256];
                let rlen = crate::fd::resolve_with_cwd(&ctx.cwd, &linkpath[..llen], &mut resolved);
                crate::fd::symlink_register(&resolved[..rlen], &target[..tlen]);
                print(b"SYMLINK [");
                for &b in &resolved[..rlen] { if b >= 0x20 && b < 0x7F { sys::debug_print(b); } }
                print(b"] -> [");
                for &b in &target[..tlen] { if b >= 0x20 && b < 0x7F { sys::debug_print(b); } }
                print(b"]\n");
                reply_val(ep_cap, 0);
            }

            // File metadata stubs — return 0 (pretend success)
            SYS_FCHMOD | SYS_FCHOWN | SYS_LCHOWN
            | SYS_FLOCK | SYS_FALLOCATE | SYS_UTIMES
            | SYS_FCHMODAT | SYS_FCHOWNAT
            | SYS_UTIMENSAT | SYS_FUTIMESAT | SYS_MKNOD | SYS_MKNODAT
            => {
                let mut ctx = make_ctx!();
                syscalls_fs::sys_file_metadata_stubs(&mut ctx, &msg);
            }

            // SYS_umask(95)
            SYS_UMASK => {
                let mut ctx = make_ctx!();
                syscalls_fs::sys_umask(&mut ctx, &msg);
            }

            // SYS_faccessat2(439) — like faccessat
            SYS_FACCESSAT2 => {
                let mut ctx = make_ctx!();
                syscalls_fs::sys_faccessat2(&mut ctx, &msg);
            }

            // ─── Phase B: Process management & signals ───────────────

            // SYS_sched_yield(24)
            SYS_SCHED_YIELD => { let mut ctx = make_ctx!(); syscalls_info::sys_sched_yield(&mut ctx, &msg); }

            // SYS_waitid(247) — like wait4
            SYS_WAITID => {
                let mut ctx = make_ctx!();
                syscalls_task::sys_waitid(&mut ctx, &msg);
            }

            // SYS_getpgid(121) / SYS_getsid(124)
            SYS_GETPGID | SYS_GETSID => {
                let mut ctx = make_ctx!();
                syscalls_task::sys_getpgid(&mut ctx, &msg);
            }

            // SYS_tgkill(234)
            SYS_TGKILL => {
                let mut ctx = make_ctx!();
                syscalls_task::sys_tgkill(&mut ctx, &msg);
            }

            // SYS_clock_getres(229)
            SYS_CLOCK_GETRES => {
                let mut ctx = make_ctx!();
                syscalls_info::sys_clock_getres(&mut ctx, &msg);
            }

            // SYS_clock_nanosleep(230)
            SYS_CLOCK_NANOSLEEP => {
                let mut ctx = make_ctx!();
                syscalls_info::sys_clock_nanosleep(&mut ctx, &msg);
            }

            // SYS_getrusage(98)
            SYS_GETRUSAGE => {
                let mut ctx = make_ctx!();
                syscalls_info::sys_getrusage(&mut ctx, &msg);
            }

            // SYS_times(100)
            SYS_TIMES => {
                let mut ctx = make_ctx!();
                syscalls_info::sys_times(&mut ctx, &msg);
            }

            // SYS_rt_sigpending(127)
            SYS_RT_SIGPENDING => {
                let mut ctx = make_ctx!();
                syscalls_signal::sys_rt_sigpending(&mut ctx, &msg);
            }

            // SYS_rt_sigtimedwait(128)
            SYS_RT_SIGTIMEDWAIT => {
                let mut ctx = make_ctx!();
                syscalls_signal::sys_rt_sigtimedwait(&mut ctx, &msg);
            }

            // SYS_rt_sigsuspend(130)
            SYS_RT_SIGSUSPEND => {
                let mut ctx = make_ctx!();
                syscalls_signal::sys_rt_sigsuspend(&mut ctx, &msg);
            }

            // SYS_rt_sigqueueinfo(129)
            SYS_RT_SIGQUEUEINFO => {
                let mut ctx = make_ctx!();
                syscalls_signal::sys_rt_sigqueueinfo(&mut ctx, &msg);
            }

            // Identity stubs
            SYS_PERSONALITY | SYS_ALARM => { let mut ctx = make_ctx!(); syscalls_info::sys_identity_stubs(&mut ctx, &msg); }
            SYS_PAUSE => { let mut ctx = make_ctx!(); syscalls_info::sys_pause(&mut ctx, &msg); }
            SYS_SETUID | SYS_SETGID | SYS_SETREUID | SYS_SETREGID
            | SYS_SETRESUID | SYS_SETRESGID | SYS_SETGROUPS
            | SYS_CAPSET | SYS_UNSHARE | SYS_SETPRIORITY
            => { let mut ctx = make_ctx!(); syscalls_info::sys_identity_stubs(&mut ctx, &msg); }

            SYS_GETPRIORITY => reply_val(ep_cap, 20), // nice=0 encoded as 20
            SYS_GETGROUPS => reply_val(ep_cap, 0), // no supplementary groups

            SYS_GETRESUID | SYS_GETRESGID => {
                let mut ctx = make_ctx!();
                syscalls_info::sys_getresuid(&mut ctx, &msg);
            }
            SYS_CAPGET => {
                let mut ctx = make_ctx!();
                syscalls_info::sys_capget(&mut ctx, &msg);
            }

            // Scheduler stubs
            SYS_SCHED_GETPARAM => {
                let mut ctx = make_ctx!();
                syscalls_info::sys_sched_getparam(&mut ctx, &msg);
            }
            SYS_SCHED_SETSCHEDULER => { let mut ctx = make_ctx!(); syscalls_info::sys_identity_stubs(&mut ctx, &msg); }
            SYS_SCHED_GETSCHEDULER => { let mut ctx = make_ctx!(); syscalls_info::sys_identity_stubs(&mut ctx, &msg); }
            SYS_SCHED_GET_PRIORITY_MAX => reply_val(ep_cap, 99),
            SYS_SCHED_GET_PRIORITY_MIN => reply_val(ep_cap, 0),

            // Timer stubs
            SYS_GETITIMER => {
                let mut ctx = make_ctx!();
                syscalls_info::sys_getitimer(&mut ctx, &msg);
            }
            SYS_SETITIMER => {
                let mut ctx = make_ctx!();
                syscalls_info::sys_setitimer(&mut ctx, &msg);
            }

            // Memory stubs
            SYS_MSYNC => { let mut ctx = make_ctx!(); syscalls_info::sys_identity_stubs(&mut ctx, &msg); }
            SYS_MINCORE => reply_val(ep_cap, -ENOMEM),
            SYS_MLOCK | SYS_MUNLOCK | SYS_MLOCKALL | SYS_MUNLOCKALL => reply_val(ep_cap, 0),

            // AIO stubs (Wine probes these)
            SYS_IO_SETUP | SYS_IO_DESTROY | SYS_IO_GETEVENTS | SYS_IO_SUBMIT | SYS_IO_CANCEL => reply_val(ep_cap, 0),

            // SysV Shared Memory (real implementation for Wine)
            SYS_SHMGET => { let mut ctx = make_ctx!(); syscalls_mm::sys_shmget(&mut ctx, &msg); }
            SYS_SHMAT  => { let mut ctx = make_ctx!(); syscalls_mm::sys_shmat(&mut ctx, &msg); }
            SYS_SHMCTL => { let mut ctx = make_ctx!(); syscalls_mm::sys_shmctl(&mut ctx, &msg); }

            // SYS_chdir(80)
            SYS_CHDIR => {
                let mut ctx = make_ctx!();
                syscalls_fs::sys_chdir(&mut ctx, &msg);
            }

            // SYS_fchdir(81)
            81 => {
                print(b"FCHDIR-HIT P"); print_u64(pid as u64);
                print(b" fd="); print_u64(msg.regs[0]);
                print(b"\n");
                let mut ctx = make_ctx!();
                syscalls_fs::sys_fchdir(&mut ctx, &msg);
            }

            // ─── Phase C: Event subsystems (epoll, eventfd, timerfd) ─

            // SYS_eventfd(284) / SYS_eventfd2(290)
            SYS_EVENTFD | SYS_EVENTFD2 => {
                let mut ctx = make_ctx!();
                syscalls_info::sys_eventfd(&mut ctx, &msg, syscall_nr);
            }

            // SYS_timerfd_create(283)
            SYS_TIMERFD_CREATE => {
                let mut ctx = make_ctx!();
                syscalls_info::sys_timerfd_create(&mut ctx, &msg);
            }

            // SYS_timerfd_settime(286)
            SYS_TIMERFD_SETTIME => {
                let mut ctx = make_ctx!();
                syscalls_info::sys_timerfd_settime(&mut ctx, &msg);
            }

            // SYS_timerfd_gettime(287)
            SYS_TIMERFD_GETTIME => {
                let mut ctx = make_ctx!();
                syscalls_info::sys_timerfd_gettime(&mut ctx, &msg);
            }

            // Improved epoll: SYS_epoll_create/create1 (213/291) — already handled above
            // but now with proper fd tracking in epoll_reg_*

            // SYS_epoll_ctl(233) — register/modify/delete fd interest
            // (override the stub above)

            // SYS_epoll_wait(232) / SYS_epoll_pwait(281) — poll registered fds
            // (override the stub above)

            // SYS_socketpair(53) — create connected AF_UNIX pair
            SYS_SOCKETPAIR => {
                let mut ctx = make_ctx!();
                syscalls_net::sys_socketpair(&mut ctx, &msg);
            }

            // SYS_accept(43) / SYS_accept4(288)
            SYS_ACCEPT | SYS_ACCEPT4 => {
                let mut ctx = make_ctx!();
                syscalls_net::sys_accept(&mut ctx, &msg);
            }

            // SYS_memfd_create(319)
            SYS_MEMFD_CREATE => {
                let mut ctx = make_ctx!();
                syscalls_info::sys_memfd_create(&mut ctx, &msg);
            }

            // SYS_splice(275) / SYS_tee(276)
            SYS_SPLICE | SYS_TEE => reply_val(ep_cap, -ENOSYS),

            // SYS_inotify_init1(294) / SYS_inotify_add_watch(254) / SYS_inotify_rm_watch(255)
            SYS_INOTIFY_INIT1 => {
                let mut ctx = make_ctx!();
                syscalls_info::sys_inotify_init1(&mut ctx, &msg);
            }
            SYS_INOTIFY_ADD_WATCH => reply_val(ep_cap, 1),
            SYS_INOTIFY_RM_WATCH => reply_val(ep_cap, 0),

            // SYS_signalfd(282) / SYS_signalfd4(289)
            SYS_SIGNALFD | SYS_SIGNALFD4 => {
                let mut ctx = make_ctx!();
                syscalls_info::sys_signalfd(&mut ctx, &msg);
            }

            // SYS_clone3(435) — modern clone
            SYS_CLONE3 => {
                // Return -ENOSYS to force fallback to clone(56)
                reply_val(ep_cap, -ENOSYS);
            }

            // SYS_membarrier(324) — memory barrier (stub)
            324 => {
                reply_val(ep_cap, 0);
            }

            // Unknown → -ENOSYS (with logging)
            _ => {
                print(b"UNHANDLED pid=");
                print_u64(pid as u64);
                print(b" sys=");
                print_u64(syscall_nr);
                print(b" a0=");
                print_u64(msg.regs[0]);
                print(b"\n");
                reply_val(ep_cap, -ENOSYS);
            }
        }
    }

    // Child handler exiting (timeout or error). Clean up and mark as zombie.
    if pid > 0 && pid <= MAX_PROCS {
        // Decrement pipe refcounts for any still-open pipe FDs.
        // This is critical when a child crashes (page fault) without calling exit_cleanup.
        unsafe {
            let tg = &mut THREAD_GROUPS[fdg];
            for f in 0..GRP_MAX_FDS {
                let kind = tg.fds[f];
                if kind == 11 {
                    let pipe_id = tg.sock_conn_id[f] as usize;
                    if pipe_id < MAX_PIPES {
                        let prev = PIPE_WRITE_REFS[pipe_id].fetch_sub(1, Ordering::AcqRel);
                        if prev <= 1 {
                            crate::framebuffer::print(b"PWC-SET ch-exit pipe=");
                            crate::framebuffer::print_u64(pipe_id as u64);
                            crate::framebuffer::print(b" wrefs=");
                            crate::framebuffer::print_u64(prev);
                            crate::framebuffer::print(b"\n");
                            PIPE_WRITE_CLOSED[pipe_id].store(1, Ordering::Release);
                            if PIPE_READ_CLOSED[pipe_id].load(Ordering::Acquire) != 0 {
                                pipe_free(pipe_id);
                            }
                        }
                    }
                } else if kind == 10 {
                    let pipe_id = tg.sock_conn_id[f] as usize;
                    if pipe_id < MAX_PIPES {
                        let prev = PIPE_READ_REFS[pipe_id].fetch_sub(1, Ordering::AcqRel);
                        if prev <= 1 {
                            PIPE_READ_CLOSED[pipe_id].store(1, Ordering::Release);
                            if PIPE_WRITE_CLOSED[pipe_id].load(Ordering::Acquire) != 0 {
                                pipe_free(pipe_id);
                            }
                        }
                    }
                } else if kind == 27 || kind == 28 {
                    // AF_UNIX socket: mark connection as dead so the other
                    // end's epoll sees EPOLLHUP. Also close the underlying pipes.
                    let conn = tg.sock_conn_id[f] as usize;
                    if conn < crate::fd::MAX_UNIX_CONNS {
                        crate::fd::UNIX_CONN_ACTIVE[conn].store(0, Ordering::Release);
                        // Close the pipes backing this connection
                        let pipe_a = crate::fd::UNIX_CONN_PIPE_A[conn] as usize;
                        let pipe_b = crate::fd::UNIX_CONN_PIPE_B[conn] as usize;
                        if pipe_a < MAX_PIPES {
                            PIPE_WRITE_CLOSED[pipe_a].store(1, Ordering::Release);
                        }
                        if pipe_b < MAX_PIPES {
                            PIPE_WRITE_CLOSED[pipe_b].store(1, Ordering::Release);
                        }
                    }
                }
                tg.fds[f] = 0;
            }
        }
        // Free child stack pages
        let sbase = PROCESSES[pid - 1].stack_base.load(Ordering::Acquire);
        let spages = PROCESSES[pid - 1].stack_pages.load(Ordering::Acquire);
        if sbase != 0 && spages != 0 {
            for p in 0..spages { let _ = sys::unmap_free(sbase + p * 0x1000); }
            PROCESSES[pid - 1].stack_base.store(0, Ordering::Release);
            PROCESSES[pid - 1].stack_pages.store(0, Ordering::Release);
        }
        // Free ELF segment pages
        let elf_lo = PROCESSES[pid - 1].elf_lo.load(Ordering::Acquire);
        let elf_hi = PROCESSES[pid - 1].elf_hi.load(Ordering::Acquire);
        if elf_lo < elf_hi {
            let mut pg = elf_lo;
            while pg < elf_hi { let _ = sys::unmap_free(pg); pg += 0x1000; }
            PROCESSES[pid - 1].elf_lo.store(0, Ordering::Release);
            PROCESSES[pid - 1].elf_hi.store(0, Ordering::Release);
        }
        // Free interpreter pages if dynamic binary
        if PROCESSES[pid - 1].has_interp.load(Ordering::Acquire) != 0 {
            for pg in 0..0x110u64 {
                let _ = sys::unmap_free(crate::exec::INTERP_LOAD_BASE + pg * 0x1000);
            }
            PROCESSES[pid - 1].has_interp.store(0, Ordering::Release);
        }
        // Free pre-TLS page
        let _ = sys::unmap_free(0xB70000);
        // Free brk pages
        let brk_lo = PROCESSES[pid - 1].brk_base.load(Ordering::Acquire);
        let brk_hi = PROCESSES[pid - 1].brk_current.load(Ordering::Acquire);
        if brk_lo != 0 && brk_hi > brk_lo {
            let mut pg = brk_lo;
            while pg < brk_hi { let _ = sys::unmap_free(pg); pg += 0x1000; }
        }
        // Free mmap pages
        let mmap_lo = PROCESSES[pid - 1].mmap_base.load(Ordering::Acquire);
        let mmap_hi = PROCESSES[pid - 1].mmap_next.load(Ordering::Acquire);
        if mmap_lo != 0 && mmap_hi > mmap_lo {
            let mut pg = mmap_lo;
            while pg < mmap_hi { let _ = sys::unmap_free(pg); pg += 0x1000; }
        }
        PROCESSES[pid - 1].brk_base.store(0, Ordering::Release);
        PROCESSES[pid - 1].brk_current.store(0, Ordering::Release);
        PROCESSES[pid - 1].mmap_base.store(0, Ordering::Release);
        PROCESSES[pid - 1].mmap_next.store(0, Ordering::Release);
        // Reset group state
        unsafe { THREAD_GROUPS[memg].brk = 0; THREAD_GROUPS[memg].mmap_next = 0; }
        // Only mark as zombie if exit_cleanup hasn't already run.
        // exit_cleanup (from SYS_EXIT/EXIT_GROUP) stores exit_code + state=2.
        // If we overwrite here, we clobber the correct exit code with 9 (SIGKILL),
        // causing parents' wait4 to see the wrong status.
        if PROCESSES[pid - 1].state.load(Ordering::Acquire) != 2 {
            PROCESSES[pid - 1].exit_code.store(9, Ordering::Release);
            PROCESSES[pid - 1].state.store(2, Ordering::Release);
            // Deliver SIGCHLD to parent
            let ppid = PROCESSES[pid - 1].parent.load(Ordering::Acquire) as usize;
            if ppid > 0 && ppid <= MAX_PROCS {
                sig_send(ppid, SIGCHLD as u64);
            }
        }
    }
    sys::thread_exit();
}
