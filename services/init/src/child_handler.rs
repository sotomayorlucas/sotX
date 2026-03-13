// ---------------------------------------------------------------------------
// child_handler: Full-featured handler for child processes.
// Extracted from main.rs.
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

const MAP_WRITABLE: u64 = 2;

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

/// Stack region save buffer for fork — child runs on parent's stack and corrupts
/// caller frames + envp strings in the setup area above initial RSP.
/// 32KB covers deep call chains (git clone → transport → start_command → fork).
const FORK_STACK_SAVE_SIZE: usize = 32768;
static mut FORK_STACK_BUF: [[u8; FORK_STACK_SAVE_SIZE]; MAX_PROCS] = [[0u8; FORK_STACK_SAVE_SIZE]; MAX_PROCS];

/// Heap (brk region) save buffer for fork — vfork child's malloc/setenv/etc.
/// modify the parent's brk heap in-place (free-list metadata, environ array).
/// We save up to 128KB of brk pages and restore after fork-child phase.
const FORK_HEAP_SAVE_SIZE: usize = 131072;
static mut FORK_HEAP_BUF: [[u8; FORK_HEAP_SAVE_SIZE]; MAX_PROCS] = [[0u8; FORK_HEAP_SAVE_SIZE]; MAX_PROCS];
static mut FORK_HEAP_USED: [usize; MAX_PROCS] = [0; MAX_PROCS];

/// Read a u64 from either saved FORK_STACK_BUF or live memory.
/// When the address falls within the saved [fork_rsp, fork_rsp + SAVE_SIZE) range,
/// reads from the pre-corruption snapshot in FORK_STACK_BUF.
#[inline]
unsafe fn read_u64_saved(addr: u64, fork_rsp: u64, pid: usize) -> u64 {
    let off = addr.wrapping_sub(fork_rsp) as usize;
    if off + 8 <= FORK_STACK_SAVE_SIZE {
        let ptr = FORK_STACK_BUF[pid - 1].as_ptr().add(off) as *const u64;
        core::ptr::read_unaligned(ptr)
    } else {
        *(addr as *const u64)
    }
}

/// Copy a null-terminated string from either saved FORK_STACK_BUF or live memory.
/// String bytes within [fork_rsp, fork_rsp + SAVE_SIZE) come from the saved snapshot.
#[inline]
unsafe fn copy_guest_path_saved(guest_ptr: u64, out: &mut [u8], fork_rsp: u64, pid: usize) -> usize {
    let max = out.len() - 1;
    let mut i = 0;
    while i < max {
        let addr = guest_ptr + i as u64;
        let off = addr.wrapping_sub(fork_rsp) as usize;
        let b = if off < FORK_STACK_SAVE_SIZE {
            FORK_STACK_BUF[pid - 1][off]
        } else {
            *(addr as *const u8)
        };
        if b == 0 { break; }
        out[i] = b;
        i += 1;
    }
    out[i] = 0;
    i
}

/// Open a virtual file (/etc/*, /proc/*, /sys/*). Returns Some(content_len) or None.
pub(crate) fn open_virtual_file(name: &[u8], dir_buf: &mut [u8]) -> Option<usize> {
    if starts_with(name, b"/etc/") {
        let gen_len: usize;
        if name == b"/etc/nanorc" {
            let c = b"set nohelp\nset nonewlines\n";
            dir_buf[..c.len()].copy_from_slice(c);
            gen_len = c.len();
        } else if name == b"/etc/resolv.conf" {
            let c = b"nameserver 10.0.2.3\n";
            dir_buf[..c.len()].copy_from_slice(c);
            gen_len = c.len();
        } else if name == b"/etc/hosts" {
            let c = b"127.0.0.1 localhost\n::1 localhost\n";
            dir_buf[..c.len()].copy_from_slice(c);
            gen_len = c.len();
        } else if name == b"/etc/nsswitch.conf" {
            let c = b"hosts: files dns\n";
            dir_buf[..c.len()].copy_from_slice(c);
            gen_len = c.len();
        } else if name == b"/etc/ld.so.cache" {
            return None;
        } else if name == b"/etc/ld.so.preload" {
            gen_len = 0;
        } else if name == b"/etc/passwd" {
            let c = b"root:x:0:0:root:/root:/bin/sh\nnobody:x:65534:65534:nobody:/:/usr/bin/nologin\n";
            let n = c.len().min(dir_buf.len());
            dir_buf[..n].copy_from_slice(&c[..n]);
            gen_len = n;
        } else if name == b"/etc/group" {
            let c = b"root:x:0:\nnogroup:x:65534:\n";
            let n = c.len().min(dir_buf.len());
            dir_buf[..n].copy_from_slice(&c[..n]);
            gen_len = n;
        } else if name == b"/etc/gai.conf" || name == b"/etc/host.conf"
               || name == b"/etc/services" || name == b"/etc/protocols"
               || name == b"/etc/shells" || name == b"/etc/inputrc"
               || name == b"/etc/terminfo" || name == b"/etc/mime.types"
               || name == b"/etc/localtime" || name == b"/etc/locale.alias" {
            gen_len = 0;
        } else {
            return None;
        }
        Some(gen_len)
    } else if starts_with(name, b"/proc/") || starts_with(name, b"/sys/") {
        let gen_len: usize;
        if name == b"/proc/self/maps" || name == b"/proc/self/smaps" {
            // Dynamic VMA-based output (pid is not available here, use group 0)
            gen_len = crate::syscalls::mm::format_proc_maps(0, dir_buf);
        } else if name == b"/proc/cpuinfo" {
            let info = b"processor\t: 0\nvendor_id\t: GenuineIntel\ncpu family\t: 6\nmodel name\t: QEMU Virtual CPU\ncache size\t: 4096 KB\nflags\t\t: fpu sse sse2 ssse3 sse4_1 sse4_2 rdtsc\n\n";
            let n = info.len().min(dir_buf.len());
            dir_buf[..n].copy_from_slice(&info[..n]);
            gen_len = n;
        } else if name == b"/proc/meminfo" {
            let info = b"MemTotal:       262144 kB\nMemFree:        131072 kB\nMemAvailable:   196608 kB\nBuffers:         8192 kB\nCached:         32768 kB\n";
            let n = info.len().min(dir_buf.len());
            dir_buf[..n].copy_from_slice(&info[..n]);
            gen_len = n;
        } else if name == b"/proc/version" {
            let info = b"Linux version 5.15.0-sotOS (root@sotOS) (gcc 12.0) #1 SMP PREEMPT\n";
            let n = info.len().min(dir_buf.len());
            dir_buf[..n].copy_from_slice(&info[..n]);
            gen_len = n;
        } else if name == b"/proc/self/exe" {
            gen_len = 0;
        } else if name == b"/sys/devices/system/cpu/online" {
            let c = b"0\n";
            dir_buf[..c.len()].copy_from_slice(c);
            gen_len = c.len();
        } else {
            return None;
        }
        Some(gen_len)
    } else {
        None
    }
}

/// CSPRNG: ChaCha20-based, seeded from RDTSC.
pub(crate) fn fill_random(buf: &mut [u8]) {
    use rand_core::{RngCore, SeedableRng};
    use rand_chacha::ChaCha20Rng;
    static mut RNG: Option<ChaCha20Rng> = None;
    unsafe {
        if RNG.is_none() {
            let mut seed = [0u8; 32];
            let tsc = rdtsc();
            seed[0..8].copy_from_slice(&tsc.to_le_bytes());
            let tsc2 = rdtsc();
            seed[8..16].copy_from_slice(&tsc2.to_le_bytes());
            let tsc3 = rdtsc();
            seed[16..24].copy_from_slice(&tsc3.to_le_bytes());
            RNG = Some(ChaCha20Rng::from_seed(seed));
        }
        RNG.as_mut().unwrap().fill_bytes(buf);
    }
}

/// Trampoline for clone(CLONE_THREAD) child threads.
/// Stack layout set up by the handler: [fn_ptr, arg, tls_ptr] (growing upward from RSP).
/// Calls arch_prctl(SET_FS, tls) if tls != 0, then calls fn(arg), then exit.
#[unsafe(no_mangle)]
#[unsafe(naked)]
pub(crate) unsafe extern "C" fn clone_child_trampoline() -> ! {
    core::arch::naked_asm!(
        "pop rsi",              // fn_ptr
        "pop rdi",              // arg
        "pop rdx",              // tls_ptr (0 if no CLONE_SETTLS)
        "test rdx, rdx",
        "jz 2f",
        // arch_prctl(ARCH_SET_FS, tls) — intercepted by kernel before redirect
        "push rsi",
        "push rdi",
        "mov rdi, 0x1002",      // ARCH_SET_FS
        "mov rsi, rdx",
        "mov rax, 158",         // SYS_arch_prctl
        "syscall",
        "pop rdi",
        "pop rsi",
        "2:",
        "xor ebp, ebp",
        "call rsi",             // fn(arg)
        "mov edi, eax",         // exit status = fn return value
        "mov eax, 60",          // SYS_exit
        "syscall",
        "ud2",
    );
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
    let clone_flags = CHILD_SETUP_FLAGS.load(Ordering::Acquire);
    let mut child_as_cap = CHILD_SETUP_AS_CAP.load(Ordering::Acquire);
    // Signal that we consumed the setup
    CHILD_SETUP_READY.store(0, Ordering::Release);

    // Resolve group indices for this thread
    let fdg = PROCESSES[pid - 1].fd_group.load(Ordering::Acquire) as usize;
    let memg = PROCESSES[pid - 1].mem_group.load(Ordering::Acquire) as usize;
    let _sigg = PROCESSES[pid - 1].sig_group.load(Ordering::Acquire) as usize;

    // Per-child brk/mmap state. Each memory group gets its own region.
    const CHILD_REGION_SIZE: u64 = 0x4000000; // 64 MiB per child (brk + mmap)
    const CHILD_BRK_BASE: u64 = 0x7000000;
    const CHILD_MMAP_OFFSET: u64 = 0x1000000; // mmap starts 16 MiB into the region
    // Initrd file buffers: separate region well above brk/mmap
    // 64 children × 64 MiB = 4 GiB → ends at 0x107000000.
    // Virtual addresses: pages are demand-allocated from physical RAM.
    const INITRD_BUF_REGION: u64 = 0x110000000;
    const INITRD_BUF_PER_GROUP: u64 = 8 * 0x300000; // 24 MiB

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
    macro_rules! make_ctx {
        () => {
            unsafe {
                let tg = &mut THREAD_GROUPS[fdg];
                let initrd_buf_base = THREAD_GROUPS[memg].initrd_buf_base;
                SyscallContext {
                    pid, ep_cap, child_as_cap,
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
        }
    }

    loop {
        // Use recv_timeout (50000 ticks) to detect hung children.
        // Wine's double-fork + CoW causes many VMM faults before next syscall.
        let msg = match sys::recv_timeout(ep_cap, 50000) {
            Ok(m) => m,
            Err(e) => {
                print(b"HANDLER-ERR P"); print_u64(pid as u64);
                print(b" e="); print_u64(e as u64);
                print(b"\n");
                break;
            },
        };

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
        // Clear retry state before dispatch. If the handler sends
        // PIPE_RETRY_TAG it will re-increment via mark_pipe_retry().
        clear_pipe_retry(pid);

        // Trace syscalls from separate-AS children (per-AS exec)
        // Suppress high-frequency syscalls that flood serial during Wine startup
        if (child_as_cap != 0 || pid == 3 || pid == 5)
           && syscall_nr != 0  // read
           && syscall_nr != 1  // write
           && syscall_nr != 3  // close
           && syscall_nr != 7  // poll
           && syscall_nr != 9  // mmap (has its own MMAP log)
           && syscall_nr != 14 // rt_sigprocmask
           && syscall_nr != 17 // pread64
           && syscall_nr != 20 // writev
           && syscall_nr != 47 // recvmsg
           && syscall_nr != 232 // epoll_wait
           && syscall_nr != 257 // openat (has OPENAT log)
           && syscall_nr != 262 // fstatat (has FSTATAT log)
           && syscall_nr != 281 // epoll_pwait
        {
            print(b"AS-SYS P"); print_u64(pid as u64);
            print(b" #"); print_u64(syscall_nr);
            print(b" a0="); crate::framebuffer::print_hex64(msg.regs[0]);
            print(b" a1="); crate::framebuffer::print_hex64(msg.regs[1]);
            print(b"\n");
        }

        match syscall_nr {
            // SYS_read(fd, buf, len)
            SYS_READ => {
                let mut ctx = make_ctx!();
                syscalls_fs::sys_read(&mut ctx, &msg);
            }

            // SYS_write(fd, buf, len)
            SYS_WRITE => {
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
                                              LAST_EXEC_ELF_LO, LAST_EXEC_ELF_HI, LAST_EXEC_HAS_INTERP};
                            PROCESSES[pid - 1].stack_base.store(LAST_EXEC_STACK_BASE.load(Ordering::Acquire), Ordering::Release);
                            PROCESSES[pid - 1].stack_pages.store(LAST_EXEC_STACK_PAGES.load(Ordering::Acquire), Ordering::Release);
                            PROCESSES[pid - 1].elf_lo.store(LAST_EXEC_ELF_LO.load(Ordering::Acquire), Ordering::Release);
                            PROCESSES[pid - 1].elf_hi.store(LAST_EXEC_ELF_HI.load(Ordering::Acquire), Ordering::Release);
                            PROCESSES[pid - 1].has_interp.store(LAST_EXEC_HAS_INTERP.load(Ordering::Acquire), Ordering::Release);
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

                        EXEC_LOCK.store(0, Ordering::Release);
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

                    let frame_rsp = fork_rsp - 56;
                    // Write fork frame (callee-saved regs) to parent's stack
                    if parent_as != 0 {
                        let mut frame_data = [0u8; 56];
                        frame_data[0..8].copy_from_slice(&fork_rbx.to_le_bytes());
                        frame_data[8..16].copy_from_slice(&fork_rbp.to_le_bytes());
                        frame_data[16..24].copy_from_slice(&fork_r12.to_le_bytes());
                        frame_data[24..32].copy_from_slice(&fork_r13.to_le_bytes());
                        frame_data[32..40].copy_from_slice(&fork_r14.to_le_bytes());
                        frame_data[40..48].copy_from_slice(&fork_r15.to_le_bytes());
                        frame_data[48..56].copy_from_slice(&fork_rip.to_le_bytes());
                        let _ = sys::vm_write(parent_as, frame_rsp, frame_data.as_ptr() as u64, 56);
                    } else {
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

                    // Write TLS/GS trampoline before cloning (child sees it in CoW copy)
                    let need_trampoline = fork_fsbase != 0 || fork_gsbase != 0;
                    if need_trampoline {
                        if parent_as != 0 {
                            vdso::write_fork_tls_trampoline_in(parent_as, fork_fsbase, fork_gsbase);
                        } else {
                            vdso::write_fork_tls_trampoline(fork_fsbase, fork_gsbase);
                        }
                    }
                    let child_entry = if need_trampoline {
                        vdso::FORK_TLS_TRAMPOLINE_ADDR
                    } else {
                        vdso::COW_FORK_RESTORE_ADDR
                    };

                    print(b"FK1 P"); print_u64(pid as u64); print(b"\n");
                    // Diagnostic: check PTE at 0x10428000 before clone_cow
                    if clone_source != 0 {
                        if let Ok((phys, fl)) = sys::pte_read(clone_source, 0x10428000) {
                            print(b"FK-PTE-B p="); crate::framebuffer::print_hex64(phys);
                            print(b" f="); crate::framebuffer::print_hex64(fl); print(b"\n");
                        } else { print(b"FK-PTE-B ABSENT\n"); }
                    }
                    let child_as_cap = match sys::addr_space_clone(clone_source) {
                        Ok(cap) => cap,
                        Err(_) => { reply_val(ep_cap, -ENOMEM); continue; }
                    };
                    // Diagnostic: check PTE at 0x10428000 after clone_cow
                    if clone_source != 0 {
                        if let Ok((phys, fl)) = sys::pte_read(clone_source, 0x10428000) {
                            print(b"FK-PTE-A p="); crate::framebuffer::print_hex64(phys);
                            print(b" f="); crate::framebuffer::print_hex64(fl); print(b"\n");
                        } else { print(b"FK-PTE-A ABSENT\n"); }
                    }
                    print(b"FK2 P"); print_u64(pid as u64); print(b"\n");

                    // Eagerly copy stack pages for child (8 pages upward)
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
                    print(b"FK4 P"); print_u64(pid as u64); print(b"\n");

                    let cidx = fork_cpid - 1;
                    PROCESSES[cidx].parent.store(pid as u64, Ordering::Release);
                    proc_group_init(fork_cpid);

                    // Inherit brk/mmap state from parent (CoW fork shares same VA layout)
                    {
                        let pidx = pid - 1;
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
                if parent_as != 0 {
                    let mut frame_data = [0u8; 56];
                    frame_data[0..8].copy_from_slice(&fork_rbx.to_le_bytes());
                    frame_data[8..16].copy_from_slice(&fork_rbp.to_le_bytes());
                    frame_data[16..24].copy_from_slice(&fork_r12.to_le_bytes());
                    frame_data[24..32].copy_from_slice(&fork_r13.to_le_bytes());
                    frame_data[32..40].copy_from_slice(&fork_r14.to_le_bytes());
                    frame_data[40..48].copy_from_slice(&fork_r15.to_le_bytes());
                    frame_data[48..56].copy_from_slice(&fork_rip.to_le_bytes());
                    let _ = sys::vm_write(parent_as, frame_rsp, frame_data.as_ptr() as u64, 56);
                } else {
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

                // Write TLS/GS trampoline that sets FS_BASE and GS_BASE BEFORE the child
                // touches any TLS-dependent or GS-dependent code.
                let need_trampoline = fork_fsbase != 0 || fork_gsbase != 0;
                if need_trampoline {
                    if parent_as != 0 {
                        vdso::write_fork_tls_trampoline_in(parent_as, fork_fsbase, fork_gsbase);
                    } else {
                        vdso::write_fork_tls_trampoline(fork_fsbase, fork_gsbase);
                    }
                }
                let child_entry = if need_trampoline {
                    vdso::FORK_TLS_TRAMPOLINE_ADDR
                } else {
                    vdso::COW_FORK_RESTORE_ADDR
                };

                // Clone the address space with CoW semantics
                // Diagnostic: check PTE at 0x10428000 before clone_cow
                if clone_source != 0 {
                    if let Ok((phys, fl)) = sys::pte_read(clone_source, 0x10428000) {
                        print(b"FK-PTE-B p="); crate::framebuffer::print_hex64(phys);
                        print(b" f="); crate::framebuffer::print_hex64(fl); print(b"\n");
                    } else { print(b"FK-PTE-B ABSENT\n"); }
                }
                let child_as_cap = match sys::addr_space_clone(clone_source) {
                    Ok(cap) => cap,
                    Err(_) => {
                        reply_val(ep_cap, -ENOMEM);
                        continue;
                    }
                };
                // Diagnostic: check PTE at 0x10428000 after clone_cow
                if clone_source != 0 {
                    if let Ok((phys, fl)) = sys::pte_read(clone_source, 0x10428000) {
                        print(b"FK-PTE-A p="); crate::framebuffer::print_hex64(phys);
                        print(b" f="); crate::framebuffer::print_hex64(fl); print(b"\n");
                    } else { print(b"FK-PTE-A ABSENT\n"); }
                }

                // Eagerly copy stack pages for the child so the parent can't
                // corrupt them (parent PTEs stay writable in this CoW model).
                // Copy 8 pages starting from restore frame page going upward
                // to cover the entire call chain (fork → git's run_command).
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

                // Create endpoint for child process
                let child_ep = match sys::endpoint_create() {
                    Ok(e) => e,
                    Err(_) => { reply_val(ep_cap, -ENOMEM); continue; }
                };

                // Create child thread in the cloned AS at the TLS trampoline.
                // The trampoline sets FS_BASE via syscall, then jumps to COW_FORK_RESTORE
                // which does xor eax + pop regs + ret to fork_rip.
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
                PROCESSES[cidx].parent.store(pid as u64, Ordering::Release);
                PROCESSES[cidx].kernel_tid.store(0, Ordering::Release);
                proc_group_init(fork_cpid);

                // Inherit brk/mmap state from parent (CoW fork shares same VA layout)
                {
                    let pidx = pid - 1;
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

            // SYS_statx — not supported, force musl to fall back to fstatat
            SYS_STATX => reply_val(ep_cap, -ENOSYS), // -ENOSYS

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

            // SYS_madvise(28) — memory advisory (glibc malloc)
            SYS_MADVISE => { let mut ctx = make_ctx!(); syscalls_info::sys_identity_stubs(&mut ctx, &msg); }

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

            // File metadata stubs — return 0 (pretend success)
            SYS_SYMLINK | SYS_FCHMOD | SYS_FCHOWN | SYS_LCHOWN
            | SYS_FLOCK | SYS_FALLOCATE | SYS_UTIMES
            | SYS_SYMLINKAT | SYS_FCHMODAT | SYS_FCHOWNAT
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

            // Shared memory stubs (SysV IPC)
            SYS_SHMGET | SYS_SHMAT | SYS_SHMCTL => reply_val(ep_cap, -ENOSYS),

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
