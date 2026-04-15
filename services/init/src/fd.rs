// ---------------------------------------------------------------------------
// FD table types, group management, and related helpers (extracted from main.rs)
//
// NOTE on `static mut` (fase 2 continuation):
//   Most `static mut` here are multi-dim byte buffers (PIPE_BUF, UNIX_PENDING,
//   SYMLINK_PATH/TARGET, DIR_FD_PATHS, MSG_QUEUE, SCM_FDS_*) or struct arrays
//   (THREAD_GROUPS) that cannot become atomics without a wrapper. They are
//   safe in practice under a single-writer-per-slot invariant (each pid has
//   exactly one handler thread). A future refactor will wrap them in
//   `sotos_common::spinlock::SpinLock<T>` or an UnsafeCell + Sync newtype
//   to satisfy Rust 2024 strict rules without per-element atomics.
//   Primitive counters (SYMLINK_COUNT, FORK_SOCK_READY, PIPE_WRITE_REFS,
//   PIPE_READ_REFS, UNIX_CONN_REFS) are already atomic.
// ---------------------------------------------------------------------------

use sotos_common::sys;
use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use crate::process::MAX_PROCS;

// ---------------------------------------------------------------------------
// LUCAS FD table types (Phase 10.4)
// ---------------------------------------------------------------------------

#[repr(u8)]
#[derive(Clone, Copy, PartialEq)]
pub(crate) enum FdKind {
    Free = 0,
    Stdin = 1,
    Stdout = 2,
    VfsFile = 3,
    DirList = 4,
    Socket = 5,      // TCP socket
    PipeRead = 6,
    PipeWrite = 7,
    SocketUdp = 8,   // UDP socket
    EpollFd = 9,     // epoll instance
    DevUrandom = 10, // /dev/urandom, /dev/random
    DevZero = 11,    // /dev/zero
    // 12=initrd file, 13=VFS file, 14=VFS dir, 15=virtual file,
    // 16=TCP socket, 17=UDP socket, 20=DevUrandom, 21=epoll,
    // 22=eventfd, 23=timerfd, 25=memfd, 26=UnixSocket (AF_UNIX)
}

#[derive(Clone, Copy)]
pub(crate) struct FdEntry {
    pub(crate) kind: FdKind,
    pub(crate) vfs_fd: u32,
    /// For Socket/SocketUdp FDs: connection/socket ID in the net service.
    pub(crate) net_conn_id: u32,
    /// For SocketUdp: local port, remote IP, remote port (set by connect/sendto).
    pub(crate) udp_local_port: u16,
    pub(crate) udp_remote_ip: u32,
    pub(crate) udp_remote_port: u16,
    /// For EpollFd: index into epoll table.
    pub(crate) epoll_idx: u16,
    /// Socket flags (SOCK_NONBLOCK, SOCK_CLOEXEC).
    pub(crate) sock_flags: u16,
}

impl FdEntry {
    pub(crate) const fn free() -> Self {
        Self {
            kind: FdKind::Free, vfs_fd: 0, net_conn_id: 0,
            udp_local_port: 0, udp_remote_ip: 0, udp_remote_port: 0,
            epoll_idx: 0, sock_flags: 0,
        }
    }
    pub(crate) const fn new(kind: FdKind, vfs_fd: u32, net_conn_id: u32) -> Self {
        Self {
            kind, vfs_fd, net_conn_id,
            udp_local_port: 0, udp_remote_ip: 0, udp_remote_port: 0,
            epoll_idx: 0, sock_flags: 0,
        }
    }
}

// ---------------------------------------------------------------------------
// Uptime offset: make the system appear to have been running for 3 days.
// Applied to clock_gettime, gettimeofday, sysinfo, /proc/uptime.
// ---------------------------------------------------------------------------
// Clock offset: make timestamps appear as 2026-03-14 12:00 UTC for TLS cert validation.
// 2026-03-14 12:00:00 UTC = 1773360000 seconds since epoch.
// GitHub's cert: notBefore=2026-03-06 (must be AFTER this date).
pub(crate) const UPTIME_OFFSET_NS: u64 = 1_773_360_000 * 1_000_000_000;
pub(crate) const UPTIME_OFFSET_SECS: u64 = 1_773_360_000;

// ---------------------------------------------------------------------------
// Epoll event flags (Linux ABI)
// ---------------------------------------------------------------------------
pub(crate) const EPOLLIN: u32 = 0x001;
pub(crate) const EPOLLOUT: u32 = 0x004;
pub(crate) const EPOLLERR: u32 = 0x008;
pub(crate) const EPOLLHUP: u32 = 0x010;

// ---------------------------------------------------------------------------
// FD constants
// ---------------------------------------------------------------------------

pub(crate) const MAX_FDS: usize = 256;
// BRK_BASE, BRK_LIMIT, MMAP_BASE centralized in sotos_common
pub(crate) use sotos_common::{BRK_BASE, BRK_LIMIT, MMAP_BASE};

// ---------------------------------------------------------------------------
// alloc_fd
// ---------------------------------------------------------------------------

/// Find the next free FD slot starting from `from`.
pub(crate) fn alloc_fd(fds: &[FdEntry; MAX_FDS], from: usize) -> Option<usize> {
    for i in from..MAX_FDS {
        if fds[i].kind == FdKind::Free {
            return Some(i);
        }
    }
    None
}

// ---------------------------------------------------------------------------
// write_linux_stat
// ---------------------------------------------------------------------------

/// Write a Linux stat structure to user memory.
/// `oid` is used as st_ino, `dev` as st_dev (default 0).
pub(crate) fn write_linux_stat_dev(stat_ptr: u64, dev: u64, oid: u64, size: u64, is_dir: bool) {
    use sotos_common::linux_abi::{Stat, S_IFREG, S_IFDIR};
    let mut st = Stat::zeroed();
    st.st_dev = dev;
    st.st_ino = oid;
    st.st_nlink = 1;
    st.st_mode = if is_dir { S_IFDIR | 0o700 } else { S_IFREG | 0o755 };
    st.st_size = size as i64;
    st.st_blksize = 512;
    st.st_blocks = ((size + 511) / 512) as i64;
    unsafe { st.write_to(stat_ptr); }
}

/// Convenience wrapper with st_dev=0 (backward compat for stubs/misc).
pub(crate) fn write_linux_stat(stat_ptr: u64, oid: u64, size: u64, is_dir: bool) {
    write_linux_stat_dev(stat_ptr, 0, oid, size, is_dir);
}

/// Build a Stat struct (for guest_write by caller). Returns raw bytes.
pub(crate) fn build_linux_stat_dev(dev: u64, oid: u64, size: u64, is_dir: bool) -> [u8; 144] {
    use sotos_common::linux_abi::{Stat, S_IFREG, S_IFDIR};
    let mut st = Stat::zeroed();
    st.st_dev = dev;
    st.st_ino = oid;
    st.st_nlink = 1;
    st.st_mode = if is_dir { S_IFDIR | 0o700 } else { S_IFREG | 0o755 };
    st.st_size = size as i64;
    st.st_blksize = 512;
    st.st_blocks = ((size + 511) / 512) as i64;
    unsafe { core::mem::transmute(st) }
}

pub(crate) fn build_linux_stat(oid: u64, size: u64, is_dir: bool) -> [u8; 144] {
    build_linux_stat_dev(0, oid, size, is_dir)
}

// ---------------------------------------------------------------------------
// Thread group constants (shared across child_handler + SyscallContext)
// ---------------------------------------------------------------------------

pub(crate) const GRP_MAX_FDS: usize = 128;
pub(crate) const GRP_MAX_INITRD: usize = 64;
pub(crate) const GRP_MAX_VFS: usize = 64;
pub(crate) const GRP_CWD_MAX: usize = 128;
pub(crate) const MAX_EVENTFDS: usize = 32;
pub(crate) const MAX_TIMERFDS: usize = 16;
pub(crate) const MAX_MEMFDS: usize = 16;
pub(crate) const MAX_EPOLL_ENTRIES: usize = 64;

// ---------------------------------------------------------------------------
// ThreadGroupState: all per-group mutable state in one struct.
// Each "group" corresponds to a thread group (process). Threads sharing
// CLONE_FILES point to the same group index.
// ---------------------------------------------------------------------------

pub(crate) struct ThreadGroupState {
    // FD table (kind per slot)
    pub fds: [u8; GRP_MAX_FDS],
    /// Close-on-exec bitset (bit i = fd i has FD_CLOEXEC)
    pub fd_cloexec: u128,
    // Initrd file tracking: [data_vaddr, file_size, read_position, fd_index]
    pub initrd: [[u64; 4]; GRP_MAX_INITRD],
    // VFS file tracking: [oid, size, position, fd_index]
    pub vfs: [[u64; 4]; GRP_MAX_VFS],
    // Directory listing state
    pub dir_buf: [u8; 4096],
    pub dir_len: usize,
    pub dir_pos: usize,
    // CWD (absolute path, NUL-terminated)
    pub cwd: [u8; GRP_CWD_MAX],
    // Memory group state (brk/mmap)
    pub brk: u64,
    pub mmap_next: u64,
    pub initrd_buf_base: u64,
    // Per-fd open file flags (O_NONBLOCK, O_APPEND, etc.) set via fcntl F_SETFL
    pub fd_flags: [u32; GRP_MAX_FDS],
    // Socket metadata (parallel arrays indexed by FD number)
    pub sock_conn_id: [u32; GRP_MAX_FDS],
    pub sock_udp_local_port: [u16; GRP_MAX_FDS],
    pub sock_udp_remote_ip: [u32; GRP_MAX_FDS],
    pub sock_udp_remote_port: [u16; GRP_MAX_FDS],
    // eventfd state (kind=22)
    pub eventfd_counter: [u64; MAX_EVENTFDS],
    pub eventfd_flags: [u32; MAX_EVENTFDS],
    pub eventfd_slot_fd: [usize; MAX_EVENTFDS],
    // timerfd state (kind=23)
    pub timerfd_interval_ns: [u64; MAX_TIMERFDS],
    pub timerfd_expiry_tsc: [u64; MAX_TIMERFDS],
    pub timerfd_slot_fd: [usize; MAX_TIMERFDS],
    // memfd state (kind=25)
    pub memfd_base: [u64; MAX_MEMFDS],
    pub memfd_size: [u64; MAX_MEMFDS],
    pub memfd_cap: [u64; MAX_MEMFDS],
    pub memfd_slot_fd: [usize; MAX_MEMFDS],
    // epoll registration state
    pub epoll_reg_fd: [i32; MAX_EPOLL_ENTRIES],
    pub epoll_reg_events: [u32; MAX_EPOLL_ENTRIES],
    pub epoll_reg_data: [u64; MAX_EPOLL_ENTRIES],
}

impl ThreadGroupState {
    pub(crate) const fn new() -> Self {
        Self {
            fds: [0; GRP_MAX_FDS],
            fd_cloexec: 0,
            initrd: [[0; 4]; GRP_MAX_INITRD],
            vfs: [[0; 4]; GRP_MAX_VFS],
            dir_buf: [0; 4096],
            dir_len: 0,
            dir_pos: 0,
            cwd: {
                let mut buf = [0u8; GRP_CWD_MAX];
                buf[0] = b'/';
                buf
            },
            brk: 0,
            mmap_next: 0,
            initrd_buf_base: 0,
            fd_flags: [0; GRP_MAX_FDS],
            sock_conn_id: [0xFFFF; GRP_MAX_FDS],
            sock_udp_local_port: [0; GRP_MAX_FDS],
            sock_udp_remote_ip: [0; GRP_MAX_FDS],
            sock_udp_remote_port: [0; GRP_MAX_FDS],
            eventfd_counter: [0; MAX_EVENTFDS],
            eventfd_flags: [0; MAX_EVENTFDS],
            eventfd_slot_fd: [usize::MAX; MAX_EVENTFDS],
            timerfd_interval_ns: [0; MAX_TIMERFDS],
            timerfd_expiry_tsc: [0; MAX_TIMERFDS],
            timerfd_slot_fd: [usize::MAX; MAX_TIMERFDS],
            memfd_base: [0; MAX_MEMFDS],
            memfd_size: [0; MAX_MEMFDS],
            memfd_cap: [0; MAX_MEMFDS],
            memfd_slot_fd: [usize::MAX; MAX_MEMFDS],
            epoll_reg_fd: [-1; MAX_EPOLL_ENTRIES],
            epoll_reg_events: [0; MAX_EPOLL_ENTRIES],
            epoll_reg_data: [0; MAX_EPOLL_ENTRIES],
        }
    }
}

/// Consolidated per-group state. Indexed by group ID (PROC_FD_GROUP / PROC_MEM_GROUP).
pub(crate) static mut THREAD_GROUPS: [ThreadGroupState; MAX_PROCS] =
    [const { ThreadGroupState::new() }; MAX_PROCS];

/// Per-FD directory path tracking for fchdir(). Index = group * 8 + slot.
/// sock_conn_id[fd] stores slot index (0..7) when kind=14.
pub(crate) const MAX_DIR_SLOTS: usize = MAX_PROCS * 8;
pub(crate) static mut DIR_FD_PATHS: [[u8; 128]; MAX_DIR_SLOTS] = [[0u8; 128]; MAX_DIR_SLOTS];

/// Spinlock per FD group (protects THREAD_GROUPS[g]).
pub(crate) static GRP_FD_LOCK: [AtomicU64; MAX_PROCS] = {
    const INIT: AtomicU64 = AtomicU64::new(0);
    [INIT; MAX_PROCS]
};

// ---------------------------------------------------------------------------
// Fork socket state handshake (serialized by CHILD_SETUP)
// Parent writes before CHILD_SETUP_READY=1, child reads on init.
// ---------------------------------------------------------------------------
pub(crate) static mut FORK_FD_FLAGS: [u32; GRP_MAX_FDS] = [0; GRP_MAX_FDS];
pub(crate) static mut FORK_SOCK_CONN: [u32; GRP_MAX_FDS] = [0xFFFF; GRP_MAX_FDS];
pub(crate) static mut FORK_SOCK_UDP_LPORT: [u16; GRP_MAX_FDS] = [0; GRP_MAX_FDS];
pub(crate) static mut FORK_SOCK_UDP_RIP: [u32; GRP_MAX_FDS] = [0; GRP_MAX_FDS];
pub(crate) static mut FORK_SOCK_UDP_RPORT: [u16; GRP_MAX_FDS] = [0; GRP_MAX_FDS];
/// Flag: 1 = fork child should copy socket state from FORK_SOCK_* on init.
pub(crate) static FORK_SOCK_READY: AtomicU64 = AtomicU64::new(0);

// ---------------------------------------------------------------------------
// Shared pipe buffers (inter-handler communication)
// ---------------------------------------------------------------------------
pub(crate) const MAX_PIPES: usize = 64;
pub(crate) const PIPE_BUF_SIZE: usize = 65536; // 64KB per pipe (Wine protocol msgs are small)

/// Pipe data buffer (ring buffer).
pub(crate) static mut PIPE_BUF: [[u8; PIPE_BUF_SIZE]; MAX_PIPES] = [[0; PIPE_BUF_SIZE]; MAX_PIPES];
/// Write position (total bytes written, mod PIPE_BUF_SIZE for index).
pub(crate) static PIPE_WRITE_POS: [AtomicU64; MAX_PIPES] = {
    const INIT: AtomicU64 = AtomicU64::new(0);
    [INIT; MAX_PIPES]
};
/// Read position (total bytes read, mod PIPE_BUF_SIZE for index).
pub(crate) static PIPE_READ_POS: [AtomicU64; MAX_PIPES] = {
    const INIT: AtomicU64 = AtomicU64::new(0);
    [INIT; MAX_PIPES]
};
/// Writer closed flag: 0=open, 1=closed (reader gets EOF when buffer empty).
pub(crate) static PIPE_WRITE_CLOSED: [AtomicU64; MAX_PIPES] = {
    const INIT: AtomicU64 = AtomicU64::new(0);
    [INIT; MAX_PIPES]
};
/// Reader closed flag.
pub(crate) static PIPE_READ_CLOSED: [AtomicU64; MAX_PIPES] = {
    const INIT: AtomicU64 = AtomicU64::new(0);
    [INIT; MAX_PIPES]
};
/// Pipe active flag: 0=free, 1=in use.
pub(crate) static PIPE_ACTIVE: [AtomicU64; MAX_PIPES] = {
    const INIT: AtomicU64 = AtomicU64::new(0);
    [INIT; MAX_PIPES]
};
/// Pipe write-end reference count: how many open fds reference the write end.
pub(crate) static PIPE_WRITE_REFS: [AtomicU64; MAX_PIPES] = {
    const INIT: AtomicU64 = AtomicU64::new(0);
    [INIT; MAX_PIPES]
};
/// Pipe read-end reference count: how many open fds reference the read end.
pub(crate) static PIPE_READ_REFS: [AtomicU64; MAX_PIPES] = {
    const INIT: AtomicU64 = AtomicU64::new(0);
    [INIT; MAX_PIPES]
};
/// Per-pipe write spinlock: prevents concurrent writers from corrupting
/// the ring buffer. Fork creates multiple producers for the same pipe
/// (parent + child both inherit write fds), so SPSC is not guaranteed.
pub(crate) static PIPE_WRITE_LOCK: [AtomicU64; MAX_PIPES] = {
    const INIT: AtomicU64 = AtomicU64::new(0);
    [INIT; MAX_PIPES]
};
/// Next pipe ID counter.
pub(crate) static NEXT_PIPE_ID: AtomicU64 = AtomicU64::new(0);

/// Allocate a new pipe, returns pipe index or None.
///
/// Uses a monotonically increasing counter to avoid reusing recently-freed
/// pipe IDs. This prevents stale fd references in one process from reading
/// another process's pipe data after the old pipe is freed and the ID reused.
pub(crate) fn pipe_alloc() -> Option<usize> {
    let start = NEXT_PIPE_ID.fetch_add(1, Ordering::AcqRel) as usize % MAX_PIPES;
    for offset in 0..MAX_PIPES {
        let i = (start + offset) % MAX_PIPES;
        if PIPE_ACTIVE[i].compare_exchange(0, 1, Ordering::AcqRel, Ordering::Relaxed).is_ok() {
            PIPE_WRITE_POS[i].store(0, Ordering::Release);
            PIPE_READ_POS[i].store(0, Ordering::Release);
            PIPE_WRITE_CLOSED[i].store(0, Ordering::Release);
            PIPE_READ_CLOSED[i].store(0, Ordering::Release);
            PIPE_WRITE_REFS[i].store(1, Ordering::Release);
            PIPE_READ_REFS[i].store(1, Ordering::Release);
            PIPE_WRITE_LOCK[i].store(0, Ordering::Release);
            return Some(i);
        }
    }
    None
}

/// Write data to pipe buffer. Returns bytes written.
/// Uses per-pipe spinlock to prevent concurrent writer corruption (fork
/// creates multiple producers when child inherits parent's pipe fds).
pub(crate) fn pipe_write(pipe_id: usize, data: &[u8]) -> usize {
    if pipe_id >= MAX_PIPES { return 0; }
    // Acquire write lock
    while PIPE_WRITE_LOCK[pipe_id].compare_exchange(0, 1, Ordering::Acquire, Ordering::Relaxed).is_err() {
        core::hint::spin_loop();
    }
    let wp = PIPE_WRITE_POS[pipe_id].load(Ordering::Acquire);
    let rp = PIPE_READ_POS[pipe_id].load(Ordering::Acquire);
    let used = (wp - rp) as usize;
    let avail = PIPE_BUF_SIZE.saturating_sub(used);
    let n = data.len().min(avail);
    if n == 0 {
        PIPE_WRITE_LOCK[pipe_id].store(0, Ordering::Release);
        return 0;
    }
    unsafe {
        for i in 0..n {
            let idx = ((wp as usize) + i) % PIPE_BUF_SIZE;
            PIPE_BUF[pipe_id][idx] = data[i];
        }
    }
    PIPE_WRITE_POS[pipe_id].store(wp + n as u64, Ordering::Release);
    // Release write lock
    PIPE_WRITE_LOCK[pipe_id].store(0, Ordering::Release);
    n
}

/// Read data from pipe buffer. Returns bytes read (0 = empty, check closed for EOF).
pub(crate) fn pipe_read(pipe_id: usize, buf: &mut [u8]) -> usize {
    if pipe_id >= MAX_PIPES { return 0; }
    let wp = PIPE_WRITE_POS[pipe_id].load(Ordering::Acquire);
    let rp = PIPE_READ_POS[pipe_id].load(Ordering::Acquire);
    let available = (wp - rp) as usize;
    let n = buf.len().min(available);
    if n == 0 { return 0; }
    unsafe {
        for i in 0..n {
            let idx = ((rp as usize) + i) % PIPE_BUF_SIZE;
            buf[i] = PIPE_BUF[pipe_id][idx];
        }
    }
    PIPE_READ_POS[pipe_id].store(rp + n as u64, Ordering::Release);
    n
}

/// Check if pipe writer is closed.
/// Triple defense against memory corruption:
/// 1. PIPE_WRITE_CLOSED must be set
/// 2. PIPE_WRITE_REFS must be 0
/// 3. No living process may still have this pipe's write end open
pub(crate) fn pipe_reader_closed(pipe_id: usize) -> bool {
    if pipe_id >= MAX_PIPES { return false; }
    PIPE_READ_CLOSED[pipe_id].load(Ordering::Acquire) != 0
}

/// Mark a pipe's write direction as closed (used by shutdown SHUT_WR).
pub(crate) fn pipe_set_write_closed(pipe_id: usize) {
    if pipe_id < MAX_PIPES {
        PIPE_WRITE_CLOSED[pipe_id].store(1, Ordering::Release);
    }
}

pub(crate) fn pipe_writer_closed(pipe_id: usize) -> bool {
    if pipe_id >= MAX_PIPES { return false; }
    if PIPE_WRITE_CLOSED[pipe_id].load(Ordering::Acquire) == 0 { return false; }
    if PIPE_WRITE_REFS[pipe_id].load(Ordering::Acquire) != 0 { return false; }
    // Process-liveness check: scan all living processes for an open write fd
    // pointing to this pipe. If any exist, the corruption set PWC/refs wrong.
    for p in 0..MAX_PROCS {
        let state = crate::process::PROCESSES[p].state.load(Ordering::Acquire);
        if state != 1 { continue; } // not running
        let fdg = crate::process::PROCESSES[p].fd_group.load(Ordering::Acquire) as usize;
        if fdg >= MAX_PROCS { continue; }
        unsafe {
            for f in 0..GRP_MAX_FDS {
                if THREAD_GROUPS[fdg].fds[f] == 11
                    && (THREAD_GROUPS[fdg].sock_conn_id[f] as usize) == pipe_id
                {
                    // Living process still has write end open
                    return false;
                }
            }
        }
    }
    true
}

/// Returns the PID (1-based) of a running process that holds the write end
/// of the given pipe, or 0 if no such process exists.
/// Used by the deadlock detector to verify real cycles.
pub(crate) fn pipe_write_owner(pipe_id: usize) -> usize {
    if pipe_id >= MAX_PIPES { return 0; }
    for p in 0..MAX_PROCS {
        let state = crate::process::PROCESSES[p].state.load(Ordering::Acquire);
        if state != 1 { continue; } // not running
        let fdg = crate::process::PROCESSES[p].fd_group.load(Ordering::Acquire) as usize;
        if fdg >= MAX_PROCS { continue; }
        unsafe {
            for f in 0..GRP_MAX_FDS {
                if THREAD_GROUPS[fdg].fds[f] == 11
                    && (THREAD_GROUPS[fdg].sock_conn_id[f] as usize) == pipe_id
                {
                    return p + 1; // 1-based pid
                }
            }
        }
    }
    0
}

/// Close all write-end FDs for a pipe across all processes.
/// Used by the deadlock detector to give readers a natural EOF.
/// This decrements PIPE_WRITE_REFS for each closed FD and sets
/// PIPE_WRITE_CLOSED when refs reach 0.
pub(crate) fn pipe_close_all_writers(pipe_id: usize) {
    if pipe_id >= MAX_PIPES { return; }
    for p in 0..MAX_PROCS {
        let state = crate::process::PROCESSES[p].state.load(Ordering::Acquire);
        if state != 1 { continue; }
        let fdg = crate::process::PROCESSES[p].fd_group.load(Ordering::Acquire) as usize;
        if fdg >= MAX_PROCS { continue; }
        unsafe {
            for f in 0..GRP_MAX_FDS {
                if THREAD_GROUPS[fdg].fds[f] == 11
                    && (THREAD_GROUPS[fdg].sock_conn_id[f] as usize) == pipe_id
                {
                    THREAD_GROUPS[fdg].fds[f] = 0;
                    THREAD_GROUPS[fdg].sock_conn_id[f] = 0xFFFF;
                    let prev = PIPE_WRITE_REFS[pipe_id].fetch_sub(1, Ordering::AcqRel);
                    if prev <= 1 {
                        PIPE_WRITE_CLOSED[pipe_id].store(1, Ordering::Release);
                    }
                }
            }
        }
    }
}

/// Check if pipe has data available for reading.
pub(crate) fn pipe_has_data(pipe_id: usize) -> bool {
    if pipe_id >= MAX_PIPES { return false; }
    let wp = PIPE_WRITE_POS[pipe_id].load(Ordering::Acquire);
    let rp = PIPE_READ_POS[pipe_id].load(Ordering::Acquire);
    wp > rp
}

/// Free a pipe buffer.
pub(crate) fn pipe_free(pipe_id: usize) {
    if pipe_id < MAX_PIPES {
        PIPE_ACTIVE[pipe_id].store(0, Ordering::Release);
    }
}

// ---------------------------------------------------------------------------
// AF_UNIX named socket infrastructure
// ---------------------------------------------------------------------------

/// Max simultaneous AF_UNIX listeners (bound + listening sockets).
pub(crate) const MAX_UNIX_LISTENERS: usize = 8;
/// Bound paths: 0-filled = unused slot.
pub(crate) static mut UNIX_LISTEN_PATH: [[u8; 128]; MAX_UNIX_LISTENERS] = [[0; 128]; MAX_UNIX_LISTENERS];
/// Slot active flag.
pub(crate) static UNIX_LISTEN_ACTIVE: [AtomicU64; MAX_UNIX_LISTENERS] = {
    const INIT: AtomicU64 = AtomicU64::new(0);
    [INIT; MAX_UNIX_LISTENERS]
};

/// Max AF_UNIX connections (each uses 2 pipes: A=client→server, B=server→client).
pub(crate) const MAX_UNIX_CONNS: usize = 32;
/// Pipe ID for client→server direction (0xFFFF = unused).
pub(crate) static mut UNIX_CONN_PIPE_A: [u16; MAX_UNIX_CONNS] = [0xFFFF; MAX_UNIX_CONNS];
/// Pipe ID for server→client direction (0xFFFF = unused).
pub(crate) static mut UNIX_CONN_PIPE_B: [u16; MAX_UNIX_CONNS] = [0xFFFF; MAX_UNIX_CONNS];
pub(crate) static UNIX_CONN_ACTIVE: [AtomicU64; MAX_UNIX_CONNS] = {
    const INIT: AtomicU64 = AtomicU64::new(0);
    [INIT; MAX_UNIX_CONNS]
};
/// Reference count for each AF_UNIX connection. Incremented on fork inheritance,
/// decremented on close. Only free connection when refs reach 0.
pub(crate) static UNIX_CONN_REFS: [AtomicU64; MAX_UNIX_CONNS] = {
    const INIT: AtomicU64 = AtomicU64::new(0);
    [INIT; MAX_UNIX_CONNS]
};

/// Pending connection queue: connect() pushes, accept() pops.
/// Each entry is a connection slot index (0xFF = empty).
pub(crate) const MAX_UNIX_PENDING: usize = 16;
/// [listener_slot][queue_pos] = connection slot index (0xFF = empty).
pub(crate) static mut UNIX_PENDING: [[u8; MAX_UNIX_PENDING]; MAX_UNIX_LISTENERS] =
    [[0xFF; MAX_UNIX_PENDING]; MAX_UNIX_LISTENERS];

/// Allocate an AF_UNIX connection (2 pipes). Returns (conn_slot, pipe_a, pipe_b) or None.
pub(crate) fn unix_conn_alloc() -> Option<(usize, usize, usize)> {
    let pipe_a = pipe_alloc()?;
    let pipe_b = match pipe_alloc() {
        Some(b) => b,
        None => { pipe_free(pipe_a); return None; }
    };
    for i in 0..MAX_UNIX_CONNS {
        if UNIX_CONN_ACTIVE[i].compare_exchange(0, 1, Ordering::AcqRel, Ordering::Relaxed).is_ok() {
            unsafe {
                UNIX_CONN_PIPE_A[i] = pipe_a as u16;
                UNIX_CONN_PIPE_B[i] = pipe_b as u16;
                // Clear stale message queue + SCM state from previous use of this slot
                for d in 0..2usize {
                    MSG_QUEUE_HEAD[i][d] = 0;
                    MSG_QUEUE_COUNT[i][d] = 0;
                    SCM_FDS_COUNT[i][d] = 0;
                    for s in 0..MSG_QUEUE_CAP {
                        MSG_QUEUE[i][d][s] = 0;
                        MSG_SCM_COUNT[i][d][s] = 0;
                    }
                    for s in 0..MAX_SCM_FDS {
                        SCM_FDS_KIND[i][d][s] = 0;
                        SCM_FDS_CONN[i][d][s] = 0;
                        SCM_FDS_OID[i][d][s] = 0;
                        SCM_FDS_SIZE[i][d][s] = 0;
                    }
                }
            }
            UNIX_CONN_REFS[i].store(1, Ordering::Release); // connect() side; accept() adds 1
            return Some((i, pipe_a, pipe_b));
        }
    }
    pipe_free(pipe_a);
    pipe_free(pipe_b);
    None
}

/// Check if a listener has pending connections.
pub(crate) fn unix_listener_has_pending(listener: usize) -> bool {
    if listener >= MAX_UNIX_LISTENERS { return false; }
    unsafe { UNIX_PENDING[listener][0] != 0xFF }
}

/// Push a pending connection onto a listener's queue.
pub(crate) fn unix_pending_push(listener: usize, conn_slot: usize) -> bool {
    if listener >= MAX_UNIX_LISTENERS { return false; }
    unsafe {
        for i in 0..MAX_UNIX_PENDING {
            if UNIX_PENDING[listener][i] == 0xFF {
                UNIX_PENDING[listener][i] = conn_slot as u8;
                return true;
            }
        }
    }
    false
}

/// Pop a pending connection from a listener's queue. Returns conn_slot or None.
pub(crate) fn unix_pending_pop(listener: usize) -> Option<usize> {
    if listener >= MAX_UNIX_LISTENERS { return None; }
    unsafe {
        if UNIX_PENDING[listener][0] == 0xFF { return None; }
        let slot = UNIX_PENDING[listener][0] as usize;
        // Shift queue left
        for i in 0..MAX_UNIX_PENDING - 1 {
            UNIX_PENDING[listener][i] = UNIX_PENDING[listener][i + 1];
        }
        UNIX_PENDING[listener][MAX_UNIX_PENDING - 1] = 0xFF;
        Some(slot)
    }
}

// ---------------------------------------------------------------------------
// SCM_RIGHTS: per-connection fd-passing queue (sender stores, receiver picks up)
// ---------------------------------------------------------------------------
/// Max fds that can be queued for SCM_RIGHTS delivery per connection direction.
pub(crate) const MAX_SCM_FDS: usize = 8;
/// Pending SCM_RIGHTS fds: [conn][direction][slot], direction 0=A→B (client→server), 1=B→A (server→client).
/// Value = (sender_fd_kind, sender_sock_conn_id, sender_vfs_oid, sender_vfs_size) encoded as u64, or 0 = empty.
/// For simplicity: store the raw fd kind + conn_id. Receiver allocates a new fd with same kind+conn_id.
pub(crate) static mut SCM_FDS_KIND: [[[u8; MAX_SCM_FDS]; 2]; MAX_UNIX_CONNS] = [[[0; MAX_SCM_FDS]; 2]; MAX_UNIX_CONNS];
pub(crate) static mut SCM_FDS_CONN: [[[u32; MAX_SCM_FDS]; 2]; MAX_UNIX_CONNS] = [[[0; MAX_SCM_FDS]; 2]; MAX_UNIX_CONNS];
/// VFS OID for kind=13 fds passed via SCM_RIGHTS (0 = not a VFS file).
pub(crate) static mut SCM_FDS_OID: [[[u64; MAX_SCM_FDS]; 2]; MAX_UNIX_CONNS] = [[[0; MAX_SCM_FDS]; 2]; MAX_UNIX_CONNS];
/// VFS file size for kind=13 fds.
pub(crate) static mut SCM_FDS_SIZE: [[[u64; MAX_SCM_FDS]; 2]; MAX_UNIX_CONNS] = [[[0; MAX_SCM_FDS]; 2]; MAX_UNIX_CONNS];
pub(crate) static mut SCM_FDS_COUNT: [[u8; 2]; MAX_UNIX_CONNS] = [[0; 2]; MAX_UNIX_CONNS];

/// Push fds into SCM_RIGHTS queue for a given connection+direction.
/// direction: 0 = client→server (kind=27 sender), 1 = server→client (kind=28 sender).
/// For kind=13 VFS files, oid and size carry the VFS metadata.
pub(crate) fn scm_push_fd(conn: usize, direction: usize, kind: u8, conn_id: u32, oid: u64, size: u64) -> bool {
    if conn >= MAX_UNIX_CONNS || direction > 1 { return false; }
    unsafe {
        let cnt = SCM_FDS_COUNT[conn][direction] as usize;
        if cnt >= MAX_SCM_FDS { return false; }
        SCM_FDS_KIND[conn][direction][cnt] = kind;
        SCM_FDS_CONN[conn][direction][cnt] = conn_id;
        SCM_FDS_OID[conn][direction][cnt] = oid;
        SCM_FDS_SIZE[conn][direction][cnt] = size;
        SCM_FDS_COUNT[conn][direction] = (cnt + 1) as u8;
    }
    // Pre-increment pipe refcounts at send time (not just receive time).
    // Prevents premature EOF: sender may close their fd before receiver
    // pops the SCM, and without this the refcount hits 0 → PIPE_WRITE_CLOSED.
    let p = conn_id as usize;
    if kind == 10 && p < MAX_PIPES {
        PIPE_READ_REFS[p].fetch_add(1, core::sync::atomic::Ordering::AcqRel);
    }
    if kind == 11 && p < MAX_PIPES {
        PIPE_WRITE_REFS[p].fetch_add(1, core::sync::atomic::Ordering::AcqRel);
    }
    if (kind == 27 || kind == 28) && p < MAX_UNIX_CONNS {
        UNIX_CONN_REFS[p].fetch_add(1, core::sync::atomic::Ordering::AcqRel);
    }
    true
}

/// Pop up to `max_pop` SCM_RIGHTS fds for a given connection+direction (receiver side).
/// Returns count of fds popped, fills kinds[], conn_ids[], oids[], sizes[].
pub(crate) fn scm_pop_fds(
    conn: usize, direction: usize,
    kinds: &mut [u8; MAX_SCM_FDS], conn_ids: &mut [u32; MAX_SCM_FDS],
    oids: &mut [u64; MAX_SCM_FDS], sizes: &mut [u64; MAX_SCM_FDS],
    max_pop: usize,
) -> usize {
    if conn >= MAX_UNIX_CONNS || direction > 1 { return 0; }
    unsafe {
        let cnt = SCM_FDS_COUNT[conn][direction] as usize;
        let to_pop = cnt.min(max_pop);
        for i in 0..to_pop {
            kinds[i] = SCM_FDS_KIND[conn][direction][i];
            conn_ids[i] = SCM_FDS_CONN[conn][direction][i];
            oids[i] = SCM_FDS_OID[conn][direction][i];
            sizes[i] = SCM_FDS_SIZE[conn][direction][i];
        }
        // Shift remaining entries left
        let remaining = cnt - to_pop;
        for i in 0..remaining {
            SCM_FDS_KIND[conn][direction][i] = SCM_FDS_KIND[conn][direction][to_pop + i];
            SCM_FDS_CONN[conn][direction][i] = SCM_FDS_CONN[conn][direction][to_pop + i];
            SCM_FDS_OID[conn][direction][i] = SCM_FDS_OID[conn][direction][to_pop + i];
            SCM_FDS_SIZE[conn][direction][i] = SCM_FDS_SIZE[conn][direction][to_pop + i];
        }
        SCM_FDS_COUNT[conn][direction] = remaining as u8;
        to_pop
    }
}

// ---------------------------------------------------------------------------
// AF_UNIX message length queue (preserves sendmsg boundaries for recvmsg)
// ---------------------------------------------------------------------------
/// Max queued message lengths per connection direction.
const MSG_QUEUE_CAP: usize = 16;
/// Ring buffer of message lengths: [conn][direction][slot].
static mut MSG_QUEUE: [[[u16; MSG_QUEUE_CAP]; 2]; MAX_UNIX_CONNS] = [[[0; MSG_QUEUE_CAP]; 2]; MAX_UNIX_CONNS];
/// Per-message SCM fd count: how many SCM fds belong to each message.
static mut MSG_SCM_COUNT: [[[u8; MSG_QUEUE_CAP]; 2]; MAX_UNIX_CONNS] = [[[0; MSG_QUEUE_CAP]; 2]; MAX_UNIX_CONNS];
/// Head (read) index.
static mut MSG_QUEUE_HEAD: [[u8; 2]; MAX_UNIX_CONNS] = [[0; 2]; MAX_UNIX_CONNS];
/// Count of entries.
static mut MSG_QUEUE_COUNT: [[u8; 2]; MAX_UNIX_CONNS] = [[0; 2]; MAX_UNIX_CONNS];

/// Push a message length + SCM count (from sendmsg). Returns false if queue full.
pub(crate) fn msg_queue_push(conn: usize, direction: usize, len: u16, scm_count: u8) -> bool {
    if conn >= MAX_UNIX_CONNS || direction > 1 { return false; }
    unsafe {
        let cnt = MSG_QUEUE_COUNT[conn][direction] as usize;
        if cnt >= MSG_QUEUE_CAP { return false; }
        let idx = ((MSG_QUEUE_HEAD[conn][direction] as usize) + cnt) % MSG_QUEUE_CAP;
        MSG_QUEUE[conn][direction][idx] = len;
        MSG_SCM_COUNT[conn][direction][idx] = scm_count;
        MSG_QUEUE_COUNT[conn][direction] = (cnt + 1) as u8;
        true
    }
}

/// Check if msg_queue has pending messages (for poll/epoll readability).
pub(crate) fn msg_queue_has_pending(conn: usize, direction: usize) -> bool {
    if conn >= MAX_UNIX_CONNS || direction > 1 { return false; }
    unsafe { MSG_QUEUE_COUNT[conn][direction] > 0 }
}

/// Peek the next message length (for recvmsg). Returns 0 if empty.
pub(crate) fn msg_queue_peek(conn: usize, direction: usize) -> u16 {
    if conn >= MAX_UNIX_CONNS || direction > 1 { return 0; }
    unsafe {
        if MSG_QUEUE_COUNT[conn][direction] == 0 { return 0; }
        MSG_QUEUE[conn][direction][MSG_QUEUE_HEAD[conn][direction] as usize]
    }
}

/// Pop a message length + SCM count (after recvmsg consumed it). Returns (len, scm_count), or (0,0) if empty.
pub(crate) fn msg_queue_pop(conn: usize, direction: usize) -> (u16, u8) {
    if conn >= MAX_UNIX_CONNS || direction > 1 { return (0, 0); }
    unsafe {
        if MSG_QUEUE_COUNT[conn][direction] == 0 { return (0, 0); }
        let head = MSG_QUEUE_HEAD[conn][direction] as usize;
        let val = MSG_QUEUE[conn][direction][head];
        let scm = MSG_SCM_COUNT[conn][direction][head];
        MSG_QUEUE_HEAD[conn][direction] = ((head + 1) % MSG_QUEUE_CAP) as u8;
        MSG_QUEUE_COUNT[conn][direction] -= 1;
        (val, scm)
    }
}

// ---------------------------------------------------------------------------
// FD group lock/unlock/init
// ---------------------------------------------------------------------------

/// Lock a FD group spinlock.
pub(crate) fn fd_grp_lock(g: usize) {
    while GRP_FD_LOCK[g].compare_exchange(0, 1, Ordering::AcqRel, Ordering::Relaxed).is_err() {
        sys::yield_now();
    }
}

/// Unlock a FD group spinlock.
pub(crate) fn fd_grp_unlock(g: usize) {
    GRP_FD_LOCK[g].store(0, Ordering::Release);
}

/// Lock two FD groups in ascending index order (ρ_repl deadlock prevention).
/// Used by fork/clone that needs cross-group access.
pub(crate) fn fd_grp_lock_pair(a: usize, b: usize) {
    let (first, second) = if a <= b { (a, b) } else { (b, a) };
    fd_grp_lock(first);
    if first != second {
        fd_grp_lock(second);
    }
}

/// Unlock two FD groups.
pub(crate) fn fd_grp_unlock_pair(a: usize, b: usize) {
    let (first, second) = if a <= b { (a, b) } else { (b, a) };
    if first != second {
        fd_grp_unlock(second);
    }
    fd_grp_unlock(first);
}

/// Initialize a thread group with default stdin/stdout/stderr.
pub(crate) fn fd_grp_init(g: usize) {
    unsafe {
        THREAD_GROUPS[g] = ThreadGroupState::new();
        THREAD_GROUPS[g].fds[0] = 1; // stdin
        THREAD_GROUPS[g].fds[1] = 2; // stdout
        THREAD_GROUPS[g].fds[2] = 2; // stderr
    }
}

/// Resolve a possibly-relative path against the CWD for FD group `g`.
/// Returns a buffer with the resolved absolute path and its length.
/// If `path` starts with '/', it's returned as-is. Otherwise, CWD + "/" + path.
pub(crate) fn resolve_with_cwd(cwd: &[u8; GRP_CWD_MAX], path: &[u8], out: &mut [u8; 256]) -> usize {
    if !path.is_empty() && path[0] == b'/' {
        let len = path.len().min(255);
        out[..len].copy_from_slice(&path[..len]);
        out[len] = 0;
        return len;
    }
    let mut cwd_len = 0;
    while cwd_len < GRP_CWD_MAX && cwd[cwd_len] != 0 { cwd_len += 1; }
    let mut pos = 0;
    let clen = cwd_len.min(250);
    out[..clen].copy_from_slice(&cwd[..clen]);
    pos = clen;
    if pos > 0 && out[pos - 1] != b'/' && pos < 255 {
        out[pos] = b'/';
        pos += 1;
    }
    let rlen = path.len().min(255 - pos);
    out[pos..pos + rlen].copy_from_slice(&path[..rlen]);
    pos += rlen;
    out[pos] = 0;
    pos
}

// ---------------------------------------------------------------------------
// Symlink table (Wine dosdevices compat)
// ---------------------------------------------------------------------------
const MAX_SYMLINKS: usize = 16;
const SYMLINK_LEN: usize = 128;
/// Symlink source paths (absolute). Zeroed = unused slot.
pub(crate) static mut SYMLINK_PATH: [[u8; SYMLINK_LEN]; MAX_SYMLINKS] = [[0; SYMLINK_LEN]; MAX_SYMLINKS];
/// Symlink targets (may be relative).
pub(crate) static mut SYMLINK_TARGET: [[u8; SYMLINK_LEN]; MAX_SYMLINKS] = [[0; SYMLINK_LEN]; MAX_SYMLINKS];
/// Count of registered symlinks. Atomic so readers (e.g. vfs_path
/// resolution) and the single writer (`symlink_register`) don't rely
/// on `static mut`. Write with Release, read with Acquire: the count
/// publishes the path/target slots up to `count - 1`.
pub(crate) static SYMLINK_COUNT: AtomicUsize = AtomicUsize::new(0);

/// Register a symlink: linkpath → target.
pub(crate) fn symlink_register(linkpath: &[u8], target: &[u8]) {
    let i = SYMLINK_COUNT.load(Ordering::Acquire);
    if i >= MAX_SYMLINKS { return; }
    unsafe {
        let plen = linkpath.len().min(SYMLINK_LEN - 1);
        let tlen = target.len().min(SYMLINK_LEN - 1);
        SYMLINK_PATH[i][..plen].copy_from_slice(&linkpath[..plen]);
        SYMLINK_PATH[i][plen] = 0;
        SYMLINK_TARGET[i][..tlen].copy_from_slice(&target[..tlen]);
        SYMLINK_TARGET[i][tlen] = 0;
    }
    SYMLINK_COUNT.store(i + 1, Ordering::Release);
}

/// Find needle in haystack, return position of start. None if not found.
fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.len() > haystack.len() { return None; }
    for i in 0..=(haystack.len() - needle.len()) {
        if &haystack[i..i + needle.len()] == needle { return Some(i); }
    }
    None
}

/// Normalize a path by substituting symlink components.
/// Also handles Wine dosdevices: .wine/dosdevices/X: → .wine/drive_X
/// Returns the new length written into `out`.
pub(crate) fn symlink_resolve(path: &[u8], out: &mut [u8; 256]) -> usize {
    // Wine compat: rewrite dosdevices/c: → drive_c (and z: → /)
    // Pattern: .../.wine/dosdevices/X:/rest → .../.wine/drive_X/rest
    if let Some(dd_pos) = find_subslice(path, b"/dosdevices/") {
        let letter_pos = dd_pos + b"/dosdevices/".len();
        if letter_pos + 1 < path.len() && path[letter_pos + 1] == b':' {
            let letter = path[letter_pos];
            if letter == b'z' || letter == b'Z' {
                // z: → / (root filesystem)
                let rest_start = letter_pos + 2; // skip "z:"
                let rest = &path[rest_start..];
                if rest.is_empty() || rest == b"/" {
                    out[0] = b'/';
                    out[1] = 0;
                    return 1;
                }
                let n = rest.len().min(255);
                out[..n].copy_from_slice(&rest[..n]);
                out[n] = 0;
                return n;
            }
            // c: → drive_c (relative to .wine parent)
            let wine_parent_end = dd_pos; // position of /dosdevices
            let mut pos = 0usize;
            // Copy path up to and including /.wine
            if wine_parent_end > 0 {
                out[..wine_parent_end].copy_from_slice(&path[..wine_parent_end]);
                pos = wine_parent_end;
            }
            // Append /drive_X
            let drive = [b'/', b'd', b'r', b'i', b'v', b'e', b'_', letter];
            let cp = drive.len().min(255 - pos);
            out[pos..pos + cp].copy_from_slice(&drive[..cp]);
            pos += cp;
            // Append rest after "X:"
            let rest_start = letter_pos + 2;
            if rest_start < path.len() {
                let rest = &path[rest_start..];
                let rn = rest.len().min(255 - pos);
                out[pos..pos + rn].copy_from_slice(&rest[..rn]);
                pos += rn;
            }
            out[pos] = 0;
            return pos;
        }
    }
    let sym_count = SYMLINK_COUNT.load(Ordering::Acquire);
    unsafe {
        for i in 0..sym_count {
            let sp = &SYMLINK_PATH[i];
            let slen = sp.iter().position(|&b| b == 0).unwrap_or(SYMLINK_LEN);
            if slen == 0 { continue; }
            // Check if path starts with this symlink path
            if path.len() >= slen && &path[..slen] == &sp[..slen]
                && (path.len() == slen || path[slen] == b'/') {
                let tgt = &SYMLINK_TARGET[i];
                let tlen = tgt.iter().position(|&b| b == 0).unwrap_or(SYMLINK_LEN);
                if tlen == 0 { continue; }
                // Build resolved path
                let mut pos = 0usize;
                if tgt[0] == b'/' {
                    // Absolute target: target + rest
                    let cp = tlen.min(255);
                    out[..cp].copy_from_slice(&tgt[..cp]);
                    pos = cp;
                } else {
                    // Relative target: parent_of(symlink) + / + target + rest
                    // Find parent directory of the symlink
                    let mut last_slash = 0;
                    for j in 0..slen {
                        if sp[j] == b'/' { last_slash = j; }
                    }
                    if last_slash > 0 {
                        out[..last_slash].copy_from_slice(&sp[..last_slash]);
                        pos = last_slash;
                    }
                    out[pos] = b'/';
                    pos += 1;
                    let cp = tlen.min(255 - pos);
                    out[pos..pos + cp].copy_from_slice(&tgt[..cp]);
                    pos += cp;
                }
                // Append remaining path after symlink
                let rest_start = slen;
                let rest_len = path.len() - rest_start;
                if rest_len > 0 && pos + rest_len <= 255 {
                    out[pos..pos + rest_len].copy_from_slice(&path[rest_start..]);
                    pos += rest_len;
                }
                out[pos] = 0;
                return pos;
            }
        }
    }
    // No symlink match — copy as-is
    let n = path.len().min(255);
    out[..n].copy_from_slice(&path[..n]);
    out[n] = 0;
    n
}
