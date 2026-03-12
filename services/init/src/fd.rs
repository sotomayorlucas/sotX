// ---------------------------------------------------------------------------
// FD table types, group management, and related helpers (extracted from main.rs)
// ---------------------------------------------------------------------------

use sotos_common::sys;
use core::sync::atomic::{AtomicU64, Ordering};
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
pub(crate) const UPTIME_OFFSET_NS: u64 = 259_200 * 1_000_000_000; // 3 days in nanoseconds
pub(crate) const UPTIME_OFFSET_SECS: u64 = 259_200; // 3 days in seconds

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
pub(crate) const BRK_BASE: u64 = 0x2000000;
pub(crate) const BRK_LIMIT: u64 = 0x100000; // 1 MiB max heap (BRK_BASE..BRK_BASE+BRK_LIMIT)
pub(crate) const MMAP_BASE: u64 = 0x3000000;

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
    st.st_mode = if is_dir { S_IFDIR | 0o755 } else { S_IFREG | 0o755 };
    st.st_size = size as i64;
    st.st_blksize = 512;
    st.st_blocks = ((size + 511) / 512) as i64;
    unsafe { st.write_to(stat_ptr); }
}

/// Convenience wrapper with st_dev=0 (backward compat for stubs/misc).
pub(crate) fn write_linux_stat(stat_ptr: u64, oid: u64, size: u64, is_dir: bool) {
    write_linux_stat_dev(stat_ptr, 0, oid, size, is_dir);
}

// ---------------------------------------------------------------------------
// Thread group constants (shared across child_handler + SyscallContext)
// ---------------------------------------------------------------------------

pub(crate) const GRP_MAX_FDS: usize = 128;
pub(crate) const GRP_MAX_INITRD: usize = 32;
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
pub(crate) const MAX_PIPES: usize = 16;
pub(crate) const PIPE_BUF_SIZE: usize = 131072; // 128KB per pipe

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
/// Next pipe ID counter.
pub(crate) static NEXT_PIPE_ID: AtomicU64 = AtomicU64::new(0);

/// Allocate a new pipe, returns pipe index or None.
pub(crate) fn pipe_alloc() -> Option<usize> {
    for i in 0..MAX_PIPES {
        if PIPE_ACTIVE[i].compare_exchange(0, 1, Ordering::AcqRel, Ordering::Relaxed).is_ok() {
            PIPE_WRITE_POS[i].store(0, Ordering::Release);
            PIPE_READ_POS[i].store(0, Ordering::Release);
            PIPE_WRITE_CLOSED[i].store(0, Ordering::Release);
            PIPE_READ_CLOSED[i].store(0, Ordering::Release);
            PIPE_WRITE_REFS[i].store(1, Ordering::Release);
            PIPE_READ_REFS[i].store(1, Ordering::Release);
            return Some(i);
        }
    }
    None
}

/// Write data to pipe buffer. Returns bytes written.
pub(crate) fn pipe_write(pipe_id: usize, data: &[u8]) -> usize {
    if pipe_id >= MAX_PIPES { return 0; }
    let wp = PIPE_WRITE_POS[pipe_id].load(Ordering::Acquire);
    let rp = PIPE_READ_POS[pipe_id].load(Ordering::Acquire);
    let used = (wp - rp) as usize;
    let avail = PIPE_BUF_SIZE.saturating_sub(used);
    let n = data.len().min(avail);
    if n == 0 { return 0; }
    unsafe {
        for i in 0..n {
            let idx = ((wp as usize) + i) % PIPE_BUF_SIZE;
            PIPE_BUF[pipe_id][idx] = data[i];
        }
    }
    PIPE_WRITE_POS[pipe_id].store(wp + n as u64, Ordering::Release);
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
