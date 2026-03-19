// ---------------------------------------------------------------------------
// SyscallContext: groups all per-process mutable state for syscall handlers.
// ---------------------------------------------------------------------------

use crate::fd::*;

/// Aggregated mutable references to per-process state.
/// Created once per syscall dispatch in child_handler, passed to sub-handlers.
/// Holds the per-group FD lock (ρ_repl) — released automatically on Drop.
pub(crate) struct SyscallContext<'a> {
    pub pid: usize,
    pub ep_cap: u64,
    /// FD group index — lock is held while this context is alive.
    pub guard_fdg: usize,

    /// If non-zero, this child has its own address space (CoW fork).
    /// All child memory reads/writes must use sys::vm_read/vm_write.
    pub child_as_cap: u64,

    // Memory management
    pub current_brk: &'a mut u64,
    pub mmap_next: &'a mut u64,
    pub my_brk_base: u64,
    pub my_mmap_base: u64,
    /// Memory group index (for VMA_LISTS access).
    pub memg: usize,

    // FD tables (shared via THREAD_GROUPS)
    pub child_fds: &'a mut [u8; GRP_MAX_FDS],
    pub fd_cloexec: &'a mut u128,
    pub initrd_files: &'a mut [[u64; 4]; GRP_MAX_INITRD],
    pub initrd_file_buf_base: u64,
    pub vfs_files: &'a mut [[u64; 4]; GRP_MAX_VFS],

    // Directory state
    pub dir_buf: &'a mut [u8; 4096],
    pub dir_len: &'a mut usize,
    pub dir_pos: &'a mut usize,
    pub cwd: &'a mut [u8; GRP_CWD_MAX],

    // Per-fd open flags (O_NONBLOCK etc.)
    pub fd_flags: &'a mut [u32; GRP_MAX_FDS],
    // Socket metadata (parallel arrays indexed by FD)
    pub sock_conn_id: &'a mut [u32; GRP_MAX_FDS],
    pub sock_udp_local_port: &'a mut [u16; GRP_MAX_FDS],
    pub sock_udp_remote_ip: &'a mut [u32; GRP_MAX_FDS],
    pub sock_udp_remote_port: &'a mut [u16; GRP_MAX_FDS],

    // eventfd state (kind=22)
    pub eventfd_counter: &'a mut [u64; MAX_EVENTFDS],
    pub eventfd_flags: &'a mut [u32; MAX_EVENTFDS],
    pub eventfd_slot_fd: &'a mut [usize; MAX_EVENTFDS],

    // timerfd state (kind=23)
    pub timerfd_interval_ns: &'a mut [u64; MAX_TIMERFDS],
    pub timerfd_expiry_tsc: &'a mut [u64; MAX_TIMERFDS],
    pub timerfd_slot_fd: &'a mut [usize; MAX_TIMERFDS],

    // memfd state (kind=25)
    pub memfd_base: &'a mut [u64; MAX_MEMFDS],
    pub memfd_size: &'a mut [u64; MAX_MEMFDS],
    pub memfd_cap: &'a mut [u64; MAX_MEMFDS],
    pub memfd_slot_fd: &'a mut [usize; MAX_MEMFDS],

    // epoll registration state
    pub epoll_reg_fd: &'a mut [i32; MAX_EPOLL_ENTRIES],
    pub epoll_reg_events: &'a mut [u32; MAX_EPOLL_ENTRIES],
    pub epoll_reg_data: &'a mut [u64; MAX_EPOLL_ENTRIES],
}

impl SyscallContext<'_> {
    /// Read bytes from the child's virtual memory into a local buffer.
    /// For same-AS children (child_as_cap==0), reads directly.
    /// For fork-children with their own AS, uses kernel vm_read.
    pub fn guest_read(&self, remote_ptr: u64, buf: &mut [u8]) {
        if self.child_as_cap == 0 || buf.is_empty() {
            unsafe {
                core::ptr::copy_nonoverlapping(remote_ptr as *const u8, buf.as_mut_ptr(), buf.len());
            }
        } else {
            // Read in chunks of up to 4096 bytes.
            // If vm_read fails (e.g. CoW page not yet faulted in by VMM),
            // yield to let the VMM handle pending faults and retry once.
            let mut done = 0;
            while done < buf.len() {
                let chunk = (buf.len() - done).min(4096);
                let r = sotos_common::sys::vm_read(
                    self.child_as_cap,
                    remote_ptr + done as u64,
                    buf[done..].as_mut_ptr() as u64,
                    chunk as u64,
                );
                if r.is_err() {
                    sotos_common::sys::yield_now();
                    let _ = sotos_common::sys::vm_read(
                        self.child_as_cap,
                        remote_ptr + done as u64,
                        buf[done..].as_mut_ptr() as u64,
                        chunk as u64,
                    );
                }
                done += chunk;
            }
        }
    }

    /// Write bytes from a local buffer into the child's virtual memory.
    /// For same-AS children, writes directly.
    /// For fork-children, uses kernel vm_write (handles CoW).
    pub fn guest_write(&self, remote_ptr: u64, data: &[u8]) {
        if self.child_as_cap == 0 || data.is_empty() {
            unsafe {
                core::ptr::copy_nonoverlapping(data.as_ptr(), remote_ptr as *mut u8, data.len());
            }
        } else {
            let mut done = 0;
            while done < data.len() {
                let chunk = (data.len() - done).min(4096);
                let _ = sotos_common::sys::vm_write(
                    self.child_as_cap,
                    remote_ptr + done as u64,
                    data[done..].as_ptr() as u64,
                    chunk as u64,
                );
                done += chunk;
            }
        }
    }

    /// Read a u64 from the child's memory.
    pub fn guest_read_u64(&self, remote_ptr: u64) -> u64 {
        let mut buf = [0u8; 8];
        self.guest_read(remote_ptr, &mut buf);
        u64::from_le_bytes(buf)
    }

    /// Map a frame into the child's address space.
    /// For same-AS children (child_as_cap==0), maps into init's AS.
    /// For separate-AS children, uses map_into.
    pub fn guest_map(&self, vaddr: u64, frame_cap: u64, flags: u64) -> Result<(), i64> {
        if self.child_as_cap == 0 {
            sotos_common::sys::map(vaddr, frame_cap, flags)
        } else {
            sotos_common::sys::map_into(self.child_as_cap, vaddr, frame_cap, flags)
        }
    }

    /// Unmap a page from the child's address space (frees the frame).
    /// For same-AS children, uses unmap_free on init's AS.
    /// For separate-AS children, uses unmap_from (frame leaked for now).
    pub fn guest_unmap(&self, vaddr: u64) {
        if self.child_as_cap == 0 {
            let _ = sotos_common::sys::unmap_free(vaddr);
        } else {
            let _ = sotos_common::sys::unmap_from(self.child_as_cap, vaddr);
        }
    }

    /// Zero-fill a page in the child's address space.
    pub fn guest_zero_page(&self, vaddr: u64) {
        if self.child_as_cap == 0 {
            unsafe { core::ptr::write_bytes(vaddr as *mut u8, 0, 4096); }
        } else {
            let zeros = [0u8; 4096];
            let _ = sotos_common::sys::vm_write(
                self.child_as_cap, vaddr, zeros.as_ptr() as u64, 4096,
            );
        }
    }

    /// Read a NUL-terminated path from the child's memory.
    /// Returns the length of the path (up to out.len() - 1).
    pub fn guest_copy_path(&self, guest_ptr: u64, out: &mut [u8]) -> usize {
        if guest_ptr == 0 || out.is_empty() { return 0; }
        // Read in small chunks, looking for NUL
        let max = out.len() - 1;
        let mut pos = 0;
        while pos < max {
            let chunk = (max - pos).min(64);
            self.guest_read(guest_ptr + pos as u64, &mut out[pos..pos + chunk]);
            // Check for NUL in the chunk we just read
            for i in pos..pos + chunk {
                if out[i] == 0 { return i; }
            }
            pos += chunk;
        }
        out[pos] = 0;
        pos
    }
}

/// RAII lock release: when SyscallContext is dropped (end of match arm,
/// break, continue, or return), the per-group FD lock is released.
/// guard_fdg == usize::MAX means no lock was acquired (skip unlock).
impl Drop for SyscallContext<'_> {
    fn drop(&mut self) {
        if self.guard_fdg < crate::process::MAX_PROCS {
            fd_grp_unlock(self.guard_fdg);
        }
    }
}

// Constants re-exported from fd.rs (authoritative source)
pub(crate) use crate::fd::{MAX_EVENTFDS, MAX_TIMERFDS, MAX_MEMFDS, MAX_EPOLL_ENTRIES};
