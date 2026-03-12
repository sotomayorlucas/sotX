// ---------------------------------------------------------------------------
// Memory management syscalls: brk, mmap, munmap, mprotect, mremap
// VMA tracking for /proc/self/maps and MAP_FIXED_NOREPLACE.
// ---------------------------------------------------------------------------

use sotos_common::sys;
use sotos_common::linux_abi::*;
use sotos_common::IpcMsg;
use core::sync::atomic::Ordering;
use crate::exec::reply_val;
use crate::process::*;
use crate::fd::*;
use crate::{vfs_lock, vfs_unlock, shared_store};
use crate::framebuffer::print;
use crate::vma::{VMA_LISTS, VmaLabel};
use super::context::SyscallContext;

/// MAP_FIXED_NOREPLACE flag (Linux 4.17+). If the range overlaps an
/// existing mapping, return -EEXIST instead of replacing it.
const MAP_FIXED_NOREPLACE_FLAG: u32 = 0x100000;
/// MAP_NORESERVE: don't reserve swap (we treat as hint for lazy alloc).
const MAP_NORESERVE_FLAG: u32 = 0x4000;

const MAP_WRITABLE: u64 = 2;

/// Helper: record a VMA for the given memory group.
fn vma_insert(memg: usize, start: u64, end: u64, prot: u8, flags: u8, label: VmaLabel) {
    unsafe { VMA_LISTS[memg].insert(start, end, prot, flags, label); }
}

/// Helper: remove VMAs in [start, end) for the given memory group.
fn vma_remove(memg: usize, start: u64, end: u64) {
    unsafe { VMA_LISTS[memg].remove(start, end); }
}

/// SYS_BRK (12): expand/query the program break.
pub(crate) fn sys_brk(ctx: &mut SyscallContext, msg: &IpcMsg) {
    let addr = msg.regs[0];
    let brk_limit = ctx.my_brk_base + CHILD_MMAP_OFFSET;

    if addr == 0 || addr <= *ctx.current_brk {
        reply_val(ctx.ep_cap, *ctx.current_brk as i64);
    } else {
        let new_brk = (addr + 0xFFF) & !0xFFF;
        if new_brk > brk_limit {
            reply_val(ctx.ep_cap, *ctx.current_brk as i64);
            return;
        }
        let old_brk = *ctx.current_brk;
        let mut ok = true;
        let mut pg = (old_brk + 0xFFF) & !0xFFF;
        while pg < new_brk {
            if let Ok(f) = sys::frame_alloc() {
                if sys::map(pg, f, MAP_WRITABLE).is_err() { ok = false; break; }
            } else { ok = false; break; }
            pg += 0x1000;
        }
        if ok {
            *ctx.current_brk = new_brk;
            if ctx.pid > 0 && ctx.pid <= MAX_PROCS {
                PROCESSES[ctx.pid - 1].brk_current.store(new_brk, Ordering::Release);
            }
            // Update heap VMA
            let heap_start = ctx.my_brk_base & !0xFFF;
            vma_remove(ctx.memg, heap_start, new_brk);
            vma_insert(ctx.memg, heap_start, new_brk, 3, 0x22, VmaLabel::Heap); // rw-p, PRIVATE|ANON
        }
        reply_val(ctx.ep_cap, *ctx.current_brk as i64);
    }
}

/// SYS_MMAP (9): map anonymous or file-backed pages.
pub(crate) fn sys_mmap(ctx: &mut SyscallContext, msg: &IpcMsg) {
    let req_addr = msg.regs[0];
    let len = msg.regs[1];
    let prot = msg.regs[2];
    let flags = msg.regs[3] as u32;
    let fd = msg.regs[4] as i64;
    let offset = msg.regs[5];

    let mflags = MFlags::from_bits_truncate(flags);
    let map_fixed = mflags.contains(MFlags::FIXED) || (flags & MAP_FIXED_NOREPLACE_FLAG) != 0;
    let map_anon = mflags.contains(MFlags::ANONYMOUS);
    let map_noreplace = (flags & MAP_FIXED_NOREPLACE_FLAG) != 0;
    let map_noreserve = (flags & MAP_NORESERVE_FLAG) != 0;
    let aligned_len = (len + 0xFFF) & !0xFFF;
    let pages = aligned_len / 0x1000;

    // PROT_NONE + MAP_NORESERVE: reservation only (no physical frames).
    // Wine uses this to reserve large address ranges (e.g. 32GB for 32-bit PE space).
    let lazy = prot == 0 && map_anon && map_noreserve;

    // MAP_FIXED_NOREPLACE: check for overlaps before anything else
    if map_noreplace && req_addr != 0 {
        let overlaps = unsafe { VMA_LISTS[ctx.memg].overlaps(req_addr, req_addr + aligned_len) };
        if overlaps {
            reply_val(ctx.ep_cap, -EEXIST);
            return;
        }
    }

    // Determine base address
    let base = if map_fixed && req_addr != 0 {
        if !map_noreplace {
            // Regular MAP_FIXED: unmap existing pages first
            vma_remove(ctx.memg, req_addr, req_addr + aligned_len);
            for p in 0..pages {
                let _ = sys::unmap_free(req_addr + p * 0x1000);
            }
        }
        req_addr
    } else if req_addr != 0 {
        // Hint address: try it first, fall back to bump allocator
        let overlaps = unsafe { VMA_LISTS[ctx.memg].overlaps(req_addr, req_addr + aligned_len) };
        if !overlaps {
            req_addr
        } else {
            let b = *ctx.mmap_next;
            *ctx.mmap_next += aligned_len;
            if ctx.pid > 0 && ctx.pid <= MAX_PROCS {
                PROCESSES[ctx.pid - 1].mmap_next.store(*ctx.mmap_next, Ordering::Release);
            }
            b
        }
    } else {
        let b = *ctx.mmap_next;
        *ctx.mmap_next += aligned_len;
        if ctx.pid > 0 && ctx.pid <= MAX_PROCS {
            PROCESSES[ctx.pid - 1].mmap_next.store(*ctx.mmap_next, Ordering::Release);
        }
        b
    };

    let prot_u8 = (prot & 7) as u8;
    let flags_u8 = (flags & 0xFF) as u8;

    // Lazy reservation: record VMA but don't allocate frames
    if lazy {
        vma_insert(ctx.memg, base, base + aligned_len, 0, flags_u8, VmaLabel::Reservation);
        reply_val(ctx.ep_cap, base as i64);
        return;
    }

    let mmap_fixup_prot = |base: u64, pages: u64, prot: u64| {
        if prot & 2 == 0 {
            let pflags = if prot & 4 != 0 { 0u64 } else { 1u64 << 63 };
            for p in 0..pages {
                let _ = sys::protect(base + p * 0x1000, pflags);
            }
        }
    };

    let label = if fd >= 0 && !map_anon { VmaLabel::Library } else { VmaLabel::Anonymous };

    if fd >= 0 && !map_anon {
        // File-backed mmap
        let fdu = fd as usize;
        let mut file_data: u64 = 0;
        let mut file_size: u64 = 0;
        let mut is_vfs = false;
        let mut vfs_oid: u64 = 0;

        if fdu < GRP_MAX_FDS {
            if ctx.child_fds[fdu] == 12 {
                for s in 0..GRP_MAX_INITRD {
                    if ctx.initrd_files[s][0] != 0
                        && ctx.initrd_files[s][3] == fdu as u64
                    {
                        file_data = ctx.initrd_files[s][0];
                        file_size = ctx.initrd_files[s][1];
                        break;
                    }
                }
                if file_data == 0 {
                    for s in 0..GRP_MAX_INITRD {
                        if ctx.initrd_files[s][0] != 0
                            && ctx.initrd_files[s][3] == u64::MAX
                        {
                            file_data = ctx.initrd_files[s][0];
                            file_size = ctx.initrd_files[s][1];
                            break;
                        }
                    }
                }
            }
            if file_data == 0 && ctx.child_fds[fdu] == 13 {
                for s in 0..GRP_MAX_VFS {
                    if ctx.vfs_files[s][0] != 0 && ctx.vfs_files[s][3] == fdu as u64 {
                        vfs_oid = ctx.vfs_files[s][0];
                        file_size = ctx.vfs_files[s][1];
                        is_vfs = true;
                        break;
                    }
                }
            }
        }

        if file_data == 0 && !is_vfs {
            reply_val(ctx.ep_cap, -EBADF);
            return;
        }

        let mut ok = true;
        for p in 0..pages {
            if let Ok(f) = sys::frame_alloc() {
                if sys::map(base + p * 0x1000, f, MAP_WRITABLE).is_err() {
                    ok = false; break;
                }
            } else {
                ok = false; break;
            }
        }
        if ok {
            let map_size = (pages * 0x1000) as usize;
            unsafe { core::ptr::write_bytes(base as *mut u8, 0, map_size); }
            let file_off = offset as usize;
            let avail = if file_off < file_size as usize { file_size as usize - file_off } else { 0 };
            let to_copy = map_size.min(avail);

            if is_vfs && to_copy > 0 {
                let dst = unsafe { core::slice::from_raw_parts_mut(base as *mut u8, to_copy) };
                vfs_lock();
                let read_result = unsafe { shared_store() }
                    .and_then(|store| store.read_obj_range(vfs_oid, file_off, dst).ok());
                vfs_unlock();

                if read_result.is_none() {
                    for p in 0..pages {
                        let _ = sys::unmap_free(base + p * 0x1000);
                    }
                    reply_val(ctx.ep_cap, -EIO);
                    return;
                }
            } else if to_copy > 0 {
                unsafe {
                    core::ptr::copy_nonoverlapping(
                        (file_data + file_off as u64) as *const u8,
                        base as *mut u8,
                        to_copy,
                    );
                }
            }
            mmap_fixup_prot(base, pages, prot);
            vma_insert(ctx.memg, base, base + aligned_len, prot_u8, flags_u8, label);
            reply_val(ctx.ep_cap, base as i64);
        } else {
            reply_val(ctx.ep_cap, -ENOMEM);
        }
        return;
    }

    // Anonymous mmap
    let mut ok = true;
    for p in 0..pages {
        let f = match sys::frame_alloc() {
            Ok(f) => f,
            Err(_) => { ok = false; break; }
        };
        if sys::map(base + p * 0x1000, f, MAP_WRITABLE).is_err() {
            ok = false; break;
        }
    }
    if ok {
        unsafe { core::ptr::write_bytes(base as *mut u8, 0, (pages * 0x1000) as usize); }
        mmap_fixup_prot(base, pages, prot);
        vma_insert(ctx.memg, base, base + aligned_len, prot_u8, flags_u8, VmaLabel::Anonymous);
        reply_val(ctx.ep_cap, base as i64);
    } else {
        reply_val(ctx.ep_cap, -ENOMEM);
    }
}

/// SYS_MPROTECT (10): change page permissions.
pub(crate) fn sys_mprotect(ctx: &mut SyscallContext, msg: &IpcMsg) {
    let addr = msg.regs[0] & !0xFFF;
    let len = msg.regs[1];
    let prot = msg.regs[2];
    let pages = ((len + 0xFFF) & !0xFFF) / 0x1000;
    let aligned_end = addr + pages * 0x1000;

    // If changing from PROT_NONE to something with frames, we may need to
    // allocate frames for lazy reservations.  Check if the VMA is a Reservation.
    let is_reservation = unsafe {
        let vl = &VMA_LISTS[ctx.memg];
        let mut found = false;
        for i in 0..vl.count {
            let v = &vl.entries[i];
            if v.start >= aligned_end { break; }
            if v.end > addr && v.label == VmaLabel::Reservation {
                found = true;
                break;
            }
        }
        found
    };

    if is_reservation && prot != 0 {
        // Materialize the lazy reservation: allocate frames
        let mut ok = true;
        for p in 0..pages {
            if let Ok(f) = sys::frame_alloc() {
                if sys::map(addr + p * 0x1000, f, MAP_WRITABLE).is_err() { ok = false; break; }
            } else { ok = false; break; }
        }
        if ok {
            unsafe { core::ptr::write_bytes(addr as *mut u8, 0, (pages * 0x1000) as usize); }
        } else {
            reply_val(ctx.ep_cap, -ENOMEM);
            return;
        }
    }

    let flags = if prot & 2 != 0 {
        MAP_WRITABLE
    } else if prot & 4 != 0 {
        0u64
    } else {
        1u64 << 63
    };
    for p in 0..pages {
        let _ = sys::protect(addr + p * 0x1000, flags);
    }

    // Update VMA prot bits
    unsafe { VMA_LISTS[ctx.memg].update_prot(addr, aligned_end, (prot & 7) as u8); }
    // If was a reservation, change label to Anonymous
    if is_reservation {
        unsafe {
            for i in 0..VMA_LISTS[ctx.memg].count {
                let v = &mut VMA_LISTS[ctx.memg].entries[i];
                if v.start >= aligned_end { break; }
                if v.end > addr && v.label == VmaLabel::Reservation {
                    v.label = VmaLabel::Anonymous;
                }
            }
        }
    }

    reply_val(ctx.ep_cap, 0);
}

/// SYS_MUNMAP (11): unmap pages and free frames.
pub(crate) fn sys_munmap(ctx: &mut SyscallContext, msg: &IpcMsg) {
    let addr = msg.regs[0];
    let len = msg.regs[1];
    let pages = ((len + 0xFFF) & !0xFFF) / 0x1000;
    let aligned_end = addr + pages * 0x1000;

    // Check if any part is a reservation (no frames to free)
    let is_reservation = unsafe {
        let vl = &VMA_LISTS[ctx.memg];
        let mut found = false;
        for i in 0..vl.count {
            let v = &vl.entries[i];
            if v.start >= aligned_end { break; }
            if v.end > addr && v.label == VmaLabel::Reservation {
                found = true;
                break;
            }
        }
        found
    };

    if !is_reservation {
        for p in 0..pages {
            let _ = sys::unmap_free(addr + p * 0x1000);
        }
    }

    vma_remove(ctx.memg, addr, aligned_end);

    let freed_end = addr + pages * 0x1000;
    if freed_end == *ctx.mmap_next {
        *ctx.mmap_next = addr;
    }
    reply_val(ctx.ep_cap, 0);
}

/// SYS_MREMAP (25): remap/resize an existing mapping.
pub(crate) fn sys_mremap(ctx: &mut SyscallContext, msg: &IpcMsg) {
    let old_addr = msg.regs[0];
    let old_size = msg.regs[1];
    let new_size = msg.regs[2];
    let flags = msg.regs[3] as u32;
    let mremap_maymove = (flags & 1) != 0;

    if new_size <= old_size {
        // Shrink
        let old_pages = ((old_size + 0xFFF) & !0xFFF) / 0x1000;
        let new_pages = ((new_size + 0xFFF) & !0xFFF) / 0x1000;
        for p in new_pages..old_pages {
            let _ = sys::unmap_free(old_addr + p * 0x1000);
        }
        let new_end = old_addr + new_pages * 0x1000;
        let old_end = old_addr + old_pages * 0x1000;
        // Shrink VMA
        vma_remove(ctx.memg, new_end, old_end);
        if old_end == *ctx.mmap_next {
            *ctx.mmap_next = new_end;
        }
        reply_val(ctx.ep_cap, old_addr as i64);
    } else if mremap_maymove {
        let old_pages = ((old_size + 0xFFF) & !0xFFF) / 0x1000;
        let new_pages = ((new_size + 0xFFF) & !0xFFF) / 0x1000;
        let old_end = old_addr + old_pages * 0x1000;
        let new_aligned = new_pages * 0x1000;

        if old_end == *ctx.mmap_next {
            // In-place growth
            let extra_pages = new_pages - old_pages;
            let mut ok = true;
            for p in 0..extra_pages {
                if let Ok(f) = sys::frame_alloc() {
                    if sys::map(*ctx.mmap_next + p * 0x1000, f, MAP_WRITABLE).is_err() { ok = false; break; }
                } else { ok = false; break; }
            }
            if ok {
                unsafe { core::ptr::write_bytes(*ctx.mmap_next as *mut u8, 0, (extra_pages * 0x1000) as usize); }
                *ctx.mmap_next += extra_pages * 0x1000;
                if ctx.pid > 0 && ctx.pid <= MAX_PROCS {
                    PROCESSES[ctx.pid - 1].mmap_next.store(*ctx.mmap_next, Ordering::Release);
                }
                // Extend VMA
                vma_remove(ctx.memg, old_addr, *ctx.mmap_next);
                vma_insert(ctx.memg, old_addr, old_addr + new_aligned, 3, 0x22, VmaLabel::Anonymous);
                reply_val(ctx.ep_cap, old_addr as i64);
            } else {
                reply_val(ctx.ep_cap, -ENOMEM);
            }
        } else {
            // Allocate new region, copy, unmap old
            let new_base = *ctx.mmap_next;
            *ctx.mmap_next += new_aligned;
            let mut ok = true;
            for p in 0..new_pages {
                if let Ok(f) = sys::frame_alloc() {
                    if sys::map(new_base + p * 0x1000, f, MAP_WRITABLE).is_err() { ok = false; break; }
                } else { ok = false; break; }
            }
            if ok {
                let copy_size = old_size.min(new_size) as usize;
                unsafe {
                    core::ptr::write_bytes(new_base as *mut u8, 0, (new_aligned) as usize);
                    core::ptr::copy_nonoverlapping(old_addr as *const u8, new_base as *mut u8, copy_size);
                }
                for p in 0..old_pages { let _ = sys::unmap_free(old_addr + p * 0x1000); }
                if ctx.pid > 0 && ctx.pid <= MAX_PROCS {
                    PROCESSES[ctx.pid - 1].mmap_next.store(*ctx.mmap_next, Ordering::Release);
                }
                // Update VMAs
                vma_remove(ctx.memg, old_addr, old_end);
                vma_insert(ctx.memg, new_base, new_base + new_aligned, 3, 0x22, VmaLabel::Anonymous);
                reply_val(ctx.ep_cap, new_base as i64);
            } else {
                reply_val(ctx.ep_cap, -ENOMEM);
            }
        }
    } else {
        reply_val(ctx.ep_cap, -ENOMEM);
    }
}

/// Format dynamic /proc/self/maps content for a memory group.
/// Called from open_virtual_file when /proc/self/maps is opened.
pub(crate) fn format_proc_maps(memg: usize, buf: &mut [u8]) -> usize {
    unsafe { VMA_LISTS[memg].format_maps(buf) }
}

// Constant re-exported for brk limit calculation
pub(crate) const CHILD_MMAP_OFFSET: u64 = 0x1000000;
