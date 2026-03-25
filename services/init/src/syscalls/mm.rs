// ---------------------------------------------------------------------------
// Memory management syscalls: brk, mmap, munmap, mprotect, mremap
// VMA tracking for /proc/self/maps and MAP_FIXED_NOREPLACE.
// ---------------------------------------------------------------------------

use sotos_common::sys;
use sotos_common::linux_abi::*;
use sotos_common::{IpcMsg, SyncUnsafeCell};
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

/// Per-process ntdll.so base address tracker (for Wine syscall dispatcher).
/// Set when we detect the initial ntdll.so reservation mmap.
pub(crate) static NTDLL_SO_BASE: SyncUnsafeCell<[u64; 16]> = SyncUnsafeCell::new([0; 16]);
/// Per-process fd that holds ntdll.so (Unix side). Set by openat handler.
pub(crate) static NTDLL_SO_FD: SyncUnsafeCell<[u8; 16]> = SyncUnsafeCell::new([0xFF; 16]);

/// Wine SharedUserData fixup: ensure PE ntdll.dll uses the indirect call
/// path (`call [0x7ffe1000]`) instead of the direct `syscall` instruction.
/// Per-process flag: set once we've confirmed the dispatcher pointer is valid.
static WINE_KUSD_DONE: SyncUnsafeCell<[bool; 16]> = SyncUnsafeCell::new([false; 16]);

fn wine_patch_shared_user_data(ctx: &mut SyscallContext, addr: u64) {
    // Only fire for addresses overlapping the KUSD pages (0x7ffe0000..0x7ffe2000)
    if addr > 0x7ffe1000 || addr + 0x1000 < 0x7ffe0000 { return; }
    if ctx.pid >= 16 { return; }
    if unsafe { (*WINE_KUSD_DONE.get())[ctx.pid] } { return; }

    // Read current SystemCall byte at offset 0x308
    let mut flag = [0u8; 1];
    ctx.guest_read(0x7ffe0308, &mut flag);
    print(b"WINE-KUSD P"); crate::framebuffer::print_u64(ctx.pid as u64);
    print(b" [0x308]="); crate::framebuffer::print_u64(flag[0] as u64);

    if flag[0] & 1 == 0 {
        ctx.guest_write(0x7ffe0308, &[1u8]);
        print(b" ->1");
    }

    // Set up dispatcher pointer at 0x7ffe1000
    let pid = ctx.pid;
    let ntdll_base = unsafe { (*NTDLL_SO_BASE.get())[pid] };
    if ntdll_base == 0 {
        print(b" NO-BASE\n");
        return;
    }
    // __wine_syscall_dispatcher at file offset 0x3caf4 in ntdll.so
    let disp_addr = ntdll_base + 0x3caf4;

    let mut disp_ptr = [0u8; 8];
    ctx.guest_read(0x7ffe1000, &mut disp_ptr);
    let ptr_val = u64::from_le_bytes(disp_ptr);
    print(b" disp="); crate::framebuffer::print_hex64(ptr_val);

    if ptr_val == 0 {
        // Try writing directly first (page may already be mapped by Wine)
        let ptr_bytes = disp_addr.to_le_bytes();
        ctx.guest_write(0x7ffe1000, &ptr_bytes);
        // Verify the write took
        ctx.guest_read(0x7ffe1000, &mut disp_ptr);
        let check = u64::from_le_bytes(disp_ptr);
        if check == disp_addr {
            print(b" wrote-disp="); crate::framebuffer::print_hex64(disp_addr);
            unsafe { (*WINE_KUSD_DONE.get())[ctx.pid] = true; }
        } else {
            // Page not mapped — allocate and map it
            if let Ok(f) = sys::frame_alloc() {
                if ctx.guest_map(0x7ffe1000, f, 2).is_ok() {
                    ctx.guest_zero_page(0x7ffe1000);
                    ctx.guest_write(0x7ffe1000, &ptr_bytes);
                    print(b" mapped-disp="); crate::framebuffer::print_hex64(disp_addr);
                    unsafe { (*WINE_KUSD_DONE.get())[ctx.pid] = true; }
                }
            }
        }
    } else if ptr_val != disp_addr {
        // Wine wrote something else — overwrite with correct dispatcher
        let ptr_bytes = disp_addr.to_le_bytes();
        ctx.guest_write(0x7ffe1000, &ptr_bytes);
        print(b" fix-disp="); crate::framebuffer::print_hex64(disp_addr);
        unsafe { (*WINE_KUSD_DONE.get())[ctx.pid] = true; }
    } else {
        unsafe { (*WINE_KUSD_DONE.get())[ctx.pid] = true; }
    }
    print(b"\n");
}
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
                if ctx.guest_map(pg, f, MAP_WRITABLE).is_err() { ok = false; break; }
            } else { ok = false; break; }
            pg += 0x1000;
        }
        if ok {
            // Zero new pages — Linux ABI requires brk-expanded memory to be zeroed.
            // Without this, recycled frames contain stale heap metadata that corrupts malloc.
            let mut zp = (old_brk + 0xFFF) & !0xFFF;
            while zp < new_brk {
                ctx.guest_zero_page(zp);
                zp += 0x1000;
            }
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

    // Suppress MMAP logging for NOREPLACE+PROT_NONE probes (Wine VA reservation
    // binary search generates thousands of these, flooding serial).
    let is_noreplace_probe = prot == 0 && (flags & MAP_FIXED_NOREPLACE_FLAG) != 0;
    if !is_noreplace_probe && ctx.pid >= 6 {
        print(b"MMAP P"); crate::framebuffer::print_u64(ctx.pid as u64);
        print(b" addr="); crate::framebuffer::print_hex64(req_addr);
        print(b" fd="); crate::framebuffer::print_u64(fd as u64);
        print(b" len="); crate::framebuffer::print_hex64(len);
        print(b" prot="); crate::framebuffer::print_u64(prot);
        print(b" fl="); crate::framebuffer::print_hex64(flags as u64);
        print(b"\n");
    }

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
            if ctx.pid == 3 {
                print(b"MMAP-FAIL P3 -EEXIST addr="); crate::framebuffer::print_hex64(req_addr);
                print(b" len="); crate::framebuffer::print_hex64(aligned_len);
                print(b"\n");
            }
            reply_val(ctx.ep_cap, -EEXIST);
            return;
        }
    }

    // Determine base address
    let base = if map_fixed && req_addr != 0 {
        if !map_noreplace {
            // MFIX-CLOB diagnostic removed (fires on every libc MAP_FIXED segment)
            // Regular MAP_FIXED: unmap existing pages first
            vma_remove(ctx.memg, req_addr, req_addr + aligned_len);
            for p in 0..pages {
                ctx.guest_unmap(req_addr + p * 0x1000);
            }
        }
        req_addr
    } else if req_addr != 0 {
        // Hint address: try it first, fall back to gap search
        let overlaps = unsafe { VMA_LISTS[ctx.memg].overlaps(req_addr, req_addr + aligned_len) };
        if !overlaps {
            req_addr
        } else {
            let b = unsafe { VMA_LISTS[ctx.memg].find_free(aligned_len, *ctx.mmap_next) }
                .unwrap_or(*ctx.mmap_next);
            let new_next = b + aligned_len;
            if new_next > *ctx.mmap_next {
                *ctx.mmap_next = new_next;
            }
            if ctx.pid > 0 && ctx.pid <= MAX_PROCS {
                PROCESSES[ctx.pid - 1].mmap_next.store(*ctx.mmap_next, Ordering::Release);
            }
            b
        }
    } else {
        // Dynamic allocation: find gap that doesn't overlap existing VMAs
        let b = unsafe { VMA_LISTS[ctx.memg].find_free(aligned_len, *ctx.mmap_next) }
            .unwrap_or(*ctx.mmap_next);
        let new_next = b + aligned_len;
        if new_next > *ctx.mmap_next {
            *ctx.mmap_next = new_next;
        }
        if ctx.pid > 0 && ctx.pid <= MAX_PROCS {
            PROCESSES[ctx.pid - 1].mmap_next.store(*ctx.mmap_next, Ordering::Release);
        }
        b
    };

    // Track ntdll.so load base: when we see a non-fixed file mmap matching
    // the ntdll.so fd, the returned base is the ELF load base.
    if !map_fixed && fd >= 0 && ctx.pid < 16 {
        let ntdll_fd = unsafe { (*NTDLL_SO_FD.get())[ctx.pid] };
        if ntdll_fd != 0xFF && fd as u8 == ntdll_fd {
            unsafe { (*NTDLL_SO_BASE.get())[ctx.pid] = base; }
            print(b"NTDLL-BASE P"); crate::framebuffer::print_u64(ctx.pid as u64);
            print(b" base="); crate::framebuffer::print_hex64(base);
            print(b"\n");
            // Re-trigger SharedUserData patch now that we know the ntdll base.
            // The 0x7ffe0000 mmap may have happened BEFORE ntdll base was known,
            // causing the patch to bail with "NO-BASE". Now we can compute the
            // correct dispatcher address.
            if !unsafe { (*WINE_KUSD_DONE.get())[ctx.pid] } {
                wine_patch_shared_user_data(ctx, 0x7ffe0000);
            }
        }
    }

    let prot_u8 = (prot & 7) as u8;
    let flags_u8 = (flags & 0xFF) as u8;

    // Lazy reservation: record VMA but don't allocate frames
    if lazy {
        vma_insert(ctx.memg, base, base + aligned_len, 0, flags_u8, VmaLabel::Reservation);
        reply_val(ctx.ep_cap, base as i64);
        return;
    }

    let mmap_fixup_prot = |base: u64, pages: u64, prot: u64, as_cap: u64| {
        if prot & 2 == 0 {
            let pflags = if prot & 4 != 0 { 0u64 } else { 1u64 << 63 };
            for p in 0..pages {
                if as_cap != 0 {
                    let _ = sys::protect_in(as_cap, base + p * 0x1000, pflags);
                } else {
                    let _ = sys::protect(base + p * 0x1000, pflags);
                }
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

        // DRM dumb buffer mmap: delegate to drm module
        if fdu < GRP_MAX_FDS && ctx.child_fds[fdu] == 30 {
            let ret = crate::drm::drm_mmap(ctx, offset, aligned_len, base);
            if ret >= 0 {
                vma_insert(ctx.memg, base, base + aligned_len, prot_u8, flags_u8, VmaLabel::Anonymous);
            }
            reply_val(ctx.ep_cap, ret);
            return;
        }

        if file_data == 0 && !is_vfs {
            if ctx.pid == 3 {
                print(b"MMAP-FAIL P3 -EBADF fd="); crate::framebuffer::print_u64(fd as u64);
                print(b" kind="); crate::framebuffer::print_u64(if fdu < GRP_MAX_FDS { ctx.child_fds[fdu] as u64 } else { 99 });
                print(b"\n");
            }
            reply_val(ctx.ep_cap, -EBADF);
            return;
        }

        let mut ok = true;
        for p in 0..pages {
            if let Ok(f) = sys::frame_alloc() {
                if ctx.guest_map(base + p * 0x1000, f, MAP_WRITABLE).is_err() {
                    ok = false; break;
                }
            } else {
                ok = false; break;
            }
        }
        if ok {
            let map_size = (pages * 0x1000) as usize;
            // Zero-fill all pages
            for p in 0..pages {
                ctx.guest_zero_page(base + p * 0x1000);
            }
            let file_off = offset as usize;
            let avail = if file_off < file_size as usize { file_size as usize - file_off } else { 0 };
            let to_copy = map_size.min(avail);

            if is_vfs && to_copy > 0 {
                // Read VFS data into local buffer, then write to child
                let mut vfs_done = 0usize;
                vfs_lock();
                while vfs_done < to_copy {
                    let chunk = (to_copy - vfs_done).min(4096);
                    let mut local_buf = [0u8; 4096];
                    let read_n = unsafe { shared_store() }
                        .and_then(|store| store.read_obj_range(vfs_oid, file_off + vfs_done, &mut local_buf[..chunk]).ok())
                        .unwrap_or(0);
                    if read_n == 0 { break; }
                    ctx.guest_write(base + vfs_done as u64, &local_buf[..read_n]);
                    vfs_done += read_n;
                }
                vfs_unlock();
            } else if to_copy > 0 {
                // Initrd file: data is in init's AS at file_data
                let src = unsafe { core::slice::from_raw_parts((file_data + file_off as u64) as *const u8, to_copy) };
                ctx.guest_write(base, src);
            }
            mmap_fixup_prot(base, pages, prot, ctx.child_as_cap);
            vma_insert(ctx.memg, base, base + aligned_len, prot_u8, flags_u8, label);
            wine_patch_shared_user_data(ctx, base);
            reply_val(ctx.ep_cap, base as i64);
        } else {
            if ctx.pid >= 3 {
                print(b"MMAP-FAIL P"); crate::framebuffer::print_u64(ctx.pid as u64);
                print(b" -ENOMEM(file) pages="); crate::framebuffer::print_u64(pages);
                print(b"\n");
            }
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
        if ctx.guest_map(base + p * 0x1000, f, MAP_WRITABLE).is_err() {
            ok = false; break;
        }
    }
    if ok {
        for p in 0..pages {
            ctx.guest_zero_page(base + p * 0x1000);
        }
        mmap_fixup_prot(base, pages, prot, ctx.child_as_cap);
        vma_insert(ctx.memg, base, base + aligned_len, prot_u8, flags_u8, VmaLabel::Anonymous);
        wine_patch_shared_user_data(ctx, base);
        reply_val(ctx.ep_cap, base as i64);
    } else {
        if ctx.pid >= 3 {
            let free = sys::debug_free_frames();
            print(b"MMAP-FAIL P"); crate::framebuffer::print_u64(ctx.pid as u64);
            print(b" -ENOMEM(anon) pg="); crate::framebuffer::print_u64(pages);
            print(b" base="); crate::framebuffer::print_hex64(base);
            print(b" free="); crate::framebuffer::print_u64(free);
            print(b"\n");
        }
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
                if ctx.guest_map(addr + p * 0x1000, f, MAP_WRITABLE).is_err() { ok = false; break; }
            } else { ok = false; break; }
        }
        if ok {
            for p in 0..pages {
                ctx.guest_zero_page(addr + p * 0x1000);
            }
        } else {
            reply_val(ctx.ep_cap, -ENOMEM);
            return;
        }
    }

    // Wine SharedUserData: re-patch before making the page read-only
    if addr <= 0x7ffe0000 && aligned_end > 0x7ffe0000 {
        wine_patch_shared_user_data(ctx, 0x7ffe0000);
    }

    {
        let flags = if prot & 2 != 0 {
            MAP_WRITABLE
        } else if prot & 4 != 0 {
            0u64
        } else {
            1u64 << 63
        };
        for p in 0..pages {
            if ctx.child_as_cap != 0 {
                let _ = sys::protect_in(ctx.child_as_cap, addr + p * 0x1000, flags);
            } else {
                let _ = sys::protect(addr + p * 0x1000, flags);
            }
        }
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
        // MUNM-CLOB diagnostic removed
        for p in 0..pages {
            ctx.guest_unmap(addr + p * 0x1000);
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

/// SYS_MADVISE (28): memory advisory hints.
///
/// MADV_DONTNEED zeroes the pages (Linux semantics for private anonymous mappings).
/// Other hints are accepted but treated as no-ops.
pub(crate) fn sys_madvise(ctx: &mut SyscallContext, msg: &IpcMsg) {
    let addr = msg.regs[0];
    let len = msg.regs[1];
    let advice = msg.regs[2] as u32;

    // Validate alignment
    if addr & 0xFFF != 0 {
        reply_val(ctx.ep_cap, -EINVAL);
        return;
    }

    match advice {
        MADV_DONTNEED => {
            // Zero the affected pages (Linux semantics: subsequent reads return zero).
            let pages = (len + 0xFFF) / 0x1000;
            for p in 0..pages {
                ctx.guest_zero_page(addr + p * 0x1000);
            }
            reply_val(ctx.ep_cap, 0);
        }
        MADV_NORMAL | MADV_RANDOM | MADV_SEQUENTIAL | MADV_WILLNEED
        | MADV_FREE | MADV_HUGEPAGE | MADV_NOHUGEPAGE => {
            // Accept but ignore advisory hints.
            reply_val(ctx.ep_cap, 0);
        }
        _ => reply_val(ctx.ep_cap, -EINVAL),
    }
}

// ─── SysV Shared Memory ─────────────────────────────────────────

const MAX_SHM_SEGMENTS: usize = 32;
/// Maximum size per SHM segment (4 MiB).
const SHM_MAX_SIZE: u64 = 4 * 1024 * 1024;

/// A SysV shared memory segment.
struct ShmSegment {
    active: bool,
    key: u32,
    size: u64,
    /// Physical frames backing this segment.
    frames: [u64; 1024], // up to 4 MiB
    frame_count: usize,
    /// Virtual address where this is mapped (per-process, simplified).
    mapped_addr: [u64; 16], // per-pid
}

static SHM_SEGMENTS: SyncUnsafeCell<[ShmSegment; MAX_SHM_SEGMENTS]> = {
    const EMPTY: ShmSegment = ShmSegment {
        active: false, key: 0, size: 0,
        frames: [0; 1024], frame_count: 0,
        mapped_addr: [0; 16],
    };
    SyncUnsafeCell::new([EMPTY; MAX_SHM_SEGMENTS])
};

/// SYS_SHMGET (29): create or get a SysV shared memory segment.
pub(crate) fn sys_shmget(ctx: &mut SyscallContext, msg: &IpcMsg) {
    let key = msg.regs[0] as u32;
    let size = msg.regs[1];
    let flags = msg.regs[2] as u32;

    unsafe {
        // Check if segment with this key already exists
        if key != 0 {
            for i in 0..MAX_SHM_SEGMENTS {
                if (*SHM_SEGMENTS.get())[i].active && (*SHM_SEGMENTS.get())[i].key == key {
                    if flags & IPC_CREAT != 0 && flags & IPC_EXCL != 0 {
                        reply_val(ctx.ep_cap, -EEXIST);
                        return;
                    }
                    reply_val(ctx.ep_cap, i as i64);
                    return;
                }
            }
        }

        if size == 0 || size > SHM_MAX_SIZE {
            reply_val(ctx.ep_cap, -EINVAL);
            return;
        }

        // Allocate a new segment
        let slot = match (0..MAX_SHM_SEGMENTS).find(|&i| !(*SHM_SEGMENTS.get())[i].active) {
            Some(s) => s,
            None => { reply_val(ctx.ep_cap, -ENOSPC); return; }
        };

        let pages = ((size + 0xFFF) & !0xFFF) / 0x1000;
        let seg = &mut (*SHM_SEGMENTS.get())[slot];
        seg.frame_count = 0;

        for _ in 0..pages {
            match sys::frame_alloc() {
                Ok(f) => {
                    seg.frames[seg.frame_count] = f;
                    seg.frame_count += 1;
                }
                Err(_) => {
                    // Free already-allocated frames
                    for j in 0..seg.frame_count {
                        let _ = sys::frame_free(seg.frames[j]);
                    }
                    seg.frame_count = 0;
                    reply_val(ctx.ep_cap, -ENOMEM);
                    return;
                }
            }
        }

        seg.active = true;
        seg.key = key;
        seg.size = size;
        seg.mapped_addr = [0; 16];
        reply_val(ctx.ep_cap, slot as i64);
    }
}

/// SYS_SHMAT (30): attach a SysV SHM segment to the process address space.
pub(crate) fn sys_shmat(ctx: &mut SyscallContext, msg: &IpcMsg) {
    let shmid = msg.regs[0] as usize;
    let shmaddr = msg.regs[1];
    let _shmflg = msg.regs[2] as u32;

    unsafe {
        if shmid >= MAX_SHM_SEGMENTS || !(*SHM_SEGMENTS.get())[shmid].active {
            reply_val(ctx.ep_cap, -EINVAL);
            return;
        }

        let seg = &mut (*SHM_SEGMENTS.get())[shmid];

        // Determine mapping address
        let map_addr = if shmaddr != 0 {
            shmaddr & !0xFFF
        } else {
            // Use mmap_next for automatic placement
            let addr = *ctx.mmap_next;
            *ctx.mmap_next += (seg.frame_count as u64) * 0x1000;
            if ctx.pid > 0 && ctx.pid <= MAX_PROCS {
                PROCESSES[ctx.pid - 1].mmap_next.store(*ctx.mmap_next, Ordering::Release);
            }
            addr
        };

        // Map the SHM frames into the process address space
        for i in 0..seg.frame_count {
            if ctx.guest_map(map_addr + (i as u64) * 0x1000, seg.frames[i], MAP_WRITABLE).is_err() {
                reply_val(ctx.ep_cap, -ENOMEM);
                return;
            }
        }

        // Zero the pages on first attach
        for i in 0..seg.frame_count {
            ctx.guest_zero_page(map_addr + (i as u64) * 0x1000);
        }

        if ctx.pid < 16 {
            seg.mapped_addr[ctx.pid] = map_addr;
        }

        reply_val(ctx.ep_cap, map_addr as i64);
    }
}

/// SYS_SHMCTL (31): SysV SHM control operations.
pub(crate) fn sys_shmctl(ctx: &mut SyscallContext, msg: &IpcMsg) {
    let shmid = msg.regs[0] as usize;
    let cmd = msg.regs[1] as u32;

    unsafe {
        if shmid >= MAX_SHM_SEGMENTS || !(*SHM_SEGMENTS.get())[shmid].active {
            reply_val(ctx.ep_cap, -EINVAL);
            return;
        }

        match cmd {
            IPC_RMID => {
                let seg = &mut (*SHM_SEGMENTS.get())[shmid];
                // Free physical frames
                for i in 0..seg.frame_count {
                    let _ = sys::frame_free(seg.frames[i]);
                }
                seg.active = false;
                seg.frame_count = 0;
                reply_val(ctx.ep_cap, 0);
            }
            IPC_STAT => {
                // Write a zeroed shmid_ds to userspace (88 bytes on x86_64)
                let buf = msg.regs[2];
                if buf != 0 {
                    let seg = &(*SHM_SEGMENTS.get())[shmid];
                    let mut ds = [0u8; 88];
                    // shm_segsz at offset 48 (u64)
                    ds[48..56].copy_from_slice(&seg.size.to_le_bytes());
                    ctx.guest_write(buf, &ds);
                }
                reply_val(ctx.ep_cap, 0);
            }
            _ => reply_val(ctx.ep_cap, -EINVAL),
        }
    }
}

/// Format dynamic /proc/self/maps content for a memory group.
/// Called from open_virtual_file when /proc/self/maps is opened.
pub(crate) fn format_proc_maps(memg: usize, buf: &mut [u8]) -> usize {
    unsafe { VMA_LISTS[memg].format_maps(buf) }
}

// Constant re-exported for brk limit calculation
pub(crate) const CHILD_MMAP_OFFSET: u64 = 0x1000000;
