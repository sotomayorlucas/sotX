//! Memory management syscall handlers: frame allocation, mapping, VM operations.

use crate::arch::x86_64::syscall::TrapFrame;
use crate::cap::{self, CapId, CapObject, Rights};
use crate::fault;
use crate::kdebug;
use crate::mm::paging::{
    self, AddressSpace, PAGE_NO_EXECUTE, PAGE_PRESENT, PAGE_USER, PAGE_WRITABLE,
};
use crate::mm::{self, PhysFrame};
use crate::sched;
use sotos_common::SysError;

use super::{
    SYS_ADDR_SPACE_CREATE, SYS_AS_CLONE, SYS_FRAME_ALLOC, SYS_FRAME_ALLOC_CONTIG, SYS_FRAME_COPY,
    SYS_FRAME_FREE, SYS_FRAME_PHYS, SYS_MAP, SYS_MAP_INTO, SYS_MAP_OFFSET, SYS_PROTECT,
    SYS_PROTECT_IN, SYS_PTE_READ, SYS_UNMAP, SYS_UNMAP_FREE, SYS_UNMAP_FROM, SYS_VM_READ,
    SYS_VM_WRITE, SYS_WX_RELAX, USER_ADDR_LIMIT, USER_FLAG_MASK,
};

/// Handle memory management syscalls. Returns `true` if the syscall was handled.
pub fn handle(frame: &mut TrapFrame, nr: u64) -> bool {
    match nr {
        // SYS_FRAME_ALLOC — allocate a physical frame, return cap_id
        SYS_FRAME_ALLOC => {
            // Check per-process memory limit.
            if !sched::track_mem_alloc() {
                frame.rax = SysError::OutOfResources as i64 as u64;
            } else {
                match mm::alloc_frame() {
                    Some(f) => {
                        // Zero the page via HHDM so physical memory is clean.
                        let hhdm = mm::hhdm_offset();
                        unsafe {
                            core::ptr::write_bytes((f.addr() + hhdm) as *mut u8, 0, 4096);
                        }
                        match cap::insert(
                            CapObject::Memory {
                                base: f.addr(),
                                size: 4096,
                            },
                            Rights::ALL,
                            None,
                        ) {
                            Some(cap_id) => frame.rax = cap_id.raw() as u64,
                            None => {
                                mm::free_frame(f);
                                sched::track_mem_free();
                                frame.rax = SysError::OutOfResources as i64 as u64;
                            }
                        }
                    }
                    None => {
                        sched::track_mem_free();
                        frame.rax = SysError::OutOfResources as i64 as u64;
                    }
                }
            }
        }

        // SYS_FRAME_FREE — free a physical frame (cap_id in rdi, requires WRITE)
        SYS_FRAME_FREE => match cap::validate(frame.rdi as u32, Rights::WRITE) {
            Ok(CapObject::Memory { base, .. }) => {
                mm::free_frame(PhysFrame::from_addr(base));
                cap::revoke(CapId::new(frame.rdi as u32));
                frame.rax = 0;
            }
            Ok(_) => frame.rax = SysError::InvalidCap as i64 as u64,
            Err(e) => frame.rax = e as i64 as u64,
        },

        // SYS_MAP — map a frame into the caller's address space
        // rdi = vaddr, rsi = frame_cap_id, rdx = user_flags
        SYS_MAP => {
            let vaddr = frame.rdi;
            let frame_cap = frame.rsi as u32;
            let user_flags = frame.rdx;

            match cap::validate(frame_cap, Rights::READ) {
                Ok(CapObject::Memory { base: paddr, .. }) => {
                    if vaddr & 0xFFF != 0 || vaddr >= USER_ADDR_LIMIT {
                        kdebug!("SYS_MAP: InvalidArg vaddr={:#x}", vaddr);
                        frame.rax = SysError::InvalidArg as i64 as u64;
                    } else {
                        let mut flags = PAGE_PRESENT | PAGE_USER | (user_flags & USER_FLAG_MASK);
                        let cr3 = paging::read_cr3();
                        // W^X: writable pages are never executable (unless relaxed)
                        if flags & PAGE_WRITABLE != 0
                            && flags & PAGE_NO_EXECUTE == 0
                            && !paging::is_wx_relaxed(cr3)
                        {
                            flags |= PAGE_NO_EXECUTE;
                        }
                        let aspace = AddressSpace::from_cr3(cr3);
                        aspace.map_page(vaddr, paddr, flags);
                        paging::invlpg(vaddr);
                        frame.rax = 0;
                    }
                }
                Ok(_) => {
                    kdebug!("SYS_MAP: cap {} is not Memory", frame_cap);
                    frame.rax = SysError::InvalidCap as i64 as u64;
                }
                Err(e) => {
                    kdebug!("SYS_MAP: validate cap={} failed: {:?}", frame_cap, e);
                    frame.rax = e as i64 as u64;
                }
            }
        }

        // SYS_UNMAP — unmap a page from the caller's address space (no cap needed)
        SYS_UNMAP => {
            let vaddr = frame.rdi;
            if vaddr & 0xFFF != 0 || vaddr >= USER_ADDR_LIMIT {
                frame.rax = SysError::InvalidArg as i64 as u64;
            } else {
                let cr3 = paging::read_cr3();
                let aspace = AddressSpace::from_cr3(cr3);
                if aspace.unmap_page(vaddr) {
                    paging::invlpg(vaddr);
                    frame.rax = 0;
                } else {
                    frame.rax = SysError::NotFound as i64 as u64;
                }
            }
        }

        // SYS_UNMAP_FREE — unmap + free physical frame in one step
        SYS_UNMAP_FREE => {
            let vaddr = frame.rdi;
            if vaddr & 0xFFF != 0 || vaddr >= USER_ADDR_LIMIT {
                frame.rax = SysError::InvalidArg as i64 as u64;
            } else {
                let cr3 = paging::read_cr3();
                let aspace = AddressSpace::from_cr3(cr3);
                if let Some(phys) = aspace.unmap_page_phys(vaddr) {
                    paging::invlpg(vaddr);
                    mm::free_frame(PhysFrame::from_addr(phys));
                    frame.rax = 0;
                } else {
                    frame.rax = SysError::NotFound as i64 as u64;
                }
            }
        }

        // SYS_FRAME_PHYS — query physical address of a frame capability
        // rdi = frame_cap (requires READ); returns rax = physical address
        SYS_FRAME_PHYS => match cap::validate(frame.rdi as u32, Rights::READ) {
            Ok(CapObject::Memory { base, .. }) => {
                frame.rax = base;
            }
            Ok(_) => frame.rax = SysError::InvalidCap as i64 as u64,
            Err(e) => frame.rax = e as i64 as u64,
        },

        // SYS_FRAME_ALLOC_CONTIG — allocate N contiguous physical frames
        // rdi = count (1–16); returns rax = cap_id (Memory cap with size = count * 4096)
        SYS_FRAME_ALLOC_CONTIG => {
            let count = frame.rdi as usize;
            if count == 0 || count > 16 {
                frame.rax = SysError::InvalidArg as i64 as u64;
            } else {
                match mm::alloc_contiguous(count) {
                    Some(f) => {
                        let size = (count as u64) * 4096;
                        // Zero the pages via HHDM so physical memory is clean
                        // before userspace (or device emulation) touches it.
                        let hhdm = mm::hhdm_offset();
                        unsafe {
                            core::ptr::write_bytes((f.addr() + hhdm) as *mut u8, 0, size as usize);
                        }
                        match cap::insert(
                            CapObject::Memory {
                                base: f.addr(),
                                size,
                            },
                            Rights::ALL,
                            None,
                        ) {
                            Some(cap_id) => frame.rax = cap_id.raw() as u64,
                            None => {
                                // Free all frames on cap insert failure
                                for i in 0..count {
                                    mm::free_frame(PhysFrame::from_addr(
                                        f.addr() + (i as u64) * 4096,
                                    ));
                                }
                                frame.rax = SysError::OutOfResources as i64 as u64;
                            }
                        }
                    }
                    None => frame.rax = SysError::OutOfResources as i64 as u64,
                }
            }
        }

        // SYS_MAP_OFFSET — map page from multi-page Memory cap at given offset
        // rdi = vaddr, rsi = mem_cap, rdx = offset (bytes, page-aligned), r8 = flags
        SYS_MAP_OFFSET => {
            let vaddr = frame.rdi;
            let mem_cap = frame.rsi as u32;
            let offset = frame.rdx;
            let user_flags = frame.r8;

            match cap::validate(mem_cap, Rights::READ) {
                Ok(CapObject::Memory { base, size }) => {
                    if vaddr & 0xFFF != 0
                        || vaddr >= USER_ADDR_LIMIT
                        || offset & 0xFFF != 0
                        || offset >= size
                    {
                        frame.rax = SysError::InvalidArg as i64 as u64;
                    } else {
                        let paddr = base + offset;
                        let mut flags = PAGE_PRESENT | PAGE_USER | (user_flags & USER_FLAG_MASK);
                        let cr3 = paging::read_cr3();
                        // W^X: writable pages are never executable (unless relaxed)
                        if flags & PAGE_WRITABLE != 0
                            && flags & PAGE_NO_EXECUTE == 0
                            && !paging::is_wx_relaxed(cr3)
                        {
                            flags |= PAGE_NO_EXECUTE;
                        }
                        let aspace = AddressSpace::from_cr3(cr3);
                        aspace.map_page(vaddr, paddr, flags);
                        paging::invlpg(vaddr);
                        frame.rax = 0;
                    }
                }
                Ok(_) => frame.rax = SysError::InvalidCap as i64 as u64,
                Err(e) => frame.rax = e as i64 as u64,
            }
        }

        // SYS_PROTECT — change page permissions (mprotect-like)
        // rdi = vaddr (page-aligned), rsi = new flags
        // W^X enforced: writable pages get NX, non-writable pages may be executable.
        SYS_PROTECT => {
            let vaddr = frame.rdi;
            let user_flags = frame.rsi;

            if vaddr & 0xFFF != 0 || vaddr >= USER_ADDR_LIMIT {
                frame.rax = SysError::InvalidArg as i64 as u64;
            } else {
                let mut flags = PAGE_PRESENT | PAGE_USER | (user_flags & USER_FLAG_MASK);
                let cr3 = paging::read_cr3();
                // W^X: writable pages are never executable (unless relaxed)
                if flags & PAGE_WRITABLE != 0
                    && flags & PAGE_NO_EXECUTE == 0
                    && !paging::is_wx_relaxed(cr3)
                {
                    flags |= PAGE_NO_EXECUTE;
                }
                let aspace = AddressSpace::from_cr3(cr3);
                if aspace.protect_page(vaddr, flags) {
                    paging::invlpg(vaddr);
                    frame.rax = 0;
                } else {
                    frame.rax = SysError::InvalidArg as i64 as u64;
                }
            }
        }

        // SYS_PROTECT_IN — change page permissions in a target address space
        // rdi = as_cap (WRITE), rsi = vaddr (page-aligned), rdx = new flags
        // W^X enforced: writable pages get NX.
        SYS_PROTECT_IN => {
            match cap::validate(frame.rdi as u32, Rights::WRITE) {
                Ok(CapObject::AddrSpace { cr3 }) => {
                    let vaddr = frame.rsi;
                    let user_flags = frame.rdx;
                    if vaddr & 0xFFF != 0 || vaddr >= USER_ADDR_LIMIT {
                        frame.rax = SysError::InvalidArg as i64 as u64;
                    } else {
                        let mut flags = PAGE_PRESENT | PAGE_USER | (user_flags & USER_FLAG_MASK);
                        // W^X: writable pages are never executable (unless relaxed)
                        if flags & PAGE_WRITABLE != 0
                            && flags & PAGE_NO_EXECUTE == 0
                            && !paging::is_wx_relaxed(cr3)
                        {
                            flags |= PAGE_NO_EXECUTE;
                        }
                        let aspace = AddressSpace::from_cr3(cr3);
                        if aspace.protect_page(vaddr, flags) {
                            if cr3 == paging::read_cr3() {
                                paging::invlpg(vaddr);
                            }
                            frame.rax = 0;
                        } else {
                            frame.rax = SysError::InvalidArg as i64 as u64;
                        }
                    }
                }
                Ok(_) => frame.rax = SysError::InvalidCap as i64 as u64,
                Err(e) => frame.rax = e as i64 as u64,
            }
        }

        // SYS_WX_RELAX — enable/disable W^X relaxation for an address space
        // rdi = as_cap (WRITE), rsi = 1 (relax) / 0 (enforce)
        SYS_WX_RELAX => match cap::validate(frame.rdi as u32, Rights::WRITE) {
            Ok(CapObject::AddrSpace { cr3 }) => {
                paging::set_wx_relaxed(cr3, frame.rsi != 0);
                frame.rax = 0;
            }
            Ok(_) => frame.rax = SysError::InvalidCap as i64 as u64,
            Err(e) => frame.rax = e as i64 as u64,
        },

        // SYS_ADDR_SPACE_CREATE — create a new empty user address space
        // Returns: rax = AS cap_id (or error)
        SYS_ADDR_SPACE_CREATE => {
            let addr_space = paging::AddressSpace::new_user();
            let cr3 = addr_space.cr3();
            match cap::insert(CapObject::AddrSpace { cr3 }, Rights::ALL, None) {
                Some(cap_id) => {
                    fault::register_cr3_cap(cr3, cap_id.raw());
                    frame.rax = cap_id.raw() as u64;
                }
                None => frame.rax = SysError::OutOfResources as i64 as u64,
            }
        }

        // SYS_MAP_INTO — map a frame into a target address space
        // rdi = as_cap (WRITE), rsi = vaddr, rdx = frame_cap (READ), r8 = flags
        SYS_MAP_INTO => {
            match cap::validate(frame.rdi as u32, Rights::WRITE) {
                Ok(CapObject::AddrSpace { cr3 }) => {
                    let vaddr = frame.rsi;
                    let frame_cap = frame.rdx as u32;
                    let user_flags = frame.r8;
                    match cap::validate(frame_cap, Rights::READ) {
                        Ok(CapObject::Memory { base: paddr, .. }) => {
                            if vaddr & 0xFFF != 0 || vaddr >= USER_ADDR_LIMIT {
                                frame.rax = SysError::InvalidArg as i64 as u64;
                            } else {
                                let mut flags =
                                    PAGE_PRESENT | PAGE_USER | (user_flags & USER_FLAG_MASK);
                                // W^X: writable pages are never executable (unless relaxed)
                                if flags & PAGE_WRITABLE != 0
                                    && flags & PAGE_NO_EXECUTE == 0
                                    && !paging::is_wx_relaxed(cr3)
                                {
                                    flags |= PAGE_NO_EXECUTE;
                                }
                                let aspace = paging::AddressSpace::from_cr3(cr3);
                                aspace.map_page(vaddr, paddr, flags);
                                if cr3 == paging::read_cr3() {
                                    paging::invlpg(vaddr);
                                }
                                frame.rax = 0;
                            }
                        }
                        Ok(_) => frame.rax = SysError::InvalidCap as i64 as u64,
                        Err(e) => frame.rax = e as i64 as u64,
                    }
                }
                Ok(_) => frame.rax = SysError::InvalidCap as i64 as u64,
                Err(e) => frame.rax = e as i64 as u64,
            }
        }

        // SYS_UNMAP_FROM — unmap a page from a target address space
        // rdi = as_cap (WRITE), rsi = vaddr
        SYS_UNMAP_FROM => {
            match cap::validate(frame.rdi as u32, Rights::WRITE) {
                Ok(CapObject::AddrSpace { cr3 }) => {
                    let vaddr = frame.rsi;
                    if vaddr & 0xFFF != 0 || vaddr >= USER_ADDR_LIMIT {
                        frame.rax = SysError::InvalidArg as i64 as u64;
                    } else {
                        let aspace = paging::AddressSpace::from_cr3(cr3);
                        if aspace.unmap_page(vaddr) {
                            // If target is current CR3, flush TLB entry.
                            if cr3 == paging::read_cr3() {
                                paging::invlpg(vaddr);
                            }
                            frame.rax = 0;
                        } else {
                            frame.rax = SysError::NotFound as i64 as u64;
                        }
                    }
                }
                Ok(_) => frame.rax = SysError::InvalidCap as i64 as u64,
                Err(e) => frame.rax = e as i64 as u64,
            }
        }

        // SYS_AS_CLONE — clone an address space with CoW semantics
        // rdi = src_as_cap (READ)
        // Returns: rax = new AS cap_id (or error)
        SYS_AS_CLONE => {
            match cap::validate(frame.rdi as u32, Rights::READ) {
                Ok(CapObject::AddrSpace { cr3 }) => {
                    let src = paging::AddressSpace::from_cr3(cr3);
                    let child = src.clone_cow();
                    // Flush TLB: symmetric CoW marks parent PTEs read-only.
                    // Stale writable TLB entries would bypass CoW protection.
                    if cr3 == paging::read_cr3() {
                        paging::flush_tlb();
                    }
                    let child_cr3 = child.cr3();
                    // Propagate W^X relaxation from parent to child AS
                    if paging::is_wx_relaxed(cr3) {
                        paging::set_wx_relaxed(child_cr3, true);
                    }
                    // Auto-enable RIP profiler on the 5th+ AS clone (Wine P7+)
                    // Auto-profiler disabled (spin loop already diagnosed)

                    match cap::insert(CapObject::AddrSpace { cr3: child_cr3 }, Rights::ALL, None) {
                        Some(cap_id) => {
                            fault::register_cr3_cap(child_cr3, cap_id.raw());
                            frame.rax = cap_id.raw() as u64;
                        }
                        None => {
                            kdebug!("AS_CLONE: cap insert failed!");
                            frame.rax = SysError::OutOfResources as i64 as u64;
                        }
                    }
                }
                Ok(_) => frame.rax = SysError::InvalidCap as i64 as u64,
                Err(e) => frame.rax = e as i64 as u64,
            }
        }

        // SYS_FRAME_COPY — copy 4KiB from a page in src AS to a frame cap
        // rdi = dst_frame_cap (WRITE), rsi = src_as_cap (READ), rdx = vaddr in src AS
        // Copies via HHDM. Returns 0 on success.
        SYS_FRAME_COPY => {
            let dst_cap = frame.rdi as u32;
            let src_as_cap = frame.rsi as u32;
            let vaddr = frame.rdx;
            match cap::validate(dst_cap, Rights::WRITE) {
                Ok(CapObject::Memory { base: dst_phys, .. }) => {
                    match cap::validate(src_as_cap, Rights::READ) {
                        Ok(CapObject::AddrSpace { cr3 }) => {
                            let src_as = paging::AddressSpace::from_cr3(cr3);
                            match src_as.lookup_phys(vaddr & !0xFFF) {
                                Some(src_phys) => {
                                    let hhdm = mm::hhdm_offset();
                                    unsafe {
                                        core::ptr::copy_nonoverlapping(
                                            (src_phys + hhdm) as *const u8,
                                            (dst_phys + hhdm) as *mut u8,
                                            4096,
                                        );
                                    }
                                    frame.rax = 0;
                                }
                                None => frame.rax = SysError::NotFound as i64 as u64,
                            }
                        }
                        Ok(_) => frame.rax = SysError::InvalidCap as i64 as u64,
                        Err(e) => frame.rax = e as i64 as u64,
                    }
                }
                Ok(_) => frame.rax = SysError::InvalidCap as i64 as u64,
                Err(e) => frame.rax = e as i64 as u64,
            }
        }

        // SYS_PTE_READ — read PTE (phys + flags) for a vaddr in an AS
        // rdi = as_cap (READ), rsi = vaddr
        // Returns: rax = phys_addr, rdi = flags (or error in rax)
        SYS_PTE_READ => match cap::validate(frame.rdi as u32, Rights::READ) {
            Ok(CapObject::AddrSpace { cr3 }) => {
                let vaddr = frame.rsi;
                let aspace = paging::AddressSpace::from_cr3(cr3);
                match aspace.lookup_pte(vaddr & !0xFFF) {
                    Some((phys, flags)) => {
                        frame.rax = phys;
                        frame.rdi = flags;
                    }
                    None => frame.rax = SysError::NotFound as i64 as u64,
                }
            }
            Ok(_) => frame.rax = SysError::InvalidCap as i64 as u64,
            Err(e) => frame.rax = e as i64 as u64,
        },

        // SYS_VM_READ — read bytes from a target AS into caller's buffer
        // rdi = as_cap, rsi = remote_vaddr, rdx = local_buf, r10 = len
        SYS_VM_READ => {
            let as_cap_id = frame.rdi as u32;
            let remote_vaddr = frame.rsi;
            let local_buf = frame.rdx;
            let len = frame.r8 as usize;
            if len > 4096 {
                frame.rax = SysError::InvalidArg as i64 as u64;
            } else {
                match cap::validate(as_cap_id, Rights::READ) {
                    Ok(CapObject::AddrSpace { cr3 }) => {
                        let target_as = paging::AddressSpace::from_cr3(cr3);
                        let hhdm = mm::hhdm_offset();
                        let mut done = 0usize;
                        let mut ok = true;
                        while done < len {
                            let vaddr = remote_vaddr + done as u64;
                            let page_off = (vaddr & 0xFFF) as usize;
                            let chunk = (4096 - page_off).min(len - done);
                            match target_as.lookup_phys(vaddr & !0xFFF) {
                                Some(phys) => {
                                    unsafe {
                                        core::ptr::copy_nonoverlapping(
                                            (phys + hhdm + page_off as u64) as *const u8,
                                            (local_buf + done as u64) as *mut u8,
                                            chunk,
                                        );
                                    }
                                    done += chunk;
                                }
                                None => {
                                    ok = false;
                                    break;
                                }
                            }
                        }
                        frame.rax = if ok {
                            0
                        } else {
                            SysError::NotFound as i64 as u64
                        };
                    }
                    Ok(_) => frame.rax = SysError::InvalidCap as i64 as u64,
                    Err(e) => frame.rax = e as i64 as u64,
                }
            }
        }

        // SYS_VM_WRITE — write bytes from caller's buffer into a target AS
        // rdi = as_cap, rsi = remote_vaddr, rdx = local_buf, r8 = len
        // Handles CoW: if the target page is read-only, does copy-on-write.
        SYS_VM_WRITE => {
            let as_cap_id = frame.rdi as u32;
            let remote_vaddr = frame.rsi;
            let local_buf = frame.rdx;
            let len = frame.r8 as usize;
            if len > 4096 {
                frame.rax = SysError::InvalidArg as i64 as u64;
            } else {
                match cap::validate(as_cap_id, Rights::WRITE) {
                    Ok(CapObject::AddrSpace { cr3 }) => {
                        let target_as = paging::AddressSpace::from_cr3(cr3);
                        let hhdm = mm::hhdm_offset();
                        let mut done = 0usize;
                        let mut ok = true;
                        while done < len {
                            let vaddr = remote_vaddr + done as u64;
                            let page_off = (vaddr & 0xFFF) as usize;
                            let chunk = (4096 - page_off).min(len - done);
                            match target_as.lookup_pte_mut(vaddr & !0xFFF) {
                                Some(pte_ptr) => {
                                    let pte = unsafe { *pte_ptr };
                                    let old_phys = pte & 0x000F_FFFF_FFFF_F000;
                                    let flags = pte & !0x000F_FFFF_FFFF_F000;

                                    let write_phys = if flags & paging::PAGE_WRITABLE == 0 {
                                        // CoW page: allocate new frame, copy old content, update PTE
                                        let new_frame = match mm::alloc_frame() {
                                            Some(f) => f.addr(),
                                            None => {
                                                ok = false;
                                                break;
                                            }
                                        };
                                        // Copy old page content to new frame
                                        unsafe {
                                            core::ptr::copy_nonoverlapping(
                                                (old_phys + hhdm) as *const u8,
                                                (new_frame + hhdm) as *mut u8,
                                                4096,
                                            );
                                        }
                                        // Update PTE to point to new frame with WRITABLE
                                        let new_pte = new_frame | (flags | paging::PAGE_WRITABLE);
                                        unsafe {
                                            *pte_ptr = new_pte;
                                        }
                                        // Decrement refcount on old frame
                                        let rc = mm::frame_refcount_dec(old_phys);
                                        if rc == 0 {
                                            mm::free_frame(mm::PhysFrame::from_addr(old_phys));
                                        }
                                        new_frame
                                    } else {
                                        old_phys
                                    };

                                    unsafe {
                                        core::ptr::copy_nonoverlapping(
                                            (local_buf + done as u64) as *const u8,
                                            (write_phys + hhdm + page_off as u64) as *mut u8,
                                            chunk,
                                        );
                                    }
                                    done += chunk;
                                }
                                None => {
                                    ok = false;
                                    break;
                                }
                            }
                        }
                        frame.rax = if ok {
                            0
                        } else {
                            SysError::NotFound as i64 as u64
                        };
                    }
                    Ok(_) => frame.rax = SysError::InvalidCap as i64 as u64,
                    Err(e) => frame.rax = e as i64 as u64,
                }
            }
        }

        _ => return false,
    }
    true
}
