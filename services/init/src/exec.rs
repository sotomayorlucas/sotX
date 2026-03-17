use sotos_common::sys;
use sotos_common::elf::{ElfInfo, LoadSegment, InterpInfo, MAX_LOAD_SEGMENTS};
use core::sync::atomic::{AtomicU64, Ordering};
use crate::framebuffer::{print, print_hex64};
use crate::process::NEXT_CHILD_STACK;
use crate::vdso;
use crate::{vfs_lock, vfs_unlock, shared_store};
use ufmt::uwrite;

/// Parse an ELF binary using goblin, returning our existing types.
/// Resets the bump allocator after extracting all needed data.
fn parse_elf_goblin(data: &[u8]) -> Result<(ElfInfo, [LoadSegment; MAX_LOAD_SEGMENTS], usize, Option<InterpInfo>), i64> {
    use goblin::elf::Elf;

    // Reset bump allocator BEFORE parsing to ensure enough heap space.
    // Caller holds EXEC_LOCK so no concurrent allocations from other execs.
    crate::bump_alloc::reset();

    let elf = Elf::parse(data).map_err(|_| -8i64)?;

    let info = ElfInfo {
        entry: elf.entry,
        phoff: elf.header.e_phoff as usize,
        phentsize: elf.header.e_phentsize as usize,
        phnum: elf.header.e_phnum as usize,
        elf_type: elf.header.e_type,
    };

    let mut segments = [const { LoadSegment { offset: 0, vaddr: 0, filesz: 0, memsz: 0, flags: 0 } }; MAX_LOAD_SEGMENTS];
    let mut seg_count = 0;
    for ph in &elf.program_headers {
        if ph.p_type == goblin::elf::program_header::PT_LOAD && seg_count < MAX_LOAD_SEGMENTS {
            segments[seg_count] = LoadSegment {
                offset: ph.p_offset as usize,
                vaddr: ph.p_vaddr,
                filesz: ph.p_filesz as usize,
                memsz: ph.p_memsz as usize,
                flags: ph.p_flags,
            };
            seg_count += 1;
        }
    }

    let interp = elf.program_headers.iter()
        .find(|ph| ph.p_type == goblin::elf::program_header::PT_INTERP)
        .map(|ph| {
            let offset = ph.p_offset as usize;
            let filesz = ph.p_filesz as usize;
            let len = if filesz > 0 && offset + filesz <= data.len() && data[offset + filesz - 1] == 0 {
                filesz - 1
            } else {
                filesz
            };
            InterpInfo { offset, len }
        });

    // Drop Elf struct (frees goblin's Vecs), then reset bump allocator
    drop(elf);
    crate::bump_alloc::reset();

    Ok((info, segments, seg_count, interp))
}

/// Spinlock for serializing execve ELF loading (shared temp buffer).
pub(crate) static EXEC_LOCK: AtomicU64 = AtomicU64::new(0);
/// Last exec's stack base (set by exec_loaded_elf, read by caller under EXEC_LOCK).
pub(crate) static LAST_EXEC_STACK_BASE: AtomicU64 = AtomicU64::new(0);
/// Last exec's stack page count.
pub(crate) static LAST_EXEC_STACK_PAGES: AtomicU64 = AtomicU64::new(0);
/// Last exec's ELF load range [lo, hi) (page-aligned).
pub(crate) static LAST_EXEC_ELF_LO: AtomicU64 = AtomicU64::new(0);
pub(crate) static LAST_EXEC_ELF_HI: AtomicU64 = AtomicU64::new(0);
/// Whether last exec used a dynamic interpreter.
pub(crate) static LAST_EXEC_HAS_INTERP: AtomicU64 = AtomicU64::new(0);
/// Temp buffer for execve ELF loading (separate from SPAWN/DL buffers).
pub(crate) const EXEC_BUF_BASE: u64 = 0x5400000;
pub(crate) const EXEC_BUF_PAGES: u64 = 1536; // 6 MiB (apk is ~5.2 MiB)
pub(crate) const EXEC_TEMP_MAP: u64 = 0x5900000; // past EXEC_BUF_BASE + 1280*4K
/// Temp buffer for loading the interpreter ELF (for dynamic binaries).
pub(crate) const INTERP_BUF_BASE: u64 = 0xA000000; // Far from other regions
pub(crate) const INTERP_BUF_PAGES: u64 = 220; // ~900 KiB, enough for ld-musl (~845 KiB)
/// Load base for the dynamic interpreter (ET_DYN, position-independent).
/// Each ET_EXEC exec allocates a unique 2MB slot from NEXT_INTERP_BASE so
/// concurrent glibc processes don't share ld-linux pages (GOT, link_map).
pub(crate) const INTERP_LOAD_BASE: u64 = 0x6000000;
pub(crate) static NEXT_INTERP_BASE: AtomicU64 = AtomicU64::new(INTERP_LOAD_BASE);
const INTERP_SLOT_SIZE: u64 = 0x200000; // 2 MiB per interpreter instance
/// Per-process ELF code base for ET_DYN (PIE) binaries.
/// Each exec gets a unique 16MB slot starting at 0x70000000.
/// 16 slots × 16MB = 256MB, ending at 0x80000000.
pub(crate) static NEXT_DYN_BASE: AtomicU64 = AtomicU64::new(0x70000000);
const DYN_BASE_SLOT_SIZE: u64 = 0x1000000; // 16 MiB per binary

/// Max args for execve (including argv[0]).
pub(crate) const MAX_EXEC_ARGS: usize = 16;
/// Max length of a single argv string.
pub(crate) const MAX_EXEC_ARG_LEN: usize = 128;
/// Max env vars passed via execve envp.
pub(crate) const MAX_EXEC_ENVS: usize = 16;

pub(crate) const MAP_WRITABLE: u64 = 2;

#[inline(always)]
pub(crate) fn rdtsc() -> u64 {
    let lo: u32;
    let hi: u32;
    unsafe {
        core::arch::asm!("rdtsc", out("eax") lo, out("edx") hi, options(nomem, nostack));
    }
    ((hi as u64) << 32) | lo as u64
}

/// Send an IPC reply with a single return value.
pub(crate) fn reply_val(ep_cap: u64, val: i64) {
    let reply = sotos_common::IpcMsg {
        tag: 0,
        regs: [val as u64, 0, 0, 0, 0, 0, 0, 0],
    };
    let _ = sys::send(ep_cap, &reply);
}

/// Format a u64 as decimal into buf. Returns number of bytes written.
pub(crate) fn format_u64_into(buf: &mut [u8], mut n: u64) -> usize {
    if n == 0 {
        if !buf.is_empty() {
            buf[0] = b'0';
        }
        return 1;
    }
    let mut tmp = [0u8; 20];
    let mut i = 0;
    while n > 0 {
        tmp[i] = b'0' + (n % 10) as u8;
        n /= 10;
        i += 1;
    }
    let len = i.min(buf.len());
    for j in 0..len {
        buf[j] = tmp[i - 1 - j];
    }
    len
}

/// A no-alloc buffer writer implementing `ufmt::uWrite`.
/// Writes directly into a `&mut [u8]` slice, tracking position.
/// Silently truncates if the buffer is full.
pub(crate) struct BufWriter<'a> {
    buf: &'a mut [u8],
    pos: usize,
}

impl<'a> BufWriter<'a> {
    pub fn new(buf: &'a mut [u8]) -> Self {
        Self { buf, pos: 0 }
    }
    pub fn pos(&self) -> usize {
        self.pos
    }
}

impl ufmt::uWrite for BufWriter<'_> {
    type Error = ();
    fn write_str(&mut self, s: &str) -> Result<(), ()> {
        let bytes = s.as_bytes();
        let avail = self.buf.len() - self.pos;
        let n = bytes.len().min(avail);
        self.buf[self.pos..self.pos + n].copy_from_slice(&bytes[..n]);
        self.pos += n;
        Ok(())
    }
}

/// Format "/proc/uptime" content: "secs.00 0.00\n"
pub(crate) fn format_uptime_into(buf: &mut [u8], secs: u64) -> usize {
    let mut w = BufWriter::new(buf);
    let _ = uwrite!(w, "{}.00 0.00\n", secs);
    w.pos()
}

/// Format minimal "/proc/self/stat": "pid (program) R 0 1 1 ...\n"
pub(crate) fn format_proc_self_stat(buf: &mut [u8], pid: usize) -> usize {
    let mut w = BufWriter::new(buf);
    let _ = uwrite!(w, "{} (program) R 0 1 1 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0\n", pid);
    w.pos()
}

/// Format a PID listing row: "pid  S      ppid\n"
pub(crate) fn format_pid_row(buf: &mut [u8], pid: usize, state: u64, ppid: u64) -> usize {
    let mut w = BufWriter::new(buf);
    let sc = if state == 1 { "R" } else { "Z" };
    let _ = uwrite!(w, "{}  {}      {}\n", pid, sc, ppid);
    w.pos()
}

/// Format wc-style output: "lines words bytes\n"
pub(crate) fn format_wc_output(buf: &mut [u8], lines: u64, words: u64, bytes: u64) -> usize {
    let mut w = BufWriter::new(buf);
    let _ = uwrite!(w, "{} {} {}\n", lines, words, bytes);
    w.pos()
}

/// Copy a NUL-terminated path from guest memory into a local buffer.
/// Returns the length (excluding NUL).
pub(crate) fn copy_guest_path(guest_ptr: u64, out: &mut [u8]) -> usize {
    let max = out.len() - 1; // leave room for NUL
    let mut i = 0;
    while i < max {
        let b = unsafe { *((guest_ptr + i as u64) as *const u8) };
        if b == 0 {
            break;
        }
        out[i] = b;
        i += 1;
    }
    out[i] = 0;
    i
}

/// Check if a byte slice starts with a prefix.
pub(crate) fn starts_with(hay: &[u8], needle: &[u8]) -> bool {
    hay.len() >= needle.len() && &hay[..needle.len()] == needle
}

/// Map ELF PT_LOAD segments from a buffer into an address space.
/// For ET_DYN (position-independent), vaddrs are offset by `base`.
/// For ET_EXEC, `base` should be 0.
/// `buf_base` is the virtual address where the ELF file data is mapped.
/// `target_as`: 0 = map into init's (current) AS, nonzero = map into that AS cap.
pub(crate) fn map_elf_segments(
    buf_base: u64,
    _elf_info: &sotos_common::elf::ElfInfo,
    segments: &[sotos_common::elf::LoadSegment; sotos_common::elf::MAX_LOAD_SEGMENTS],
    seg_count: usize,
    base: u64,
    target_as: u64,
) -> Result<(), i64> {
    for si in 0..seg_count {
        let seg = &segments[si];
        if seg.memsz == 0 { continue; }
        let load_vaddr = base + seg.vaddr;
        let seg_start = load_vaddr & !0xFFF;
        let seg_end = (load_vaddr + seg.memsz as u64 + 0xFFF) & !0xFFF;
        let is_writable = (seg.flags & 2) != 0;

        let mut page_vaddr = seg_start;
        while page_vaddr < seg_end {
            let frame_cap = match sys::frame_alloc() {
                Ok(f) => f,
                Err(_) => {
                    return Err(-12);
                }
            };

            // Map temporarily to copy data
            if sys::map(EXEC_TEMP_MAP, frame_cap, MAP_WRITABLE).is_err() {
                return Err(-12);
            }

            unsafe { core::ptr::write_bytes(EXEC_TEMP_MAP as *mut u8, 0, 4096); }

            // Copy file data for this page
            let page_start = page_vaddr;
            let page_end = page_vaddr + 4096;
            let file_region_start = load_vaddr;
            let file_region_end = load_vaddr + seg.filesz as u64;
            let copy_start = page_start.max(file_region_start);
            let copy_end = page_end.min(file_region_end);

            if copy_start < copy_end {
                let dst_offset = (copy_start - page_start) as usize;
                let src_offset = seg.offset + (copy_start - load_vaddr) as usize;
                let count = (copy_end - copy_start) as usize;
                unsafe {
                    core::ptr::copy_nonoverlapping(
                        (buf_base as *const u8).add(src_offset),
                        (EXEC_TEMP_MAP as *mut u8).add(dst_offset),
                        count,
                    );
                }
            }

            let _ = sys::unmap(EXEC_TEMP_MAP);

            let flags = if is_writable { MAP_WRITABLE } else { 0 };
            if target_as != 0 {
                let _ = sys::unmap_from(target_as, page_vaddr);
                if sys::map_into(target_as, page_vaddr, frame_cap, flags).is_err() {
                    return Err(-12);
                }
            } else {
                if sys::map(page_vaddr, frame_cap, flags).is_err() {
                    return Err(-12);
                }
            }

            page_vaddr += 4096;
        }
    }
    Ok(())
}

/// Map a temporary buffer for reading ELF files from initrd.
pub(crate) fn map_temp_buf(base: u64, pages: u64) -> Result<(), i64> {
    for i in 0..pages {
        let f = sys::frame_alloc().map_err(|_| -12i64)?;
        if sys::map(base + i * 0x1000, f, MAP_WRITABLE).is_err() {
            for j in 0..i { let _ = sys::unmap_free(base + j * 0x1000); }
            return Err(-12);
        }
    }
    Ok(())
}

/// Unmap a temporary buffer and free the underlying physical frames.
pub(crate) fn unmap_temp_buf(base: u64, pages: u64) {
    for i in 0..pages { let _ = sys::unmap_free(base + i * 0x1000); }
}

/// Load an ELF from initrd into the current address space, create a thread
/// with syscall redirect, and return the new endpoint cap.
/// Supports both static (ET_EXEC) and dynamic (ET_DYN with PT_INTERP) binaries.
/// Caller must hold EXEC_LOCK.
pub(crate) fn exec_from_initrd(bin_name: &[u8]) -> Result<(u64, u64), i64> {
    let empty: [[u8; MAX_EXEC_ARG_LEN]; 0] = [];
    exec_from_initrd_argv(bin_name, &empty, &empty)
}

pub(crate) fn exec_from_initrd_into(bin_name: &[u8], target_as: u64) -> Result<(u64, u64), i64> {
    let empty: [[u8; MAX_EXEC_ARG_LEN]; 0] = [];
    exec_from_initrd_argv_into(bin_name, &empty, &empty, target_as)
}

pub(crate) fn exec_from_initrd_argv(bin_name: &[u8], argv: &[[u8; MAX_EXEC_ARG_LEN]], envp: &[[u8; MAX_EXEC_ARG_LEN]]) -> Result<(u64, u64), i64> {
    exec_from_initrd_argv_into(bin_name, argv, envp, 0)
}

pub(crate) fn exec_from_initrd_argv_into(bin_name: &[u8], argv: &[[u8; MAX_EXEC_ARG_LEN]], envp: &[[u8; MAX_EXEC_ARG_LEN]], target_as: u64) -> Result<(u64, u64), i64> {
    // Step 1: Map temp buffer and read main ELF from initrd
    map_temp_buf(EXEC_BUF_BASE, EXEC_BUF_PAGES)?;

    let file_size = match sys::initrd_read(
        bin_name.as_ptr() as u64,
        bin_name.len() as u64,
        EXEC_BUF_BASE,
        EXEC_BUF_PAGES * 0x1000,
    ) {
        Ok(sz) => sz as usize,
        Err(_) => {
            unmap_temp_buf(EXEC_BUF_BASE, EXEC_BUF_PAGES);
            return Err(-2);
        }
    };

    // Delegate to shared ELF loading path
    exec_loaded_elf(file_size, bin_name, argv, envp, target_as)
}

/// Load an ELF from VFS into the current address space, create a redirected thread.
/// Caller must hold EXEC_LOCK.
pub(crate) fn exec_from_vfs(path: &[u8]) -> Result<(u64, u64), i64> {
    let empty: [[u8; MAX_EXEC_ARG_LEN]; 0] = [];
    exec_from_vfs_argv(path, &empty, &empty)
}

pub(crate) fn exec_from_vfs_into(path: &[u8], target_as: u64) -> Result<(u64, u64), i64> {
    let empty: [[u8; MAX_EXEC_ARG_LEN]; 0] = [];
    exec_from_vfs_argv_into(path, &empty, &empty, target_as)
}

/// Load an ELF from VFS with argv support.
/// Caller must hold EXEC_LOCK.
pub(crate) fn exec_from_vfs_argv(path: &[u8], argv: &[[u8; MAX_EXEC_ARG_LEN]], envp: &[[u8; MAX_EXEC_ARG_LEN]]) -> Result<(u64, u64), i64> {
    exec_from_vfs_argv_into(path, argv, envp, 0)
}

pub(crate) fn exec_from_vfs_argv_into(path: &[u8], argv: &[[u8; MAX_EXEC_ARG_LEN]], envp: &[[u8; MAX_EXEC_ARG_LEN]], target_as: u64) -> Result<(u64, u64), i64> {
    // Step 1: Map temp buffer and read main ELF from VFS
    map_temp_buf(EXEC_BUF_BASE, EXEC_BUF_PAGES)?;

    let buf_cap = (EXEC_BUF_PAGES * 0x1000) as usize;
    let file_size: usize;

    vfs_lock();
    let vfs_result = unsafe { shared_store() }.and_then(|store| {
        use sotos_objstore::ROOT_OID;
        let oid = store.resolve_path(path, ROOT_OID).ok()?;
        let entry = store.stat(oid)?;
        let size = entry.size as usize;
        if size > buf_cap { return None; }
        let dst = unsafe { core::slice::from_raw_parts_mut(EXEC_BUF_BASE as *mut u8, size) };
        store.read_obj(oid, dst).ok()?;
        Some(size)
    });
    vfs_unlock();

    match vfs_result {
        Some(sz) => file_size = sz,
        None => {
            unmap_temp_buf(EXEC_BUF_BASE, EXEC_BUF_PAGES);
            return Err(-2);
        }
    }

    // Step 2-8 are identical to exec_from_initrd_argv — factor into shared helper
    exec_loaded_elf(file_size, path, argv, envp, target_as)
}

/// Common ELF loading path after the binary data is already at EXEC_BUF_BASE.
/// Used by both exec_from_initrd_argv and exec_from_vfs_argv.
/// Check if an env entry (e.g., b"HOME=/tmp\0...") has the given key prefix.
fn env_key_eq(entry: &[u8; MAX_EXEC_ARG_LEN], key: &[u8]) -> bool {
    if key.len() >= MAX_EXEC_ARG_LEN { return false; }
    if entry[key.len()] != b'=' { return false; }
    let mut i = 0;
    while i < key.len() {
        if entry[i] != key[i] { return false; }
        i += 1;
    }
    true
}

fn exec_loaded_elf(file_size: usize, bin_name: &[u8], argv: &[[u8; MAX_EXEC_ARG_LEN]], envp: &[[u8; MAX_EXEC_ARG_LEN]], target_as: u64) -> Result<(u64, u64), i64> {
    let elf_data = unsafe { core::slice::from_raw_parts(EXEC_BUF_BASE as *const u8, file_size) };
    let (elf_info, segments, seg_count, interp_info) = match parse_elf_goblin(elf_data) {
        Ok(parsed) => parsed,
        Err(e) => {
            unmap_temp_buf(EXEC_BUF_BASE, EXEC_BUF_PAGES);
            return Err(e);
        }
    };
    let is_dynamic = interp_info.is_some();

    // ET_DYN (PIE): each process gets a unique 16MB slot to avoid code overlap.
    // ET_EXEC uses the fixed address from the ELF (main_base = 0).
    let main_base: u64 = if elf_info.elf_type == 3 {
        let b = NEXT_DYN_BASE.fetch_add(DYN_BASE_SLOT_SIZE, Ordering::SeqCst);
        crate::framebuffer::print(b"DYN-BASE "); crate::framebuffer::print_hex64(b);
        crate::framebuffer::print(b" entry="); crate::framebuffer::print_hex64(b + elf_info.entry);
        crate::framebuffer::print(b"\n");
        b
    } else {
        0
    };

    // Unmap previous binary's ELF pages (leftover from prior exec).
    // For target_as != 0, we use unmap_from on the target AS (CoW pages);
    // map_elf_segments will also unmap_from before map_into, so this is
    // just an optimization to release CoW page table entries early.
    if target_as == 0 {
        let mut range_lo = u64::MAX;
        let mut range_hi = 0u64;
        for si in 0..seg_count {
            let seg = &segments[si];
            if seg.memsz == 0 { continue; }
            let lo = (main_base + seg.vaddr) & !0xFFF;
            let hi = ((main_base + seg.vaddr + seg.memsz as u64) + 0xFFF) & !0xFFF;
            if lo < range_lo { range_lo = lo; }
            if hi > range_hi { range_hi = hi; }
        }
        if range_lo < range_hi {
            let mut pg = range_lo;
            while pg < range_hi {
                let _ = sys::unmap_free(pg);
                pg += 0x1000;
            }
        }
    }

    // For statically-linked PIE (ET_DYN without PT_INTERP): apply RELR
    // relocations to the buffer BEFORE mapping. The binary has no interpreter
    // to self-relocate — the loader must do it (like Linux kernel does).
    if elf_info.elf_type == 3 && interp_info.is_none() && main_base != 0 {
        let buf = unsafe { core::slice::from_raw_parts_mut(EXEC_BUF_BASE as *mut u8, file_size) };
        apply_relr_to_buf(buf, &elf_info, &segments, seg_count, main_base);
    }

    if let Err(e) = map_elf_segments(EXEC_BUF_BASE, &elf_info, &segments, seg_count, main_base, target_as) {
        unmap_temp_buf(EXEC_BUF_BASE, EXEC_BUF_PAGES);
        return Err(e);
    }

    let mut exec_entry = main_base + elf_info.entry;
    let mut interp_base: u64 = 0;

    if let Some(ref interp) = interp_info {
        let mut interp_name_buf = [0u8; 64];
        let interp_path = &elf_data[interp.offset..interp.offset + interp.len];
        let mut basename_start = 0;
        for idx in 0..interp.len {
            if interp_path[idx] == b'/' { basename_start = idx + 1; }
        }
        let interp_name_len = interp.len - basename_start;
        let safe_len = interp_name_len.min(63);
        interp_name_buf[..safe_len].copy_from_slice(&interp_path[basename_start..basename_start + safe_len]);
        let interp_name = &interp_name_buf[..safe_len];

        if let Err(e) = map_temp_buf(INTERP_BUF_BASE, INTERP_BUF_PAGES) {
            unmap_temp_buf(EXEC_BUF_BASE, EXEC_BUF_PAGES);
            return Err(e);
        }

        // Try initrd first, then VFS for the interpreter
        let interp_size = match sys::initrd_read(
            interp_name.as_ptr() as u64,
            interp_name.len() as u64,
            INTERP_BUF_BASE,
            INTERP_BUF_PAGES * 0x1000,
        ) {
            Ok(sz) => sz as usize,
            Err(_) => {
                let mut vfs_size: usize = 0;
                let interp_full = &elf_data[interp.offset..interp.offset + interp.len];
                for try_path in [interp_full, interp_name].iter() {
                    vfs_lock();
                    let result = unsafe { shared_store() }.and_then(|store| {
                        use sotos_objstore::ROOT_OID;
                        let oid = store.resolve_path(try_path, ROOT_OID).ok()?;
                        let entry = store.stat(oid)?;
                        let size = entry.size as usize;
                        let buf_cap = (INTERP_BUF_PAGES * 0x1000) as usize;
                        if size > buf_cap { return None; }
                        let dst = unsafe { core::slice::from_raw_parts_mut(INTERP_BUF_BASE as *mut u8, size) };
                        store.read_obj(oid, dst).ok()?;
                        Some(size)
                    });
                    vfs_unlock();
                    if let Some(sz) = result { vfs_size = sz; break; }
                }
                if vfs_size == 0 {
                    print(b"EXEC: interpreter not found: ");
                    print(interp_name);
                    print(b"\n");
                    unmap_temp_buf(INTERP_BUF_BASE, INTERP_BUF_PAGES);
                    unmap_temp_buf(EXEC_BUF_BASE, EXEC_BUF_PAGES);
                    return Err(-2);
                }
                vfs_size
            }
        };

        let interp_data = unsafe { core::slice::from_raw_parts(INTERP_BUF_BASE as *const u8, interp_size) };

        let (interp_elf, interp_segs, interp_seg_count, _) = match parse_elf_goblin(interp_data) {
            Ok(parsed) => parsed,
            Err(_) => {
                unmap_temp_buf(INTERP_BUF_BASE, INTERP_BUF_PAGES);
                unmap_temp_buf(EXEC_BUF_BASE, EXEC_BUF_PAGES);
                return Err(-8);
            }
        };

        // Each exec gets a unique interpreter base to avoid concurrent
        // processes sharing ld-linux pages (GOT, link_map, etc.).
        // ET_DYN (PIE): place 8MB past main_base (within the 16MB slot).
        // ET_EXEC: allocate fresh 2MB slot from NEXT_INTERP_BASE.
        interp_base = if elf_info.elf_type == 3 {
            main_base + 0x800000
        } else {
            let b = NEXT_INTERP_BASE.fetch_add(INTERP_SLOT_SIZE, Ordering::SeqCst);
            if b >= 0x70000000 {
                NEXT_INTERP_BASE.store(INTERP_LOAD_BASE, Ordering::SeqCst);
            }
            b
        };
        // Unmap previous interpreter pages at this location (only for init's AS)
        if target_as == 0 {
            for pg in 0..0x110u64 {
                let _ = sys::unmap_free(interp_base + pg * 0x1000);
            }
        }

        // Pre-apply relocations to the buffer so map_elf_segments copies
        // already-relocated data into whichever AS we're targeting.
        // For separate AS (target_as != 0), skip pre-application — the
        // interpreter's bootstrap handles its own relocations (RELA + RELR).
        // Pre-applying RELA RELATIVE here is harmless (idempotent), but
        // pre-applying GLOB_DAT/JUMP_SLOT can interfere with the bootstrap
        // if the interpreter expects to resolve these itself.
        if target_as == 0 {
            let interp_data_mut = unsafe { core::slice::from_raw_parts_mut(INTERP_BUF_BASE as *mut u8, interp_size) };
            apply_interp_relocs_to_buf(interp_data_mut, &interp_elf, &interp_segs, interp_seg_count, interp_base);
        }

        if let Err(e) = map_elf_segments(INTERP_BUF_BASE, &interp_elf, &interp_segs, interp_seg_count, interp_base, target_as) {
            unmap_temp_buf(INTERP_BUF_BASE, INTERP_BUF_PAGES);
            unmap_temp_buf(EXEC_BUF_BASE, EXEC_BUF_PAGES);
            return Err(e);
        }

        exec_entry = interp_base + interp_elf.entry;

        // Apply RELA relocations to mapped pages.
        // For init's AS: direct memory writes (legacy path).
        // For separate AS: vm_write to child's pages — catches BSS-resident
        // GOT entries that apply_interp_relocs_to_buf missed (it can only
        // patch file-resident data, not zero-filled BSS beyond filesz).
        if target_as == 0 {
            apply_interp_relocs(interp_data, &interp_elf, interp_base);
        }
        // For separate AS: no post-mapping relocs needed — the interpreter's
        // bootstrap self-relocates via RELA RELATIVE + RELR.

        unmap_temp_buf(INTERP_BUF_BASE, INTERP_BUF_PAGES);
    }

    // Allocate stack (32 pages = 128 KiB — glibc ld-linux needs ~66 KiB during startup)
    const CHILD_STACK_PAGES: u64 = 256; // 1 MiB (was 128KB — too small for git+TLS)
    const CHILD_STACK_SIZE: u64 = CHILD_STACK_PAGES * 0x1000;
    let stack_addr = NEXT_CHILD_STACK.fetch_add(CHILD_STACK_SIZE, Ordering::SeqCst);
    let mut stack_frames = [0u64; CHILD_STACK_PAGES as usize];
    for pg in 0..CHILD_STACK_PAGES {
        let f = sys::frame_alloc().map_err(|_| -12i64)?;
        stack_frames[pg as usize] = f;
        if sys::map(stack_addr + pg * 0x1000, f, MAP_WRITABLE).is_err() {
            unmap_temp_buf(EXEC_BUF_BASE, EXEC_BUF_PAGES);
            return Err(-12);
        }
    }

    // Build Linux-style initial stack
    let stack_top = stack_addr + CHILD_STACK_SIZE;
    let str_area = stack_top - 4096; // 4K for argv/envp strings + AT_RANDOM
    let mut spos: usize = 0;

    let argc: usize = if argv.is_empty() { 1 } else { argv.len() };
    let mut argv_addrs = [0u64; MAX_EXEC_ARGS];
    if argv.is_empty() {
        argv_addrs[0] = str_area + spos as u64;
        unsafe {
            let dst = (str_area + spos as u64) as *mut u8;
            core::ptr::copy_nonoverlapping(bin_name.as_ptr(), dst, bin_name.len());
            *dst.add(bin_name.len()) = 0;
        }
        spos += bin_name.len() + 1;
    } else {
        for a in 0..argv.len() {
            argv_addrs[a] = str_area + spos as u64;
            let mut alen = 0;
            while alen < MAX_EXEC_ARG_LEN && argv[a][alen] != 0 { alen += 1; }
            unsafe {
                let dst = (str_area + spos as u64) as *mut u8;
                core::ptr::copy_nonoverlapping(argv[a].as_ptr(), dst, alen);
                *dst.add(alen) = 0;
            }
            spos += alen + 1;
        }
    }

    spos = (spos + 7) & !7;

    let random_addr = str_area + spos as u64;
    unsafe {
        let rp = random_addr as *mut u64;
        let mut seed = rdtsc();
        seed ^= seed << 13; seed ^= seed >> 7; seed ^= seed << 17;
        *rp = seed;
        seed ^= seed << 13; seed ^= seed >> 7; seed ^= seed << 17;
        *rp.add(1) = seed;
    }
    spos += 16;

    let elf_base = main_base + if seg_count > 0 { segments[0].vaddr & !0xFFF } else { 0 };
    let phdr_vaddr = elf_base + elf_info.phoff as u64;

    // Environment: user envp first (overrides defaults), then defaults for non-overridden keys
    let defaults: [&[u8]; 5] = [
        b"TERM=xterm\0", b"HOME=/root\0",
        b"TERMINFO=/usr/share/terminfo\0", b"PATH=/usr/bin:/bin:/usr/sbin:/sbin\0",
        b"XDG_RUNTIME_DIR=/run/user/0\0",
    ];
    let default_keys: [&[u8]; 5] = [b"TERM", b"HOME", b"TERMINFO", b"PATH", b"XDG_RUNTIME_DIR"];
    let mut env_addrs = [0u64; MAX_EXEC_ENVS + 5];
    let mut env_count: usize = 0;

    // User env vars first (they take priority — libc uses first occurrence)
    for e in 0..envp.len() {
        let mut elen = 0;
        while elen < MAX_EXEC_ARG_LEN && envp[e][elen] != 0 { elen += 1; }
        if elen == 0 { continue; }
        env_addrs[env_count] = str_area + spos as u64;
        unsafe {
            let dst = (str_area + spos as u64) as *mut u8;
            core::ptr::copy_nonoverlapping(envp[e].as_ptr(), dst, elen);
            *dst.add(elen) = 0;
        }
        spos += elen + 1;
        env_count += 1;
    }

    // Defaults only if key not already provided by user
    for d in 0..5 {
        let mut overridden = false;
        for e in 0..envp.len() {
            if env_key_eq(&envp[e], default_keys[d]) { overridden = true; break; }
        }
        if !overridden {
            let val = defaults[d];
            env_addrs[env_count] = str_area + spos as u64;
            unsafe { core::ptr::copy_nonoverlapping(val.as_ptr(), (str_area + spos as u64) as *mut u8, val.len()); }
            spos += val.len(); // val includes \0
            env_count += 1;
        }
    }

    // Auxv pairs: PHDR+PHENT+PHNUM+PAGESZ+RANDOM+ENTRY
    //             +UID+EUID+GID+EGID+CLKTCK+NULL = 12
    //             +AT_SYSINFO_EHDR (only target_as==0) +AT_BASE (only dynamic)
    let mut auxv_pairs: u64 = 12;
    if target_as == 0 { auxv_pairs += 1; } // AT_SYSINFO_EHDR
    if is_dynamic { auxv_pairs += 1; }      // AT_BASE
    let entries: u64 = 1 + argc as u64 + 1 + env_count as u64 + 1 + auxv_pairs * 2;
    let rsp = (str_area - entries as u64 * 8) & !0xF;

    unsafe {
        let sp = rsp as *mut u64;
        let mut i: usize = 0;
        *sp.add(i) = argc as u64; i += 1;
        for a in 0..argc { *sp.add(i) = argv_addrs[a]; i += 1; }
        *sp.add(i) = 0; i += 1; // argv NULL terminator
        for e in 0..env_count { *sp.add(i) = env_addrs[e]; i += 1; }
        *sp.add(i) = 0; i += 1; // envp NULL terminator
        // AT_PHDR(3) — pointer to program headers in mapped memory
        *sp.add(i) = 3; i += 1; *sp.add(i) = phdr_vaddr; i += 1;
        // AT_PHENT(4) — size of each program header entry
        *sp.add(i) = 4; i += 1; *sp.add(i) = 56; i += 1;
        // AT_PHNUM(5) — number of program headers
        *sp.add(i) = 5; i += 1; *sp.add(i) = elf_info.phnum as u64; i += 1;
        // AT_PAGESZ(6)
        *sp.add(i) = 6; i += 1; *sp.add(i) = 4096; i += 1;
        // AT_RANDOM(25) — 16 bytes of random data
        *sp.add(i) = 25; i += 1; *sp.add(i) = random_addr; i += 1;
        // AT_ENTRY(9) — main binary's entry point (NOT interpreter)
        *sp.add(i) = 9; i += 1; *sp.add(i) = main_base + elf_info.entry; i += 1;
        // AT_SYSINFO_EHDR(33) — vDSO base address
        // Only set for init's own AS. For separate AS, musl's dynamic linker
        // processes the vDSO as a shared object during startup, and our forged
        // ELF (lacking proper GOT/PLT/relocation entries) causes the linker
        // to compute wrong addresses and crash. TODO: add full dynamic linker
        // compatibility to the vDSO ELF (proper section headers, DT_SONAME,
        // empty relocation tables) to enable this for all processes.
        if target_as == 0 {
            *sp.add(i) = 33; i += 1; *sp.add(i) = vdso::VDSO_BASE; i += 1;
        }
        // AT_UID(11), AT_EUID(12), AT_GID(13), AT_EGID(14)
        // All four required: musl checks UID==EUID && GID==EGID for secure mode
        *sp.add(i) = 11; i += 1; *sp.add(i) = 0; i += 1; // AT_UID
        *sp.add(i) = 12; i += 1; *sp.add(i) = 0; i += 1; // AT_EUID
        *sp.add(i) = 13; i += 1; *sp.add(i) = 0; i += 1; // AT_GID
        *sp.add(i) = 14; i += 1; *sp.add(i) = 0; i += 1; // AT_EGID
        // AT_CLKTCK(17) — clock ticks per second
        *sp.add(i) = 17; i += 1; *sp.add(i) = 100; i += 1;
        // AT_BASE(7) — interpreter load base (dynamic binaries only)
        if is_dynamic {
            *sp.add(i) = 7; i += 1; *sp.add(i) = interp_base; i += 1;
        }
        // AT_NULL(0) — auxv terminator
        *sp.add(i) = 0; i += 1;
        *sp.add(i) = 0; i += 1;
        // Verify: written entries must match the calculated count
        // Auxv count mismatch is non-fatal (some entries conditionally skipped)
    }

    // Save canary before stack pages are moved (random_addr is on the stack)
    let saved_canary = unsafe { core::ptr::read(random_addr as *const u64) & !0xFF_u64 };

    // If target_as: move stack pages from init to target AS
    if target_as != 0 {
        for pg in 0..CHILD_STACK_PAGES {
            let _ = sys::unmap(stack_addr + pg * 0x1000); // unmap from init (keep frame)
            let _ = sys::unmap_from(target_as, stack_addr + pg * 0x1000); // clear CoW entry
            let _ = sys::map_into(target_as, stack_addr + pg * 0x1000, stack_frames[pg as usize], MAP_WRITABLE);
        }
    }

    // Pre-TLS: minimal musl __pthread struct + AT_RANDOM canary.
    // musl's __pthread layout (x86_64):
    //   0x00: self pointer (tp->self == tp validation)
    //   0x08: dtv pointer (dynamic thread vector, 0 = no TLS segments)
    //   0x10: prev (linked list, self-referential for single thread)
    //   0x18: next (linked list, self-referential for single thread)
    //   0x28: canary (stack protector, matches AT_RANDOM)
    // glibc also reads canary from fs:0x28 (tcbhead_t.stack_guard).
    const PRE_TLS_ADDR: u64 = 0xB70000; // below vDSO (0xB80000)
    if target_as != 0 {
        // For separate AS: alloc frame, write via temp map, map into target
        if let Ok(f) = sys::frame_alloc() {
            if sys::map(EXEC_TEMP_MAP, f, MAP_WRITABLE).is_ok() {
                unsafe {
                    core::ptr::write_bytes(EXEC_TEMP_MAP as *mut u8, 0, 4096);
                    // __pthread.self = PRE_TLS_ADDR (musl validates self == tp)
                    core::ptr::write((EXEC_TEMP_MAP) as *mut u64, PRE_TLS_ADDR);
                    // __pthread.prev = __pthread.next = self (single thread)
                    core::ptr::write((EXEC_TEMP_MAP + 0x10) as *mut u64, PRE_TLS_ADDR);
                    core::ptr::write((EXEC_TEMP_MAP + 0x18) as *mut u64, PRE_TLS_ADDR);
                    // canary at offset 0x28
                    core::ptr::write((EXEC_TEMP_MAP + 0x28) as *mut u64, saved_canary);
                }
                let _ = sys::unmap(EXEC_TEMP_MAP);
                let _ = sys::unmap_from(target_as, PRE_TLS_ADDR);
                let _ = sys::map_into(target_as, PRE_TLS_ADDR, f, MAP_WRITABLE);
            }
        }
    } else {
        let _ = sys::unmap_free(PRE_TLS_ADDR);
        if let Ok(f) = sys::frame_alloc() {
            if sys::map(PRE_TLS_ADDR, f, MAP_WRITABLE).is_ok() {
                unsafe {
                    core::ptr::write_bytes(PRE_TLS_ADDR as *mut u8, 0, 4096);
                    core::ptr::write((PRE_TLS_ADDR) as *mut u64, PRE_TLS_ADDR);
                    core::ptr::write((PRE_TLS_ADDR + 0x10) as *mut u64, PRE_TLS_ADDR);
                    core::ptr::write((PRE_TLS_ADDR + 0x18) as *mut u64, PRE_TLS_ADDR);
                    core::ptr::write((PRE_TLS_ADDR + 0x28) as *mut u64, saved_canary);
                }
            }
        }
    }

    // Write a trampoline at the vDSO pre-TLS setup stub.
    // (This also maps a private vDSO copy into target_as if target_as != 0.)
    let trampoline_addr = crate::vdso::PRE_TLS_TRAMPOLINE_ADDR;
    let trampoline_page = trampoline_addr & !0xFFF;
    let trampoline_off = (trampoline_addr - trampoline_page) as usize;

    if target_as != 0 {
        // For separate AS: create a private copy of the vDSO page with the trampoline
        if let Ok(vf) = sys::frame_alloc() {
            if sys::map(EXEC_TEMP_MAP, vf, MAP_WRITABLE).is_ok() {
                // Copy existing vDSO page content from init's AS
                unsafe {
                    core::ptr::copy_nonoverlapping(
                        trampoline_page as *const u8,
                        EXEC_TEMP_MAP as *mut u8,
                        4096,
                    );
                    // Write trampoline at the correct offset within the page
                    let p = (EXEC_TEMP_MAP as *mut u8).add(trampoline_off);
                    *p = 0xBF; *p.add(1) = 0x02; *p.add(2) = 0x10; *p.add(3) = 0x00; *p.add(4) = 0x00;
                    *p.add(5) = 0x48; *p.add(6) = 0xBE;
                    core::ptr::copy_nonoverlapping(&PRE_TLS_ADDR as *const u64 as *const u8, p.add(7), 8);
                    *p.add(15) = 0xB8; *p.add(16) = 0x9E; *p.add(17) = 0x00; *p.add(18) = 0x00; *p.add(19) = 0x00;
                    *p.add(20) = 0x0F; *p.add(21) = 0x05;
                    *p.add(22) = 0x48; *p.add(23) = 0xB8;
                    core::ptr::copy_nonoverlapping(&exec_entry as *const u64 as *const u8, p.add(24), 8);
                    *p.add(32) = 0xFF; *p.add(33) = 0xE0;
                }
                let _ = sys::unmap(EXEC_TEMP_MAP);
                let _ = sys::unmap_from(target_as, trampoline_page);
                let _ = sys::map_into(target_as, trampoline_page, vf, 0); // 0 = R+X
            }
        }
    } else {
        let _ = sys::protect(trampoline_page, MAP_WRITABLE);
        unsafe {
            let p = trampoline_addr as *mut u8;
            *p = 0xBF; *p.add(1) = 0x02; *p.add(2) = 0x10; *p.add(3) = 0x00; *p.add(4) = 0x00;
            *p.add(5) = 0x48; *p.add(6) = 0xBE;
            core::ptr::copy_nonoverlapping(&PRE_TLS_ADDR as *const u64 as *const u8, p.add(7), 8);
            *p.add(15) = 0xB8; *p.add(16) = 0x9E; *p.add(17) = 0x00; *p.add(18) = 0x00; *p.add(19) = 0x00;
            *p.add(20) = 0x0F; *p.add(21) = 0x05;
            *p.add(22) = 0x48; *p.add(23) = 0xB8;
            core::ptr::copy_nonoverlapping(&exec_entry as *const u64 as *const u8, p.add(24), 8);
            *p.add(32) = 0xFF; *p.add(33) = 0xE0;
        }
        let _ = sys::protect(trampoline_page, 0); // R+X
    }

    let child_entry = trampoline_addr;

    let new_ep = match sys::endpoint_create() {
        Ok(e) => e,
        Err(_) => {
            unmap_temp_buf(EXEC_BUF_BASE, EXEC_BUF_PAGES);
            return Err(-12);
        }
    };
    let new_thread = if target_as != 0 {
        match sys::thread_create_in(target_as, child_entry, rsp, new_ep) {
            Ok(t) => t,
            Err(_) => {
                unmap_temp_buf(EXEC_BUF_BASE, EXEC_BUF_PAGES);
                return Err(-12);
            }
        }
    } else {
        match sys::thread_create_redirected(child_entry, rsp, new_ep) {
            Ok(t) => t,
            Err(_) => {
                unmap_temp_buf(EXEC_BUF_BASE, EXEC_BUF_PAGES);
                return Err(-12);
            }
        }
    };
    let _ = sys::signal_entry(new_thread, vdso::SIGNAL_TRAMPOLINE_ADDR);

    // NOTE: vDSO page is already mapped by the pre-TLS trampoline code above
    // (it creates a custom copy with the trampoline embedded). Do NOT re-map
    // or it would overwrite the trampoline with the original vDSO content.

    // Record page info for per-process cleanup on exit
    LAST_EXEC_STACK_BASE.store(stack_addr, Ordering::Release);
    LAST_EXEC_STACK_PAGES.store(CHILD_STACK_PAGES, Ordering::Release);
    // Compute full ELF segment range
    {
        let mut elf_lo = u64::MAX;
        let mut elf_hi = 0u64;
        for si in 0..seg_count {
            let seg = &segments[si];
            if seg.memsz == 0 { continue; }
            let lo = (main_base + seg.vaddr) & !0xFFF;
            let hi = ((main_base + seg.vaddr + seg.memsz as u64) + 0xFFF) & !0xFFF;
            if lo < elf_lo { elf_lo = lo; }
            if hi > elf_hi { elf_hi = hi; }
        }
        LAST_EXEC_ELF_LO.store(elf_lo, Ordering::Release);
        LAST_EXEC_ELF_HI.store(elf_hi, Ordering::Release);
    }
    LAST_EXEC_HAS_INTERP.store(if is_dynamic { interp_base } else { 0 }, Ordering::Release);

    unmap_temp_buf(EXEC_BUF_BASE, EXEC_BUF_PAGES);
    Ok((new_ep, new_thread))
}

/// Convert a virtual address (relative to binary base 0) to a file offset
/// using PT_LOAD segment mappings.
fn vaddr_to_file_offset(
    vaddr: u64,
    segments: &[sotos_common::elf::LoadSegment; sotos_common::elf::MAX_LOAD_SEGMENTS],
    seg_count: usize,
) -> Option<usize> {
    for i in 0..seg_count {
        let seg = &segments[i];
        if vaddr >= seg.vaddr && vaddr < seg.vaddr + seg.filesz as u64 {
            return Some(seg.offset + (vaddr - seg.vaddr) as usize);
        }
    }
    None
}

/// Apply interpreter relocations directly to the ELF data buffer (before mapping).
/// This allows the relocated data to be mapped into any address space via
/// map_elf_segments without needing write access to the target AS pages.
fn apply_interp_relocs_to_buf(
    elf_data: &mut [u8],
    elf_info: &sotos_common::elf::ElfInfo,
    segments: &[sotos_common::elf::LoadSegment; sotos_common::elf::MAX_LOAD_SEGMENTS],
    seg_count: usize,
    base: u64,
) {
    // Find PT_DYNAMIC segment
    let mut dyn_offset = 0usize;
    let mut dyn_size = 0usize;
    let mut found = false;
    for i in 0..elf_info.phnum {
        let ph = elf_info.phoff + i * elf_info.phentsize;
        if ph + elf_info.phentsize > elf_data.len() { break; }
        let p_type = u32::from_le_bytes([
            elf_data[ph], elf_data[ph+1], elf_data[ph+2], elf_data[ph+3],
        ]);
        if p_type == 2 { // PT_DYNAMIC
            dyn_offset = u64::from_le_bytes([
                elf_data[ph+8], elf_data[ph+9], elf_data[ph+10], elf_data[ph+11],
                elf_data[ph+12], elf_data[ph+13], elf_data[ph+14], elf_data[ph+15],
            ]) as usize;
            dyn_size = u64::from_le_bytes([
                elf_data[ph+32], elf_data[ph+33], elf_data[ph+34], elf_data[ph+35],
                elf_data[ph+36], elf_data[ph+37], elf_data[ph+38], elf_data[ph+39],
            ]) as usize;
            found = true;
            break;
        }
    }
    if !found { return; }

    let mut rela_off: u64 = 0;
    let mut rela_sz: u64 = 0;
    let mut jmprel_off: u64 = 0;
    let mut jmprel_sz: u64 = 0;
    let mut symtab_off: u64 = 0;
    let mut syment_sz: u64 = 24;
    let mut pos = dyn_offset;
    let end = (dyn_offset + dyn_size).min(elf_data.len());
    while pos + 16 <= end {
        let tag = u64::from_le_bytes([
            elf_data[pos], elf_data[pos+1], elf_data[pos+2], elf_data[pos+3],
            elf_data[pos+4], elf_data[pos+5], elf_data[pos+6], elf_data[pos+7],
        ]);
        let val = u64::from_le_bytes([
            elf_data[pos+8], elf_data[pos+9], elf_data[pos+10], elf_data[pos+11],
            elf_data[pos+12], elf_data[pos+13], elf_data[pos+14], elf_data[pos+15],
        ]);
        match tag {
            0 => break,
            2 => jmprel_sz = val,  // DT_PLTRELSZ
            6 => symtab_off = val, // DT_SYMTAB
            7 => rela_off = val,   // DT_RELA
            8 => rela_sz = val,    // DT_RELASZ
            11 => syment_sz = val, // DT_SYMENT
            23 => jmprel_off = val, // DT_JMPREL
            _ => {}
        }
        pos += 16;
    }

    if rela_off == 0 && jmprel_off == 0 { return; }

    // Process both RELA and JMPREL tables
    let tables: [(u64, u64); 2] = [(rela_off, rela_sz), (jmprel_off, jmprel_sz)];
    for (tbl_off, tbl_sz) in tables {
    if tbl_off == 0 || tbl_sz == 0 { continue; }
    let rela_file_off = tbl_off as usize;
    let mut rp = rela_file_off;
    let rela_end = (rela_file_off + tbl_sz as usize).min(elf_data.len());
    while rp + 24 <= rela_end {
        let r_offset = u64::from_le_bytes([
            elf_data[rp], elf_data[rp+1], elf_data[rp+2], elf_data[rp+3],
            elf_data[rp+4], elf_data[rp+5], elf_data[rp+6], elf_data[rp+7],
        ]);
        let r_info = u64::from_le_bytes([
            elf_data[rp+8], elf_data[rp+9], elf_data[rp+10], elf_data[rp+11],
            elf_data[rp+12], elf_data[rp+13], elf_data[rp+14], elf_data[rp+15],
        ]);
        let r_addend = u64::from_le_bytes([
            elf_data[rp+16], elf_data[rp+17], elf_data[rp+18], elf_data[rp+19],
            elf_data[rp+20], elf_data[rp+21], elf_data[rp+22], elf_data[rp+23],
        ]);
        let r_type = (r_info & 0xFFFFFFFF) as u32;

        if let Some(file_off) = vaddr_to_file_offset(r_offset, segments, seg_count) {
            if file_off + 8 <= elf_data.len() {
                match r_type {
                    8 => { // R_X86_64_RELATIVE
                        let val = (base + r_addend).to_le_bytes();
                        elf_data[file_off..file_off+8].copy_from_slice(&val);
                    }
                    6 | 7 => { // R_X86_64_GLOB_DAT / JUMP_SLOT — resolve via .dynsym
                        let sym_idx = (r_info >> 32) as usize;
                        let mut sym_val: u64 = 0;
                        if r_addend != 0 {
                            sym_val = base + r_addend;
                        } else if symtab_off != 0 && sym_idx != 0 {
                            let sym_off = symtab_off as usize + sym_idx * syment_sz as usize;
                            if sym_off + 16 <= elf_data.len() {
                                let st_value = u64::from_le_bytes([
                                    elf_data[sym_off+8], elf_data[sym_off+9],
                                    elf_data[sym_off+10], elf_data[sym_off+11],
                                    elf_data[sym_off+12], elf_data[sym_off+13],
                                    elf_data[sym_off+14], elf_data[sym_off+15],
                                ]);
                                if st_value != 0 {
                                    sym_val = base + st_value;
                                }
                            }
                        }
                        let val = sym_val.to_le_bytes();
                        elf_data[file_off..file_off+8].copy_from_slice(&val);
                    }
                    _ => {}
                }
            }
        }
        rp += 24;
    }
    } // end for tables
}

/// Pre-apply interpreter relocations (RELR + RELA) so the dynamic linker's
/// self-relocation bootstrap becomes a no-op. This works around kernels that
/// don't save/restore SSE state (glibc's ld-linux uses movaps in bootstrap).
///
/// `elf_data`: raw ELF bytes of the interpreter (still in temp buffer).
/// `elf_info`: parsed ELF header.
/// `base`: load base address where segments are mapped.
fn apply_interp_relocs(elf_data: &[u8], elf_info: &sotos_common::elf::ElfInfo, base: u64) {
    // Find PT_DYNAMIC segment
    let mut dyn_offset = 0usize;
    let mut dyn_size = 0usize;
    let mut found = false;
    for i in 0..elf_info.phnum {
        let ph = elf_info.phoff + i * elf_info.phentsize;
        if ph + elf_info.phentsize > elf_data.len() { break; }
        let p_type = u32::from_le_bytes([
            elf_data[ph], elf_data[ph+1], elf_data[ph+2], elf_data[ph+3],
        ]);
        if p_type == 2 { // PT_DYNAMIC
            dyn_offset = u64::from_le_bytes([
                elf_data[ph+8], elf_data[ph+9], elf_data[ph+10], elf_data[ph+11],
                elf_data[ph+12], elf_data[ph+13], elf_data[ph+14], elf_data[ph+15],
            ]) as usize;
            dyn_size = u64::from_le_bytes([
                elf_data[ph+32], elf_data[ph+33], elf_data[ph+34], elf_data[ph+35],
                elf_data[ph+36], elf_data[ph+37], elf_data[ph+38], elf_data[ph+39],
            ]) as usize;
            found = true;
            break;
        }
    }
    if !found { return; }

    // Parse DYNAMIC entries to find DT_RELA, DT_RELASZ, DT_RELR, DT_RELRSZ
    let mut rela_off: u64 = 0;
    let mut rela_sz: u64 = 0;
    let mut relr_off: u64 = 0;
    let mut relr_sz: u64 = 0;
    let mut pos = dyn_offset;
    let end = (dyn_offset + dyn_size).min(elf_data.len());
    while pos + 16 <= end {
        let tag = u64::from_le_bytes([
            elf_data[pos], elf_data[pos+1], elf_data[pos+2], elf_data[pos+3],
            elf_data[pos+4], elf_data[pos+5], elf_data[pos+6], elf_data[pos+7],
        ]);
        let val = u64::from_le_bytes([
            elf_data[pos+8], elf_data[pos+9], elf_data[pos+10], elf_data[pos+11],
            elf_data[pos+12], elf_data[pos+13], elf_data[pos+14], elf_data[pos+15],
        ]);
        match tag {
            0 => break,       // DT_NULL
            7 => rela_off = val,  // DT_RELA
            8 => rela_sz = val,   // DT_RELASZ
            0x24 => relr_off = val, // DT_RELR
            0x23 => relr_sz = val,  // DT_RELRSZ
            _ => {}
        }
        pos += 16;
    }

    // Apply RELA RELATIVE relocations (type 8 = R_X86_64_RELATIVE)
    if rela_off != 0 && rela_sz != 0 {
        let rela_file_off = rela_off as usize;
        let mut rp = rela_file_off;
        let rela_end = (rela_file_off + rela_sz as usize).min(elf_data.len());
        while rp + 24 <= rela_end {
            let r_offset = u64::from_le_bytes([
                elf_data[rp], elf_data[rp+1], elf_data[rp+2], elf_data[rp+3],
                elf_data[rp+4], elf_data[rp+5], elf_data[rp+6], elf_data[rp+7],
            ]);
            let r_info = u64::from_le_bytes([
                elf_data[rp+8], elf_data[rp+9], elf_data[rp+10], elf_data[rp+11],
                elf_data[rp+12], elf_data[rp+13], elf_data[rp+14], elf_data[rp+15],
            ]);
            let r_addend = u64::from_le_bytes([
                elf_data[rp+16], elf_data[rp+17], elf_data[rp+18], elf_data[rp+19],
                elf_data[rp+20], elf_data[rp+21], elf_data[rp+22], elf_data[rp+23],
            ]);
            let r_type = (r_info & 0xFFFFFFFF) as u32;
            let target = base + r_offset;
            match r_type {
                8 => { // R_X86_64_RELATIVE
                    unsafe { *(target as *mut u64) = base + r_addend; }
                }
                6 => { // R_X86_64_GLOB_DAT — set to symbol value (0 for unresolved)
                    let sym_idx = (r_info >> 32) as usize;
                    // For ld-linux, symbols like __rseq_offset/size are internal
                    // and point to addresses within ld-linux's own data
                    if r_addend != 0 {
                        unsafe { *(target as *mut u64) = base + r_addend; }
                    } else {
                        // Try to resolve: symbol value is in .dynsym
                        // sym_value = read from dynsym[sym_idx].st_value
                        // For now, just set to 0 (safe for rseq)
                        let _ = sym_idx;
                        unsafe { *(target as *mut u64) = 0; }
                    }
                }
                0x25 => { // R_X86_64_IRELATIVE — call resolver at base+addend
                    // We can't safely call the resolver from the loader.
                    // Skip — ld-linux's bootstrap will handle this.
                }
                _ => {}
            }
            rp += 24;
        }
    }

    // RELR relocations: NOT pre-applied.
    // RELR format does `*ptr += base` which is NOT idempotent — if we pre-apply,
    // glibc's bootstrap will add base again (double relocation → crash).
    // RELA RELATIVE is safe because it sets `*(base+off) = base+addend` (idempotent).
    // ld-linux's bootstrap handles RELR itself.
}

/// Apply RELR (compact relative) relocations to a raw ELF buffer.
/// RELR format: each `*ptr += base`. Used for statically-linked PIE binaries
/// that have no interpreter to self-relocate.
fn apply_relr_to_buf(
    elf_data: &mut [u8],
    elf_info: &sotos_common::elf::ElfInfo,
    segments: &[sotos_common::elf::LoadSegment; sotos_common::elf::MAX_LOAD_SEGMENTS],
    seg_count: usize,
    base: u64,
) -> usize {
    let mut applied: usize = 0;
    // Find PT_DYNAMIC
    let mut dyn_offset = 0usize;
    let mut dyn_size = 0usize;
    let mut found = false;
    for i in 0..elf_info.phnum {
        let ph = elf_info.phoff + i * elf_info.phentsize;
        if ph + elf_info.phentsize > elf_data.len() { break; }
        let p_type = u32::from_le_bytes([
            elf_data[ph], elf_data[ph+1], elf_data[ph+2], elf_data[ph+3],
        ]);
        if p_type == 2 {
            dyn_offset = u64::from_le_bytes([
                elf_data[ph+8], elf_data[ph+9], elf_data[ph+10], elf_data[ph+11],
                elf_data[ph+12], elf_data[ph+13], elf_data[ph+14], elf_data[ph+15],
            ]) as usize;
            dyn_size = u64::from_le_bytes([
                elf_data[ph+32], elf_data[ph+33], elf_data[ph+34], elf_data[ph+35],
                elf_data[ph+36], elf_data[ph+37], elf_data[ph+38], elf_data[ph+39],
            ]) as usize;
            found = true;
            break;
        }
    }
    if !found { return 0; }

    // Also apply RELA RELATIVE while we're at it
    let mut rela_off: u64 = 0;
    let mut rela_sz: u64 = 0;
    let mut relr_off: u64 = 0;
    let mut relr_sz: u64 = 0;
    let mut pos = dyn_offset;
    let end = (dyn_offset + dyn_size).min(elf_data.len());
    while pos + 16 <= end {
        let tag = u64::from_le_bytes([
            elf_data[pos], elf_data[pos+1], elf_data[pos+2], elf_data[pos+3],
            elf_data[pos+4], elf_data[pos+5], elf_data[pos+6], elf_data[pos+7],
        ]);
        let val = u64::from_le_bytes([
            elf_data[pos+8], elf_data[pos+9], elf_data[pos+10], elf_data[pos+11],
            elf_data[pos+12], elf_data[pos+13], elf_data[pos+14], elf_data[pos+15],
        ]);
        match tag {
            0 => break,
            7 => rela_off = val,
            8 => rela_sz = val,
            0x24 => relr_off = val,
            0x23 => relr_sz = val,
            _ => {}
        }
        pos += 16;
    }

    // RELA RELATIVE
    if rela_off != 0 && rela_sz != 0 {
        let mut rp = rela_off as usize;
        let rela_end = (rp + rela_sz as usize).min(elf_data.len());
        while rp + 24 <= rela_end {
            let r_offset = u64::from_le_bytes(elf_data[rp..rp+8].try_into().unwrap());
            let r_info = u64::from_le_bytes(elf_data[rp+8..rp+16].try_into().unwrap());
            let r_addend = u64::from_le_bytes(elf_data[rp+16..rp+24].try_into().unwrap());
            if (r_info & 0xFFFFFFFF) == 8 { // R_X86_64_RELATIVE
                if let Some(foff) = vaddr_to_file_offset(r_offset, segments, seg_count) {
                    if foff + 8 <= elf_data.len() {
                        let val = (base + r_addend).to_le_bytes();
                        elf_data[foff..foff+8].copy_from_slice(&val);
                    }
                }
            }
            rp += 24;
        }
    }

    // RELR: NOT pre-applied. RELR format is `*ptr += base` which is NOT
    // idempotent. Static PIE binaries (musl) have their own _dlstart bootstrap
    // that applies RELR. Pre-applying would double-relocate → all pointers
    // off by `base`, causing an infinite loop in demand-paged zero pages.
    applied
}

/// Apply interpreter RELA + JMPREL relocations to a REMOTE address space via vm_write.
/// Handles GLOB_DAT/JUMP_SLOT with .dynsym symbol lookup, and R_X86_64_RELATIVE.
/// Processes both DT_RELA and DT_JMPREL (PLT) relocation tables.
fn apply_interp_relocs_remote(
    elf_data: &[u8],
    elf_info: &sotos_common::elf::ElfInfo,
    base: u64,
    target_as: u64,
) {
    // Find PT_DYNAMIC
    let mut dyn_offset = 0usize;
    let mut dyn_size = 0usize;
    let mut found = false;
    for i in 0..elf_info.phnum {
        let ph = elf_info.phoff + i * elf_info.phentsize;
        if ph + elf_info.phentsize > elf_data.len() { break; }
        let p_type = u32::from_le_bytes([
            elf_data[ph], elf_data[ph+1], elf_data[ph+2], elf_data[ph+3],
        ]);
        if p_type == 2 {
            dyn_offset = u64::from_le_bytes([
                elf_data[ph+8], elf_data[ph+9], elf_data[ph+10], elf_data[ph+11],
                elf_data[ph+12], elf_data[ph+13], elf_data[ph+14], elf_data[ph+15],
            ]) as usize;
            dyn_size = u64::from_le_bytes([
                elf_data[ph+32], elf_data[ph+33], elf_data[ph+34], elf_data[ph+35],
                elf_data[ph+36], elf_data[ph+37], elf_data[ph+38], elf_data[ph+39],
            ]) as usize;
            found = true;
            break;
        }
    }
    if !found { return; }

    let mut rela_off: u64 = 0;
    let mut rela_sz: u64 = 0;
    let mut jmprel_off: u64 = 0;
    let mut jmprel_sz: u64 = 0;
    let mut symtab_off: u64 = 0;
    let mut syment_sz: u64 = 24; // default Elf64_Sym size
    let mut pos = dyn_offset;
    let end = (dyn_offset + dyn_size).min(elf_data.len());
    while pos + 16 <= end {
        let tag = u64::from_le_bytes([
            elf_data[pos], elf_data[pos+1], elf_data[pos+2], elf_data[pos+3],
            elf_data[pos+4], elf_data[pos+5], elf_data[pos+6], elf_data[pos+7],
        ]);
        let val = u64::from_le_bytes([
            elf_data[pos+8], elf_data[pos+9], elf_data[pos+10], elf_data[pos+11],
            elf_data[pos+12], elf_data[pos+13], elf_data[pos+14], elf_data[pos+15],
        ]);
        match tag {
            0 => break,
            2 => jmprel_sz = val,  // DT_PLTRELSZ
            6 => symtab_off = val, // DT_SYMTAB
            7 => rela_off = val,   // DT_RELA
            8 => rela_sz = val,    // DT_RELASZ
            11 => syment_sz = val, // DT_SYMENT
            23 => jmprel_off = val, // DT_JMPREL
            _ => {}
        }
        pos += 16;
    }

    if rela_off == 0 && jmprel_off == 0 { return; }

    // Process both RELA and JMPREL tables with the same logic
    let tables: [(u64, u64); 2] = [
        (rela_off, rela_sz),
        (jmprel_off, jmprel_sz),
    ];
    for (tbl_off, tbl_sz) in tables {
        if tbl_off == 0 || tbl_sz == 0 { continue; }
        let rela_file_off = tbl_off as usize;
        let mut rp = rela_file_off;
        let rela_end = (rela_file_off + tbl_sz as usize).min(elf_data.len());
    while rp + 24 <= rela_end {
        let r_offset = u64::from_le_bytes([
            elf_data[rp], elf_data[rp+1], elf_data[rp+2], elf_data[rp+3],
            elf_data[rp+4], elf_data[rp+5], elf_data[rp+6], elf_data[rp+7],
        ]);
        let r_info = u64::from_le_bytes([
            elf_data[rp+8], elf_data[rp+9], elf_data[rp+10], elf_data[rp+11],
            elf_data[rp+12], elf_data[rp+13], elf_data[rp+14], elf_data[rp+15],
        ]);
        let r_addend = u64::from_le_bytes([
            elf_data[rp+16], elf_data[rp+17], elf_data[rp+18], elf_data[rp+19],
            elf_data[rp+20], elf_data[rp+21], elf_data[rp+22], elf_data[rp+23],
        ]);
        let r_type = (r_info & 0xFFFFFFFF) as u32;
        let target = base + r_offset;

        match r_type {
            8 => { // R_X86_64_RELATIVE: *(base+off) = base+addend
                let val = (base + r_addend).to_le_bytes();
                let _ = sys::vm_write(target_as, target, val.as_ptr() as u64, 8);
            }
            6 | 7 => { // R_X86_64_GLOB_DAT (6) / R_X86_64_JUMP_SLOT (7)
                let sym_idx = (r_info >> 32) as usize;
                let mut sym_val: u64 = 0;
                // Look up symbol in .dynsym
                if symtab_off != 0 && sym_idx != 0 {
                    let sym_off = symtab_off as usize + sym_idx * syment_sz as usize;
                    if sym_off + 24 <= elf_data.len() {
                        // Elf64_Sym.st_value is at offset 8 within the entry
                        let st_value = u64::from_le_bytes([
                            elf_data[sym_off+8], elf_data[sym_off+9],
                            elf_data[sym_off+10], elf_data[sym_off+11],
                            elf_data[sym_off+12], elf_data[sym_off+13],
                            elf_data[sym_off+14], elf_data[sym_off+15],
                        ]);
                        if st_value != 0 {
                            sym_val = base + st_value;
                        }
                    }
                }
                // Addend takes priority if non-zero
                if r_addend != 0 {
                    sym_val = base + r_addend;
                }
                let val = sym_val.to_le_bytes();
                let _ = sys::vm_write(target_as, target, val.as_ptr() as u64, 8);
            }
            _ => {}
        }
        rp += 24;
    }
    } // end for tables
}
