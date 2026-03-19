//! vDSO (Virtual Dynamic Shared Object) forger.
//!
//! Builds a minimal ELF shared library in a single 4096-byte page that exports
//! `__vdso_clock_gettime` (and stubs for gettimeofday/time/getcpu).
//! Mapped into the init address space; AT_SYSINFO_EHDR points here.
//! musl/glibc parse this ELF at startup for fast userspace time queries.

/// Virtual address where the vDSO page is mapped (from sotos-common).
pub use sotos_common::VDSO_BASE;

// ---------------------------------------------------------------
// Internal layout offsets within the 4096-byte vDSO page
// ---------------------------------------------------------------
const PHDR_OFF: usize = 0x040; // 2 program headers
const DYNAMIC_OFF: usize = 0x100; // .dynamic section
const DYNSYM_OFF: usize = 0x200; // .dynsym (5 entries × 24)
const DYNSTR_OFF: usize = 0x280; // .dynstr
const HASH_OFF: usize = 0x300; // SysV .hash
const VERSYM_OFF: usize = 0x340; // .gnu.version (versym)
const VERDEF_OFF: usize = 0x350; // .gnu.version_d (verdef)
const TEXT_OFF: usize = 0x600; // .text (machine code)
const SIGNAL_TRAMPOLINE_OFF: usize = 0x100; // signal trampoline (within .text)
const SIGRETURN_RESTORER_OFF: usize = 0x110; // rt_sigreturn restorer (within .text)
const FORK_RESTORE_OFF: usize = 0x120; // fork callee-saved register restore trampoline
const EXIT_STUB_OFF: usize = 0x130; // exit_group(rdi) stub
const COW_FORK_RESTORE_OFF: usize = 0x140; // CoW fork child restore: xor eax + pop regs + ret
const FORK_TLS_TRAMPOLINE_OFF: usize = 0x160; // dynamic: arch_prctl(SET_FS+SET_GS,X) then jmp COW_FORK_RESTORE
const PRE_TLS_TRAMPOLINE_OFF: usize = 0x1C0; // exec-time: arch_prctl(SET_FS,PRE_TLS) then jmp exec_entry
const YIELD_LOOP_OFF: usize = 0x1E0; // yield loop stub (keeps thread alive without exiting)
const DATA_OFF: usize = 0xE00; // boot_tsc storage

/// Virtual address of the signal trampoline (for SYS_SIGNAL_ENTRY).
pub const SIGNAL_TRAMPOLINE_ADDR: u64 = VDSO_BASE + (TEXT_OFF + SIGNAL_TRAMPOLINE_OFF) as u64;

/// Virtual address of the rt_sigreturn restorer stub in the vDSO.
/// Used as sa_restorer when no user-provided restorer is available,
/// and to resume a thread after an async signal trampoline with no pending signal.
pub const SIGRETURN_RESTORER_ADDR: u64 = VDSO_BASE + (TEXT_OFF + SIGRETURN_RESTORER_OFF) as u64;

/// Fork restore trampoline: pop rbx, rbp, r12-r15, then ret to fork return point.
pub const FORK_RESTORE_ADDR: u64 = VDSO_BASE + (TEXT_OFF + FORK_RESTORE_OFF) as u64;

/// Exit stub: mov eax, 231 (exit_group); syscall; hlt
/// RDI = exit code (set via SIG_REDIRECT_TAG regs[1])
pub const EXIT_STUB_ADDR: u64 = VDSO_BASE + (TEXT_OFF + EXIT_STUB_OFF) as u64;

/// CoW fork child restore trampoline: xor eax,eax + pop callee-saved + ret.
/// Child returns from fork() with RAX=0.
pub const COW_FORK_RESTORE_ADDR: u64 = VDSO_BASE + (TEXT_OFF + COW_FORK_RESTORE_OFF) as u64;

/// Yield loop: thread yields CPU in an infinite loop (keeps process alive).
/// Used for orphaned exec threads that must NOT exit (to keep wineserver connections alive).
pub const YIELD_LOOP_ADDR: u64 = VDSO_BASE + (TEXT_OFF + YIELD_LOOP_OFF) as u64;

/// Fork TLS trampoline: written dynamically before each fork.
/// Does arch_prctl(ARCH_SET_FS, fork_fsbase), then jumps to COW_FORK_RESTORE_ADDR.
pub const FORK_TLS_TRAMPOLINE_ADDR: u64 = VDSO_BASE + (TEXT_OFF + FORK_TLS_TRAMPOLINE_OFF) as u64;

/// Pre-TLS entry trampoline: written by exec_loaded_elf at exec time.
/// Does arch_prctl(SET_FS, PRE_TLS_ADDR), then jumps to the ELF entry point.
/// MUST NOT overlap with COW_FORK_RESTORE or FORK_TLS_TRAMPOLINE.
pub const PRE_TLS_TRAMPOLINE_ADDR: u64 = VDSO_BASE + (TEXT_OFF + PRE_TLS_TRAMPOLINE_OFF) as u64;

// Number of symbols (including STN_UNDEF)
const NUM_SYMS: usize = 5;

// ---------------------------------------------------------------
// .dynstr layout
// ---------------------------------------------------------------
// offset 0:  \0
// offset 1:  "linux-vdso.so.1\0"  (16 bytes)
// offset 17: "LINUX_2.6\0"        (10 bytes)
// offset 27: "__vdso_clock_gettime\0" (21 bytes)
// offset 48: "__vdso_gettimeofday\0"  (20 bytes)
// offset 68: "__vdso_time\0"          (12 bytes)
// offset 80: "__vdso_getcpu\0"        (14 bytes)
// total: 94 bytes

const STR_SONAME: usize = 1;
const STR_LINUX26: usize = 17;
const STR_CGT: usize = 27;
const STR_GTOD: usize = 48;
const STR_TIME: usize = 68;
const STR_GETCPU: usize = 80;
const DYNSTR_SIZE: usize = 94;

// Code offsets within .text
const CODE_CGT: usize = 0x00; // __vdso_clock_gettime
const CODE_GTOD: usize = 0x4A; // stub
const CODE_TIME: usize = 0x50; // stub
const CODE_GETCPU: usize = 0x56; // stub

// ---------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------

fn w16(p: &mut [u8], off: usize, v: u16) {
    p[off..off + 2].copy_from_slice(&v.to_le_bytes());
}

fn w32(p: &mut [u8], off: usize, v: u32) {
    p[off..off + 4].copy_from_slice(&v.to_le_bytes());
}

fn w64(p: &mut [u8], off: usize, v: u64) {
    p[off..off + 8].copy_from_slice(&v.to_le_bytes());
}

fn wbs(p: &mut [u8], off: usize, data: &[u8]) {
    p[off..off + data.len()].copy_from_slice(data);
}

/// ELF SysV hash (from the ELF specification).
const fn elf_hash(name: &[u8]) -> u32 {
    let mut h: u32 = 0;
    let mut i = 0;
    while i < name.len() {
        h = (h << 4).wrapping_add(name[i] as u32);
        let g = h & 0xF000_0000;
        if g != 0 {
            h ^= g >> 24;
        }
        h &= !g;
        i += 1;
    }
    h
}

// ---------------------------------------------------------------
// Machine code for __vdso_clock_gettime
// ---------------------------------------------------------------
// Calling convention: rdi=clock_id (ignored), rsi=*timespec
// Uses RDTSC and boot_tsc from the data area (RIP-relative).
// Assumes 2 GHz TSC (elapsed_ns = (tsc - boot_tsc) / 2).
//
// Layout:
//   0x00  push rbx
//   0x01  lea rbx, [rip + disp32]    ; -> DATA_OFF within page
//   0x08  mov rcx, [rbx]             ; boot_tsc
//   0x0B  rdtsc
//   0x0D  shl rdx, 32
//   0x11  or rax, rdx
//   0x14  sub rax, rcx
//   0x17  jb .zero                   ; carry → elapsed < 0
//   0x19  shr rax, 1                 ; ns = cycles / 2
//   0x1C  xor edx, edx
//   0x1E  movabs rcx, 1000000000
//   0x28  div rcx                    ; rax=sec, rdx=nsec
//   0x2B  mov [rsi], rax
//   0x2E  mov [rsi+8], rdx
//   0x32  xor eax, eax
//   0x34  pop rbx
//   0x35  ret
//   ; .zero (0x37):
//   0x37  mov qword [rsi], 0
//   0x3E  mov qword [rsi+8], 0
//   0x46  xor eax, eax
//   0x48  pop rbx
//   0x49  ret

fn emit_clock_gettime(p: &mut [u8], text_base: usize, data_base: usize) {
    let off = text_base + CODE_CGT;

    // push rbx
    p[off] = 0x53;

    // lea rbx, [rip + disp32] — 7 bytes, RIP = off+1+7 = off+8
    let disp = (data_base as i64) - ((off + 8) as i64);
    p[off + 1] = 0x48;
    p[off + 2] = 0x8D;
    p[off + 3] = 0x1D;
    w32(p, off + 4, disp as i32 as u32);

    // mov rcx, [rbx]
    wbs(p, off + 0x08, &[0x48, 0x8B, 0x0B]);

    // rdtsc
    wbs(p, off + 0x0B, &[0x0F, 0x31]);

    // shl rdx, 32
    wbs(p, off + 0x0D, &[0x48, 0xC1, 0xE2, 0x20]);

    // or rax, rdx
    wbs(p, off + 0x11, &[0x48, 0x09, 0xD0]);

    // sub rax, rcx
    wbs(p, off + 0x14, &[0x48, 0x29, 0xC8]);

    // jb .zero (displacement = 0x37 - 0x19 = 0x1E)
    wbs(p, off + 0x17, &[0x72, 0x1E]);

    // shr rax, 1
    wbs(p, off + 0x19, &[0x48, 0xD1, 0xE8]);

    // xor edx, edx
    wbs(p, off + 0x1C, &[0x31, 0xD2]);

    // movabs rcx, 1000000000 (0x3B9ACA00)
    wbs(p, off + 0x1E, &[
        0x48, 0xB9,
        0x00, 0xCA, 0x9A, 0x3B, 0x00, 0x00, 0x00, 0x00,
    ]);

    // div rcx
    wbs(p, off + 0x28, &[0x48, 0xF7, 0xF1]);

    // mov [rsi], rax
    wbs(p, off + 0x2B, &[0x48, 0x89, 0x06]);

    // mov [rsi+8], rdx
    wbs(p, off + 0x2E, &[0x48, 0x89, 0x56, 0x08]);

    // xor eax, eax
    wbs(p, off + 0x32, &[0x31, 0xC0]);

    // pop rbx
    p[off + 0x34] = 0x5B;

    // ret
    p[off + 0x35] = 0xC3;

    // --- .zero handler at +0x37 ---

    // mov qword [rsi], 0
    wbs(p, off + 0x37, &[0x48, 0xC7, 0x06, 0x00, 0x00, 0x00, 0x00]);

    // mov qword [rsi+8], 0
    wbs(p, off + 0x3E, &[0x48, 0xC7, 0x46, 0x08, 0x00, 0x00, 0x00, 0x00]);

    // xor eax, eax
    wbs(p, off + 0x46, &[0x31, 0xC0]);

    // pop rbx
    p[off + 0x48] = 0x5B;

    // ret
    p[off + 0x49] = 0xC3;
}

/// Emit a stub that returns -ENOSYS (38) → mov eax, -38; ret
fn emit_stub(p: &mut [u8], off: usize) {
    // mov eax, 0xFFFFFFDA (-38 as i32)
    wbs(p, off, &[0xB8, 0xDA, 0xFF, 0xFF, 0xFF]);
    // ret
    p[off + 5] = 0xC3;
}

// ---------------------------------------------------------------
// Main forger
// ---------------------------------------------------------------

/// Forge the vDSO ELF into `page` (must be a zeroed 4096-byte buffer).
/// `boot_tsc` is the TSC value captured at boot time.
pub fn forge(page: &mut [u8], boot_tsc: u64) {
    // All addresses in .dynamic and .dynsym are ABSOLUTE (VDSO_BASE-based).
    // musl's dynamic linker computes base = eh + p_offset - p_vaddr
    //   = VDSO_BASE + 0 - VDSO_BASE = 0
    // Then laddr(p, val) = 0 + val = val, so .dynamic values must be
    // the actual runtime addresses (VDSO_BASE + page_offset).
    let vb = VDSO_BASE as u64;

    // ---- ELF Header (64 bytes at offset 0) ----
    wbs(page, 0, &[0x7F, b'E', b'L', b'F']); // e_ident magic
    page[4] = 2; // ELFCLASS64
    page[5] = 1; // ELFDATA2LSB
    page[6] = 1; // EV_CURRENT
    // e_ident[7..16] = 0 (ELFOSABI_NONE, padding)

    w16(page, 16, 3); // e_type = ET_DYN
    w16(page, 18, 0x3E); // e_machine = EM_X86_64
    w32(page, 20, 1); // e_version = EV_CURRENT
    w64(page, 24, vb + TEXT_OFF as u64); // e_entry (absolute vaddr)
    w64(page, 32, PHDR_OFF as u64); // e_phoff (file offset, not vaddr)
    w64(page, 40, 0); // e_shoff (no section headers)
    w32(page, 48, 0); // e_flags
    w16(page, 52, 64); // e_ehsize
    w16(page, 54, 56); // e_phentsize
    w16(page, 56, 2); // e_phnum (PT_LOAD + PT_DYNAMIC)
    w16(page, 58, 0); // e_shentsize
    w16(page, 60, 0); // e_shnum
    w16(page, 62, 0); // e_shstrndx

    // ---- Program Header 0: PT_LOAD (56 bytes at PHDR_OFF) ----
    let ph0 = PHDR_OFF;
    w32(page, ph0, 1); // p_type = PT_LOAD
    w32(page, ph0 + 4, 5); // p_flags = PF_R | PF_X
    w64(page, ph0 + 8, 0); // p_offset (file offset)
    w64(page, ph0 + 16, vb); // p_vaddr = VDSO_BASE (absolute)
    w64(page, ph0 + 24, vb); // p_paddr
    w64(page, ph0 + 32, 0x1000); // p_filesz
    w64(page, ph0 + 40, 0x1000); // p_memsz
    w64(page, ph0 + 48, 0x1000); // p_align

    // ---- Program Header 1: PT_DYNAMIC (56 bytes at PHDR_OFF+56) ----
    let ph1 = PHDR_OFF + 56;
    let dyn_size: u64 = 9 * 16; // 9 entries × 16 bytes
    w32(page, ph1, 2); // p_type = PT_DYNAMIC
    w32(page, ph1 + 4, 4); // p_flags = PF_R
    w64(page, ph1 + 8, DYNAMIC_OFF as u64); // p_offset (file offset)
    w64(page, ph1 + 16, vb + DYNAMIC_OFF as u64); // p_vaddr (absolute)
    w64(page, ph1 + 24, vb + DYNAMIC_OFF as u64); // p_paddr
    w64(page, ph1 + 32, dyn_size); // p_filesz
    w64(page, ph1 + 40, dyn_size); // p_memsz
    w64(page, ph1 + 48, 8); // p_align

    // ---- .dynamic section (at DYNAMIC_OFF) ----
    // All address values are ABSOLUTE (VDSO_BASE + page_offset).
    let mut d = DYNAMIC_OFF;
    let dyn_entry = |p: &mut [u8], d: &mut usize, tag: u64, val: u64| {
        w64(p, *d, tag);
        w64(p, *d + 8, val);
        *d += 16;
    };

    dyn_entry(page, &mut d, 4, vb + HASH_OFF as u64); // DT_HASH
    dyn_entry(page, &mut d, 5, vb + DYNSTR_OFF as u64); // DT_STRTAB
    dyn_entry(page, &mut d, 6, vb + DYNSYM_OFF as u64); // DT_SYMTAB
    dyn_entry(page, &mut d, 10, DYNSTR_SIZE as u64); // DT_STRSZ (size, not addr)
    dyn_entry(page, &mut d, 11, 24); // DT_SYMENT (size, not addr)
    dyn_entry(page, &mut d, 0x6FFF_FFF0, vb + VERSYM_OFF as u64); // DT_VERSYM
    dyn_entry(page, &mut d, 0x6FFF_FFFC, vb + VERDEF_OFF as u64); // DT_VERDEF
    dyn_entry(page, &mut d, 0x6FFF_FFFD, 2); // DT_VERDEFNUM (count, not addr)
    dyn_entry(page, &mut d, 0, 0); // DT_NULL

    // ---- .dynsym (at DYNSYM_OFF, 5 entries × 24 bytes) ----
    // Symbol st_value is ABSOLUTE (VDSO_BASE + code_offset).
    // [0] STN_UNDEF — all zeros (already zeroed)
    let sym = |p: &mut [u8], idx: usize, name: u32, value: u64, size: u64| {
        let base = DYNSYM_OFF + idx * 24;
        w32(p, base, name);
        p[base + 4] = 0x12; // STB_GLOBAL(1) | STT_FUNC(2)
        p[base + 5] = 0; // STV_DEFAULT
        w16(p, base + 6, 1); // st_shndx = 1 (first section, our code)
        w64(p, base + 8, value);
        w64(p, base + 16, size);
    };

    sym(page, 1, STR_CGT as u32, vb + (TEXT_OFF + CODE_CGT) as u64, 0x4A);
    sym(page, 2, STR_GTOD as u32, vb + (TEXT_OFF + CODE_GTOD) as u64, 6);
    sym(page, 3, STR_TIME as u32, vb + (TEXT_OFF + CODE_TIME) as u64, 6);
    sym(page, 4, STR_GETCPU as u32, vb + (TEXT_OFF + CODE_GETCPU) as u64, 6);

    // ---- .dynstr (at DYNSTR_OFF) ----
    page[DYNSTR_OFF] = 0; // null string at offset 0
    wbs(page, DYNSTR_OFF + STR_SONAME, b"linux-vdso.so.1\0");
    wbs(page, DYNSTR_OFF + STR_LINUX26, b"LINUX_2.6\0");
    wbs(page, DYNSTR_OFF + STR_CGT, b"__vdso_clock_gettime\0");
    wbs(page, DYNSTR_OFF + STR_GTOD, b"__vdso_gettimeofday\0");
    wbs(page, DYNSTR_OFF + STR_TIME, b"__vdso_time\0");
    wbs(page, DYNSTR_OFF + STR_GETCPU, b"__vdso_getcpu\0");

    // ---- .hash — SysV hash table (at HASH_OFF) ----
    // nbucket=1, nchain=5, bucket[0]=1, chain=[0,2,3,4,0]
    w32(page, HASH_OFF, 1); // nbucket
    w32(page, HASH_OFF + 4, NUM_SYMS as u32); // nchain
    w32(page, HASH_OFF + 8, 1); // bucket[0] = first non-null symbol
    w32(page, HASH_OFF + 12, 0); // chain[0] = 0 (STN_UNDEF end)
    w32(page, HASH_OFF + 16, 2); // chain[1] → sym 2
    w32(page, HASH_OFF + 20, 3); // chain[2] → sym 3
    w32(page, HASH_OFF + 24, 4); // chain[3] → sym 4
    w32(page, HASH_OFF + 28, 0); // chain[4] → end

    // ---- .gnu.version / versym (at VERSYM_OFF, NUM_SYMS × 2 bytes) ----
    w16(page, VERSYM_OFF, 0); // sym[0] = VER_NDX_LOCAL
    w16(page, VERSYM_OFF + 2, 2); // sym[1] = version index 2 (LINUX_2.6)
    w16(page, VERSYM_OFF + 4, 2); // sym[2]
    w16(page, VERSYM_OFF + 6, 2); // sym[3]
    w16(page, VERSYM_OFF + 8, 2); // sym[4]

    // ---- .gnu.version_d / verdef (at VERDEF_OFF) ----
    // Verdef[0]: base version (soname)
    //   Elf64_Verdef: vd_version(2) vd_flags(2) vd_ndx(2) vd_cnt(2) vd_hash(4) vd_aux(4) vd_next(4)
    //   Total: 20 bytes
    let vd0 = VERDEF_OFF;
    w16(page, vd0, 1); // vd_version
    w16(page, vd0 + 2, 1); // vd_flags = VER_FLG_BASE
    w16(page, vd0 + 4, 1); // vd_ndx = 1
    w16(page, vd0 + 6, 1); // vd_cnt = 1
    w32(page, vd0 + 8, elf_hash(b"linux-vdso.so.1")); // vd_hash
    w32(page, vd0 + 12, 20); // vd_aux (offset to verdaux from this verdef)
    w32(page, vd0 + 16, 28); // vd_next (sizeof verdef + sizeof verdaux = 20 + 8)

    // Verdaux[0]: vda_name(4) vda_next(4)
    let va0 = vd0 + 20;
    w32(page, va0, STR_SONAME as u32); // vda_name → "linux-vdso.so.1"
    w32(page, va0 + 4, 0); // vda_next = 0

    // Verdef[1]: LINUX_2.6
    let vd1 = vd0 + 28;
    w16(page, vd1, 1); // vd_version
    w16(page, vd1 + 2, 0); // vd_flags = 0
    w16(page, vd1 + 4, 2); // vd_ndx = 2
    w16(page, vd1 + 6, 1); // vd_cnt = 1
    w32(page, vd1 + 8, elf_hash(b"LINUX_2.6")); // vd_hash
    w32(page, vd1 + 12, 20); // vd_aux
    w32(page, vd1 + 16, 0); // vd_next = 0 (last)

    // Verdaux[1]
    let va1 = vd1 + 20;
    w32(page, va1, STR_LINUX26 as u32); // vda_name → "LINUX_2.6"
    w32(page, va1 + 4, 0); // vda_next = 0

    // ---- vDSO data (at DATA_OFF) ----
    w64(page, DATA_OFF, boot_tsc);

    // ---- .text — machine code (at TEXT_OFF) ----
    emit_clock_gettime(page, TEXT_OFF, DATA_OFF);
    emit_stub(page, TEXT_OFF + CODE_GTOD);
    emit_stub(page, TEXT_OFF + CODE_TIME);
    emit_stub(page, TEXT_OFF + CODE_GETCPU);

    // ---- Signal trampoline (at TEXT_OFF + SIGNAL_TRAMPOLINE_OFF) ----
    // Entered by the kernel when a timer interrupt detects a pending async signal.
    // All GPRs are the user's original values (restored by the timer handler).
    // Calls SYSCALL(0x7F00) to let LUCAS deliver the signal.
    // If the syscall returns normally (shouldn't happen, but can in edge cases
    // when the IPC reply is not SIG_REDIRECT), retry instead of crashing.
    //   mov eax, 0x7F00   → B8 00 7F 00 00
    //   syscall            → 0F 05
    //   jmp -7 (back to mov) → EB F7
    let t = TEXT_OFF + SIGNAL_TRAMPOLINE_OFF;
    page[t]     = 0xB8;  // mov eax, imm32
    page[t + 1] = 0x00;
    page[t + 2] = 0x7F;
    page[t + 3] = 0x00;
    page[t + 4] = 0x00;
    page[t + 5] = 0x0F;  // syscall
    page[t + 6] = 0x05;
    page[t + 7] = 0xEB;  // jmp rel8
    page[t + 8] = 0xF7;  // -9 (back to offset t)

    // ---- Sigreturn restorer (at TEXT_OFF + SIGRETURN_RESTORER_OFF) ----
    // Used as sa_restorer / fallback restorer. Just calls rt_sigreturn.
    //   mov eax, 15       → B8 0F 00 00 00
    //   syscall            → 0F 05
    //   ud2                → 0F 0B
    let r = TEXT_OFF + SIGRETURN_RESTORER_OFF;
    page[r]     = 0xB8;  // mov eax, imm32
    page[r + 1] = 0x0F;  // 15
    page[r + 2] = 0x00;
    page[r + 3] = 0x00;
    page[r + 4] = 0x00;
    page[r + 5] = 0x0F;  // syscall
    page[r + 6] = 0x05;
    page[r + 7] = 0x0F;  // ud2
    page[r + 8] = 0x0B;

    // ---- Fork restore trampoline (at TEXT_OFF + FORK_RESTORE_OFF) ----
    // Restores callee-saved registers pushed onto the stack by the fork handler,
    // then returns to the fork return point (address is on the stack).
    //   pop rbx    → 5B
    //   pop rbp    → 5D
    //   pop r12    → 41 5C
    //   pop r13    → 41 5D
    //   pop r14    → 41 5E
    //   pop r15    → 41 5F
    //   ret        → C3
    let f = TEXT_OFF + FORK_RESTORE_OFF;
    page[f]      = 0x5B;  // pop rbx
    page[f + 1]  = 0x5D;  // pop rbp
    page[f + 2]  = 0x41;  // pop r12
    page[f + 3]  = 0x5C;
    page[f + 4]  = 0x41;  // pop r13
    page[f + 5]  = 0x5D;
    page[f + 6]  = 0x41;  // pop r14
    page[f + 7]  = 0x5E;
    page[f + 8]  = 0x41;  // pop r15
    page[f + 9]  = 0x5F;
    page[f + 10] = 0xC3;  // ret

    // ---- Exit stub (at TEXT_OFF + EXIT_STUB_OFF) ----
    // RDI already set via SIG_REDIRECT_TAG (regs[1] → rdi)
    //   mov eax, 231   → B8 E7 00 00 00
    //   syscall         → 0F 05
    //   hlt             → F4
    let e = TEXT_OFF + EXIT_STUB_OFF;
    page[e]     = 0xB8;  // mov eax, imm32
    page[e + 1] = 0xE7;  // 231 = exit_group
    page[e + 2] = 0x00;
    page[e + 3] = 0x00;
    page[e + 4] = 0x00;
    page[e + 5] = 0x0F;  // syscall
    page[e + 6] = 0x05;
    page[e + 7] = 0xF4;  // hlt

    // ---- CoW fork child restore trampoline (at TEXT_OFF + COW_FORK_RESTORE_OFF) ----
    // Like FORK_RESTORE but zeroes RAX first (child fork returns 0).
    //   xor eax, eax → 31 C0
    //   pop rbx      → 5B
    //   pop rbp      → 5D
    //   pop r12      → 41 5C
    //   pop r13      → 41 5D
    //   pop r14      → 41 5E
    //   pop r15      → 41 5F
    //   ret          → C3
    let c = TEXT_OFF + COW_FORK_RESTORE_OFF;
    page[c]      = 0x31;  // xor eax, eax
    page[c + 1]  = 0xC0;
    page[c + 2]  = 0x5B;  // pop rbx
    page[c + 3]  = 0x5D;  // pop rbp
    page[c + 4]  = 0x41;  // pop r12
    page[c + 5]  = 0x5C;
    page[c + 6]  = 0x41;  // pop r13
    page[c + 7]  = 0x5D;
    page[c + 8]  = 0x41;  // pop r14
    page[c + 9]  = 0x5E;
    page[c + 10] = 0x41;  // pop r15
    page[c + 11] = 0x5F;
    page[c + 12] = 0xC3;  // ret

    // ---- Yield loop (at TEXT_OFF + YIELD_LOOP_OFF) ----
    // Infinite loop: mov eax,24(sched_yield); syscall; jmp back
    //   mov eax, 24  → B8 18 00 00 00
    //   syscall       → 0F 05
    //   jmp -7        → EB F7
    let y = TEXT_OFF + YIELD_LOOP_OFF;
    page[y]     = 0xB8;
    page[y + 1] = 0x18; // 24 = sched_yield
    page[y + 2] = 0x00;
    page[y + 3] = 0x00;
    page[y + 4] = 0x00;
    page[y + 5] = 0x0F; // syscall
    page[y + 6] = 0x05;
    page[y + 7] = 0xEB; // jmp rel8
    page[y + 8] = 0xF7; // -9 (back to mov)
}

/// Write a dynamic fork TLS trampoline at FORK_TLS_TRAMPOLINE_ADDR.
/// This is called before each CoW fork to embed the parent's FS_BASE and GS_BASE
/// into a code stub that the child executes BEFORE touching TLS/GS.
///
/// Generated code (up to 49 bytes if gs_base != 0, else 27 bytes):
///   [if gs_base != 0:]
///     mov edi, 0x1001          ; ARCH_SET_GS
///     movabs rsi, <gs_base>    ; 8-byte immediate
///     mov eax, 158             ; SYS_arch_prctl
///     syscall
///   mov edi, 0x1002            ; ARCH_SET_FS
///   movabs rsi, <fs_base>      ; 8-byte immediate
///   mov eax, 158               ; SYS_arch_prctl
///   syscall
///   jmp COW_FORK_RESTORE_ADDR
pub fn write_fork_tls_trampoline(fs_base: u64, gs_base: u64) {
    let addr = FORK_TLS_TRAMPOLINE_ADDR;
    // Make vDSO page writable
    let _ = sotos_common::sys::protect(addr & !0xFFF, 2); // 2 = writable
    unsafe {
        let p = addr as *mut u8;
        let mut off = 0usize;

        // Optional: SET_GS if gs_base != 0
        if gs_base != 0 {
            // mov edi, 0x1001 (5 bytes)
            *p.add(off) = 0xBF; off += 1;
            *p.add(off) = 0x01; off += 1; *p.add(off) = 0x10; off += 1;
            *p.add(off) = 0x00; off += 1; *p.add(off) = 0x00; off += 1;
            // movabs rsi, gs_base (10 bytes)
            *p.add(off) = 0x48; off += 1; *p.add(off) = 0xBE; off += 1;
            core::ptr::copy_nonoverlapping(&gs_base as *const u64 as *const u8, p.add(off), 8); off += 8;
            // mov eax, 158 (5 bytes)
            *p.add(off) = 0xB8; off += 1; *p.add(off) = 0x9E; off += 1;
            *p.add(off) = 0x00; off += 1; *p.add(off) = 0x00; off += 1; *p.add(off) = 0x00; off += 1;
            // syscall (2 bytes)
            *p.add(off) = 0x0F; off += 1; *p.add(off) = 0x05; off += 1;
        }

        // SET_FS
        // mov edi, 0x1002 (5 bytes)
        *p.add(off) = 0xBF; off += 1;
        *p.add(off) = 0x02; off += 1; *p.add(off) = 0x10; off += 1;
        *p.add(off) = 0x00; off += 1; *p.add(off) = 0x00; off += 1;
        // movabs rsi, fs_base (10 bytes)
        *p.add(off) = 0x48; off += 1; *p.add(off) = 0xBE; off += 1;
        core::ptr::copy_nonoverlapping(&fs_base as *const u64 as *const u8, p.add(off), 8); off += 8;
        // mov eax, 158 (5 bytes)
        *p.add(off) = 0xB8; off += 1; *p.add(off) = 0x9E; off += 1;
        *p.add(off) = 0x00; off += 1; *p.add(off) = 0x00; off += 1; *p.add(off) = 0x00; off += 1;
        // syscall (2 bytes)
        *p.add(off) = 0x0F; off += 1; *p.add(off) = 0x05; off += 1;

        // jmp rel32 to COW_FORK_RESTORE_ADDR (5 bytes)
        let target = COW_FORK_RESTORE_ADDR as i64;
        let here = (addr as usize + off + 5) as i64;
        let rel = (target - here) as i32;
        *p.add(off) = 0xE9; off += 1;
        core::ptr::copy_nonoverlapping(&rel as *const i32 as *const u8, p.add(off), 4);
    }
    // Make vDSO page executable again (read+execute, no write)
    let _ = sotos_common::sys::protect(addr & !0xFFF, 0);
}

/// Same as `write_fork_tls_trampoline` but writes to a separate address space.
///
/// This function is CoW-safe: it allocates a new physical frame for the vDSO page
/// in the target AS, copies the existing content, writes the trampoline, and maps
/// the new frame. This avoids corrupting shared CoW frames (which `protect_in` +
/// direct write would do, since `protect_page` doesn't handle CoW).
///
/// Must be called AFTER `clone_cow()` with the **child's** AS cap, not the parent's.
pub fn write_fork_tls_trampoline_in(as_cap: u64, fs_base: u64, gs_base: u64) {
    use sotos_common::sys;

    let addr = FORK_TLS_TRAMPOLINE_ADDR;
    let page = addr & !0xFFF; // 0xB80000

    // Build trampoline code in a local buffer (max 49 bytes with GS, 27 without)
    let mut buf = [0u8; 64];
    let mut off = 0usize;

    // Optional: SET_GS if gs_base != 0
    if gs_base != 0 {
        buf[off] = 0xBF; off += 1; // mov edi, 0x1001
        buf[off] = 0x01; off += 1; buf[off] = 0x10; off += 1;
        buf[off] = 0x00; off += 1; buf[off] = 0x00; off += 1;
        buf[off] = 0x48; off += 1; buf[off] = 0xBE; off += 1; // movabs rsi, gs_base
        buf[off..off+8].copy_from_slice(&gs_base.to_le_bytes()); off += 8;
        buf[off] = 0xB8; off += 1; buf[off] = 0x9E; off += 1; // mov eax, 158
        buf[off] = 0x00; off += 1; buf[off] = 0x00; off += 1; buf[off] = 0x00; off += 1;
        buf[off] = 0x0F; off += 1; buf[off] = 0x05; off += 1; // syscall
    }

    // SET_FS
    buf[off] = 0xBF; off += 1; // mov edi, 0x1002
    buf[off] = 0x02; off += 1; buf[off] = 0x10; off += 1;
    buf[off] = 0x00; off += 1; buf[off] = 0x00; off += 1;
    buf[off] = 0x48; off += 1; buf[off] = 0xBE; off += 1; // movabs rsi, fs_base
    buf[off..off+8].copy_from_slice(&fs_base.to_le_bytes()); off += 8;
    buf[off] = 0xB8; off += 1; buf[off] = 0x9E; off += 1; // mov eax, 158
    buf[off] = 0x00; off += 1; buf[off] = 0x00; off += 1; buf[off] = 0x00; off += 1;
    buf[off] = 0x0F; off += 1; buf[off] = 0x05; off += 1; // syscall

    // jmp rel32 to COW_FORK_RESTORE_ADDR
    let target = COW_FORK_RESTORE_ADDR as i64;
    let here = (addr as usize + off + 5) as i64;
    let rel = (target - here) as i32;
    buf[off] = 0xE9; off += 1;
    buf[off..off+4].copy_from_slice(&rel.to_le_bytes()); off += 4;

    // CoW-safe write: allocate a private frame for the child's vDSO page,
    // copy the parent's content, then write the trampoline into the private copy.
    if let Ok(nf) = sys::frame_alloc() {
        if sys::frame_copy(nf, as_cap, page).is_ok() {
            let _ = sys::unmap_from(as_cap, page);
            // Map writable so vm_write doesn't trigger another CoW allocation
            let _ = sys::map_into(as_cap, page, nf, 2); // 2 = writable
            // Write trampoline into the private frame
            let _ = sys::vm_write(as_cap, addr, buf.as_ptr() as u64, off as u64);
            // Restore R+X permissions (executable, not writable)
            let _ = sys::protect_in(as_cap, page, 0);
        }
    }
}
