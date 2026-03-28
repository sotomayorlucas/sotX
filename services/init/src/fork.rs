// ---------------------------------------------------------------------------
// fork.rs: Fork/vfork/clone stack management and static buffers.
// Extracted from child_handler.rs.
// ---------------------------------------------------------------------------

use crate::process::MAX_PROCS;

/// Stack region save buffer for fork -- child runs on parent's stack and corrupts
/// caller frames + envp strings in the setup area above initial RSP.
/// 32KB covers deep call chains (git clone -> transport -> start_command -> fork).
pub(crate) const FORK_STACK_SAVE_SIZE: usize = 32768;
pub(crate) static mut FORK_STACK_BUF: [[u8; FORK_STACK_SAVE_SIZE]; MAX_PROCS] = [[0u8; FORK_STACK_SAVE_SIZE]; MAX_PROCS];

/// Heap (brk region) save buffer for fork -- vfork child's malloc/setenv/etc.
/// modify the parent's brk heap in-place (free-list metadata, environ array).
/// We save up to 128KB of brk pages and restore after fork-child phase.
pub(crate) const FORK_HEAP_SAVE_SIZE: usize = 131072;
pub(crate) static mut FORK_HEAP_BUF: [[u8; FORK_HEAP_SAVE_SIZE]; MAX_PROCS] = [[0u8; FORK_HEAP_SAVE_SIZE]; MAX_PROCS];
pub(crate) static mut FORK_HEAP_USED: [usize; MAX_PROCS] = [0; MAX_PROCS];

/// Read a u64 from either saved FORK_STACK_BUF or live memory.
/// When the address falls within the saved [fork_rsp, fork_rsp + SAVE_SIZE) range,
/// reads from the pre-corruption snapshot in FORK_STACK_BUF.
#[inline]
pub(crate) unsafe fn read_u64_saved(addr: u64, fork_rsp: u64, pid: usize) -> u64 {
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
pub(crate) unsafe fn copy_guest_path_saved(guest_ptr: u64, out: &mut [u8], fork_rsp: u64, pid: usize) -> usize {
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
        // arch_prctl(ARCH_SET_FS, tls) -- intercepted by kernel before redirect
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
