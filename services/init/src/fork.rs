// ---------------------------------------------------------------------------
// fork.rs: Fork/vfork/clone stack management, static buffers, and the
// SYS_FORK/SYS_VFORK CoW implementation.
// Extracted from child_handler.rs.
// ---------------------------------------------------------------------------

use sotos_common::sys;
use sotos_common::linux_abi::{ENOMEM, ENOSYS, CLONE_CHILD_SETTID,
                              CLONE_CHILD_CLEARTID, CLONE_PARENT_SETTID,
                              CLONE_SETTLS};
use sotos_common::IpcMsg;
use core::sync::atomic::Ordering;
use crate::framebuffer::{print, print_u64};
use crate::process::{MAX_PROCS, NEXT_PID, NEXT_CHILD_STACK, PROCESSES,
                     INIT_SELF_AS_CAP, proc_group_init, proc_thread_init,
                     CHILD_SETUP_EP, CHILD_SETUP_PID, CHILD_SETUP_FLAGS,
                     CHILD_SETUP_AS_CAP, CHILD_SETUP_READY};
use crate::fd::{THREAD_GROUPS, DIR_FD_PATHS, MAX_DIR_SLOTS, GRP_MAX_FDS,
                FORK_FD_FLAGS, FORK_SOCK_CONN, FORK_SOCK_UDP_LPORT,
                FORK_SOCK_UDP_RIP, FORK_SOCK_UDP_RPORT, FORK_SOCK_READY,
                PIPE_WRITE_REFS, PIPE_READ_REFS, MAX_PIPES,
                UNIX_CONN_REFS, MAX_UNIX_CONNS};
use crate::vdso;
use crate::child_handler::child_handler;

const MAP_WRITABLE: u64 = 2;

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

// ---------------------------------------------------------------------------
// SYS_FORK / SYS_VFORK implementation (extracted from child_handler, fase 2b).
// ---------------------------------------------------------------------------

/// SYS_FORK / SYS_VFORK — real CoW fork via addr_space_clone.
///
/// Flow:
/// 1. Clone parent's address space (all pages CoW).
/// 2. Build restore frame below fork_rsp so child resumes via
///    COW_FORK_RESTORE trampoline with callee-saved regs + RIP.
/// 3. Eagerly copy the top 8 stack pages + TLS page into the child's
///    private AS so the child doesn't fault on its own stack.
/// 4. Fix up glibc fork atfork list + TLS thread-id fields.
/// 5. Spawn the child handler thread in init's AS, child guest thread
///    in the cloned AS.
///
/// Returns the value the caller should `reply_val(ep_cap, ...)` with:
/// negative errno on failure, child_pid on success.
///
/// `parent_as` is the caller's child_as_cap (0 for PID 1's own AS).
/// `fdg` / `memg` are the FD/memory group indices of the parent.
///
/// `clone_flags` enables the CLONE_*_TID families used by SYS_CLONE in
/// its fork-style path (no CLONE_VM). Pass 0 for SYS_FORK / SYS_VFORK
/// which do not expose those flags.
pub(crate) fn do_cow_fork(pid: usize, fdg: usize, memg: usize,
                          parent_as: u64, msg: &IpcMsg,
                          clone_flags: u64) -> i64 {
    let fork_cpid = NEXT_PID.fetch_add(1, Ordering::SeqCst) as usize;
    if fork_cpid > MAX_PROCS {
        return -ENOMEM;
    }

    // Determine source AS: parent's separate AS if non-zero, else init's AS.
    let clone_source = if parent_as != 0 {
        parent_as
    } else {
        let cap = INIT_SELF_AS_CAP.load(Ordering::Acquire);
        if cap == 0 {
            print(b"FORK: no self_as_cap!\n");
            return -ENOSYS;
        }
        cap
    };

    // Get parent's register state.
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
    // Write fork frame (callee-saved regs) to parent's stack.
    // For parent_as != 0, vm_write is deferred until AFTER the eager
    // stack page copy to avoid the copy overwriting the frame.
    if parent_as == 0 {
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

    // Trampoline needed if TLS/GS is set.
    let need_trampoline = fork_fsbase != 0 || fork_gsbase != 0;
    let child_entry = if need_trampoline {
        vdso::FORK_TLS_TRAMPOLINE_ADDR
    } else {
        vdso::COW_FORK_RESTORE_ADDR
    };

    // For init's own AS (no CoW sharing), write TLS/GS trampoline pre-clone.
    if need_trampoline && parent_as == 0 {
        vdso::write_fork_tls_trampoline(fork_fsbase, fork_gsbase);
    }

    // Clone the address space with CoW semantics.
    let child_as_cap = match sys::addr_space_clone(clone_source) {
        Ok(cap) => cap,
        Err(_) => return -ENOMEM,
    };

    // For separate AS: write TLS trampoline into the child's private vDSO page.
    if need_trampoline && parent_as != 0 {
        vdso::write_fork_tls_trampoline_in(child_as_cap, fork_fsbase, fork_gsbase);
    }

    // Fix glibc fork atfork list.
    if fork_rbx != 0 {
        let head_addr = fork_rbx.wrapping_add(0x1088);
        let _ = sys::vm_write(child_as_cap, 0,
            &head_addr as *const u64 as u64, 8);
        if head_addr > 0x10000 && head_addr < 0x0000_8000_0000_0000 {
            let _ = sys::vm_write(child_as_cap, head_addr,
                &head_addr as *const u64 as u64, 8);
            let _ = sys::vm_write(child_as_cap, head_addr + 8,
                &head_addr as *const u64 as u64, 8);
        }
    }

    // Eagerly copy stack pages for the child.
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

    // Write fork frame AFTER eager stack copy so it isn't overwritten.
    if parent_as != 0 {
        let mut frame_data = [0u8; 56];
        frame_data[0..8].copy_from_slice(&fork_rbx.to_le_bytes());
        frame_data[8..16].copy_from_slice(&fork_rbp.to_le_bytes());
        frame_data[16..24].copy_from_slice(&fork_r12.to_le_bytes());
        frame_data[24..32].copy_from_slice(&fork_r13.to_le_bytes());
        frame_data[32..40].copy_from_slice(&fork_r14.to_le_bytes());
        frame_data[40..48].copy_from_slice(&fork_r15.to_le_bytes());
        frame_data[48..56].copy_from_slice(&fork_rip.to_le_bytes());
        let _ = sys::vm_write(child_as_cap, frame_rsp, frame_data.as_ptr() as u64, 56);
    }

    // Fix glibc fork spin: eagerly copy TLS page and patch TID.
    if fork_fsbase != 0 {
        let tls_vaddr = fork_fsbase & !0xFFF;
        if let Ok(nf) = sys::frame_alloc() {
            if sys::frame_copy(nf, child_as_cap, tls_vaddr).is_ok() {
                let _ = sys::unmap_from(child_as_cap, tls_vaddr);
                let _ = sys::map_into(child_as_cap, tls_vaddr, nf, 2);
                let tid_val = fork_cpid as u32;
                let one: u32 = 1;
                let _ = sys::vm_write(child_as_cap, fork_fsbase + 0x2D0,
                    &tid_val as *const u32 as u64, 4);
                let _ = sys::vm_write(child_as_cap, fork_fsbase + 0x2D4,
                    &tid_val as *const u32 as u64, 4);
                let _ = sys::vm_write(child_as_cap, fork_fsbase + 0x2E0,
                    &one as *const u32 as u64, 4);
                print(b"TLS-FIX2 cpid="); print_u64(fork_cpid as u64); print(b"\n");
            }
        }
        let tls_vaddr2 = (fork_fsbase & !0xFFF) + 0x1000;
        if let Ok(nf2) = sys::frame_alloc() {
            if sys::frame_copy(nf2, child_as_cap, tls_vaddr2).is_ok() {
                let _ = sys::unmap_from(child_as_cap, tls_vaddr2);
                let _ = sys::map_into(child_as_cap, tls_vaddr2, nf2, 2);
            }
        }
    }

    // Create endpoint for child process.
    let child_ep = match sys::endpoint_create() {
        Ok(e) => e,
        Err(_) => return -ENOMEM,
    };

    // Create child thread in the cloned AS at the TLS trampoline.
    let child_thread = match sys::thread_create_in(
        child_as_cap, child_entry, frame_rsp, child_ep,
    ) {
        Ok(t) => t,
        Err(_) => return -ENOMEM,
    };
    let _ = sys::signal_entry(child_thread, vdso::SIGNAL_TRAMPOLINE_ADDR);

    // CLONE_*_TID flags (only set when called from SYS_CLONE fork-style).
    let ctid_ptr = msg.regs[3];
    let ptid_ptr = msg.regs[2];
    if clone_flags & CLONE_CHILD_SETTID != 0 && ctid_ptr != 0 {
        let tid_val = fork_cpid as u32;
        let _ = sys::vm_write(child_as_cap, ctid_ptr,
            &tid_val as *const u32 as u64, 4);
    }
    if clone_flags & CLONE_CHILD_CLEARTID != 0 && ctid_ptr != 0 {
        PROCESSES[fork_cpid - 1].clear_tid.store(ctid_ptr, Ordering::Release);
    }
    if clone_flags & CLONE_PARENT_SETTID != 0 && ptid_ptr != 0 {
        if parent_as != 0 {
            let tid_val = fork_cpid as u32;
            let _ = sys::vm_write(parent_as, ptid_ptr,
                &tid_val as *const u32 as u64, 4);
        } else {
            unsafe { core::ptr::write_volatile(ptid_ptr as *mut u32, fork_cpid as u32); }
        }
    }

    // Set up child process metadata.
    let cidx = fork_cpid - 1;
    let pidx = pid - 1;
    PROCESSES[cidx].parent.store(pid as u64, Ordering::Release);
    PROCESSES[cidx].kernel_tid.store(0, Ordering::Release);
    proc_group_init(fork_cpid);

    // Inherit personality from parent.
    PROCESSES[cidx].personality.store(
        PROCESSES[pidx].personality.load(Ordering::Acquire),
        Ordering::Release,
    );

    // Inherit brk/mmap state from parent (CoW fork shares same VA layout).
    {
        let pb = PROCESSES[pidx].brk_base.load(Ordering::Acquire);
        let pc = PROCESSES[pidx].brk_current.load(Ordering::Acquire);
        let pmb = PROCESSES[pidx].mmap_base.load(Ordering::Acquire);
        let pmn = PROCESSES[pidx].mmap_next.load(Ordering::Acquire);
        PROCESSES[cidx].brk_base.store(pb, Ordering::Release);
        PROCESSES[cidx].brk_current.store(pc, Ordering::Release);
        PROCESSES[cidx].mmap_base.store(pmb, Ordering::Release);
        PROCESSES[cidx].mmap_next.store(pmn, Ordering::Release);
    }

    // Copy parent's VMA list to child.
    unsafe {
        let src = &crate::vma::VMA_LISTS[memg];
        let dst = &mut crate::vma::VMA_LISTS[cidx];
        dst.count = src.count;
        for i in 0..src.count {
            dst.entries[i] = src.entries[i];
        }
    }

    // Copy parent's FD state to child.
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

    // Copy DIR_FD_PATHS from parent to child.
    {
        let parent_base = pidx * 8;
        let child_base = cidx * 8;
        for s in 0..8usize {
            let ps = parent_base + s;
            let cs = child_base + s;
            if ps < MAX_DIR_SLOTS && cs < MAX_DIR_SLOTS {
                unsafe { DIR_FD_PATHS[cs] = DIR_FD_PATHS[ps]; }
            }
        }
    }

    // Increment pipe + unix-socket refcounts for fds inherited by child.
    for cfd in 0..GRP_MAX_FDS {
        let k = unsafe { THREAD_GROUPS[cidx].fds[cfd] };
        let p = unsafe { THREAD_GROUPS[cidx].sock_conn_id[cfd] } as usize;
        if k == 11 && p < MAX_PIPES {
            PIPE_WRITE_REFS[p].fetch_add(1, Ordering::AcqRel);
        } else if k == 10 && p < MAX_PIPES {
            PIPE_READ_REFS[p].fetch_add(1, Ordering::AcqRel);
        }
        if (k == 27 || k == 28) && p < MAX_UNIX_CONNS {
            UNIX_CONN_REFS[p].fetch_add(1, Ordering::AcqRel);
        }
    }

    // Copy socket state for child handler.
    unsafe {
        FORK_FD_FLAGS = THREAD_GROUPS[fdg].fd_flags;
        FORK_SOCK_CONN = THREAD_GROUPS[fdg].sock_conn_id;
        FORK_SOCK_UDP_LPORT = THREAD_GROUPS[fdg].sock_udp_local_port;
        FORK_SOCK_UDP_RIP = THREAD_GROUPS[fdg].sock_udp_remote_ip;
        FORK_SOCK_UDP_RPORT = THREAD_GROUPS[fdg].sock_udp_remote_port;
    }

    // Allocate handler stack (32 pages = 128KB) for child handler thread.
    let handler_stack_base = NEXT_CHILD_STACK.fetch_add(0x20000, Ordering::SeqCst);
    for hp in 0..32u64 {
        if let Ok(f) = sys::frame_alloc() {
            let _ = sys::map(handler_stack_base + hp * 0x1000, f, MAP_WRITABLE);
        }
    }

    // Pass setup info to child handler.
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

    fork_cpid as i64
}

// ---------------------------------------------------------------------------
// SYS_CLONE thread-style (CLONE_VM) — pthread creation.
// ---------------------------------------------------------------------------

/// SYS_CLONE thread-style path — creates a new thread in the parent's
/// address space (CLONE_VM).
///
/// Stack layout for the trampoline: [fn_ptr, arg, tls_ptr] pushed just
/// below `child_stack`. `clone_child_trampoline` pops those and then
/// optionally runs `arch_prctl(SET_FS, tls)` before calling `fn(arg)`.
///
/// Returns child_pid on success, negative errno on failure.
pub(crate) fn do_thread_clone(pid: usize, msg: &IpcMsg) -> i64 {
    let flags = msg.regs[0];
    let child_stack = msg.regs[1];
    let ptid_ptr = msg.regs[2];
    let ctid_ptr = msg.regs[3];
    let newtls = msg.regs[4];
    let fn_ptr = msg.regs[5]; // r9 = fn (from musl's __clone)

    // Allocate child PID.
    let child_pid = NEXT_PID.fetch_add(1, Ordering::SeqCst) as usize;
    if child_pid > MAX_PROCS {
        return -ENOMEM;
    }

    // Thread-group state inheritance.
    PROCESSES[child_pid - 1].parent.store(pid as u64, Ordering::Release);
    proc_thread_init(child_pid, pid, flags);

    // CLONE_PARENT_SETTID: write child TID to *ptid.
    if flags & CLONE_PARENT_SETTID != 0 && ptid_ptr != 0 {
        unsafe { core::ptr::write_volatile(ptid_ptr as *mut u32, child_pid as u32); }
    }
    // CLONE_CHILD_CLEARTID: store ctid pointer for exit cleanup.
    if flags & CLONE_CHILD_CLEARTID != 0 && ctid_ptr != 0 {
        PROCESSES[child_pid - 1].clear_tid.store(ctid_ptr, Ordering::Release);
    }

    // Trampoline setup: musl __clone pushed arg at [child_stack].
    let arg = if child_stack != 0 {
        unsafe { core::ptr::read_volatile(child_stack as *const u64) }
    } else { 0 };
    let tls = if flags & CLONE_SETTLS != 0 { newtls } else { 0 };

    // Write [fn_ptr, arg, tls] 24 bytes below child_stack (stack grows down).
    let child_sp = child_stack - 24;
    unsafe {
        core::ptr::write_volatile((child_sp) as *mut u64, fn_ptr);
        core::ptr::write_volatile((child_sp + 8) as *mut u64, arg);
        core::ptr::write_volatile((child_sp + 16) as *mut u64, tls);
    }

    // Allocate handler stack (32 pages = 128KB).
    let handler_stack_base = NEXT_CHILD_STACK.fetch_add(0x20000, Ordering::SeqCst);
    for hp in 0..32u64 {
        let hf = match sys::frame_alloc() {
            Ok(f) => f,
            Err(_) => return -ENOMEM,
        };
        if sys::map(handler_stack_base + hp * 0x1000, hf, MAP_WRITABLE).is_err() {
            return -ENOMEM;
        }
    }

    // Child endpoint.
    let child_ep = match sys::endpoint_create() {
        Ok(e) => e,
        Err(_) => return -ENOMEM,
    };

    // Hand setup to the child handler thread.
    while CHILD_SETUP_READY.load(Ordering::Acquire) != 0 { sys::yield_now(); }
    CHILD_SETUP_EP.store(child_ep, Ordering::Release);
    CHILD_SETUP_PID.store(child_pid as u64, Ordering::Release);
    CHILD_SETUP_FLAGS.store(flags, Ordering::Release);
    CHILD_SETUP_AS_CAP.store(0, Ordering::Release);
    CHILD_SETUP_READY.store(1, Ordering::Release);

    if sys::thread_create(
        child_handler as *const () as u64,
        handler_stack_base + 0x20000,
    ).is_err() {
        CHILD_SETUP_READY.store(0, Ordering::Release);
        return -ENOMEM;
    }

    // Wait for the handler to consume setup before starting guest thread.
    while CHILD_SETUP_READY.load(Ordering::Acquire) != 0 { sys::yield_now(); }

    // Spawn guest thread at the trampoline, redirected to its child handler.
    let child_thread = match sys::thread_create_redirected(
        clone_child_trampoline as *const () as u64,
        child_sp,
        child_ep,
    ) {
        Ok(t) => t,
        Err(_) => return -ENOMEM,
    };
    let _ = sys::signal_entry(child_thread, vdso::SIGNAL_TRAMPOLINE_ADDR);

    PROCESSES[child_pid - 1].state.store(1, Ordering::Release);

    child_pid as i64
}
