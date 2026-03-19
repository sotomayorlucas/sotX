//! Syscall dispatcher.
//!
//! Called from the SYSCALL entry trampoline with a pointer to the
//! saved register frame. Decodes rax as the syscall number and
//! dispatches to the appropriate handler.
//!
//! Submodules handle groups of related syscalls. Each exports a
//! `handle(frame, nr) -> bool` function that returns true if it
//! handled the syscall number.

mod ipc;
mod memory;
mod thread;
mod cap;
mod irq;
mod notify;
mod fault;
mod domain;
mod service;
mod shm;
mod debug;

use crate::kdebug;
use crate::arch::x86_64::syscall::TrapFrame;
use crate::cap::{self as cap_mod, CapObject, Rights};
use crate::ipc::endpoint::{self, Message};
use crate::mm::paging;
use crate::pool::PoolHandle;
use crate::sched;
use sotos_common::SysError;

/// Syscall numbers — IPC (sync endpoints).
pub(super) const SYS_SEND: u64 = 1;
pub(super) const SYS_RECV: u64 = 2;
pub(super) const SYS_CALL: u64 = 3;

/// Syscall numbers — IPC (async channels).
pub(super) const SYS_CHANNEL_CREATE: u64 = 4;
pub(super) const SYS_CHANNEL_SEND: u64 = 5;
pub(super) const SYS_CHANNEL_RECV: u64 = 6;
pub(super) const SYS_CHANNEL_CLOSE: u64 = 7;

pub(super) const SYS_ENDPOINT_CREATE: u64 = 10;

/// Syscall numbers — memory management.
pub(super) const SYS_FRAME_ALLOC: u64 = 20;
pub(super) const SYS_FRAME_FREE: u64 = 21;
pub(super) const SYS_MAP: u64 = 22;
pub(super) const SYS_UNMAP: u64 = 23;

/// Syscall numbers — capabilities.
pub(super) const SYS_CAP_GRANT: u64 = 30;
pub(super) const SYS_CAP_REVOKE: u64 = 31;

/// Syscall numbers — threads.
pub(super) const SYS_THREAD_CREATE: u64 = 40;
pub(super) const SYS_THREAD_EXIT: u64 = 42;
pub(super) const SYS_THREAD_RESUME: u64 = 43;

/// Syscall numbers — IRQ virtualization.
pub(super) const SYS_IRQ_REGISTER: u64 = 50;
pub(super) const SYS_IRQ_ACK: u64 = 51;

/// Syscall numbers — I/O ports.
pub(super) const SYS_PORT_IN: u64 = 60;
pub(super) const SYS_PORT_OUT: u64 = 61;

/// Syscall numbers — notifications (shared-memory IPC).
pub(super) const SYS_NOTIFY_CREATE: u64 = 70;
pub(super) const SYS_NOTIFY_WAIT: u64 = 71;
pub(super) const SYS_NOTIFY_SIGNAL: u64 = 72;

/// Syscall numbers — fault forwarding (VMM).
pub(super) const SYS_FAULT_REGISTER: u64 = 80;
pub(super) const SYS_FAULT_RECV: u64 = 81;

/// Syscall numbers — scheduling domains.
pub(super) const SYS_DOMAIN_CREATE: u64 = 90;
pub(super) const SYS_DOMAIN_ATTACH: u64 = 91;
pub(super) const SYS_DOMAIN_DETACH: u64 = 92;
pub(super) const SYS_DOMAIN_ADJUST: u64 = 93;
pub(super) const SYS_DOMAIN_INFO: u64 = 94;

/// Syscall numbers — device infrastructure.
pub(super) const SYS_FRAME_PHYS: u64 = 100;
pub(super) const SYS_IOPORT_CREATE: u64 = 101;
pub(super) const SYS_FRAME_ALLOC_CONTIG: u64 = 102;
pub(super) const SYS_IRQ_CREATE: u64 = 103;
pub(super) const SYS_MAP_OFFSET: u64 = 104;

/// Syscall numbers — LUCAS (syscall redirection).
pub(super) const SYS_REDIRECT_SET: u64 = 110;

/// Syscall numbers — multi-address-space.
pub(super) const SYS_ADDR_SPACE_CREATE: u64 = 120;
pub(super) const SYS_MAP_INTO: u64 = 121;
pub(super) const SYS_THREAD_CREATE_IN: u64 = 122;
pub(super) const SYS_UNMAP_FROM: u64 = 123;
pub(super) const SYS_AS_CLONE: u64 = 125;
pub(super) const SYS_FRAME_COPY: u64 = 126;
pub(super) const SYS_PTE_READ: u64 = 127;
pub(super) const SYS_VM_READ: u64 = 128;
pub(super) const SYS_VM_WRITE: u64 = 129;

/// Syscall numbers — service registry.
pub(super) const SYS_SVC_REGISTER: u64 = 130;
pub(super) const SYS_SVC_LOOKUP: u64 = 131;

/// Syscall numbers — shared memory.
pub(super) const SYS_SHM_CREATE: u64 = 180;
pub(super) const SYS_SHM_MAP: u64 = 181;
pub(super) const SYS_SHM_UNMAP: u64 = 182;
pub(super) const SYS_SHM_DESTROY: u64 = 183;

/// Syscall numbers — userspace process spawning.
pub(super) const SYS_INITRD_READ: u64 = 132;
pub(super) const SYS_BOOTINFO_WRITE: u64 = 133;

/// Syscall number — page permission change (mprotect-like).
pub(super) const SYS_PROTECT: u64 = 134;
pub(super) const SYS_PROTECT_IN: u64 = 175;
pub(super) const SYS_WX_RELAX: u64 = 177;

/// Syscall number — unmap + free physical frame in one step.
pub(super) const SYS_UNMAP_FREE: u64 = 24;

/// Syscall number — IPC call with timeout.
pub(super) const SYS_CALL_TIMEOUT: u64 = 135;
/// Syscall number — IPC recv with timeout.
pub(super) const SYS_RECV_TIMEOUT: u64 = 136;

/// Syscall number — set FS_BASE for current thread (TLS support).
pub(super) const SYS_SET_FSBASE: u64 = 160;
/// Syscall number — get FS_BASE for current thread.
pub(super) const SYS_GET_FSBASE: u64 = 161;

/// Syscall numbers — file permission management.
pub(super) const SYS_CHMOD: u64 = 150;
pub(super) const SYS_CHOWN: u64 = 151;

/// Syscall numbers — thread info and resource limits.
pub(super) const SYS_THREAD_INFO: u64 = 140;
pub(super) const SYS_RESOURCE_LIMIT: u64 = 141;
pub(super) const SYS_THREAD_COUNT: u64 = 142;

/// Debug syscall: write a single byte to serial (COM1).
pub(super) const SYS_DEBUG_PRINT: u64 = 255;
/// Debug syscall: non-blocking serial input (returns 0 if no data).
pub(super) const SYS_DEBUG_READ: u64 = 253;

/// Upper bound of user-space virtual addresses.
pub(super) const USER_ADDR_LIMIT: u64 = 0x0000_8000_0000_0000;

/// User-controllable page flags: WRITABLE (bit 1) and NO_EXECUTE (bit 63).
pub(super) const USER_FLAG_MASK: u64 = paging::PAGE_WRITABLE | paging::PAGE_NO_EXECUTE;

/// Extract an IPC Message from the TrapFrame registers.
///
/// Register convention:
///   rsi = tag (lower 32 bits = tag, upper 32 bits = cap transfer ID or 0)
///   rdx/r8/r9/r10/r12/r13/r14/r15 = msg regs 0-7
pub(super) fn msg_from_frame(frame: &TrapFrame) -> Message {
    let raw_tag = frame.rsi;
    let cap_xfer = (raw_tag >> 32) as u32;
    Message {
        tag: raw_tag & 0xFFFF_FFFF,
        regs: [
            frame.rdx,
            frame.r8,
            frame.r9,
            frame.r10,
            frame.r12,
            frame.r13,
            frame.r14,
            frame.r15,
        ],
        cap_transfer: if cap_xfer != 0 { Some(cap_xfer) } else { None },
    }
}

/// Write an IPC Message back into the TrapFrame registers.
pub(super) fn msg_to_frame(frame: &mut TrapFrame, msg: &Message) {
    let cap_hi = msg.cap_transfer.unwrap_or(0) as u64;
    frame.rsi = (cap_hi << 32) | (msg.tag & 0xFFFF_FFFF);
    frame.rdx = msg.regs[0];
    frame.r8 = msg.regs[1];
    frame.r9 = msg.regs[2];
    frame.r10 = msg.regs[3];
    frame.r12 = msg.regs[4];
    frame.r13 = msg.regs[5];
    frame.r14 = msg.regs[6];
    frame.r15 = msg.regs[7];
}

/// Restore GPRs + RIP/RSP/RFLAGS from a ucontext (glibc gregset_t) on
/// the user stack. Factored out of syscall_dispatch to keep its stack frame
/// small enough not to overflow the kernel stack canary in debug builds.
#[inline(never)]
unsafe fn restore_ucontext(frame: &mut TrapFrame, ucontext_ptr: u64,
                           rip: &mut u64, rsp: &mut u64, rflags: &mut u64) {
    let gregs = (ucontext_ptr + 40) as *const u64;
    let uc_rip    = core::ptr::read_volatile(gregs.add(16));
    let uc_rsp    = core::ptr::read_volatile(gregs.add(15));
    let uc_rflags = core::ptr::read_volatile(gregs.add(17));
    let uc_trapno = core::ptr::read_volatile(gregs.add(20));
    let uc_rax = core::ptr::read_volatile(gregs.add(13));
    let uc_rcx = core::ptr::read_volatile(gregs.add(14));
    let uc_rdx = core::ptr::read_volatile(gregs.add(12));
    let uc_rbx = core::ptr::read_volatile(gregs.add(11));
    let uc_rbp = core::ptr::read_volatile(gregs.add(10));
    let uc_r11_val = core::ptr::read_volatile(gregs.add(3));
    kdebug!("rt_sigreturn: uc_ptr={:#x} frame_rip={:#x} uc_rip={:#x} uc_rsp={:#x} uc_trapno={}", ucontext_ptr, *rip, uc_rip, uc_rsp, uc_trapno);
    kdebug!("  uc_gregs: rax={:#x} rbx={:#x} rcx={:#x} rdx={:#x} rbp={:#x} r11={:#x}", uc_rax, uc_rbx, uc_rcx, uc_rdx, uc_rbp, uc_r11_val);
    if uc_trapno == 14 {
        let uc_rdi = core::ptr::read_volatile(gregs.add(8));
        let uc_rsi = core::ptr::read_volatile(gregs.add(9));
        let uc_r8  = core::ptr::read_volatile(gregs.add(0));
        let uc_r9  = core::ptr::read_volatile(gregs.add(1));
        let uc_r10 = core::ptr::read_volatile(gregs.add(2));
        let uc_r12 = core::ptr::read_volatile(gregs.add(4));
        let uc_r13 = core::ptr::read_volatile(gregs.add(5));
        let uc_r14 = core::ptr::read_volatile(gregs.add(6));
        let uc_r15 = core::ptr::read_volatile(gregs.add(7));
        kdebug!("  uc_extra: rdi={:#x} rsi={:#x} r8={:#x} r9={:#x} r10={:#x}",
            uc_rdi, uc_rsi, uc_r8, uc_r9, uc_r10);
        kdebug!("  uc_extra: r12={:#x} r13={:#x} r14={:#x} r15={:#x}",
            uc_r12, uc_r13, uc_r14, uc_r15);
    }
    if uc_rip != 0 { *rip = uc_rip; }
    if uc_rsp != 0 { *rsp = uc_rsp; }
    if uc_rflags != 0 { *rflags = uc_rflags; }
    // Restore GPRs from ucontext
    frame.r8  = core::ptr::read_volatile(gregs.add(0));
    frame.r9  = core::ptr::read_volatile(gregs.add(1));
    frame.r10 = core::ptr::read_volatile(gregs.add(2));
    frame.r12 = core::ptr::read_volatile(gregs.add(4));
    frame.r13 = core::ptr::read_volatile(gregs.add(5));
    frame.r14 = core::ptr::read_volatile(gregs.add(6));
    frame.r15 = core::ptr::read_volatile(gregs.add(7));
    frame.rdi = core::ptr::read_volatile(gregs.add(8));
    frame.rsi = core::ptr::read_volatile(gregs.add(9));
    frame.rbp = core::ptr::read_volatile(gregs.add(10));
    frame.rbx = core::ptr::read_volatile(gregs.add(11));
    frame.rdx = core::ptr::read_volatile(gregs.add(12));
    frame.rax = core::ptr::read_volatile(gregs.add(13));
    frame.r11 = core::ptr::read_volatile(gregs.add(17));
}

/// Main syscall dispatcher — called from assembly with IF=0.
#[no_mangle]
pub extern "C" fn syscall_dispatch(frame: &mut TrapFrame) {
    // Save user RSP from per-CPU storage to the kernel stack.
    // If this syscall blocks (context switch), another thread's syscall
    // entry will overwrite percpu.user_rsp_save. This local survives the
    // context switch because it lives on the per-thread kernel stack.
    use crate::arch::x86_64::percpu;
    let mut saved_user_rsp = percpu::current_percpu().user_rsp_save;

    // --- LUCAS syscall redirect (ρ_fuse optimized) ---
    // Fused: prepare_redirect() does get_redirect_ep + save_regs + get_tid
    // in ONE SCHEDULER.lock() (was 3 separate). call_fused() batches
    // write_ipc_msg + wake + set_ipc + block into 1 SCHEDULER.lock() + 2 per-thread
    // IPC locks (was 7 separate SCHEDULER.lock()). Net: 10 → 2 SCHEDULER locks.
    if let Some((ep_raw, caller_tid)) = sched::prepare_redirect(frame, saved_user_rsp) {
        // Intercept arch_prctl — requires Ring 0 (FS_BASE/GS_BASE MSR writes).
        // Linux syscall 158 = arch_prctl: rdi = subcommand, rsi = addr.
        if frame.rax == 158 {
            match frame.rdi {
                0x1001 => { // ARCH_SET_GS
                    sched::set_current_gs_base(frame.rsi);
                    frame.rax = 0;
                }
                0x1002 => { // ARCH_SET_FS
                    sched::set_current_fs_base(frame.rsi);
                    frame.rax = 0;
                }
                0x1003 => { // ARCH_GET_FS
                    frame.rax = sched::get_current_fs_base();
                }
                0x1004 => { // ARCH_GET_GS
                    frame.rax = sched::get_current_gs_base();
                }
                _ => {
                    frame.rax = (-22i64) as u64; // -EINVAL
                }
            }
            percpu::current_percpu().user_rsp_save = saved_user_rsp;
            return;
        }

        // Intercept rt_sigreturn (Linux syscall 15) — restore pre-signal context.
        if frame.rax == 15 {
            let frame_ptr = saved_user_rsp as *const u64;
            if saved_user_rsp != 0 && saved_user_rsp < USER_ADDR_LIMIT {
                unsafe {
                    // SignalFrame layout: [restorer, signo, rax..r15, rip, rsp, rflags, fs_base, old_sigmask]
                    let _restorer = core::ptr::read_volatile(frame_ptr);
                    let _signo    = core::ptr::read_volatile(frame_ptr.add(1));
                    frame.rax     = core::ptr::read_volatile(frame_ptr.add(2));
                    frame.rbx     = core::ptr::read_volatile(frame_ptr.add(3));
                    frame.rcx     = core::ptr::read_volatile(frame_ptr.add(4));
                    frame.rdx     = core::ptr::read_volatile(frame_ptr.add(5));
                    frame.rsi     = core::ptr::read_volatile(frame_ptr.add(6));
                    frame.rdi     = core::ptr::read_volatile(frame_ptr.add(7));
                    frame.rbp     = core::ptr::read_volatile(frame_ptr.add(8));
                    frame.r8      = core::ptr::read_volatile(frame_ptr.add(9));
                    frame.r9      = core::ptr::read_volatile(frame_ptr.add(10));
                    frame.r10     = core::ptr::read_volatile(frame_ptr.add(11));
                    frame.r11     = core::ptr::read_volatile(frame_ptr.add(12));
                    frame.r12     = core::ptr::read_volatile(frame_ptr.add(13));
                    frame.r13     = core::ptr::read_volatile(frame_ptr.add(14));
                    frame.r14     = core::ptr::read_volatile(frame_ptr.add(15));
                    frame.r15     = core::ptr::read_volatile(frame_ptr.add(16));
                    let mut rip       = core::ptr::read_volatile(frame_ptr.add(17));
                    let mut rsp       = core::ptr::read_volatile(frame_ptr.add(18));
                    let mut rflags    = core::ptr::read_volatile(frame_ptr.add(19));
                    let fs_base   = core::ptr::read_volatile(frame_ptr.add(20));
                    let ucontext_ptr = core::ptr::read_volatile(frame_ptr.add(22));

                    if ucontext_ptr != 0 && ucontext_ptr < USER_ADDR_LIMIT {
                        restore_ucontext(frame, ucontext_ptr, &mut rip, &mut rsp, &mut rflags);
                    }

                    frame.rcx = rip;
                    frame.r11 = rflags;
                    saved_user_rsp = rsp;

                    if fs_base != 0 {
                        sched::set_current_fs_base(fs_base);
                    }

                    sched::clear_signal_ctx(caller_tid);
                }
                kdebug!("rt_sigreturn: restored context, rip={:#x} rsp={:#x}", frame.rcx, saved_user_rsp);
            } else {
                frame.rax = (-22i64) as u64; // -EINVAL
            }
            percpu::current_percpu().user_rsp_save = saved_user_rsp;
            return;
        }

        // β₁ aniquilación: return -ENOSYS for stub syscalls directly,
        // bypassing the IPC round-trip to LUCAS.
        if sotos_common::linux_abi::STUB_BYPASS_SYSCALLS.contains(&frame.rax) {
            frame.rax = (-sotos_common::linux_abi::ENOSYS) as u64;
            percpu::current_percpu().user_rsp_save = saved_user_rsp;
            return;
        }

        let tid = caller_tid.0 as u64;

        // Periodic HLT so QEMU TCG can process its event loop (virtio TX/RX,
        // timers). Without this, non-pipe syscall loops starve QEMU's I/O backend.
        {
            static REDIRECT_COUNT: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);
            let n = REDIRECT_COUNT.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
            if n & 255 == 0 {
                unsafe { core::arch::asm!("sti; hlt", options(nomem, nostack)); }
            }
        }

        let msg = Message {
            tag: frame.rax, // Linux syscall number
            regs: [frame.rdi, frame.rsi, frame.rdx, frame.r10, frame.r8, frame.r9, tid, saved_user_rsp],
            cap_transfer: None,
        };

        // Retry loop: init may reply PIPE_RETRY_TAG for pipe reads/polls
        let mut retries = 0u32;
        loop {
            match endpoint::call_fused(PoolHandle::from_raw(ep_raw), msg, caller_tid) {
                Ok(reply) => {
                    if reply.tag == sotos_common::PIPE_RETRY_TAG {
                        retries += 1;
                        sched::schedule();
                        if retries & 4095 == 0 {
                            unsafe { core::arch::asm!("sti; hlt", options(nomem, nostack)); }
                        }
                        continue;
                    } else if reply.tag == sotos_common::SIG_REDIRECT_TAG {
                        frame.rcx = reply.regs[0];
                        frame.rdi = reply.regs[1] as u64;
                        frame.rsi = reply.regs[2];
                        frame.rdx = reply.regs[3];
                        saved_user_rsp = reply.regs[4];
                        frame.rax = reply.regs[5];
                        frame.r11 = 0x202;
                        kdebug!("SIG_REDIRECT: handler={:#x} signo={} rsp={:#x}", reply.regs[0], reply.regs[1], reply.regs[4]);
                        break;
                    } else {
                        frame.rax = reply.regs[0];
                        break;
                    }
                }
                Err(e) => {
                    frame.rax = e as i64 as u64;
                    break;
                }
            }
        }
        percpu::current_percpu().user_rsp_save = saved_user_rsp;
        return;
    }

    // Trace: log first direct kernel syscall >= 100 to verify the path works
    if frame.rax == SYS_AS_CLONE {
        crate::kprintln!("K-DIRECT AS_CLONE rdi={}", frame.rdi);
    }

    let nr = frame.rax;

    match nr {
        // SYS_YIELD — give up remaining timeslice
        0 => {
            sched::schedule();
            frame.rax = 0;
        }

        // SYS_FAULT_REGISTER — register notification for page fault delivery
        // rdi = notify_cap (requires WRITE right), rsi = as_cap (0 = global fallback)
        // Kept in mod.rs because it needs saved_user_rsp for early return.
        SYS_FAULT_REGISTER => {
            match cap_mod::validate(frame.rdi as u32, Rights::WRITE) {
                Ok(CapObject::Notification { id }) => {
                    let cr3 = if frame.rsi == 0 {
                        // Register as global fallback handler (cr3=0).
                        0
                    } else {
                        // Register for a specific address space.
                        match cap_mod::validate(frame.rsi as u32, Rights::READ) {
                            Ok(CapObject::AddrSpace { cr3 }) => cr3,
                            Ok(_) => {
                                frame.rax = SysError::InvalidCap as i64 as u64;
                                percpu::current_percpu().user_rsp_save = saved_user_rsp;
                                return;
                            }
                            Err(e) => {
                                frame.rax = e as i64 as u64;
                                percpu::current_percpu().user_rsp_save = saved_user_rsp;
                                return;
                            }
                        }
                    };
                    crate::fault::register(PoolHandle::from_raw(id), cr3);
                    // Also register cr3 -> as_cap mapping if a specific AS was given.
                    if frame.rsi != 0 {
                        crate::fault::register_cr3_cap(cr3, frame.rsi as u32);
                    }
                    frame.rax = 0;
                }
                Ok(_) => frame.rax = SysError::InvalidCap as i64 as u64,
                Err(e) => frame.rax = e as i64 as u64,
            }
        }

        // SYS_THREAD_CREATE_IN — create a thread in a target address space
        // rdi = as_cap (WRITE), rsi = rip, rdx = rsp, r8 = redirect_ep_cap (0 = none)
        // r10 = signal_trampoline (0 = none) — set atomically before enqueue
        // Kept in mod.rs because it needs saved_user_rsp for early return.
        SYS_THREAD_CREATE_IN => {
            match cap_mod::validate(frame.rdi as u32, Rights::WRITE) {
                Ok(CapObject::AddrSpace { cr3 }) => {
                    let rip = frame.rsi;
                    let rsp = frame.rdx;
                    let redirect_cap = frame.r8;
                    let signal_tramp = frame.r10;
                    if rip == 0 || rsp == 0 || rip >= USER_ADDR_LIMIT || rsp >= USER_ADDR_LIMIT {
                        frame.rax = SysError::InvalidArg as i64 as u64;
                    } else {
                        let redirect_ep = if redirect_cap != 0 {
                            match cap_mod::validate(redirect_cap as u32, Rights::READ.or(Rights::WRITE)) {
                                Ok(CapObject::Endpoint { id: ep_id }) => Some(ep_id),
                                _ => {
                                    frame.rax = SysError::InvalidCap as i64 as u64;
                                    percpu::current_percpu().user_rsp_save = saved_user_rsp;
                                    return;
                                }
                            }
                        } else {
                            None
                        };
                        let tid = if let Some(ep_id) = redirect_ep {
                            sched::spawn_user_with_redirect_and_signal(rip, rsp, cr3, ep_id, signal_tramp)
                        } else {
                            sched::spawn_user(rip, rsp, cr3)
                        };
                        match cap_mod::insert(CapObject::Thread { id: tid.0 }, Rights::ALL, None) {
                            Some(cap_id) => frame.rax = cap_id.raw() as u64,
                            None => frame.rax = SysError::OutOfResources as i64 as u64,
                        }
                    }
                }
                Ok(_) => frame.rax = SysError::InvalidCap as i64 as u64,
                Err(e) => frame.rax = e as i64 as u64,
            }
        }

        // Dispatch to submodule handlers
        _ if ipc::handle(frame, nr) => {}
        _ if memory::handle(frame, nr) => {}
        _ if thread::handle(frame, nr) => {}
        _ if cap::handle(frame, nr) => {}
        _ if irq::handle(frame, nr) => {}
        _ if notify::handle(frame, nr) => {}
        _ if fault::handle(frame, nr) => {}
        _ if domain::handle(frame, nr) => {}
        _ if service::handle(frame, nr) => {}
        _ if shm::handle(frame, nr) => {}
        _ if debug::handle(frame, nr) => {}

        // Unknown syscall
        _ => {
            frame.rax = SysError::InvalidArg as i64 as u64;
        }
    }

    // Restore user RSP to per-CPU storage before the asm exit path reads it.
    percpu::current_percpu().user_rsp_save = saved_user_rsp;
}
