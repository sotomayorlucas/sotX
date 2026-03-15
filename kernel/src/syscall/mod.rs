//! Syscall dispatcher.
//!
//! Called from the SYSCALL entry trampoline with a pointer to the
//! saved register frame. Decodes rax as the syscall number and
//! dispatches to the appropriate handler.

use crate::kdebug;
use crate::arch::serial;
use crate::arch::x86_64::io;
use crate::arch::x86_64::syscall::TrapFrame;
use crate::cap::{self, CapId, CapObject, Rights};
use crate::fault;
use crate::ipc::endpoint::{self, Message};
use crate::ipc::channel;
use crate::ipc::notify;
use crate::mm::{self, PhysFrame};
use crate::mm::paging::{self, AddressSpace, PAGE_PRESENT, PAGE_USER, PAGE_WRITABLE, PAGE_NO_EXECUTE};
use crate::pool::PoolHandle;
use crate::sched::ThreadId;
use crate::{irq, sched};
use sotos_common::SysError;

/// Syscall numbers — IPC (sync endpoints).
const SYS_SEND: u64 = 1;
const SYS_RECV: u64 = 2;
const SYS_CALL: u64 = 3;

/// Syscall numbers — IPC (async channels).
const SYS_CHANNEL_CREATE: u64 = 4;
const SYS_CHANNEL_SEND: u64 = 5;
const SYS_CHANNEL_RECV: u64 = 6;
const SYS_CHANNEL_CLOSE: u64 = 7;

const SYS_ENDPOINT_CREATE: u64 = 10;

/// Syscall numbers — memory management.
const SYS_FRAME_ALLOC: u64 = 20;
const SYS_FRAME_FREE: u64 = 21;
const SYS_MAP: u64 = 22;
const SYS_UNMAP: u64 = 23;

/// Syscall numbers — capabilities.
const SYS_CAP_GRANT: u64 = 30;
const SYS_CAP_REVOKE: u64 = 31;

/// Syscall numbers — threads.
const SYS_THREAD_CREATE: u64 = 40;
const SYS_THREAD_EXIT: u64 = 42;
const SYS_THREAD_RESUME: u64 = 43;

/// Syscall numbers — IRQ virtualization.
const SYS_IRQ_REGISTER: u64 = 50;
const SYS_IRQ_ACK: u64 = 51;

/// Syscall numbers — I/O ports.
const SYS_PORT_IN: u64 = 60;
const SYS_PORT_OUT: u64 = 61;

/// Syscall numbers — notifications (shared-memory IPC).
const SYS_NOTIFY_CREATE: u64 = 70;
const SYS_NOTIFY_WAIT: u64 = 71;
const SYS_NOTIFY_SIGNAL: u64 = 72;

/// Syscall numbers — fault forwarding (VMM).
const SYS_FAULT_REGISTER: u64 = 80;
const SYS_FAULT_RECV: u64 = 81;

/// Syscall numbers — scheduling domains.
const SYS_DOMAIN_CREATE: u64 = 90;
const SYS_DOMAIN_ATTACH: u64 = 91;
const SYS_DOMAIN_DETACH: u64 = 92;
const SYS_DOMAIN_ADJUST: u64 = 93;
const SYS_DOMAIN_INFO: u64 = 94;

/// Syscall numbers — device infrastructure.
const SYS_FRAME_PHYS: u64 = 100;
const SYS_IOPORT_CREATE: u64 = 101;
const SYS_FRAME_ALLOC_CONTIG: u64 = 102;
const SYS_IRQ_CREATE: u64 = 103;
const SYS_MAP_OFFSET: u64 = 104;

/// Syscall numbers — LUCAS (syscall redirection).
const SYS_REDIRECT_SET: u64 = 110;

/// Syscall numbers — multi-address-space.
const SYS_ADDR_SPACE_CREATE: u64 = 120;
const SYS_MAP_INTO: u64 = 121;
const SYS_THREAD_CREATE_IN: u64 = 122;
const SYS_UNMAP_FROM: u64 = 123;
const SYS_AS_CLONE: u64 = 125;
const SYS_FRAME_COPY: u64 = 126;
const SYS_PTE_READ: u64 = 127;
const SYS_VM_READ: u64 = 128;
const SYS_VM_WRITE: u64 = 129;

/// Syscall numbers — service registry.
const SYS_SVC_REGISTER: u64 = 130;
const SYS_SVC_LOOKUP: u64 = 131;

/// Syscall numbers — userspace process spawning.
const SYS_INITRD_READ: u64 = 132;
const SYS_BOOTINFO_WRITE: u64 = 133;

/// Syscall number — page permission change (mprotect-like).
const SYS_PROTECT: u64 = 134;
const SYS_PROTECT_IN: u64 = 175;
const SYS_WX_RELAX: u64 = 177;

/// Syscall number — unmap + free physical frame in one step.
const SYS_UNMAP_FREE: u64 = 24;

/// Syscall number — IPC call with timeout.
const SYS_CALL_TIMEOUT: u64 = 135;
/// Syscall number — IPC recv with timeout.
const SYS_RECV_TIMEOUT: u64 = 136;

/// Syscall number — set FS_BASE for current thread (TLS support).
const SYS_SET_FSBASE: u64 = 160;
/// Syscall number — get FS_BASE for current thread.
const SYS_GET_FSBASE: u64 = 161;

/// Syscall numbers — file permission management.
const SYS_CHMOD: u64 = 150;
const SYS_CHOWN: u64 = 151;

/// Syscall numbers — thread info and resource limits.
const SYS_THREAD_INFO: u64 = 140;
const SYS_RESOURCE_LIMIT: u64 = 141;
const SYS_THREAD_COUNT: u64 = 142;

/// Debug syscall: write a single byte to serial (COM1).
const SYS_DEBUG_PRINT: u64 = 255;
/// Debug syscall: non-blocking serial input (returns 0 if no data).
const SYS_DEBUG_READ: u64 = 253;

/// Upper bound of user-space virtual addresses.
const USER_ADDR_LIMIT: u64 = 0x0000_8000_0000_0000;

/// User-controllable page flags: WRITABLE (bit 1) and NO_EXECUTE (bit 63).
const USER_FLAG_MASK: u64 = PAGE_WRITABLE | PAGE_NO_EXECUTE;

/// Extract an IPC Message from the TrapFrame registers.
///
/// Register convention:
///   rsi = tag (lower 32 bits = tag, upper 32 bits = cap transfer ID or 0)
///   rdx/r8/r9/r10/r12/r13/r14/r15 = msg regs 0–7
fn msg_from_frame(frame: &TrapFrame) -> Message {
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
fn msg_to_frame(frame: &mut TrapFrame, msg: &Message) {
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

    // --- LUCAS syscall redirect ---
    // If the current thread has a redirect endpoint set, forward the syscall
    // as an IPC message to the LUCAS handler. The handler translates Linux
    // syscalls to sotOS primitives and replies with the result.
    if let Some(ep_raw) = sched::get_current_redirect_ep() {
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
        // The user stack contains a SignalFrame that was pushed during signal delivery.
        if frame.rax == 15 {
            // Read SignalFrame from user stack. The restorer did `ret` to reach
            // rt_sigreturn, so RSP now points past the restorer's return address.
            // Actually, musl's restorer is: mov $15, %eax; syscall
            // So the user RSP is still where it was when the handler returned.
            // The signal frame starts at saved_user_rsp (the handler's RSP on entry
            // pointed at the SignalFrame with restorer as first field).
            let frame_ptr = saved_user_rsp as *const u64;
            if saved_user_rsp != 0 && saved_user_rsp < USER_ADDR_LIMIT {
                unsafe {
                    // SignalFrame layout: [restorer, signo, rax..r15, rip, rsp, rflags, fs_base, old_sigmask]
                    let _restorer = core::ptr::read_volatile(frame_ptr);
                    let _signo    = core::ptr::read_volatile(frame_ptr.add(1));
                    frame.rax     = core::ptr::read_volatile(frame_ptr.add(2));
                    frame.rbx     = core::ptr::read_volatile(frame_ptr.add(3));
                    frame.rcx     = core::ptr::read_volatile(frame_ptr.add(4));  // user RIP
                    frame.rdx     = core::ptr::read_volatile(frame_ptr.add(5));
                    frame.rsi     = core::ptr::read_volatile(frame_ptr.add(6));
                    frame.rdi     = core::ptr::read_volatile(frame_ptr.add(7));
                    frame.rbp     = core::ptr::read_volatile(frame_ptr.add(8));
                    frame.r8      = core::ptr::read_volatile(frame_ptr.add(9));
                    frame.r9      = core::ptr::read_volatile(frame_ptr.add(10));
                    frame.r10     = core::ptr::read_volatile(frame_ptr.add(11));
                    frame.r11     = core::ptr::read_volatile(frame_ptr.add(12)); // user RFLAGS
                    frame.r12     = core::ptr::read_volatile(frame_ptr.add(13));
                    frame.r13     = core::ptr::read_volatile(frame_ptr.add(14));
                    frame.r14     = core::ptr::read_volatile(frame_ptr.add(15));
                    frame.r15     = core::ptr::read_volatile(frame_ptr.add(16));
                    let mut rip       = core::ptr::read_volatile(frame_ptr.add(17));
                    let mut rsp       = core::ptr::read_volatile(frame_ptr.add(18));
                    let mut rflags    = core::ptr::read_volatile(frame_ptr.add(19));
                    let fs_base   = core::ptr::read_volatile(frame_ptr.add(20));
                    // let old_mask = core::ptr::read_volatile(frame_ptr.add(21));
                    let ucontext_ptr = core::ptr::read_volatile(frame_ptr.add(22));

                    // If signal handler had SA_SIGINFO and a ucontext was provided,
                    // restore GPRs/RIP/RSP/RFLAGS from the (possibly modified) ucontext.
                    // Factored into a separate #[inline(never)] fn to reduce stack pressure.
                    if ucontext_ptr != 0 && ucontext_ptr < USER_ADDR_LIMIT {
                        restore_ucontext(frame, ucontext_ptr, &mut rip, &mut rsp, &mut rflags);
                    }

                    // Restore user RIP and RSP
                    frame.rcx = rip;      // sysretq uses rcx as return RIP
                    frame.r11 = rflags;   // sysretq uses r11 as return RFLAGS
                    saved_user_rsp = rsp;

                    // Restore FS_BASE (TLS)
                    if fs_base != 0 {
                        sched::set_current_fs_base(fs_base);
                    }

                    // Clear async signal context flag
                    if let Some(tid) = sched::current_tid() {
                        sched::clear_signal_ctx(tid);
                    }
                }
                kdebug!("rt_sigreturn: restored context, rip={:#x} rsp={:#x}", frame.rcx, saved_user_rsp);
            } else {
                frame.rax = (-22i64) as u64; // -EINVAL
            }
            percpu::current_percpu().user_rsp_save = saved_user_rsp;
            return;
        }

        // Save full register state before blocking in IPC redirect.
        // LUCAS can read this via SYS_GET_THREAD_REGS for signal frame construction.
        sched::save_current_redirect_regs(frame, saved_user_rsp);

        let tid = sched::current_tid().map(|t| t.0 as u64).unwrap_or(0);

        // Periodic HLT so QEMU TCG can process its event loop (virtio TX/RX,
        // timers). Without this, non-pipe syscall loops (e.g. libcurl's
        // non-blocking recv→poll→recv cycle) starve QEMU's I/O backend.
        // NOTE: SYSCALL masks IF via SFMASK, so we must STI before HLT.
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
        // when no data is available. The kernel yields (letting other threads
        // write pipe data) then re-sends the syscall to init.
        let mut retries = 0u32;
        loop {
            match endpoint::call(PoolHandle::from_raw(ep_raw), msg) {
                Ok(reply) => {
                    if reply.tag == sotos_common::PIPE_RETRY_TAG {
                        retries += 1;
                        sched::schedule(); // yield to let other threads run
                        // Every 4096 retries, briefly HLT so QEMU TCG can
                        // process its event loop (network I/O, timers).
                        if retries & 4095 == 0 {
                            unsafe { core::arch::asm!("sti; hlt", options(nomem, nostack)); }
                        }
                        continue; // re-send message to init (no limit — init handles deadlocks)
                    } else if reply.tag == sotos_common::SIG_REDIRECT_TAG {
                        // Signal delivery: LUCAS built a signal frame on the child's
                        // stack and wants to redirect execution to the signal handler.
                        frame.rcx = reply.regs[0]; // new user RIP = handler address
                        frame.rdi = reply.regs[1] as u64; // arg0 = signal number
                        frame.rsi = reply.regs[2]; // arg1 = &siginfo (or 0)
                        frame.rdx = reply.regs[3]; // arg2 = &ucontext (or 0)
                        saved_user_rsp = reply.regs[4]; // new user RSP (below signal frame)
                        frame.rax = reply.regs[5]; // custom RAX (0 for signals, child_pid for fork)
                        frame.r11 = 0x202; // RFLAGS with IF=1
                        kdebug!("SIG_REDIRECT: handler={:#x} signo={} rsp={:#x}", reply.regs[0], reply.regs[1], reply.regs[4]);
                        break;
                    } else {
                        frame.rax = reply.regs[0]; // return value
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

    match frame.rax {
        // SYS_YIELD — give up remaining timeslice
        0 => {
            sched::schedule();
            frame.rax = 0;
        }

        // SYS_SEND — synchronous send on endpoint (cap_id in rdi, requires WRITE)
        SYS_SEND => {
            match cap::validate(frame.rdi as u32, Rights::WRITE) {
                Ok(CapObject::Endpoint { id }) => {
                    let msg = msg_from_frame(frame);
                    match endpoint::send(PoolHandle::from_raw(id), msg) {
                        Ok(()) => frame.rax = 0,
                        Err(e) => frame.rax = e as i64 as u64,
                    }
                }
                Ok(_) => frame.rax = SysError::InvalidCap as i64 as u64,
                Err(e) => frame.rax = e as i64 as u64,
            }
        }

        // SYS_RECV — synchronous receive on endpoint (cap_id in rdi, requires READ)
        SYS_RECV => {
            match cap::validate(frame.rdi as u32, Rights::READ) {
                Ok(CapObject::Endpoint { id }) => {
                    match endpoint::recv(PoolHandle::from_raw(id)) {
                        Ok(msg) => {
                            frame.rax = 0;
                            msg_to_frame(frame, &msg);
                        }
                        Err(e) => frame.rax = e as i64 as u64,
                    }
                }
                Ok(_) => frame.rax = SysError::InvalidCap as i64 as u64,
                Err(e) => frame.rax = e as i64 as u64,
            }
        }

        // SYS_CALL — send then receive on endpoint (cap_id in rdi, requires READ|WRITE)
        SYS_CALL => {
            match cap::validate(frame.rdi as u32, Rights::READ.or(Rights::WRITE)) {
                Ok(CapObject::Endpoint { id }) => {
                    let msg = msg_from_frame(frame);
                    match endpoint::call(PoolHandle::from_raw(id), msg) {
                        Ok(reply) => {
                            frame.rax = 0;
                            msg_to_frame(frame, &reply);
                        }
                        Err(e) => frame.rax = e as i64 as u64,
                    }
                }
                Ok(_) => frame.rax = SysError::InvalidCap as i64 as u64,
                Err(e) => frame.rax = e as i64 as u64,
            }
        }

        // SYS_CALL_TIMEOUT — call with timeout (ep_cap in rdi[31:0], timeout in rdi[63:32])
        SYS_CALL_TIMEOUT => {
            let ep_cap = (frame.rdi & 0xFFFFFFFF) as u32;
            let timeout_ticks = (frame.rdi >> 32) as u64;
            match cap::validate(ep_cap, Rights::READ.or(Rights::WRITE)) {
                Ok(CapObject::Endpoint { id }) => {
                    let msg = msg_from_frame(frame);
                    let timeout = if timeout_ticks == 0 { u64::MAX } else { timeout_ticks };
                    match endpoint::call_timeout(PoolHandle::from_raw(id), msg, timeout) {
                        Ok(reply) => {
                            frame.rax = 0;
                            msg_to_frame(frame, &reply);
                        }
                        Err(e) => frame.rax = e as i64 as u64,
                    }
                }
                Ok(_) => frame.rax = SysError::InvalidCap as i64 as u64,
                Err(e) => frame.rax = e as i64 as u64,
            }
        }

        // SYS_RECV_TIMEOUT — recv with timeout (ep_cap in rdi[31:0], timeout in rdi[63:32])
        SYS_RECV_TIMEOUT => {
            let ep_cap = (frame.rdi & 0xFFFFFFFF) as u32;
            let timeout_ticks = (frame.rdi >> 32) as u64;
            match cap::validate(ep_cap, Rights::READ) {
                Ok(CapObject::Endpoint { id }) => {
                    let timeout = if timeout_ticks == 0 { u64::MAX } else { timeout_ticks };
                    match endpoint::recv_timeout(PoolHandle::from_raw(id), timeout) {
                        Ok(msg) => {
                            frame.rax = 0;
                            msg_to_frame(frame, &msg);
                        }
                        Err(e) => frame.rax = e as i64 as u64,
                    }
                }
                Ok(_) => frame.rax = SysError::InvalidCap as i64 as u64,
                Err(e) => frame.rax = e as i64 as u64,
            }
        }

        // SYS_CHANNEL_CREATE — create a new async channel, return cap_id
        SYS_CHANNEL_CREATE => {
            match channel::create() {
                Some(ch) => {
                    match cap::insert(CapObject::Channel { id: ch.0.raw() }, Rights::ALL, None) {
                        Some(cap_id) => frame.rax = cap_id.raw() as u64,
                        None => frame.rax = SysError::OutOfResources as i64 as u64,
                    }
                }
                None => frame.rax = SysError::OutOfResources as i64 as u64,
            }
        }

        // SYS_CHANNEL_SEND — async send on channel (cap_id in rdi, requires WRITE)
        SYS_CHANNEL_SEND => {
            match cap::validate(frame.rdi as u32, Rights::WRITE) {
                Ok(CapObject::Channel { id }) => {
                    let msg = msg_from_frame(frame);
                    match channel::send(PoolHandle::from_raw(id), msg) {
                        Ok(()) => frame.rax = 0,
                        Err(e) => frame.rax = e as i64 as u64,
                    }
                }
                Ok(_) => frame.rax = SysError::InvalidCap as i64 as u64,
                Err(e) => frame.rax = e as i64 as u64,
            }
        }

        // SYS_CHANNEL_RECV — async receive from channel (cap_id in rdi, requires READ)
        SYS_CHANNEL_RECV => {
            match cap::validate(frame.rdi as u32, Rights::READ) {
                Ok(CapObject::Channel { id }) => {
                    match channel::recv(PoolHandle::from_raw(id)) {
                        Ok(msg) => {
                            frame.rax = 0;
                            msg_to_frame(frame, &msg);
                        }
                        Err(e) => frame.rax = e as i64 as u64,
                    }
                }
                Ok(_) => frame.rax = SysError::InvalidCap as i64 as u64,
                Err(e) => frame.rax = e as i64 as u64,
            }
        }

        // SYS_CHANNEL_CLOSE — close async channel (cap_id in rdi, requires REVOKE)
        SYS_CHANNEL_CLOSE => {
            match cap::validate(frame.rdi as u32, Rights::REVOKE) {
                Ok(CapObject::Channel { id }) => {
                    match channel::close(PoolHandle::from_raw(id)) {
                        Ok(()) => {
                            cap::revoke(CapId::new(frame.rdi as u32));
                            frame.rax = 0;
                        }
                        Err(e) => frame.rax = e as i64 as u64,
                    }
                }
                Ok(_) => frame.rax = SysError::InvalidCap as i64 as u64,
                Err(e) => frame.rax = e as i64 as u64,
            }
        }

        // SYS_ENDPOINT_CREATE — create a new IPC endpoint, return cap_id
        SYS_ENDPOINT_CREATE => {
            match endpoint::create() {
                Some(ep) => {
                    match cap::insert(CapObject::Endpoint { id: ep.0.raw() }, Rights::ALL, None) {
                        Some(cap_id) => frame.rax = cap_id.raw() as u64,
                        None => frame.rax = SysError::OutOfResources as i64 as u64,
                    }
                }
                None => frame.rax = SysError::OutOfResources as i64 as u64,
            }
        }

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
                        match cap::insert(CapObject::Memory { base: f.addr(), size: 4096 }, Rights::ALL, None) {
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
        SYS_FRAME_FREE => {
            match cap::validate(frame.rdi as u32, Rights::WRITE) {
                Ok(CapObject::Memory { base, .. }) => {
                    mm::free_frame(PhysFrame::from_addr(base));
                    cap::revoke(CapId::new(frame.rdi as u32));
                    frame.rax = 0;
                }
                Ok(_) => frame.rax = SysError::InvalidCap as i64 as u64,
                Err(e) => frame.rax = e as i64 as u64,
            }
        }

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
                        if flags & PAGE_WRITABLE != 0 && flags & PAGE_NO_EXECUTE == 0
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

        // SYS_IRQ_REGISTER — bind IRQ to notification (rdi=irq_cap, rsi=notify_cap)
        SYS_IRQ_REGISTER => {
            match cap::validate(frame.rdi as u32, Rights::READ) {
                Ok(CapObject::Irq { line }) => {
                    match cap::validate(frame.rsi as u32, Rights::WRITE) {
                        Ok(CapObject::Notification { id }) => {
                            match irq::register(line as u8, PoolHandle::from_raw(id)) {
                                Ok(()) => frame.rax = 0,
                                Err(e) => frame.rax = e as i64 as u64,
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

        // SYS_IRQ_ACK — unmask IRQ line (cap_id in rdi, requires READ)
        SYS_IRQ_ACK => {
            match cap::validate(frame.rdi as u32, Rights::READ) {
                Ok(CapObject::Irq { line }) => {
                    match irq::ack(line as u8) {
                        Ok(()) => frame.rax = 0,
                        Err(e) => frame.rax = e as i64 as u64,
                    }
                }
                Ok(_) => frame.rax = SysError::InvalidCap as i64 as u64,
                Err(e) => frame.rax = e as i64 as u64,
            }
        }

        // SYS_PORT_IN — read from I/O port (rdi=cap, rsi=port, rdx=width 1/2/4, requires READ)
        // Width defaults to 1 for any value other than 2 or 4 (backward compatible).
        SYS_PORT_IN => {
            match cap::validate(frame.rdi as u32, Rights::READ) {
                Ok(CapObject::IoPort { base, count }) => {
                    let port = frame.rsi as u16;
                    let width: u16 = match frame.rdx {
                        2 => 2,
                        4 => 4,
                        _ => 1,
                    };
                    if port < base || port.wrapping_add(width) > base.wrapping_add(count) {
                        frame.rax = SysError::InvalidArg as i64 as u64;
                    } else {
                        let val = match width {
                            1 => (unsafe { io::inb(port) }) as u64,
                            2 => (unsafe { io::inw(port) }) as u64,
                            4 => (unsafe { io::inl(port) }) as u64,
                            _ => unreachable!(),
                        };
                        frame.rax = val;
                    }
                }
                Ok(_) => frame.rax = SysError::InvalidCap as i64 as u64,
                Err(e) => frame.rax = e as i64 as u64,
            }
        }

        // SYS_PORT_OUT — write to I/O port (rdi=cap, rsi=port, rdx=value, r8=width 1/2/4, requires WRITE)
        // Width defaults to 1 for any value other than 2 or 4 (backward compatible).
        SYS_PORT_OUT => {
            match cap::validate(frame.rdi as u32, Rights::WRITE) {
                Ok(CapObject::IoPort { base, count }) => {
                    let port = frame.rsi as u16;
                    let width: u16 = match frame.r8 {
                        2 => 2,
                        4 => 4,
                        _ => 1,
                    };
                    if port < base || port.wrapping_add(width) > base.wrapping_add(count) {
                        frame.rax = SysError::InvalidArg as i64 as u64;
                    } else {
                        match width {
                            1 => unsafe { io::outb(port, frame.rdx as u8) },
                            2 => unsafe { io::outw(port, frame.rdx as u16) },
                            4 => unsafe { io::outl(port, frame.rdx as u32) },
                            _ => unreachable!(),
                        }
                        frame.rax = 0;
                    }
                }
                Ok(_) => frame.rax = SysError::InvalidCap as i64 as u64,
                Err(e) => frame.rax = e as i64 as u64,
            }
        }

        // SYS_CAP_GRANT — delegate a capability with restricted rights
        // rdi = source cap_id, rsi = rights mask
        SYS_CAP_GRANT => {
            match cap::grant(frame.rdi as u32, frame.rsi as u32) {
                Ok(cap_id) => frame.rax = cap_id.raw() as u64,
                Err(e) => frame.rax = e as i64 as u64,
            }
        }

        // SYS_CAP_REVOKE — revoke a capability and all derivatives
        // rdi = cap_id (requires REVOKE right)
        SYS_CAP_REVOKE => {
            match cap::validate(frame.rdi as u32, Rights::REVOKE) {
                Ok(_) => {
                    cap::revoke(CapId::new(frame.rdi as u32));
                    frame.rax = 0;
                }
                Err(e) => frame.rax = e as i64 as u64,
            }
        }

        // SYS_THREAD_CREATE — create a new user thread in caller's address space
        // rdi = entry RIP, rsi = stack RSP, rdx = optional redirect endpoint cap (0 = none)
        // returns thread cap_id
        SYS_THREAD_CREATE => {
            let rip = frame.rdi;
            let rsp = frame.rsi;
            let redirect_cap = frame.rdx;
            if rip == 0 || rsp == 0 || rip >= USER_ADDR_LIMIT || rsp >= USER_ADDR_LIMIT {
                frame.rax = SysError::InvalidArg as i64 as u64;
            } else {
                // Validate optional redirect endpoint cap
                let redirect_ep = if redirect_cap != 0 {
                    match cap::validate(redirect_cap as u32, Rights::READ.or(Rights::WRITE)) {
                        Ok(CapObject::Endpoint { id: ep_id }) => Some(ep_id),
                        _ => {
                            frame.rax = SysError::InvalidCap as i64 as u64;
                            return;
                        }
                    }
                } else {
                    None
                };
                let cr3 = paging::read_cr3();
                let tid = if let Some(ep_id) = redirect_ep {
                    sched::spawn_user_with_redirect(rip, rsp, cr3, ep_id)
                } else {
                    sched::spawn_user(rip, rsp, cr3)
                };
                match cap::insert(CapObject::Thread { id: tid.0 }, Rights::ALL, None) {
                    Some(cap_id) => frame.rax = cap_id.raw() as u64,
                    None => frame.rax = SysError::OutOfResources as i64 as u64,
                }
            }
        }

        // SYS_THREAD_EXIT — terminate the current thread (never returns)
        SYS_THREAD_EXIT => {
            sched::exit_current();
        }

        // SYS_THREAD_RESUME — resume a faulted thread (rdi = tid)
        SYS_THREAD_RESUME => {
            let tid = frame.rdi as u32;
            if sched::resume_faulted(ThreadId(tid)) {
                frame.rax = 0;
            } else {
                frame.rax = SysError::InvalidArg as i64 as u64;
            }
        }

        // SYS_NOTIFY_CREATE — create a new notification object, return cap_id
        SYS_NOTIFY_CREATE => {
            match notify::create() {
                Some(n) => {
                    match cap::insert(CapObject::Notification { id: n.0.raw() }, Rights::ALL, None) {
                        Some(cap_id) => frame.rax = cap_id.raw() as u64,
                        None => frame.rax = SysError::OutOfResources as i64 as u64,
                    }
                }
                None => frame.rax = SysError::OutOfResources as i64 as u64,
            }
        }

        // SYS_NOTIFY_WAIT — wait on notification (cap_id in rdi, requires READ)
        SYS_NOTIFY_WAIT => {
            match cap::validate(frame.rdi as u32, Rights::READ) {
                Ok(CapObject::Notification { id }) => {
                    match notify::wait(PoolHandle::from_raw(id)) {
                        Ok(()) => frame.rax = 0,
                        Err(e) => frame.rax = e as i64 as u64,
                    }
                }
                Ok(_) => frame.rax = SysError::InvalidCap as i64 as u64,
                Err(e) => frame.rax = e as i64 as u64,
            }
        }

        // SYS_NOTIFY_SIGNAL — signal notification (cap_id in rdi, requires WRITE)
        SYS_NOTIFY_SIGNAL => {
            match cap::validate(frame.rdi as u32, Rights::WRITE) {
                Ok(CapObject::Notification { id }) => {
                    match notify::signal(PoolHandle::from_raw(id)) {
                        Ok(()) => frame.rax = 0,
                        Err(e) => frame.rax = e as i64 as u64,
                    }
                }
                Ok(_) => frame.rax = SysError::InvalidCap as i64 as u64,
                Err(e) => frame.rax = e as i64 as u64,
            }
        }

        // SYS_FAULT_REGISTER — register notification for page fault delivery
        // rdi = notify_cap (requires WRITE right), rsi = as_cap (0 = global fallback)
        SYS_FAULT_REGISTER => {
            match cap::validate(frame.rdi as u32, Rights::WRITE) {
                Ok(CapObject::Notification { id }) => {
                    let cr3 = if frame.rsi == 0 {
                        // Register as global fallback handler (cr3=0).
                        0
                    } else {
                        // Register for a specific address space.
                        match cap::validate(frame.rsi as u32, Rights::READ) {
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
                    fault::register(PoolHandle::from_raw(id), cr3);
                    // Also register cr3 → as_cap mapping if a specific AS was given.
                    if frame.rsi != 0 {
                        fault::register_cr3_cap(cr3, frame.rsi as u32);
                    }
                    frame.rax = 0;
                }
                Ok(_) => frame.rax = SysError::InvalidCap as i64 as u64,
                Err(e) => frame.rax = e as i64 as u64,
            }
        }

        // SYS_FAULT_RECV — pop next fault from queue
        // Returns: rdi=addr, rsi=code, rdx=tid, r8=cr3, r9=as_cap_id (or WouldBlock)
        SYS_FAULT_RECV => {
            match fault::pop_fault() {
                Some(info) => {
                    frame.rax = 0;
                    frame.rdi = info.addr;
                    frame.rsi = info.code;
                    frame.rdx = info.tid as u64;
                    frame.r8 = info.cr3;
                    frame.r9 = info.as_cap_id as u64;
                }
                None => {
                    frame.rax = SysError::WouldBlock as i64 as u64;
                }
            }
        }

        // SYS_DOMAIN_CREATE — create a scheduling domain
        // rdi = quantum_ms, rsi = period_ms; returns domain cap_id
        SYS_DOMAIN_CREATE => {
            let quantum_ms = frame.rdi;
            let period_ms = frame.rsi;
            if quantum_ms == 0 || period_ms == 0 || quantum_ms > period_ms {
                frame.rax = SysError::InvalidArg as i64 as u64;
            } else {
                // Convert ms to ticks: 1 tick = 10ms (100 Hz timer).
                let quantum_ticks = core::cmp::max(1, (quantum_ms / 10) as u32);
                let period_ticks = core::cmp::max(1, (period_ms / 10) as u32);
                match sched::create_domain(quantum_ticks, period_ticks) {
                    Some(handle) => {
                        match cap::insert(CapObject::Domain { id: handle.raw() }, Rights::ALL, None) {
                            Some(cap_id) => frame.rax = cap_id.raw() as u64,
                            None => frame.rax = SysError::OutOfResources as i64 as u64,
                        }
                    }
                    None => frame.rax = SysError::OutOfResources as i64 as u64,
                }
            }
        }

        // SYS_DOMAIN_ATTACH — attach thread to domain
        // rdi = domain_cap, rsi = thread_cap; requires WRITE on both
        SYS_DOMAIN_ATTACH => {
            match cap::validate(frame.rdi as u32, Rights::WRITE) {
                Ok(CapObject::Domain { id: dom_id }) => {
                    match cap::validate(frame.rsi as u32, Rights::WRITE) {
                        Ok(CapObject::Thread { id: tid }) => {
                            match sched::attach_to_domain(PoolHandle::from_raw(dom_id), ThreadId(tid)) {
                                Ok(()) => frame.rax = 0,
                                Err(e) => frame.rax = e as i64 as u64,
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

        // SYS_DOMAIN_DETACH — detach thread from domain
        // rdi = domain_cap, rsi = thread_cap; requires WRITE on both
        SYS_DOMAIN_DETACH => {
            match cap::validate(frame.rdi as u32, Rights::WRITE) {
                Ok(CapObject::Domain { id: dom_id }) => {
                    match cap::validate(frame.rsi as u32, Rights::WRITE) {
                        Ok(CapObject::Thread { id: tid }) => {
                            match sched::detach_from_domain(PoolHandle::from_raw(dom_id), ThreadId(tid)) {
                                Ok(()) => frame.rax = 0,
                                Err(e) => frame.rax = e as i64 as u64,
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

        // SYS_DOMAIN_ADJUST — adjust domain quantum
        // rdi = domain_cap (WRITE), rsi = new_quantum_ms
        SYS_DOMAIN_ADJUST => {
            match cap::validate(frame.rdi as u32, Rights::WRITE) {
                Ok(CapObject::Domain { id: dom_id }) => {
                    let new_quantum_ms = frame.rsi;
                    if new_quantum_ms == 0 {
                        frame.rax = SysError::InvalidArg as i64 as u64;
                    } else {
                        let new_quantum_ticks = core::cmp::max(1, (new_quantum_ms / 10) as u32);
                        match sched::adjust_domain(PoolHandle::from_raw(dom_id), new_quantum_ticks) {
                            Ok(()) => frame.rax = 0,
                            Err(e) => frame.rax = e as i64 as u64,
                        }
                    }
                }
                Ok(_) => frame.rax = SysError::InvalidCap as i64 as u64,
                Err(e) => frame.rax = e as i64 as u64,
            }
        }

        // SYS_DOMAIN_INFO — query domain budget info
        // rdi = domain_cap (READ); returns rdi=quantum, rsi=consumed, rdx=period
        SYS_DOMAIN_INFO => {
            match cap::validate(frame.rdi as u32, Rights::READ) {
                Ok(CapObject::Domain { id: dom_id }) => {
                    match sched::domain_info(PoolHandle::from_raw(dom_id)) {
                        Some((quantum, consumed, period)) => {
                            frame.rax = 0;
                            frame.rdi = quantum as u64;
                            frame.rsi = consumed as u64;
                            frame.rdx = period as u64;
                        }
                        None => frame.rax = SysError::InvalidArg as i64 as u64,
                    }
                }
                Ok(_) => frame.rax = SysError::InvalidCap as i64 as u64,
                Err(e) => frame.rax = e as i64 as u64,
            }
        }

        // SYS_FRAME_PHYS — query physical address of a frame capability
        // rdi = frame_cap (requires READ); returns rax = physical address
        SYS_FRAME_PHYS => {
            match cap::validate(frame.rdi as u32, Rights::READ) {
                Ok(CapObject::Memory { base, .. }) => {
                    frame.rax = base;
                }
                Ok(_) => frame.rax = SysError::InvalidCap as i64 as u64,
                Err(e) => frame.rax = e as i64 as u64,
            }
        }

        // SYS_IOPORT_CREATE — create an I/O port capability dynamically
        // rdi = base port, rsi = count; returns rax = cap_id
        SYS_IOPORT_CREATE => {
            let base = frame.rdi as u16;
            let count = frame.rsi as u16;
            if count == 0 || count > 256 {
                frame.rax = SysError::InvalidArg as i64 as u64;
            } else {
                match cap::insert(CapObject::IoPort { base, count }, Rights::ALL, None) {
                    Some(cap_id) => frame.rax = cap_id.raw() as u64,
                    None => frame.rax = SysError::OutOfResources as i64 as u64,
                }
            }
        }

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
                            core::ptr::write_bytes(
                                (f.addr() + hhdm) as *mut u8,
                                0,
                                size as usize,
                            );
                        }
                        match cap::insert(CapObject::Memory { base: f.addr(), size }, Rights::ALL, None) {
                            Some(cap_id) => frame.rax = cap_id.raw() as u64,
                            None => {
                                // Free all frames on cap insert failure
                                for i in 0..count {
                                    mm::free_frame(PhysFrame::from_addr(f.addr() + (i as u64) * 4096));
                                }
                                frame.rax = SysError::OutOfResources as i64 as u64;
                            }
                        }
                    }
                    None => frame.rax = SysError::OutOfResources as i64 as u64,
                }
            }
        }

        // SYS_IRQ_CREATE — create an IRQ capability dynamically
        // rdi = irq_line (0–15); returns rax = cap_id
        SYS_IRQ_CREATE => {
            let line = frame.rdi as u32;
            if line >= 16 {
                frame.rax = SysError::InvalidArg as i64 as u64;
            } else {
                match cap::insert(CapObject::Irq { line }, Rights::ALL, None) {
                    Some(cap_id) => frame.rax = cap_id.raw() as u64,
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
                    if vaddr & 0xFFF != 0 || vaddr >= USER_ADDR_LIMIT
                        || offset & 0xFFF != 0 || offset >= size
                    {
                        frame.rax = SysError::InvalidArg as i64 as u64;
                    } else {
                        let paddr = base + offset;
                        let mut flags = PAGE_PRESENT | PAGE_USER | (user_flags & USER_FLAG_MASK);
                        let cr3 = paging::read_cr3();
                        // W^X: writable pages are never executable (unless relaxed)
                        if flags & PAGE_WRITABLE != 0 && flags & PAGE_NO_EXECUTE == 0
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
                if flags & PAGE_WRITABLE != 0 && flags & PAGE_NO_EXECUTE == 0
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
                        if flags & PAGE_WRITABLE != 0 && flags & PAGE_NO_EXECUTE == 0
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

        // SYS_REDIRECT_SET — set syscall redirect endpoint on a thread (LUCAS)
        // rdi = thread_cap (WRITE), rsi = endpoint_cap (READ|WRITE)
        SYS_REDIRECT_SET => {
            match cap::validate(frame.rdi as u32, Rights::WRITE) {
                Ok(CapObject::Thread { id: tid }) => {
                    match cap::validate(frame.rsi as u32, Rights::READ.or(Rights::WRITE)) {
                        Ok(CapObject::Endpoint { id: ep_id }) => {
                            sched::set_thread_redirect_ep(ThreadId(tid), ep_id);
                            frame.rax = 0;
                        }
                        Ok(_) => frame.rax = SysError::InvalidCap as i64 as u64,
                        Err(e) => frame.rax = e as i64 as u64,
                    }
                }
                Ok(_) => frame.rax = SysError::InvalidCap as i64 as u64,
                Err(e) => frame.rax = e as i64 as u64,
            }
        }

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
                                let mut flags = PAGE_PRESENT | PAGE_USER | (user_flags & USER_FLAG_MASK);
                                // W^X: writable pages are never executable (unless relaxed)
                                if flags & PAGE_WRITABLE != 0 && flags & PAGE_NO_EXECUTE == 0
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

        // SYS_THREAD_CREATE_IN — create a thread in a target address space
        // rdi = as_cap (WRITE), rsi = rip, rdx = rsp, r8 = redirect_ep_cap (0 = none)
        SYS_THREAD_CREATE_IN => {
            match cap::validate(frame.rdi as u32, Rights::WRITE) {
                Ok(CapObject::AddrSpace { cr3 }) => {
                    let rip = frame.rsi;
                    let rsp = frame.rdx;
                    let redirect_cap = frame.r8;
                    if rip == 0 || rsp == 0 || rip >= USER_ADDR_LIMIT || rsp >= USER_ADDR_LIMIT {
                        frame.rax = SysError::InvalidArg as i64 as u64;
                    } else {
                        let redirect_ep = if redirect_cap != 0 {
                            match cap::validate(redirect_cap as u32, Rights::READ.or(Rights::WRITE)) {
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
                            sched::spawn_user_with_redirect(rip, rsp, cr3, ep_id)
                        } else {
                            sched::spawn_user(rip, rsp, cr3)
                        };
                        match cap::insert(CapObject::Thread { id: tid.0 }, Rights::ALL, None) {
                            Some(cap_id) => frame.rax = cap_id.raw() as u64,
                            None => frame.rax = SysError::OutOfResources as i64 as u64,
                        }
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

        // SYS_SVC_REGISTER — register a service name → endpoint mapping
        // rdi = name_ptr, rsi = name_len, rdx = ep_cap
        SYS_SVC_REGISTER => {
            let name_ptr = frame.rdi;
            let name_len = frame.rsi as usize;
            let ep_cap_id = frame.rdx as u32;

            if name_len == 0 || name_len > 31 || name_ptr >= USER_ADDR_LIMIT {
                frame.rax = SysError::InvalidArg as i64 as u64;
            } else {
                // Validate the endpoint capability.
                match cap::validate(ep_cap_id, Rights::READ.or(Rights::WRITE)) {
                    Ok(CapObject::Endpoint { id }) => {
                        // Read the name from userspace (via HHDM for the current AS).
                        let mut name_buf = [0u8; 31];
                        unsafe {
                            core::ptr::copy_nonoverlapping(
                                name_ptr as *const u8,
                                name_buf.as_mut_ptr(),
                                name_len,
                            );
                        }
                        match crate::svc_registry::register(&name_buf[..name_len], id) {
                            Ok(()) => frame.rax = 0,
                            Err(e) => frame.rax = e as i64 as u64,
                        }
                    }
                    Ok(_) => frame.rax = SysError::InvalidCap as i64 as u64,
                    Err(e) => frame.rax = e as i64 as u64,
                }
            }
        }

        // SYS_SVC_LOOKUP — look up a service by name, return derived endpoint cap
        // rdi = name_ptr, rsi = name_len
        SYS_SVC_LOOKUP => {
            let name_ptr = frame.rdi;
            let name_len = frame.rsi as usize;

            if name_len == 0 || name_len > 31 || name_ptr >= USER_ADDR_LIMIT {
                frame.rax = SysError::InvalidArg as i64 as u64;
            } else {
                let mut name_buf = [0u8; 31];
                unsafe {
                    core::ptr::copy_nonoverlapping(
                        name_ptr as *const u8,
                        name_buf.as_mut_ptr(),
                        name_len,
                    );
                }
                match crate::svc_registry::lookup(&name_buf[..name_len]) {
                    Ok(ep_id) => {
                        // Create a derived endpoint cap with READ|WRITE for the caller.
                        match cap::insert(
                            CapObject::Endpoint { id: ep_id },
                            Rights::READ.or(Rights::WRITE),
                            None,
                        ) {
                            Some(cap_id) => frame.rax = cap_id.raw() as u64,
                            None => frame.rax = SysError::OutOfResources as i64 as u64,
                        }
                    }
                    Err(e) => frame.rax = e as i64 as u64,
                }
            }
        }

        // SYS_INITRD_READ — read a file from initrd CPIO into userspace buffer
        // rdi = name_ptr, rsi = name_len, rdx = buf_ptr, r8 = buf_len
        // Returns: rax = file size (or error)
        SYS_INITRD_READ => {
            let name_ptr = frame.rdi;
            let name_len = frame.rsi as usize;
            let buf_ptr = frame.rdx;
            let buf_len = frame.r8 as usize;

            if name_len == 0 || name_len > 63 || name_ptr >= USER_ADDR_LIMIT
                || buf_ptr >= USER_ADDR_LIMIT
            {
                frame.rax = SysError::InvalidArg as i64 as u64;
            } else {
                // Read name from userspace.
                let mut name_buf = [0u8; 63];
                unsafe {
                    core::ptr::copy_nonoverlapping(
                        name_ptr as *const u8,
                        name_buf.as_mut_ptr(),
                        name_len,
                    );
                }
                let name_str = core::str::from_utf8(&name_buf[..name_len]).unwrap_or("");

                match crate::initrd::initrd_base_size() {
                    Some((base_phys, size)) => {
                        let hhdm = mm::hhdm_offset();
                        let initrd_data = unsafe {
                            core::slice::from_raw_parts(
                                (base_phys + hhdm) as *const u8,
                                size as usize,
                            )
                        };
                        match crate::initrd::find(initrd_data, name_str) {
                            Some(file_data) => {
                                let file_size = file_data.len();
                                let copy_len = file_size.min(buf_len);
                                if copy_len > 0 {
                                    unsafe {
                                        core::ptr::copy_nonoverlapping(
                                            file_data.as_ptr(),
                                            buf_ptr as *mut u8,
                                            copy_len,
                                        );
                                    }
                                }
                                frame.rax = file_size as u64;
                            }
                            None => frame.rax = SysError::NotFound as i64 as u64,
                        }
                    }
                    None => frame.rax = SysError::NotFound as i64 as u64,
                }
            }
        }

        // SYS_BOOTINFO_WRITE — write BootInfo page into target AS at 0xB00000
        // rdi = as_cap, rsi = caps_ptr (array of u64 cap IDs), rdx = cap_count
        SYS_BOOTINFO_WRITE => {
            match cap::validate(frame.rdi as u32, Rights::WRITE) {
                Ok(CapObject::AddrSpace { cr3 }) => {
                    let caps_ptr = frame.rsi;
                    let cap_count = frame.rdx as usize;

                    if cap_count > sotos_common::BOOT_INFO_MAX_CAPS || caps_ptr >= USER_ADDR_LIMIT {
                        frame.rax = SysError::InvalidArg as i64 as u64;
                    } else {
                        let hhdm = mm::hhdm_offset();

                        // Allocate and zero a frame for BootInfo.
                        match mm::alloc_frame() {
                            Some(f) => {
                                let phys = f.addr();
                                unsafe {
                                    core::ptr::write_bytes((phys + hhdm) as *mut u8, 0, 4096);
                                }

                                // Build BootInfo.
                                let mut info = sotos_common::BootInfo::empty();
                                info.magic = sotos_common::BOOT_INFO_MAGIC;
                                info.cap_count = cap_count as u64;

                                // Copy cap IDs from userspace.
                                if cap_count > 0 {
                                    unsafe {
                                        core::ptr::copy_nonoverlapping(
                                            caps_ptr as *const u64,
                                            info.caps.as_mut_ptr(),
                                            cap_count,
                                        );
                                    }
                                }

                                // Write BootInfo into the frame.
                                unsafe {
                                    let ptr = (phys + hhdm) as *mut sotos_common::BootInfo;
                                    core::ptr::write(ptr, info);
                                }

                                // Map read-only at 0xB00000 in target AS.
                                let target_as = paging::AddressSpace::from_cr3(cr3);
                                target_as.map_page(
                                    sotos_common::BOOT_INFO_ADDR,
                                    phys,
                                    PAGE_PRESENT | PAGE_USER,
                                );

                                frame.rax = 0;
                            }
                            None => frame.rax = SysError::OutOfResources as i64 as u64,
                        }
                    }
                }
                Ok(_) => frame.rax = SysError::InvalidCap as i64 as u64,
                Err(e) => frame.rax = e as i64 as u64,
            }
        }

        // SYS_THREAD_INFO — get info about a thread by pool index
        // rdi = thread pool index; returns rdi=tid, rsi=state, rdx=priority,
        // r8=cpu_ticks, r9=mem_pages, r10=is_user
        SYS_THREAD_INFO => {
            let idx = frame.rdi as u32;
            match sched::thread_info(idx) {
                Some((tid, state, pri, ticks, mem, is_user)) => {
                    frame.rax = 0;
                    frame.rdi = tid as u64;
                    frame.rsi = state as u64;
                    frame.rdx = pri as u64;
                    frame.r8 = ticks;
                    frame.r9 = mem as u64;
                    frame.r10 = if is_user { 1 } else { 0 };
                }
                None => frame.rax = SysError::NotFound as i64 as u64,
            }
        }

        // SYS_RESOURCE_LIMIT — set resource limits on current thread
        // rdi = cpu_tick_limit (0 = unlimited), rsi = mem_page_limit (0 = unlimited)
        SYS_RESOURCE_LIMIT => {
            if let Some(tid) = sched::current_tid() {
                sched::set_resource_limits(tid, frame.rdi, frame.rsi as u32);
                frame.rax = 0;
            } else {
                frame.rax = SysError::InvalidArg as i64 as u64;
            }
        }

        // SYS_THREAD_COUNT — get total live thread count
        SYS_THREAD_COUNT => {
            frame.rax = sched::thread_count() as u64;
        }

        // SYS_CHMOD — change file permissions
        // rdi = path_ptr, rsi = path_len, rdx = mode
        // Forwarded to LUCAS interceptor for threads with redirect set.
        // For non-redirected threads, returns InvalidArg (FS lives in userspace).
        SYS_CHMOD => {
            let path_ptr = frame.rdi;
            let path_len = frame.rsi as usize;
            let _mode = frame.rdx;

            if path_len == 0 || path_len > 255 || path_ptr >= USER_ADDR_LIMIT {
                frame.rax = SysError::InvalidArg as i64 as u64;
            } else {
                // Non-redirected thread — FS operations require LUCAS.
                frame.rax = SysError::InvalidArg as i64 as u64;
            }
        }

        // SYS_CHOWN — change file ownership
        // rdi = path_ptr, rsi = path_len, rdx = uid, r8 = gid
        // Forwarded to LUCAS interceptor for threads with redirect set.
        // For non-redirected threads, returns InvalidArg (FS lives in userspace).
        SYS_CHOWN => {
            let path_ptr = frame.rdi;
            let path_len = frame.rsi as usize;
            let _uid = frame.rdx;
            let _gid = frame.r8;

            if path_len == 0 || path_len > 255 || path_ptr >= USER_ADDR_LIMIT {
                frame.rax = SysError::InvalidArg as i64 as u64;
            } else {
                // Non-redirected thread — FS operations require LUCAS.
                frame.rax = SysError::InvalidArg as i64 as u64;
            }
        }

        // SYS_SET_FSBASE — set FS_BASE MSR for current thread (TLS)
        // rdi = new FS base address
        SYS_SET_FSBASE => {
            sched::set_current_fs_base(frame.rdi);
            frame.rax = 0;
        }

        // SYS_GET_FSBASE — get FS_BASE of current thread
        SYS_GET_FSBASE => {
            frame.rax = sched::get_current_fs_base();
        }

        // SYS_SET_THREAD_FSBASE (162) — set FS_BASE for a target thread (by thread cap)
        // rdi = thread_cap (WRITE), rsi = new FS base address
        162 => {
            match cap::validate(frame.rdi as u32, Rights::WRITE) {
                Ok(CapObject::Thread { id: tid }) => {
                    sched::set_thread_fs_base(ThreadId(tid), frame.rsi);
                    frame.rax = 0;
                }
                Ok(_) => frame.rax = SysError::InvalidCap as i64 as u64,
                Err(e) => frame.rax = e as i64 as u64,
            }
        }

        // SYS_DEBUG_PRINT — write a single byte to serial
        SYS_DEBUG_PRINT => {
            serial::write_byte(frame.rdi as u8);
            frame.rax = 0;
        }

        // SYS_DEBUG_READ — non-blocking read one byte from serial (returns -1 if none)
        SYS_DEBUG_READ => {
            frame.rax = serial::read_byte_nonblocking()
                .map(|b| b as u64)
                .unwrap_or(u64::MAX); // -1 as unsigned = no data
        }

        // SYS_DEBUG_FREE_FRAMES (252) — return number of free physical frames
        252 => {
            frame.rax = mm::frame::free_count() as u64;
        }

        // SYS_DEBUG_PROFILE_CR3 (253) — set the CR3 to profile via LAPIC timer.
        // rdi = as_cap (READ). Extracts CR3 from the cap and stores it for profiling.
        // rdi = 0 to disable profiling.
        253 => {
            use crate::arch::x86_64::idt::DEBUG_PROFILE_CR3;
            if frame.rdi == 0 {
                DEBUG_PROFILE_CR3.store(0, core::sync::atomic::Ordering::Release);
                frame.rax = 0;
            } else {
                match cap::validate(frame.rdi as u32, Rights::READ) {
                    Ok(CapObject::AddrSpace { cr3 }) => {
                        crate::kprintln!("PROFILE: cr3={:#x} from cap={}", cr3, frame.rdi);
                        DEBUG_PROFILE_CR3.store(cr3, core::sync::atomic::Ordering::Release);
                        frame.rax = 0;
                    }
                    _ => { frame.rax = SysError::InvalidCap as i64 as u64; }
                }
            }
        }

        // SYS_DEBUG_PHYS_READ (254) — read u64 from physical address via HHDM
        254 => {
            let phys_addr = frame.rdi;
            let hhdm = mm::hhdm_offset();
            let virt = (phys_addr + hhdm) as *const u64;
            frame.rax = unsafe { core::ptr::read_volatile(virt) };
        }

        // SYS_GET_THREAD_REGS (172) — read saved user registers of a blocked thread.
        // Used by LUCAS for signal frame construction.
        // rdi = thread_id, rsi = output buffer pointer (20 u64s in caller's space).
        // Returns: [0..14]=GPRs, [15]=RSP, [16]=fs_base, [17]=kernel_signal,
        //          [18]=real_rip, [19]=real_rflags (non-zero when from interrupt context).
        sotos_common::SYS_GET_THREAD_REGS => {
            let target_tid = frame.rdi as u32;
            let buf_ptr = frame.rsi;
            if buf_ptr == 0 || buf_ptr >= USER_ADDR_LIMIT {
                frame.rax = SysError::InvalidArg as i64 as u64;
            } else {
                match sched::get_thread_signal_regs(ThreadId(target_tid)) {
                    Some(regs) => {
                        let out = buf_ptr as *mut u64;
                        unsafe {
                            for i in 0..20 {
                                core::ptr::write_volatile(out.add(i), regs[i]);
                            }
                        }
                        frame.rax = 0;
                    }
                    None => {
                        frame.rax = SysError::NotFound as i64 as u64;
                    }
                }
            }
        }

        // SYS_SIGNAL_ENTRY (173) — set the async signal trampoline address for a thread.
        // rdi = thread_cap (WRITE), rsi = trampoline address in child's address space.
        sotos_common::SYS_SIGNAL_ENTRY => {
            match cap::validate(frame.rdi as u32, Rights::WRITE) {
                Ok(CapObject::Thread { id: tid }) => {
                    sched::set_signal_trampoline(ThreadId(tid), frame.rsi);
                    frame.rax = 0;
                }
                Ok(_) => frame.rax = SysError::InvalidCap as i64 as u64,
                Err(e) => frame.rax = e as i64 as u64,
            }
        }

        // SYS_SIGNAL_INJECT (174) — inject an async signal into a thread.
        // rdi = thread_id (raw), rsi = signal number (1..31).
        // Sets the pending_signals bit. The timer handler will deliver it on
        // the next return-to-user.
        sotos_common::SYS_SIGNAL_INJECT => {
            let target_tid = frame.rdi as u32;
            let sig = frame.rsi;
            if sig == 0 || sig >= 32 {
                frame.rax = SysError::InvalidArg as i64 as u64;
            } else {
                sched::set_pending_signal(ThreadId(target_tid), sig);
                frame.rax = 0;
            }
        }

        // SYS_GET_FAULT_INFO (175) — get fault addr/code for a thread's last kernel signal.
        // rdi = thread_id (raw), returns: rax = fault_addr, rdx = fault_code.
        sotos_common::SYS_GET_FAULT_INFO => {
            let target_tid = frame.rdi as u32;
            let mut sched_lock = sched::SCHEDULER.lock();
            if let Some(slot) = sched_lock.slot_of(ThreadId(target_tid)) {
                if let Some(t) = sched_lock.threads.get_mut_by_index(slot) {
                    frame.rax = t.fault_addr;
                    frame.rdx = t.fault_code;
                    // Consume: clear after read
                    t.fault_addr = 0;
                    t.fault_code = 0;
                } else {
                    frame.rax = 0;
                    frame.rdx = 0;
                }
            } else {
                frame.rax = 0;
                frame.rdx = 0;
            }
            drop(sched_lock);
        }

        // SYS_WX_RELAX — enable/disable W^X relaxation for an address space
        // rdi = as_cap (WRITE), rsi = 1 (relax) / 0 (enforce)
        SYS_WX_RELAX => {
            match cap::validate(frame.rdi as u32, Rights::WRITE) {
                Ok(CapObject::AddrSpace { cr3 }) => {
                    paging::set_wx_relaxed(cr3, frame.rsi != 0);
                    frame.rax = 0;
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
                    {
                        use core::sync::atomic::{AtomicU32, Ordering};
                        static CLONE_COUNT: AtomicU32 = AtomicU32::new(0);
                        let n = CLONE_COUNT.fetch_add(1, Ordering::Relaxed);
                        crate::kprintln!("AS-CLONE #{} cr3={:#x}", n, child_cr3);
                        if n >= 2 {
                            crate::arch::x86_64::idt::DEBUG_PROFILE_CR3
                                .store(child_cr3, Ordering::Release);
                        }
                    }

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
        SYS_PTE_READ => {
            match cap::validate(frame.rdi as u32, Rights::READ) {
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
            }
        }

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
                                None => { ok = false; break; }
                            }
                        }
                        frame.rax = if ok { 0 } else { SysError::NotFound as i64 as u64 };
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
                                            None => { ok = false; break; }
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
                                        unsafe { *pte_ptr = new_pte; }
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
                                None => { ok = false; break; }
                            }
                        }
                        frame.rax = if ok { 0 } else { SysError::NotFound as i64 as u64 };
                    }
                    Ok(_) => frame.rax = SysError::InvalidCap as i64 as u64,
                    Err(e) => frame.rax = e as i64 as u64,
                }
            }
        }

        // Unknown syscall
        _ => {
            frame.rax = SysError::InvalidArg as i64 as u64;
        }
    }

    // Restore user RSP to per-CPU storage before the asm exit path reads it.
    percpu::current_percpu().user_rsp_save = saved_user_rsp;
}
