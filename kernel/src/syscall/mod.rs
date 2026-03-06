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

/// Syscall numbers — service registry.
const SYS_SVC_REGISTER: u64 = 130;
const SYS_SVC_LOOKUP: u64 = 131;

/// Syscall numbers — userspace process spawning.
const SYS_INITRD_READ: u64 = 132;
const SYS_BOOTINFO_WRITE: u64 = 133;

/// Syscall number — page permission change (mprotect-like).
const SYS_PROTECT: u64 = 134;

/// Syscall number — IPC call with timeout.
const SYS_CALL_TIMEOUT: u64 = 135;

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

/// Main syscall dispatcher — called from assembly with IF=0.
#[no_mangle]
pub extern "C" fn syscall_dispatch(frame: &mut TrapFrame) {
    // Save user RSP from per-CPU storage to the kernel stack.
    // If this syscall blocks (context switch), another thread's syscall
    // entry will overwrite percpu.user_rsp_save. This local survives the
    // context switch because it lives on the per-thread kernel stack.
    use crate::arch::x86_64::percpu;
    let saved_user_rsp = percpu::current_percpu().user_rsp_save;

    // --- LUCAS syscall redirect ---
    // If the current thread has a redirect endpoint set, forward the syscall
    // as an IPC message to the LUCAS handler. The handler translates Linux
    // syscalls to sotOS primitives and replies with the result.
    if let Some(ep_raw) = sched::get_current_redirect_ep() {
        // Intercept arch_prctl — requires Ring 0 (FS_BASE/GS_BASE MSR writes).
        // Linux syscall 158 = arch_prctl: rdi = subcommand, rsi = addr.
        if frame.rax == 158 {
            match frame.rdi {
                0x1002 => { // ARCH_SET_FS
                    kdebug!("arch_prctl(ARCH_SET_FS, {:#x})", frame.rsi);
                    sched::set_current_fs_base(frame.rsi);
                    frame.rax = 0;
                }
                0x1003 => { // ARCH_GET_FS
                    frame.rax = sched::get_current_fs_base();
                }
                _ => {
                    frame.rax = (-22i64) as u64; // -EINVAL
                }
            }
            percpu::current_percpu().user_rsp_save = saved_user_rsp;
            return;
        }

        let tid = sched::current_tid().map(|t| t.0 as u64).unwrap_or(0);
        let msg = Message {
            tag: frame.rax, // Linux syscall number
            regs: [frame.rdi, frame.rsi, frame.rdx, frame.r10, frame.r8, frame.r9, tid, 0],
            cap_transfer: None,
        };
        match endpoint::call(PoolHandle::from_raw(ep_raw), msg) {
            Ok(reply) => {
                frame.rax = reply.regs[0]; // return value
                // For SYS_read: handler returns byte data in regs[1].
                // Write it to the user's buffer from kernel context.
                // For SYS_read (tag=0): if handler returned inline byte
                // data in regs[1], write it to the user buffer from kernel
                // context as insurance (redundant with handler's write).
                if msg.tag == 0 && reply.regs[0] > 0 {
                    let buf_ptr = frame.rsi;
                    let byte_count = reply.regs[0] as usize;
                    if buf_ptr != 0 && buf_ptr < USER_ADDR_LIMIT && byte_count == 1 {
                        unsafe { core::ptr::write_volatile(buf_ptr as *mut u8, reply.regs[1] as u8); }
                    }
                }
            }
            Err(e) => {
                frame.rax = e as i64 as u64;
            }
        }
        percpu::current_percpu().user_rsp_save = saved_user_rsp;
        return;
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
                        // W^X: writable pages are never executable
                        if flags & PAGE_WRITABLE != 0 && flags & PAGE_NO_EXECUTE == 0 {
                            flags |= PAGE_NO_EXECUTE;
                        }
                        let cr3 = paging::read_cr3();
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
        // rdi = notify_cap (requires WRITE right), rsi = as_cap (0 = caller's own AS)
        SYS_FAULT_REGISTER => {
            match cap::validate(frame.rdi as u32, Rights::WRITE) {
                Ok(CapObject::Notification { id }) => {
                    let cr3 = if frame.rsi == 0 {
                        // Register for caller's own address space.
                        paging::read_cr3()
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
                    frame.rax = 0;
                }
                Ok(_) => frame.rax = SysError::InvalidCap as i64 as u64,
                Err(e) => frame.rax = e as i64 as u64,
            }
        }

        // SYS_FAULT_RECV — pop next fault from queue
        // Returns: rdi=addr, rsi=code, rdx=tid, r8=cr3 (or WouldBlock if empty)
        SYS_FAULT_RECV => {
            match fault::pop_fault() {
                Some(info) => {
                    frame.rax = 0;
                    frame.rdi = info.addr;
                    frame.rsi = info.code;
                    frame.rdx = info.tid as u64;
                    frame.r8 = info.cr3;
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
                        // W^X: writable pages are never executable
                        if flags & PAGE_WRITABLE != 0 && flags & PAGE_NO_EXECUTE == 0 {
                            flags |= PAGE_NO_EXECUTE;
                        }
                        let cr3 = paging::read_cr3();
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
                // W^X: writable pages are never executable
                if flags & PAGE_WRITABLE != 0 && flags & PAGE_NO_EXECUTE == 0 {
                    flags |= PAGE_NO_EXECUTE;
                }
                let cr3 = paging::read_cr3();
                let aspace = AddressSpace::from_cr3(cr3);
                if aspace.protect_page(vaddr, flags) {
                    paging::invlpg(vaddr);
                    frame.rax = 0;
                } else {
                    frame.rax = SysError::InvalidArg as i64 as u64;
                }
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
                Some(cap_id) => frame.rax = cap_id.raw() as u64,
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
                                // W^X: writable pages are never executable
                                if flags & PAGE_WRITABLE != 0 && flags & PAGE_NO_EXECUTE == 0 {
                                    flags |= PAGE_NO_EXECUTE;
                                }
                                let aspace = paging::AddressSpace::from_cr3(cr3);
                                aspace.map_page(vaddr, paddr, flags);
                                // No invlpg needed — target AS may not be current CR3.
                                // If it is, the caller can issue invlpg themselves or
                                // it will be flushed on next CR3 load.
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
        // rdi = as_cap (WRITE), rsi = rip, rdx = rsp
        SYS_THREAD_CREATE_IN => {
            match cap::validate(frame.rdi as u32, Rights::WRITE) {
                Ok(CapObject::AddrSpace { cr3 }) => {
                    let rip = frame.rsi;
                    let rsp = frame.rdx;
                    if rip == 0 || rsp == 0 || rip >= USER_ADDR_LIMIT || rsp >= USER_ADDR_LIMIT {
                        frame.rax = SysError::InvalidArg as i64 as u64;
                    } else {
                        let tid = sched::spawn_user(rip, rsp, cr3);
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

        // SYS_DEBUG_PHYS_READ (254) — read u64 from physical address via HHDM
        254 => {
            let phys_addr = frame.rdi;
            let hhdm = mm::hhdm_offset();
            let virt = (phys_addr + hhdm) as *const u64;
            frame.rax = unsafe { core::ptr::read_volatile(virt) };
        }

        // Unknown syscall
        _ => {
            frame.rax = SysError::InvalidArg as i64 as u64;
        }
    }

    // Restore user RSP to per-CPU storage before the asm exit path reads it.
    percpu::current_percpu().user_rsp_save = saved_user_rsp;
}
