//! Syscall dispatcher.
//!
//! Called from the SYSCALL entry trampoline with a pointer to the
//! saved register frame. Decodes rax as the syscall number and
//! dispatches to the appropriate handler.

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

/// Temporary syscall number for debug serial output.
const SYS_DEBUG_PRINT: u64 = 255;

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
            match mm::alloc_frame() {
                Some(f) => {
                    match cap::insert(CapObject::Memory { base: f.addr(), size: 4096 }, Rights::ALL, None) {
                        Some(cap_id) => frame.rax = cap_id.raw() as u64,
                        None => {
                            mm::free_frame(f);
                            frame.rax = SysError::OutOfResources as i64 as u64;
                        }
                    }
                }
                None => frame.rax = SysError::OutOfResources as i64 as u64,
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
                        frame.rax = SysError::InvalidArg as i64 as u64;
                    } else {
                        let flags = PAGE_PRESENT | PAGE_USER | (user_flags & USER_FLAG_MASK);
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

        // SYS_PORT_IN — read a byte from I/O port (rdi=cap, rsi=port, requires READ)
        SYS_PORT_IN => {
            match cap::validate(frame.rdi as u32, Rights::READ) {
                Ok(CapObject::IoPort { base, count }) => {
                    let port = frame.rsi as u16;
                    if port < base || port >= base + count {
                        frame.rax = SysError::InvalidArg as i64 as u64;
                    } else {
                        let val = unsafe { io::inb(port) };
                        frame.rax = val as u64;
                    }
                }
                Ok(_) => frame.rax = SysError::InvalidCap as i64 as u64,
                Err(e) => frame.rax = e as i64 as u64,
            }
        }

        // SYS_PORT_OUT — write a byte to I/O port (rdi=cap, rsi=port, rdx=value, requires WRITE)
        SYS_PORT_OUT => {
            match cap::validate(frame.rdi as u32, Rights::WRITE) {
                Ok(CapObject::IoPort { base, count }) => {
                    let port = frame.rsi as u16;
                    if port < base || port >= base + count {
                        frame.rax = SysError::InvalidArg as i64 as u64;
                    } else {
                        unsafe { io::outb(port, frame.rdx as u8) };
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
        // rdi = entry RIP, rsi = stack RSP; returns thread cap_id
        SYS_THREAD_CREATE => {
            let rip = frame.rdi;
            let rsp = frame.rsi;
            if rip == 0 || rsp == 0 || rip >= USER_ADDR_LIMIT || rsp >= USER_ADDR_LIMIT {
                frame.rax = SysError::InvalidArg as i64 as u64;
            } else {
                let cr3 = paging::read_cr3();
                let tid = sched::spawn_user(rip, rsp, cr3);
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
        // rdi = notify_cap (requires WRITE right)
        SYS_FAULT_REGISTER => {
            match cap::validate(frame.rdi as u32, Rights::WRITE) {
                Ok(CapObject::Notification { id }) => {
                    fault::register(PoolHandle::from_raw(id));
                    frame.rax = 0;
                }
                Ok(_) => frame.rax = SysError::InvalidCap as i64 as u64,
                Err(e) => frame.rax = e as i64 as u64,
            }
        }

        // SYS_FAULT_RECV — pop next fault from queue
        // Returns: rdi=addr, rsi=code, rdx=tid (or WouldBlock if empty)
        SYS_FAULT_RECV => {
            match fault::pop_fault() {
                Some(info) => {
                    frame.rax = 0;
                    frame.rdi = info.addr;
                    frame.rsi = info.code;
                    frame.rdx = info.tid as u64;
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

        // SYS_DEBUG_PRINT — write a single byte to serial (temporary)
        SYS_DEBUG_PRINT => {
            serial::write_byte(frame.rdi as u8);
            frame.rax = 0;
        }

        // Unknown syscall
        _ => {
            frame.rax = SysError::InvalidArg as i64 as u64;
        }
    }

    // Restore user RSP to per-CPU storage before the asm exit path reads it.
    percpu::current_percpu().user_rsp_save = saved_user_rsp;
}
