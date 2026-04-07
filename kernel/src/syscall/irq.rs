//! IRQ and I/O port syscall handlers.

use crate::arch::x86_64::io;
use crate::arch::x86_64::syscall::TrapFrame;
use crate::cap::{self, CapObject, Rights};
use crate::pool::PoolHandle;
use crate::irq;
use sotos_common::SysError;

use super::{
    SYS_IRQ_REGISTER, SYS_IRQ_ACK, SYS_IRQ_CREATE,
    SYS_PORT_IN, SYS_PORT_OUT, SYS_IOPORT_CREATE,
};

/// Handle IRQ and I/O port syscalls. Returns `true` if the syscall was handled.
pub fn handle(frame: &mut TrapFrame, nr: u64) -> bool {
    match nr {
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

        _ => return false,
    }
    true
}
