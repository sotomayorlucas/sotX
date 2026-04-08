//! IPC syscall handlers: sync endpoints and async channels.

use crate::arch::x86_64::syscall::TrapFrame;
use crate::cap::{self, CapId, CapObject, Rights};
use crate::ipc::channel;
use crate::ipc::endpoint;
use crate::pool::PoolHandle;
use sotos_common::SysError;

use super::{
    msg_from_frame, msg_to_frame, SYS_CALL, SYS_CALL_TIMEOUT, SYS_CHANNEL_CLOSE,
    SYS_CHANNEL_CREATE, SYS_CHANNEL_RECV, SYS_CHANNEL_SEND, SYS_ENDPOINT_CREATE, SYS_RECV,
    SYS_RECV_TIMEOUT, SYS_SEND,
};

/// Handle IPC syscalls. Returns `true` if the syscall was handled.
pub fn handle(frame: &mut TrapFrame, nr: u64) -> bool {
    match nr {
        // SYS_SEND — synchronous send on endpoint (cap_id in rdi, requires WRITE)
        SYS_SEND => match cap::validate(frame.rdi as u32, Rights::WRITE) {
            Ok(CapObject::Endpoint { id }) => {
                let msg = msg_from_frame(frame);
                match endpoint::send(PoolHandle::from_raw(id), msg) {
                    Ok(()) => frame.rax = 0,
                    Err(e) => frame.rax = e as i64 as u64,
                }
            }
            Ok(_) => frame.rax = SysError::InvalidCap as i64 as u64,
            Err(e) => frame.rax = e as i64 as u64,
        },

        // SYS_RECV — synchronous receive on endpoint (cap_id in rdi, requires READ)
        SYS_RECV => match cap::validate(frame.rdi as u32, Rights::READ) {
            Ok(CapObject::Endpoint { id }) => match endpoint::recv(PoolHandle::from_raw(id)) {
                Ok(msg) => {
                    frame.rax = 0;
                    msg_to_frame(frame, &msg);
                }
                Err(e) => frame.rax = e as i64 as u64,
            },
            Ok(_) => frame.rax = SysError::InvalidCap as i64 as u64,
            Err(e) => frame.rax = e as i64 as u64,
        },

        // SYS_CALL — send then receive on endpoint (cap_id in rdi, requires READ|WRITE)
        SYS_CALL => match cap::validate(frame.rdi as u32, Rights::READ.or(Rights::WRITE)) {
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
        },

        // SYS_CALL_TIMEOUT — call with timeout (ep_cap in rdi[31:0], timeout in rdi[63:32])
        SYS_CALL_TIMEOUT => {
            let ep_cap = (frame.rdi & 0xFFFFFFFF) as u32;
            let timeout_ticks = (frame.rdi >> 32) as u64;
            match cap::validate(ep_cap, Rights::READ.or(Rights::WRITE)) {
                Ok(CapObject::Endpoint { id }) => {
                    let msg = msg_from_frame(frame);
                    let timeout = if timeout_ticks == 0 {
                        u64::MAX
                    } else {
                        timeout_ticks
                    };
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
                    let timeout = if timeout_ticks == 0 {
                        u64::MAX
                    } else {
                        timeout_ticks
                    };
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
        SYS_CHANNEL_CREATE => match channel::create() {
            Some(ch) => {
                match cap::insert(CapObject::Channel { id: ch.0.raw() }, Rights::ALL, None) {
                    Some(cap_id) => frame.rax = cap_id.raw() as u64,
                    None => frame.rax = SysError::OutOfResources as i64 as u64,
                }
            }
            None => frame.rax = SysError::OutOfResources as i64 as u64,
        },

        // SYS_CHANNEL_SEND — async send on channel (cap_id in rdi, requires WRITE)
        SYS_CHANNEL_SEND => match cap::validate(frame.rdi as u32, Rights::WRITE) {
            Ok(CapObject::Channel { id }) => {
                let msg = msg_from_frame(frame);
                match channel::send(PoolHandle::from_raw(id), msg) {
                    Ok(()) => frame.rax = 0,
                    Err(e) => frame.rax = e as i64 as u64,
                }
            }
            Ok(_) => frame.rax = SysError::InvalidCap as i64 as u64,
            Err(e) => frame.rax = e as i64 as u64,
        },

        // SYS_CHANNEL_RECV — async receive from channel (cap_id in rdi, requires READ)
        SYS_CHANNEL_RECV => match cap::validate(frame.rdi as u32, Rights::READ) {
            Ok(CapObject::Channel { id }) => match channel::recv(PoolHandle::from_raw(id)) {
                Ok(msg) => {
                    frame.rax = 0;
                    msg_to_frame(frame, &msg);
                }
                Err(e) => frame.rax = e as i64 as u64,
            },
            Ok(_) => frame.rax = SysError::InvalidCap as i64 as u64,
            Err(e) => frame.rax = e as i64 as u64,
        },

        // SYS_CHANNEL_CLOSE — close async channel (cap_id in rdi, requires REVOKE)
        SYS_CHANNEL_CLOSE => match cap::validate(frame.rdi as u32, Rights::REVOKE) {
            Ok(CapObject::Channel { id }) => match channel::close(PoolHandle::from_raw(id)) {
                Ok(()) => {
                    cap::revoke(CapId::new(frame.rdi as u32));
                    frame.rax = 0;
                }
                Err(e) => frame.rax = e as i64 as u64,
            },
            Ok(_) => frame.rax = SysError::InvalidCap as i64 as u64,
            Err(e) => frame.rax = e as i64 as u64,
        },

        // SYS_ENDPOINT_CREATE — create a new IPC endpoint, return cap_id
        SYS_ENDPOINT_CREATE => match endpoint::create() {
            Some(ep) => {
                match cap::insert(CapObject::Endpoint { id: ep.0.raw() }, Rights::ALL, None) {
                    Some(cap_id) => frame.rax = cap_id.raw() as u64,
                    None => frame.rax = SysError::OutOfResources as i64 as u64,
                }
            }
            None => frame.rax = SysError::OutOfResources as i64 as u64,
        },

        _ => return false,
    }
    true
}
