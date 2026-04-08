//! Service registry and process spawning syscall handlers.

use crate::arch::x86_64::syscall::TrapFrame;
use crate::cap::{self, CapObject, Rights};
use crate::mm;
use crate::mm::paging::{self, PAGE_PRESENT, PAGE_USER};
use crate::sched::{self, ThreadId};
use sotos_common::SysError;

use super::{
    USER_ADDR_LIMIT,
    SYS_SVC_REGISTER, SYS_SVC_LOOKUP, SYS_INITRD_READ,
    SYS_BOOTINFO_WRITE, SYS_REDIRECT_SET,
};

/// Handle service registry and process spawning syscalls. Returns `true` if handled.
pub fn handle(frame: &mut TrapFrame, nr: u64) -> bool {
    match nr {
        // SYS_SVC_REGISTER — register a service name -> endpoint mapping
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

        _ => return false,
    }
    true
}
