//! Shared memory syscall handlers.

use crate::arch::x86_64::syscall::TrapFrame;
use crate::cap::{self, CapObject, Rights};
use sotos_common::SysError;

use super::{SYS_SHM_CREATE, SYS_SHM_MAP, SYS_SHM_UNMAP, SYS_SHM_DESTROY};

/// Handle shared memory syscalls. Returns `true` if the syscall was handled.
pub fn handle(frame: &mut TrapFrame, nr: u64) -> bool {
    match nr {
        // SYS_SHM_CREATE (180) — create a shared memory region
        // rdi = num_pages (max 256)
        // Returns: rax = handle (or negative error)
        SYS_SHM_CREATE => {
            frame.rax = crate::shm::shm_create(frame.rdi as usize) as u64;
        }

        // SYS_SHM_MAP (181) — map shared memory into an address space
        // rdi = handle, rsi = as_cap, rdx = vaddr, r8 = flags (bit 0 = writable)
        SYS_SHM_MAP => {
            let handle = frame.rdi as u32;
            let as_cap_id = frame.rsi as u32;
            let vaddr = frame.rdx;
            let flags = frame.r8;
            match cap::validate(as_cap_id, Rights::WRITE) {
                Ok(CapObject::AddrSpace { cr3 }) => {
                    frame.rax = crate::shm::shm_map(handle, cr3, vaddr, flags) as u64;
                }
                Ok(_) => frame.rax = SysError::InvalidCap as i64 as u64,
                Err(e) => frame.rax = e as i64 as u64,
            }
        }

        // SYS_SHM_UNMAP (182) — unmap shared memory from an address space
        // rdi = handle, rsi = as_cap
        SYS_SHM_UNMAP => {
            let handle = frame.rdi as u32;
            let as_cap_id = frame.rsi as u32;
            let vaddr = frame.rdx;
            match cap::validate(as_cap_id, Rights::WRITE) {
                Ok(CapObject::AddrSpace { cr3 }) => {
                    frame.rax = crate::shm::shm_unmap(handle, cr3, vaddr) as u64;
                }
                Ok(_) => frame.rax = SysError::InvalidCap as i64 as u64,
                Err(e) => frame.rax = e as i64 as u64,
            }
        }

        // SYS_SHM_DESTROY (183) — destroy shared memory, free frames if refcount=0
        // rdi = handle
        SYS_SHM_DESTROY => {
            frame.rax = crate::shm::shm_destroy(frame.rdi as u32) as u64;
        }

        _ => return false,
    }
    true
}
