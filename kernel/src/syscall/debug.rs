//! Debug and profiling syscall handlers.

use crate::arch::serial;
use crate::arch::x86_64::syscall::TrapFrame;
use crate::cap::{self, CapObject, Rights};
use crate::mm;
use sotos_common::SysError;

use super::{SYS_DEBUG_PRINT, SYS_DEBUG_READ, SYS_SHUTDOWN};

/// Handle debug/profiling syscalls. Returns `true` if the syscall was handled.
pub fn handle(frame: &mut TrapFrame, nr: u64) -> bool {
    match nr {
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

        // SYS_SHUTDOWN — power off the machine via ACPI with HW fallbacks.
        // Never returns. Open to any caller for now (no capability check) —
        // the laptop bringup needs `poweroff` to work from LUCAS shell.
        // Tighten with a `Reboot` capability once the security model gels.
        SYS_SHUTDOWN => {
            crate::acpi::shutdown::shutdown();
        }

        // SYS_DEBUG_FREE_FRAMES (252) — return number of free physical frames
        252 => {
            frame.rax = mm::frame::free_count() as u64;
        }

        // SYS_DEBUG_PROFILE_CR3 (256) — set the CR3 to profile via LAPIC timer.
        // rdi = as_cap (READ). Extracts CR3 from the cap and stores it for profiling.
        // rdi = 0 to disable profiling.
        256 => {
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
                    _ => {
                        frame.rax = SysError::InvalidCap as i64 as u64;
                    }
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

        // SYS_PROVENANCE_DRAIN (260) — pop up to N entries from the per-CPU
        // provenance ring into a userspace buffer. rdi = userspace dest ptr,
        // rsi = max entries (each is sizeof::<ProvenanceEntry>() == 48 bytes),
        // rdx = cpu_id (typically 0 on single-CPU). Returns the entry count.
        260 => {
            let dest = frame.rdi as *mut crate::sot::provenance::ProvenanceEntry;
            let max = frame.rsi as usize;
            let cpu = frame.rdx as usize;
            let buf = unsafe { core::slice::from_raw_parts_mut(dest, max) };
            frame.rax = crate::sot::provenance::drain_cpu(cpu, buf) as u64;
        }

        // SYS_PROVENANCE_STATS (262) — return ring statistics for cpu_id.
        //   rdi = cpu_id
        //   returns rax=len, rdx=dropped, r8=total_pushed, r9=capacity
        262 => {
            let cpu = frame.rdi as usize;
            let (len, dropped, total, cap) = crate::sot::provenance::stats_cpu(cpu);
            frame.rax = len;
            frame.rdx = dropped;
            frame.r8 = total;
            frame.r9 = cap;
        }

        // SYS_PROVENANCE_EMIT (261) — let userspace push a synthetic
        // provenance entry into the current CPU's ring. The shape mirrors
        // the kernel `record_provenance_typed` path so the deception
        // pipeline can be exercised end-to-end without instrumenting
        // every kernel object operation.
        //
        //   rdi = operation  (matches `sotos_provenance::Operation` u16)
        //   rsi = so_type    (matches `sotos_provenance::SoType`  u8)
        //   rdx = so_id      (logical object id)
        //   r8  = owner_domain (u32)
        //
        // Always returns 0. Intentionally unprivileged for now -- the
        // ring is observation only, the worst a malicious caller can do
        // is pollute it with fake events. Tightening this is tracked
        // under Tier 3 follow-ups.
        261 => {
            use crate::sot::provenance::{record, ProvenanceEntry};
            let cpu = if crate::mm::slab::is_percpu_ready() {
                crate::arch::x86_64::percpu::current_percpu().cpu_index as usize
            } else {
                0
            };
            record(
                cpu,
                ProvenanceEntry {
                    epoch: crate::cap::current_epoch(),
                    domain_id: frame.r8 as u32,
                    operation: frame.rdi as u16,
                    so_type: frame.rsi as u8,
                    _pad: 0,
                    so_id: frame.rdx,
                    version: 0,
                    tx_id: 0,
                    timestamp: unsafe { core::arch::x86_64::_rdtsc() },
                },
            );
            frame.rax = 0;
        }

        _ => return false,
    }
    true
}
