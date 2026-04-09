//! Phase C — VM control-plane syscall handlers.
//!
//! Bridges userspace `sys::vm_*` wrappers (in `sotos-common`) to the
//! kernel-side `vm::` module that owns `VmObject` and the VMX backend.
//! Implements:
//!
//!   200 SYS_VM_CREATE         — alloc VM, return Vm capability
//!   201 SYS_VM_SET_REGS       — set vCPU GPRs
//!   202 SYS_VM_GET_REGS       — read vCPU GPRs
//!   203 SYS_VM_SET_PROFILE    — install built-in deception profile
//!   204 SYS_VM_RUN            — promote calling thread to vCPU thread
//!   205 SYS_VM_INJECT_IRQ     — inject hardware vector into vCPU
//!   206 SYS_VM_INTROSPECT_DRAIN — drain ring into userspace buffer
//!   207 SYS_VM_DESTROY        — tear down VM, free frames
//!
//! Phase C only wires CREATE / SET_PROFILE / RUN / INTROSPECT_DRAIN /
//! DESTROY end-to-end. SET_REGS / GET_REGS / INJECT_IRQ are stubs that
//! return `Ok(())` so the type-level scaffolding compiles; Phase D
//! (EPT lazy fault) and Phase F (Linux boot) will fill them in with
//! real semantics.

use crate::arch::x86_64::syscall::TrapFrame;
use crate::cap::{self, CapObject, Rights};
use crate::pool::PoolHandle;
use sotos_common::{SysError, VmIntrospectEvent as UVmIntrospectEvent, VmProfileSelector};

/// Syscall numbers (mirror of `sotos_common::Syscall::Vm*`).
const SYS_VM_CREATE: u64 = 200;
const SYS_VM_SET_REGS: u64 = 201;
const SYS_VM_GET_REGS: u64 = 202;
const SYS_VM_SET_PROFILE: u64 = 203;
const SYS_VM_RUN: u64 = 204;
const SYS_VM_INJECT_IRQ: u64 = 205;
const SYS_VM_INTROSPECT_DRAIN: u64 = 206;
const SYS_VM_DESTROY: u64 = 207;
const SYS_VM_RUN_BZIMAGE: u64 = 208;

const USER_ADDR_LIMIT: u64 = super::USER_ADDR_LIMIT;
const MAX_DRAIN_EVENTS: u64 = 256;

/// Look up a `Vm` capability by raw u32 from userspace, requiring
/// `required` rights. Returns the `PoolHandle` into `VM_POOL` on
/// success, or `SysError::InvalidCap` if the cap doesn't refer to a
/// live VM.
fn validate_vm_cap(raw: u32, required: Rights) -> Result<PoolHandle, SysError> {
    match cap::validate(raw, required)? {
        CapObject::Vm { id } => Ok(PoolHandle::from_raw(id)),
        _ => Err(SysError::InvalidCap),
    }
}

/// Phase C — main entry point. Returns true if `nr` was a VM syscall
/// number (handled or rejected), false if the dispatcher should keep
/// looking.
pub fn handle(frame: &mut TrapFrame, nr: u64) -> bool {
    match nr {
        SYS_VM_CREATE => sys_vm_create(frame),
        SYS_VM_SET_REGS => sys_vm_set_regs(frame),
        SYS_VM_GET_REGS => sys_vm_get_regs(frame),
        SYS_VM_SET_PROFILE => sys_vm_set_profile(frame),
        SYS_VM_RUN => sys_vm_run(frame),
        SYS_VM_INJECT_IRQ => sys_vm_inject_irq(frame),
        SYS_VM_INTROSPECT_DRAIN => sys_vm_introspect_drain(frame),
        SYS_VM_DESTROY => sys_vm_destroy(frame),
        SYS_VM_RUN_BZIMAGE => sys_vm_run_bzimage(frame),
        _ => return false,
    }
    true
}

fn sys_vm_create(frame: &mut TrapFrame) {
    let vcpu_count = frame.rdi as u32;
    let mem_pages = frame.rsi as u32;
    if vcpu_count == 0 || vcpu_count > 16 {
        frame.rax = SysError::InvalidArg as i64 as u64;
        return;
    }
    // Reject silly memory budgets up front. Phase D will replace this
    // with a real per-domain `mem_page_limit` check.
    if mem_pages == 0 || mem_pages > 1024 * 1024 {
        frame.rax = SysError::InvalidArg as i64 as u64;
        return;
    }
    // Distinguish "no VT-x" from "ran out of frames" so userspace can
    // tell whether to skip the kernel backend (TCG/WHPX) or treat it
    // as a hard failure. `crate::vm::create_vm` collapses both into
    // `VmObjError`; we re-check `cpu_has_vmx` here to surface the
    // correct error code.
    if !crate::arch::x86_64::vmx::cpu_has_vmx() {
        frame.rax = SysError::NotFound as i64 as u64;
        return;
    }
    match crate::vm::create_vm(vcpu_count as u8, mem_pages) {
        Ok(handle) => {
            // Store the raw PoolHandle in CapObject::Vm.id. The kernel
            // round-trips it back through `validate_vm_cap` on every
            // subsequent SYS_VM_*; PoolHandle's generation bits make
            // stale caps automatically reject.
            match cap::insert(
                CapObject::Vm { id: handle.raw() },
                Rights::ALL,
                None,
            ) {
                Some(cap_id) => frame.rax = cap_id.raw() as u64,
                None => {
                    let _ = crate::vm::destroy_vm(handle);
                    frame.rax = SysError::OutOfResources as i64 as u64;
                }
            }
        }
        Err(_) => frame.rax = SysError::OutOfResources as i64 as u64,
    }
}

fn sys_vm_set_regs(frame: &mut TrapFrame) {
    // Phase C scaffolding only — Phase F will copy `VmGuestRegs` from
    // userspace into the kernel vCPU's `gprs` field. We still validate
    // the cap so userspace can't smuggle a stale id past us.
    match validate_vm_cap(frame.rdi as u32, Rights::WRITE) {
        Ok(_) => frame.rax = 0,
        Err(e) => frame.rax = e as i64 as u64,
    }
}

fn sys_vm_get_regs(frame: &mut TrapFrame) {
    match validate_vm_cap(frame.rdi as u32, Rights::READ) {
        Ok(_) => frame.rax = 0,
        Err(e) => frame.rax = e as i64 as u64,
    }
}

fn sys_vm_set_profile(frame: &mut TrapFrame) {
    let handle = match validate_vm_cap(frame.rdi as u32, Rights::WRITE) {
        Ok(h) => h,
        Err(e) => {
            frame.rax = e as i64 as u64;
            return;
        }
    };
    let selector = frame.rsi as u8;
    if selector != VmProfileSelector::BareMetalIntel as u8 {
        frame.rax = SysError::InvalidArg as i64 as u64;
        return;
    }
    // Phase C only ships `bare_metal_intel`, but the kernel already
    // installs that as the default profile in `VmObject::create`. So
    // this syscall is a no-op for the supported selector — we still
    // return success so userspace can sequence its setup linearly.
    let _ = handle;
    frame.rax = 0;
}

fn sys_vm_run(frame: &mut TrapFrame) {
    let handle = match validate_vm_cap(frame.rdi as u32, Rights::WRITE) {
        Ok(h) => h,
        Err(e) => {
            frame.rax = e as i64 as u64;
            return;
        }
    };
    let vcpu_idx = frame.rsi as u8;
    if vcpu_idx as usize >= crate::vm::MAX_VCPUS_PER_VM {
        frame.rax = SysError::InvalidArg as i64 as u64;
        return;
    }
    // Phase C runs the same `cpuid; hlt` test payload as Phase B but
    // gates it on the userspace caller having proven cap ownership.
    // Phase F will replace this with a real bzImage entry that the
    // user thread is pinned to.
    if !crate::arch::x86_64::vmx::cpu_has_vmx() {
        frame.rax = SysError::NotFound as i64 as u64;
        return;
    }
    match crate::vm::run_payload_on_vm(handle, vcpu_idx) {
        Ok(()) => frame.rax = 0,
        Err(_) => frame.rax = SysError::OutOfResources as i64 as u64,
    }
}

fn sys_vm_inject_irq(frame: &mut TrapFrame) {
    match validate_vm_cap(frame.rdi as u32, Rights::WRITE) {
        Ok(_) => frame.rax = 0,
        Err(e) => frame.rax = e as i64 as u64,
    }
}

fn sys_vm_introspect_drain(frame: &mut TrapFrame) {
    let handle = match validate_vm_cap(frame.rdi as u32, Rights::READ) {
        Ok(h) => h,
        Err(e) => {
            frame.rax = e as i64 as u64;
            return;
        }
    };
    let dest = frame.rsi;
    let max = frame.rdx;
    if dest == 0 || dest >= USER_ADDR_LIMIT {
        frame.rax = SysError::InvalidArg as i64 as u64;
        return;
    }
    if max == 0 || max > MAX_DRAIN_EVENTS {
        frame.rax = SysError::InvalidArg as i64 as u64;
        return;
    }
    let max_usize = max as usize;
    // Drain into a kernel-side scratch buffer first, then copy into the
    // userspace pointer. This avoids holding `VM_POOL.lock()` across a
    // potentially-faulting userspace write (Phase D will land EPT
    // lazy-mapping; until then a write to an unmapped userspace page
    // would deadlock against fault delivery).
    let mut scratch: [crate::vm::VmIntrospectEvent; MAX_DRAIN_EVENTS as usize] =
        [crate::vm::VmIntrospectEvent::default(); MAX_DRAIN_EVENTS as usize];
    let n = crate::vm::drain_introspect_events(handle, &mut scratch[..max_usize]);
    // Copy out — `UVmIntrospectEvent` and `crate::vm::VmIntrospectEvent`
    // are layout-compatible (#[repr(C)] with identical fields) so a
    // raw byte copy is correct.
    let dst = dest as *mut UVmIntrospectEvent;
    for i in 0..n {
        let src = scratch[i];
        // SAFETY: bounds-checked above; `dest` is a userspace VA below
        // USER_ADDR_LIMIT and we copy `n` slots whose count came from
        // `drain_into` (≤ `max_usize`).
        unsafe {
            core::ptr::write_volatile(
                dst.add(i),
                UVmIntrospectEvent {
                    kind: src.kind,
                    _pad: src._pad,
                    a: src.a,
                    b: src.b,
                    c: src.c,
                    d: src.d,
                },
            );
        }
    }
    frame.rax = n as u64;
}

fn sys_vm_destroy(frame: &mut TrapFrame) {
    let handle = match validate_vm_cap(frame.rdi as u32, Rights::WRITE) {
        Ok(h) => h,
        Err(e) => {
            frame.rax = e as i64 as u64;
            return;
        }
    };
    match crate::vm::destroy_vm(handle) {
        Ok(()) => frame.rax = 0,
        Err(_) => frame.rax = SysError::InvalidCap as i64 as u64,
    }
}

/// Phase F.4 — load the registered bzImage and run it as the guest.
/// Bypasses the canned Phase B/C/D test payload entirely; the guest
/// memory layout, page tables, boot_params, and entry state are all
/// computed by `vm::run_bzimage_on_vm` from the parsed bzImage.
fn sys_vm_run_bzimage(frame: &mut TrapFrame) {
    let handle = match validate_vm_cap(frame.rdi as u32, Rights::WRITE) {
        Ok(h) => h,
        Err(e) => {
            frame.rax = e as i64 as u64;
            return;
        }
    };
    if !crate::arch::x86_64::vmx::cpu_has_vmx() {
        frame.rax = SysError::NotFound as i64 as u64;
        return;
    }
    match crate::vm::run_bzimage_on_vm(handle) {
        Ok(()) => frame.rax = 0,
        Err(crate::vm::VmObjError::NotFound) => {
            // No bzImage registered (e.g. initrd lacks the file).
            frame.rax = SysError::NotFound as i64 as u64;
        }
        Err(_) => frame.rax = SysError::OutOfResources as i64 as u64,
    }
}
