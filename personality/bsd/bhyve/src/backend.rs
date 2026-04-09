//! Phase C — sotOS kernel-backed control plane.
//!
//! Wraps the `SYS_VM_*` syscalls (200..207) in a small typed API so the
//! rest of `sot-bhyve` (and tier4_demo) can talk to the kernel without
//! reaching into raw `sotos_common::sys::syscall*` calls.
//!
//! The whole module is gated behind the `kernel-backend` cargo feature
//! so the type-level scaffolding still builds (and `cargo test
//! -p sot-bhyve` still passes) on the host where there is no kernel.

use sotos_common::{VmIntrospectEvent, VmProfileSelector, sys};

/// Opaque kernel VM capability handle. The raw `u64` is a sotOS
/// `CapId` masked into the low 32 bits — opaque to userspace, but
/// stable for the lifetime of the VM.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VmCap(pub u64);

/// Errors from the kernel control plane. Kernel returns negative
/// `SysError` codes; we surface them as `KernelError(i64)` rather than
/// re-decoding them here, so the caller can match on the exact value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BackendError {
    /// Kernel-side error. Negated `sotos_common::SysError`.
    KernelError(i64),
    /// `cpu_has_vmx() == false` and the kernel reported NotFound. The
    /// caller should treat this as a "skip" rather than a hard failure.
    VmxUnavailable,
}

impl From<i64> for BackendError {
    fn from(e: i64) -> Self {
        // -6 = SysError::NotFound, which the kernel returns when
        // `cpu_has_vmx()` is false. Translate that into a dedicated
        // variant so call sites can detect "no VT-x" cleanly.
        if e == -6 {
            Self::VmxUnavailable
        } else {
            Self::KernelError(e)
        }
    }
}

/// Allocate a VM in the kernel and return its capability.
pub fn vm_create(vcpu_count: u8, mem_pages: u32) -> Result<VmCap, BackendError> {
    sys::vm_create(vcpu_count as u64, mem_pages as u64)
        .map(VmCap)
        .map_err(BackendError::from)
}

/// Install a built-in deception profile (Phase C only ships
/// `VmProfileSelector::BareMetalIntel`).
pub fn vm_set_profile(cap: VmCap, selector: VmProfileSelector) -> Result<(), BackendError> {
    sys::vm_set_profile(cap.0, selector as u64).map_err(BackendError::from)
}

/// Run the VM until the guest terminates (Phase B/C: until HLT exit).
/// Blocks the calling thread inside the kernel for the duration.
pub fn vm_run(cap: VmCap, vcpu_idx: u8) -> Result<(), BackendError> {
    sys::vm_run(cap.0, vcpu_idx as u64).map_err(BackendError::from)
}

/// Drain at most `out.len()` introspection events from the VM's ring
/// into the caller-provided slice. Returns the number of events
/// actually written.
pub fn vm_introspect_drain(
    cap: VmCap,
    out: &mut [VmIntrospectEvent],
) -> Result<usize, BackendError> {
    let max = out.len() as u64;
    // SAFETY: `out.as_mut_ptr()` is a pointer into a writable userspace
    // slice with `out.len()` elements; we pass `out.len()` as `max` so
    // the kernel never writes past the end.
    let n = unsafe { sys::vm_introspect_drain(cap.0, out.as_mut_ptr(), max) }?;
    Ok(n as usize)
}

/// Tear down the VM. Subsequent operations on `cap` return InvalidCap.
pub fn vm_destroy(cap: VmCap) -> Result<(), BackendError> {
    sys::vm_destroy(cap.0).map_err(BackendError::from)
}

/// Phase F.4 — load the registered Linux bzImage as the guest's
/// payload and run. Blocks the calling thread inside the kernel
/// until the guest terminates. Distinct from `vm_run` because the
/// kernel uses a completely different memory layout, page tables,
/// and entry state for the 64-bit Linux boot protocol.
pub fn vm_run_bzimage(cap: VmCap) -> Result<(), BackendError> {
    sys::vm_run_bzimage(cap.0).map_err(BackendError::from)
}
