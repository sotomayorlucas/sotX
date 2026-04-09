//! Intel VT-x backend (Phase B of the bhyve VT-x project).
//!
//! This module is the *only* place in the kernel that touches raw VMX
//! instructions (`vmxon`, `vmxoff`, `vmclear`, `vmptrld`, `vmread`,
//! `vmwrite`, `vmlaunch`, `vmresume`). Everything else uses the safe
//! Rust wrappers exported here.
//!
//! ## Phase shape (incremental, each commit a stage)
//!
//! - **B.0** Feature detection only (this commit): `cpu_has_vmx`,
//!   `read_feature_control`, `read_vmx_basic`, `print_capabilities`.
//!   No state modification, no instructions executed. Validates that
//!   the test environment actually exposes what we need before we
//!   write any VMX-state-modifying code.
//! - **B.1** VMXON region allocation + per-CPU VMX state in `PerCpu`.
//! - **B.2** `enable_vmx()`: IA32_FEATURE_CONTROL lock+enable, CR4.VMXE,
//!   `vmxon` instruction.
//! - **B.3** VMCS allocation + `vmclear` + `vmptrld` intrinsics +
//!   `vmread` / `vmwrite` with active-VMCS assertion.
//! - **B.4** Host-state population from current kernel CR0/CR3/CR4/
//!   GDTR/IDTR/TR/RSP/RIP.
//! - **B.5** Exit trampoline + `vm_exit_handler_rust` dispatch with
//!   CPUID/HLT/RDMSR arms.
//!
//! ## Key invariants (locked in from day one)
//!
//! 1. VM-exits do NOT use IST. Each vCPU thread's `HOST_RSP` points
//!    at a per-CPU exit stack distinct from any thread's kernel
//!    stack — same shape as the `#PF + IST` corruption gotcha.
//! 2. `vmread` / `vmwrite` assert `PerCpu::active_vmcs == this_vmcs_phys`
//!    before issuing the instruction. Without this, writing fields
//!    into the wrong VMCS silently corrupts state.
//! 3. Use VPID. `VmcsConfig::default_intel()` already sets the bit;
//!    without it every `vmresume` is a full TLB flush.
//! 4. Host CR0/CR4 in the VMCS come from `read_cr0()` / `read_cr4()`
//!    at VMXON time, never hardcoded.

use crate::arch::x86_64::percpu;
use crate::kprintln;
use crate::mm;

// ---------------------------------------------------------------------------
// CPUID + MSR helpers (read-only, no state changes — safe to call anywhere)
// ---------------------------------------------------------------------------

/// `IA32_FEATURE_CONTROL` MSR (lock + VMX enable bits).
const IA32_FEATURE_CONTROL: u32 = 0x3A;

/// `IA32_VMX_BASIC` MSR — bits [30:0] are the VMCS revision id, plus
/// VMCS region size (bits 44:32) and other capability flags.
const IA32_VMX_BASIC: u32 = 0x480;

/// Bit 0 of `IA32_FEATURE_CONTROL`: lock bit. Once set, the MSR is
/// read-only until the next reset. The BIOS sets this in production;
/// some virtual environments (KVM, simple VMs) leave it clear.
pub const FC_LOCK: u64 = 1 << 0;

/// Bit 1 of `IA32_FEATURE_CONTROL`: enable VMX inside SMX (TXT).
/// Not used here, but defined so the bit value is named.
#[allow(dead_code)]
pub const FC_VMXON_INSIDE_SMX: u64 = 1 << 1;

/// Bit 2 of `IA32_FEATURE_CONTROL`: enable VMX outside SMX (the bit
/// that actually matters for us).
pub const FC_VMXON_OUTSIDE_SMX: u64 = 1 << 2;

/// Read an MSR via `rdmsr`.
#[inline]
fn rdmsr(msr: u32) -> u64 {
    let lo: u32;
    let hi: u32;
    // SAFETY: rdmsr is unprivileged at CPL 0 and only reads two registers.
    // Caller is responsible for passing a valid MSR; bogus MSRs raise #GP.
    unsafe {
        core::arch::asm!(
            "rdmsr",
            in("ecx") msr,
            out("eax") lo,
            out("edx") hi,
            options(nomem, nostack, preserves_flags),
        );
    }
    ((hi as u64) << 32) | (lo as u64)
}

// ---------------------------------------------------------------------------
// Feature detection (B.0)
// ---------------------------------------------------------------------------

/// Returns `true` iff CPUID.1:ECX bit 5 (VMX) is set.
///
/// This bit is exposed by:
/// - Real Intel hardware with VT-x enabled in firmware
/// - KVM with `-cpu host,+vmx` (nested VMX, supported since Linux 3.11)
/// - QEMU TCG with `-cpu max` (BUT VMX instructions still raise #UD —
///   the bit is informational only, not executable)
///
/// Returns `false` under WHPX (which does not expose nested
/// virtualization to its guests).
pub fn cpu_has_vmx() -> bool {
    let r = core::arch::x86_64::__cpuid(1);
    (r.ecx & (1 << 5)) != 0
}

/// Returns `true` iff CPUID.1:ECX bit 31 (hypervisor) is set, indicating
/// we're running under some hypervisor (KVM, WHPX, TCG-with-cpu-max all
/// set this). Useful for diagnostics — if `cpu_has_vmx()` is true and
/// `running_under_hypervisor()` is true, we're inside KVM (good); if
/// the latter is false, we're on bare metal (also good).
pub fn running_under_hypervisor() -> bool {
    let r = core::arch::x86_64::__cpuid(1);
    (r.ecx & (1 << 31)) != 0
}

/// Read `IA32_FEATURE_CONTROL`. Returns the raw 64-bit value.
///
/// On Intel CPUs the BIOS sets the lock bit (`FC_LOCK`) to freeze the
/// MSR before handing control to the OS. KVM passes through the host's
/// value, which is normally already locked-and-enabled. WHPX-without-
/// nested-VMX hides the MSR (returns 0) — the caller should check
/// `cpu_has_vmx()` first.
pub fn read_feature_control() -> u64 {
    rdmsr(IA32_FEATURE_CONTROL)
}

/// Read `IA32_VMX_BASIC`. The low 31 bits are the **VMCS revision id**
/// that must be written to the first 4 bytes of every VMXON region
/// and every VMCS. Bits 44:32 are the VMCS region size in bytes
/// (always ≤ 4096 on current CPUs). Bit 54 is the "true" controls
/// bit, bit 55 is "in/out information available", etc.
///
/// Only valid to call after `cpu_has_vmx()` returns true; otherwise
/// the MSR access raises #GP.
pub fn read_vmx_basic() -> u64 {
    rdmsr(IA32_VMX_BASIC)
}

/// Extract the VMCS revision id from `IA32_VMX_BASIC` (low 31 bits).
pub fn vmcs_revision_id() -> u32 {
    (read_vmx_basic() & 0x7FFF_FFFF) as u32
}

/// Extract the VMCS region size from `IA32_VMX_BASIC` (bits 44:32).
pub fn vmcs_region_size() -> u32 {
    ((read_vmx_basic() >> 32) & 0x1FFF) as u32
}

/// Print a one-line VMX capability summary to the kernel serial console.
/// Called once from `kmain` after `lapic::init()`.
pub fn print_capabilities() {
    let has_vmx = cpu_has_vmx();
    let in_hv = running_under_hypervisor();

    if !has_vmx {
        kprintln!(
            "  vmx: NOT SUPPORTED (cpuid.1:ecx bit 5 = 0, hypervisor={})",
            in_hv as u8
        );
        kprintln!("  vmx: bhyve VT-x backend disabled — needs `-accel kvm -cpu host,+vmx`");
        return;
    }

    let fc = read_feature_control();
    let basic = read_vmx_basic();
    let rev = vmcs_revision_id();
    let size = vmcs_region_size();
    let locked = (fc & FC_LOCK) != 0;
    let enabled_outside_smx = (fc & FC_VMXON_OUTSIDE_SMX) != 0;

    kprintln!(
        "  vmx: supported (rev_id={:#x} vmcs_size={} hypervisor={})",
        rev,
        size,
        in_hv as u8
    );
    kprintln!(
        "  vmx: feature_control={:#x} (lock={} vmxon_outside_smx={})",
        fc,
        locked as u8,
        enabled_outside_smx as u8
    );

    if !enabled_outside_smx {
        kprintln!("  vmx: WARNING — feature_control bit 2 clear; vmxon will #GP unless we set+lock it (B.2 task)");
    }
}

// ---------------------------------------------------------------------------
// VMX bringup (B.1 + B.2): per-CPU VMXON region + IA32_FEATURE_CONTROL +
// CR4.VMXE + the `vmxon` instruction itself.
// ---------------------------------------------------------------------------

/// Errors that the VMX bringup path can return. None of these panic — the
/// caller logs and continues with VMX disabled, leaving TCG/WHPX boots
/// unaffected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VmxError {
    /// CPUID.1:ECX bit 5 is clear — VMX not supported (TCG, WHPX).
    NotSupported,
    /// `IA32_FEATURE_CONTROL` is locked with bit 2 (vmxon-outside-smx)
    /// clear. Production firmware would have already set+locked this;
    /// when we see it locked-and-disabled it usually means the BIOS
    /// disabled VT-x and we cannot recover from CPL 0.
    FeatureControlLockedDisabled,
    /// `mm::alloc_frame()` returned `None` — the frame allocator is
    /// exhausted before VMX bringup completes. Should never happen on a
    /// 2 GiB system but graceful regardless.
    OutOfFrames,
    /// `vmxon` set CF=1 (VMfailInvalid). Causes: CR4.VMXE not set,
    /// already in VMX root, revision id mismatch, or the region is not
    /// in writable RAM.
    VmFailInvalid,
    /// `vmxon` set ZF=1 (VMfailValid). Should not happen for `vmxon`
    /// itself (which always returns VMfailInvalid on error), but kept
    /// for completeness when we extend this to other VMX instructions.
    VmFailValid,
}

/// `IA32_FEATURE_CONTROL` MSR write. Only safe before the lock bit is
/// set; once locked, `wrmsr` raises #GP.
#[inline]
unsafe fn wrmsr(msr: u32, value: u64) {
    // SAFETY: caller is responsible for picking an MSR that is writable
    // at CPL 0 and a value that the CPU will accept. WRMSR with bad
    // values raises #GP and the kernel #GP handler reports it.
    unsafe {
        core::arch::asm!(
            "wrmsr",
            in("ecx") msr,
            in("eax") (value & 0xFFFF_FFFF) as u32,
            in("edx") (value >> 32) as u32,
            options(nomem, nostack, preserves_flags),
        );
    }
}

/// Set CR4.VMXE (bit 13). Required before `vmxon`.
#[inline]
unsafe fn enable_cr4_vmxe() {
    let mut cr4: u64;
    unsafe {
        core::arch::asm!("mov {}, cr4", out(reg) cr4, options(nomem, nostack, preserves_flags));
        cr4 |= 1 << 13; // CR4.VMXE
        core::arch::asm!("mov cr4, {}", in(reg) cr4, options(nomem, nostack, preserves_flags));
    }
}

/// Execute the `vmxon` instruction. The operand is a memory location
/// holding the 64-bit physical address of the VMXON region.
///
/// Returns `Ok(())` on success (CF=0, ZF=0), `Err(VmFailInvalid)` if
/// CF=1, `Err(VmFailValid)` if ZF=1 (the latter cannot happen for
/// `vmxon` per the SDM, but is reported defensively).
///
/// # Safety
///
/// Caller must guarantee:
/// - The CPU supports VMX (`cpu_has_vmx()` returned true)
/// - `IA32_FEATURE_CONTROL` is locked with bit 2 set (or unlocked)
/// - CR4.VMXE is set
/// - `region_phys` points at a 4 KiB-aligned page of writable RAM whose
///   first 4 bytes hold the VMCS revision id from `IA32_VMX_BASIC[30:0]`
/// - The CPU is not already in VMX root operation
unsafe fn vmxon(region_phys: u64) -> Result<(), VmxError> {
    let phys = region_phys;
    let cf: u8;
    let zf: u8;
    // SAFETY: see fn-level safety contract. The asm reads the 64-bit
    // value at &phys (a stack local) as the VMXON region pointer.
    unsafe {
        core::arch::asm!(
            "vmxon [{ptr}]",
            "setc {cf}",
            "setz {zf}",
            ptr = in(reg) &phys,
            cf = out(reg_byte) cf,
            zf = out(reg_byte) zf,
            options(nostack),
        );
    }
    if cf != 0 {
        Err(VmxError::VmFailInvalid)
    } else if zf != 0 {
        Err(VmxError::VmFailValid)
    } else {
        Ok(())
    }
}

/// Execute the `vmxoff` instruction. Currently unused — kept for the
/// eventual `disable_vmx_on_current_cpu()` cleanup path.
///
/// # Safety
///
/// CPU must currently be in VMX root operation.
#[allow(dead_code)]
unsafe fn vmxoff() {
    // SAFETY: must be in VMX root; otherwise raises #UD.
    unsafe {
        core::arch::asm!("vmxoff", options(nomem, nostack));
    }
}

/// Allocate a 4 KiB VMXON region from the frame allocator and write the
/// VMCS revision id at offset 0. Returns the physical address of the
/// region on success.
///
/// The first 4 bytes of every VMXON region (and every VMCS) must hold
/// `IA32_VMX_BASIC[30:0]`; otherwise `vmxon` fails with VMfailInvalid.
fn allocate_vmxon_region() -> Result<u64, VmxError> {
    let frame = mm::alloc_frame().ok_or(VmxError::OutOfFrames)?;
    let phys = frame.addr();
    let virt = phys + mm::hhdm_offset();
    let rev = vmcs_revision_id();
    // SAFETY: the frame is freshly allocated and HHDM-mapped writable
    // by the kernel boot setup. We write 4 bytes at the start; no other
    // reference to this physical page exists yet.
    unsafe {
        core::ptr::write_volatile(virt as *mut u32, rev);
    }
    Ok(phys)
}

/// Validate `IA32_FEATURE_CONTROL` and, if necessary and possible,
/// program it to `LOCK | VMXON_OUTSIDE_SMX`. On real hardware the BIOS
/// has usually already done this; on virtualised CPUs (KVM with default
/// settings) it may be unlocked-and-zero, in which case we do it
/// ourselves before the lock latches.
fn ensure_feature_control_enabled() -> Result<(), VmxError> {
    let fc = read_feature_control();
    if (fc & FC_LOCK) != 0 {
        // Locked. Either bit 2 is set (good) or it isn't (we cannot
        // recover from CPL 0).
        if (fc & FC_VMXON_OUTSIDE_SMX) == 0 {
            return Err(VmxError::FeatureControlLockedDisabled);
        }
        return Ok(());
    }
    // Unlocked: set bit 2 + lock bit, write back. Once we wrmsr with
    // FC_LOCK set, the MSR latches read-only until the next reset.
    // SAFETY: we just verified the lock bit is clear, so wrmsr is allowed.
    unsafe {
        wrmsr(IA32_FEATURE_CONTROL, fc | FC_LOCK | FC_VMXON_OUTSIDE_SMX);
    }
    Ok(())
}

/// Bring the *current* CPU into VMX root operation.
///
/// Steps (per Intel SDM Vol 3C §24.10):
///   1. Verify CPUID.1:ECX bit 5 (`cpu_has_vmx`)
///   2. Set / verify `IA32_FEATURE_CONTROL` lock + vmxon-outside-smx
///   3. Set CR4.VMXE
///   4. Allocate a 4 KiB VMXON region, write the revision id at offset 0
///   5. `vmxon` with the region's physical address
///   6. Stash the region phys in `PerCpu.vmxon_region_phys`
///
/// Returns `Ok(())` on success or a `VmxError` describing which step
/// failed. The caller logs and continues with VMX disabled — TCG and
/// WHPX boots will return `Err(NotSupported)` here, which is the
/// expected outcome under either accelerator.
pub fn enable_on_current_cpu() -> Result<(), VmxError> {
    if !cpu_has_vmx() {
        return Err(VmxError::NotSupported);
    }
    ensure_feature_control_enabled()?;
    // SAFETY: cpu_has_vmx() returned true, so CR4.VMXE is a defined
    // bit on this CPU; setting it cannot fault.
    unsafe {
        enable_cr4_vmxe();
    }
    let region_phys = allocate_vmxon_region()?;
    // SAFETY: we just allocated the region, set CR4.VMXE, ensured
    // feature_control is locked-and-enabled, and verified VMX is
    // supported. We are not yet in VMX root (this is the first vmxon
    // on this CPU). All preconditions of the vmxon contract are met.
    unsafe {
        vmxon(region_phys)?;
    }
    percpu::current_percpu().vmxon_region_phys = region_phys;
    Ok(())
}

/// Bring up VMX on the BSP. Called from `kmain` after
/// `print_capabilities()`. On failure, logs and returns — the rest of
/// the kernel boots normally with the bhyve VT-x backend disabled.
pub fn init_bsp() {
    match enable_on_current_cpu() {
        Ok(()) => {
            let region = percpu::current_percpu().vmxon_region_phys;
            kprintln!(
                "  vmx: BSP entered VMX root operation (vmxon_region_phys={:#x})",
                region
            );
        }
        Err(VmxError::NotSupported) => {
            // print_capabilities already announced this; no extra noise.
        }
        Err(e) => {
            kprintln!("  vmx: BSP enable failed: {:?} — bhyve backend disabled", e);
        }
    }
}

// ---------------------------------------------------------------------------
// VMCS lifecycle (B.3): allocation, vmclear, vmptrld, vmread, vmwrite
// ---------------------------------------------------------------------------

/// A VMCS region — 4 KiB physical frame whose first 4 bytes hold the
/// `IA32_VMX_BASIC` revision id, identical layout to a VMXON region but
/// used to back a single vCPU rather than the per-CPU VMX root state.
///
/// `#[repr(C)]` so it can be embedded in `KernelVCpuState` (also
/// `#[repr(C)]`) without disturbing the asm-visible field offsets the
/// trampoline relies on.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct VmcsRegion {
    /// Physical address of the 4 KiB region. Used as the operand to
    /// `vmptrld` and `vmclear`.
    pub phys: u64,
}

impl VmcsRegion {
    /// Allocate a new VMCS region from the frame allocator. Writes the
    /// VMCS revision id to offset 0 (mandatory per Intel SDM Vol 3C
    /// §24.2). Returns `Err(OutOfFrames)` on allocation failure.
    pub fn allocate() -> Result<Self, VmxError> {
        let frame = mm::alloc_frame().ok_or(VmxError::OutOfFrames)?;
        let phys = frame.addr();
        let virt = phys + mm::hhdm_offset();
        let rev = vmcs_revision_id();
        // SAFETY: freshly-allocated frame, HHDM-mapped writable, no
        // other reference exists. We write 4 bytes at offset 0.
        unsafe {
            core::ptr::write_volatile(virt as *mut u32, rev);
        }
        Ok(Self { phys })
    }
}

/// Execute `vmclear`. Transitions the target VMCS to the *clear* state
/// and (if it was the active VMCS on this CPU) flushes any cached state
/// back to memory. Required before the first `vmptrld` of a new region.
///
/// # Safety
///
/// Caller must already be in VMX root operation (`vmxon` succeeded).
unsafe fn vmclear(vmcs_phys: u64) -> Result<(), VmxError> {
    let phys = vmcs_phys;
    let cf: u8;
    let zf: u8;
    // SAFETY: see fn-level safety contract.
    unsafe {
        core::arch::asm!(
            "vmclear [{ptr}]",
            "setc {cf}",
            "setz {zf}",
            ptr = in(reg) &phys,
            cf = out(reg_byte) cf,
            zf = out(reg_byte) zf,
            options(nostack),
        );
    }
    if cf != 0 {
        Err(VmxError::VmFailInvalid)
    } else if zf != 0 {
        Err(VmxError::VmFailValid)
    } else {
        Ok(())
    }
}

/// Execute `vmptrld`. Loads the target VMCS as the active VMCS on this
/// logical CPU. After this returns successfully, all `vmread`/`vmwrite`
/// operations target the loaded VMCS.
///
/// # Safety
///
/// - Must be in VMX root operation
/// - `vmcs_phys` must point at a 4 KiB-aligned page whose first 4 bytes
///   hold the correct VMCS revision id (call `VmcsRegion::allocate`)
/// - The VMCS must already have been `vmclear`ed at least once on
///   *this* logical CPU before its first `vmptrld` here
unsafe fn vmptrld_raw(vmcs_phys: u64) -> Result<(), VmxError> {
    let phys = vmcs_phys;
    let cf: u8;
    let zf: u8;
    // SAFETY: see fn-level safety contract.
    unsafe {
        core::arch::asm!(
            "vmptrld [{ptr}]",
            "setc {cf}",
            "setz {zf}",
            ptr = in(reg) &phys,
            cf = out(reg_byte) cf,
            zf = out(reg_byte) zf,
            options(nostack),
        );
    }
    if cf != 0 {
        Err(VmxError::VmFailInvalid)
    } else if zf != 0 {
        Err(VmxError::VmFailValid)
    } else {
        Ok(())
    }
}

/// `vmclear` + update `PerCpu::active_vmcs_phys` if we just clobbered
/// the active VMCS. Safe wrapper around the raw intrinsic.
pub fn vmcs_clear(region: &VmcsRegion) -> Result<(), VmxError> {
    if percpu::current_percpu().vmxon_region_phys == 0 {
        return Err(VmxError::NotSupported);
    }
    // SAFETY: we just verified the CPU is in VMX root operation
    // (`vmxon_region_phys != 0` is set only by `enable_on_current_cpu`
    // after a successful `vmxon`). The `vmclear` instruction is always
    // legal in VMX root regardless of which VMCS, if any, is active.
    unsafe { vmclear(region.phys)? };
    let pc = percpu::current_percpu();
    if pc.active_vmcs_phys == region.phys {
        pc.active_vmcs_phys = 0;
    }
    Ok(())
}

/// `vmptrld` + update `PerCpu::active_vmcs_phys`. Safe wrapper around
/// the raw intrinsic.
pub fn vmcs_load(region: &VmcsRegion) -> Result<(), VmxError> {
    if percpu::current_percpu().vmxon_region_phys == 0 {
        return Err(VmxError::NotSupported);
    }
    // SAFETY: in VMX root operation (see `vmcs_clear` rationale).
    // Caller is expected to have called `vmcs_clear` at least once on
    // this logical CPU; we trust the type-state convention here rather
    // than tracking it in the kernel.
    unsafe { vmptrld_raw(region.phys)? };
    percpu::current_percpu().active_vmcs_phys = region.phys;
    Ok(())
}

/// Execute `vmread` against the currently-active VMCS.
///
/// **Asserts** that the active VMCS on this CPU matches what the caller
/// expects, by passing the expected VMCS phys as `expected_vmcs_phys`.
/// If they disagree, returns `Err(VmFailInvalid)` instead of issuing
/// the instruction. Without this assertion, a missed `vmptrld` between
/// vCPUs would silently read fields from the wrong VMCS — the kind of
/// bug that takes weeks to find.
///
/// `field` is one of the VMCS encoding constants (host/guest/control
/// fields, see Intel SDM Vol 3C Appendix B).
pub fn vmread(field: u64, expected_vmcs_phys: u64) -> Result<u64, VmxError> {
    let pc = percpu::current_percpu();
    if pc.active_vmcs_phys == 0 || pc.active_vmcs_phys != expected_vmcs_phys {
        return Err(VmxError::VmFailInvalid);
    }
    let value: u64;
    let cf: u8;
    let zf: u8;
    // SAFETY: we just verified the active VMCS matches the caller's
    // expectation, so vmread targets a known VMCS. `field` is checked
    // by the CPU itself; an unsupported field sets ZF (VMfailValid).
    unsafe {
        core::arch::asm!(
            "vmread {value}, {field}",
            "setc {cf}",
            "setz {zf}",
            value = out(reg) value,
            field = in(reg) field,
            cf = out(reg_byte) cf,
            zf = out(reg_byte) zf,
            options(nostack),
        );
    }
    if cf != 0 {
        Err(VmxError::VmFailInvalid)
    } else if zf != 0 {
        Err(VmxError::VmFailValid)
    } else {
        Ok(value)
    }
}

/// Execute `vmwrite` against the currently-active VMCS, with the same
/// active-VMCS assertion as `vmread`.
pub fn vmwrite(field: u64, value: u64, expected_vmcs_phys: u64) -> Result<(), VmxError> {
    let pc = percpu::current_percpu();
    if pc.active_vmcs_phys == 0 || pc.active_vmcs_phys != expected_vmcs_phys {
        return Err(VmxError::VmFailInvalid);
    }
    let cf: u8;
    let zf: u8;
    // SAFETY: same reasoning as vmread — we verified the target VMCS.
    unsafe {
        core::arch::asm!(
            "vmwrite {field}, {value}",
            "setc {cf}",
            "setz {zf}",
            field = in(reg) field,
            value = in(reg) value,
            cf = out(reg_byte) cf,
            zf = out(reg_byte) zf,
            options(nostack),
        );
    }
    if cf != 0 {
        Err(VmxError::VmFailInvalid)
    } else if zf != 0 {
        Err(VmxError::VmFailValid)
    } else {
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// VMCS field encodings (Intel SDM Vol 3C Appendix B)
// ---------------------------------------------------------------------------
//
// Only the fields we actually use in Phase B are spelled out here.
// More will land as Phase B.4 (host state) and B.5 (exit handler) need
// them. The encoding scheme is:
//   bit 0:    access type (0 = full, 1 = high half of 64-bit fields)
//   bits 1-9: index
//   bits 10-11: type (0=control, 1=read-only, 2=guest, 3=host)
//   bits 12-13: width (0=16b, 1=64b, 2=32b, 3=natural)

// 16-bit control fields
#[allow(dead_code)]
pub const VMCS_VPID: u64 = 0x0000;
// 16-bit guest state
#[allow(dead_code)]
pub const VMCS_GUEST_CS_SELECTOR: u64 = 0x0802;
// 16-bit host state
#[allow(dead_code)]
pub const VMCS_HOST_CS_SELECTOR: u64 = 0x0C02;
#[allow(dead_code)]
pub const VMCS_HOST_DS_SELECTOR: u64 = 0x0C06;
#[allow(dead_code)]
pub const VMCS_HOST_ES_SELECTOR: u64 = 0x0C00;
#[allow(dead_code)]
pub const VMCS_HOST_FS_SELECTOR: u64 = 0x0C08;
#[allow(dead_code)]
pub const VMCS_HOST_GS_SELECTOR: u64 = 0x0C0A;
#[allow(dead_code)]
pub const VMCS_HOST_SS_SELECTOR: u64 = 0x0C04;
#[allow(dead_code)]
pub const VMCS_HOST_TR_SELECTOR: u64 = 0x0C0C;

// 64-bit control fields
#[allow(dead_code)]
pub const VMCS_IO_BITMAP_A: u64 = 0x2000;
#[allow(dead_code)]
pub const VMCS_IO_BITMAP_B: u64 = 0x2002;
#[allow(dead_code)]
pub const VMCS_MSR_BITMAP: u64 = 0x2004;
#[allow(dead_code)]
pub const VMCS_EPTP: u64 = 0x201A;

// 32-bit control fields
#[allow(dead_code)]
pub const VMCS_PIN_BASED_CTLS: u64 = 0x4000;
#[allow(dead_code)]
pub const VMCS_PROC_BASED_CTLS: u64 = 0x4002;
#[allow(dead_code)]
pub const VMCS_EXCEPTION_BITMAP: u64 = 0x4004;
#[allow(dead_code)]
pub const VMCS_PROC_BASED_CTLS2: u64 = 0x401E;
#[allow(dead_code)]
pub const VMCS_EXIT_CTLS: u64 = 0x400C;
#[allow(dead_code)]
pub const VMCS_ENTRY_CTLS: u64 = 0x4012;

// 32-bit read-only data fields (exit info)
#[allow(dead_code)]
pub const VMCS_VM_INSTRUCTION_ERROR: u64 = 0x4400;
#[allow(dead_code)]
pub const VMCS_VM_EXIT_REASON: u64 = 0x4402;
#[allow(dead_code)]
pub const VMCS_VM_EXIT_INTR_INFO: u64 = 0x4404;
#[allow(dead_code)]
pub const VMCS_EXIT_QUALIFICATION: u64 = 0x6400;

// Natural-width host state
#[allow(dead_code)]
pub const VMCS_HOST_CR0: u64 = 0x6C00;
#[allow(dead_code)]
pub const VMCS_HOST_CR3: u64 = 0x6C02;
#[allow(dead_code)]
pub const VMCS_HOST_CR4: u64 = 0x6C04;
#[allow(dead_code)]
pub const VMCS_HOST_FS_BASE: u64 = 0x6C06;
#[allow(dead_code)]
pub const VMCS_HOST_GS_BASE: u64 = 0x6C08;
#[allow(dead_code)]
pub const VMCS_HOST_TR_BASE: u64 = 0x6C0A;
#[allow(dead_code)]
pub const VMCS_HOST_GDTR_BASE: u64 = 0x6C0C;
#[allow(dead_code)]
pub const VMCS_HOST_IDTR_BASE: u64 = 0x6C0E;
#[allow(dead_code)]
pub const VMCS_HOST_RSP: u64 = 0x6C14;
#[allow(dead_code)]
pub const VMCS_HOST_RIP: u64 = 0x6C16;

// Natural-width guest state
#[allow(dead_code)]
pub const VMCS_GUEST_CR0: u64 = 0x6800;
#[allow(dead_code)]
pub const VMCS_GUEST_CR3: u64 = 0x6802;
#[allow(dead_code)]
pub const VMCS_GUEST_CR4: u64 = 0x6804;
#[allow(dead_code)]
pub const VMCS_GUEST_RSP: u64 = 0x681C;
#[allow(dead_code)]
pub const VMCS_GUEST_RIP: u64 = 0x681E;
#[allow(dead_code)]
pub const VMCS_GUEST_RFLAGS: u64 = 0x6820;

// Additional natural-width host state needed by `setup_host_state`.
#[allow(dead_code)]
pub const VMCS_HOST_IA32_SYSENTER_ESP: u64 = 0x6C10;
#[allow(dead_code)]
pub const VMCS_HOST_IA32_SYSENTER_EIP: u64 = 0x6C12;
#[allow(dead_code)]
pub const VMCS_HOST_IA32_SYSENTER_CS: u64 = 0x4C00;
#[allow(dead_code)]
pub const VMCS_HOST_IA32_EFER: u64 = 0x2C02;
#[allow(dead_code)]
pub const VMCS_HOST_IA32_EFER_HIGH: u64 = 0x2C03;

// Guest segment fields (used by 32-bit protected-mode test guest)
#[allow(dead_code)]
pub const VMCS_GUEST_ES_SELECTOR: u64 = 0x0800;
#[allow(dead_code)]
pub const VMCS_GUEST_SS_SELECTOR: u64 = 0x0804;
#[allow(dead_code)]
pub const VMCS_GUEST_DS_SELECTOR: u64 = 0x0806;
#[allow(dead_code)]
pub const VMCS_GUEST_FS_SELECTOR: u64 = 0x0808;
#[allow(dead_code)]
pub const VMCS_GUEST_GS_SELECTOR: u64 = 0x080A;
#[allow(dead_code)]
pub const VMCS_GUEST_LDTR_SELECTOR: u64 = 0x080C;
#[allow(dead_code)]
pub const VMCS_GUEST_TR_SELECTOR: u64 = 0x080E;

#[allow(dead_code)]
pub const VMCS_GUEST_ES_BASE: u64 = 0x6806;
#[allow(dead_code)]
pub const VMCS_GUEST_CS_BASE: u64 = 0x6808;
#[allow(dead_code)]
pub const VMCS_GUEST_SS_BASE: u64 = 0x680A;
#[allow(dead_code)]
pub const VMCS_GUEST_DS_BASE: u64 = 0x680C;
#[allow(dead_code)]
pub const VMCS_GUEST_FS_BASE: u64 = 0x680E;
#[allow(dead_code)]
pub const VMCS_GUEST_GS_BASE: u64 = 0x6810;
#[allow(dead_code)]
pub const VMCS_GUEST_LDTR_BASE: u64 = 0x6812;
#[allow(dead_code)]
pub const VMCS_GUEST_TR_BASE: u64 = 0x6814;
#[allow(dead_code)]
pub const VMCS_GUEST_GDTR_BASE: u64 = 0x6816;
#[allow(dead_code)]
pub const VMCS_GUEST_IDTR_BASE: u64 = 0x6818;

#[allow(dead_code)]
pub const VMCS_GUEST_ES_LIMIT: u64 = 0x4800;
#[allow(dead_code)]
pub const VMCS_GUEST_CS_LIMIT: u64 = 0x4802;
#[allow(dead_code)]
pub const VMCS_GUEST_SS_LIMIT: u64 = 0x4804;
#[allow(dead_code)]
pub const VMCS_GUEST_DS_LIMIT: u64 = 0x4806;
#[allow(dead_code)]
pub const VMCS_GUEST_FS_LIMIT: u64 = 0x4808;
#[allow(dead_code)]
pub const VMCS_GUEST_GS_LIMIT: u64 = 0x480A;
#[allow(dead_code)]
pub const VMCS_GUEST_LDTR_LIMIT: u64 = 0x480C;
#[allow(dead_code)]
pub const VMCS_GUEST_TR_LIMIT: u64 = 0x480E;
#[allow(dead_code)]
pub const VMCS_GUEST_GDTR_LIMIT: u64 = 0x4810;
#[allow(dead_code)]
pub const VMCS_GUEST_IDTR_LIMIT: u64 = 0x4812;

#[allow(dead_code)]
pub const VMCS_GUEST_ES_ACCESS_RIGHTS: u64 = 0x4814;
#[allow(dead_code)]
pub const VMCS_GUEST_CS_ACCESS_RIGHTS: u64 = 0x4816;
#[allow(dead_code)]
pub const VMCS_GUEST_SS_ACCESS_RIGHTS: u64 = 0x4818;
#[allow(dead_code)]
pub const VMCS_GUEST_DS_ACCESS_RIGHTS: u64 = 0x481A;
#[allow(dead_code)]
pub const VMCS_GUEST_FS_ACCESS_RIGHTS: u64 = 0x481C;
#[allow(dead_code)]
pub const VMCS_GUEST_GS_ACCESS_RIGHTS: u64 = 0x481E;
#[allow(dead_code)]
pub const VMCS_GUEST_LDTR_ACCESS_RIGHTS: u64 = 0x4820;
#[allow(dead_code)]
pub const VMCS_GUEST_TR_ACCESS_RIGHTS: u64 = 0x4822;
#[allow(dead_code)]
pub const VMCS_GUEST_INTERRUPTIBILITY_STATE: u64 = 0x4824;
#[allow(dead_code)]
pub const VMCS_GUEST_ACTIVITY_STATE: u64 = 0x4826;
#[allow(dead_code)]
pub const VMCS_VMCS_LINK_POINTER: u64 = 0x2800;

// ---------------------------------------------------------------------------
// B.4 — VMX capability MSRs + control fixed-bit machinery
// ---------------------------------------------------------------------------

#[allow(dead_code)]
const IA32_VMX_PINBASED_CTLS: u32 = 0x481;
#[allow(dead_code)]
const IA32_VMX_PROCBASED_CTLS: u32 = 0x482;
#[allow(dead_code)]
const IA32_VMX_EXIT_CTLS: u32 = 0x483;
#[allow(dead_code)]
const IA32_VMX_ENTRY_CTLS: u32 = 0x484;
const IA32_VMX_PROCBASED_CTLS2: u32 = 0x48B;
const IA32_VMX_TRUE_PINBASED_CTLS: u32 = 0x48D;
const IA32_VMX_TRUE_PROCBASED_CTLS: u32 = 0x48E;
const IA32_VMX_TRUE_EXIT_CTLS: u32 = 0x48F;
const IA32_VMX_TRUE_ENTRY_CTLS: u32 = 0x490;

#[allow(dead_code)]
const IA32_VMX_CR0_FIXED0: u32 = 0x486;
#[allow(dead_code)]
const IA32_VMX_CR0_FIXED1: u32 = 0x487;
#[allow(dead_code)]
const IA32_VMX_CR4_FIXED0: u32 = 0x488;
#[allow(dead_code)]
const IA32_VMX_CR4_FIXED1: u32 = 0x489;

const IA32_FS_BASE: u32 = 0xC000_0100;
const IA32_GS_BASE: u32 = 0xC000_0101;
const IA32_EFER: u32 = 0xC000_0080;
const IA32_SYSENTER_CS: u32 = 0x174;
const IA32_SYSENTER_ESP: u32 = 0x175;
const IA32_SYSENTER_EIP: u32 = 0x176;

/// Apply VMX fixed-bit constraints to a desired control value.
///
/// Each "true" control MSR encodes:
///   - bits  [31:0]: allowed-zero — bit X = 0 means the control bit X
///     MUST be 1 (cannot be cleared)
///   - bits [63:32]: allowed-one  — bit X = 1 means the control bit X
///     MAY be 1 (otherwise it MUST be 0)
///
/// The result that the CPU will accept is `(desired | must_be_1) & allowed_one`,
/// where `must_be_1 = !allowed_zero`.
fn adjust_controls(desired: u32, msr: u32) -> u32 {
    let m = rdmsr(msr);
    let allowed_zero = m as u32; // bits [31:0]
    let allowed_one = (m >> 32) as u32; // bits [63:32]
    let must_be_1 = !allowed_zero;
    (desired | must_be_1) & allowed_one
}

/// Apply CR0/CR4 fixed-bit constraints. Each FIXED0/FIXED1 MSR pair has:
///   - FIXED0: bit X = 1 means the bit MUST be set
///   - FIXED1: bit X = 0 means the bit MUST be clear
fn adjust_cr(value: u64, fixed0_msr: u32, fixed1_msr: u32) -> u64 {
    let must_be_1 = rdmsr(fixed0_msr);
    let must_be_0 = !rdmsr(fixed1_msr);
    (value | must_be_1) & !must_be_0
}

// ---------------------------------------------------------------------------
// B.4 — Host state read helpers
// ---------------------------------------------------------------------------

#[inline]
fn read_cr0() -> u64 {
    let v: u64;
    unsafe {
        core::arch::asm!("mov {}, cr0", out(reg) v, options(nomem, nostack, preserves_flags));
    }
    v
}

#[inline]
fn read_cr3() -> u64 {
    let v: u64;
    unsafe {
        core::arch::asm!("mov {}, cr3", out(reg) v, options(nomem, nostack, preserves_flags));
    }
    v
}

#[inline]
fn read_cr4() -> u64 {
    let v: u64;
    unsafe {
        core::arch::asm!("mov {}, cr4", out(reg) v, options(nomem, nostack, preserves_flags));
    }
    v
}

/// Read GDTR base address via `sgdt`.
#[inline]
fn read_gdtr_base() -> u64 {
    #[repr(C, packed)]
    struct Gdtr {
        limit: u16,
        base: u64,
    }
    let mut g = Gdtr { limit: 0, base: 0 };
    unsafe {
        core::arch::asm!("sgdt [{}]", in(reg) &mut g, options(nostack, preserves_flags));
    }
    g.base
}

/// Read IDTR base address via `sidt`.
#[inline]
fn read_idtr_base() -> u64 {
    #[repr(C, packed)]
    struct Idtr {
        limit: u16,
        base: u64,
    }
    let mut i = Idtr { limit: 0, base: 0 };
    unsafe {
        core::arch::asm!("sidt [{}]", in(reg) &mut i, options(nostack, preserves_flags));
    }
    i.base
}

#[inline]
fn read_cs() -> u16 {
    let v: u16;
    unsafe {
        core::arch::asm!("mov {0:x}, cs", out(reg) v, options(nomem, nostack, preserves_flags));
    }
    v
}

#[inline]
fn read_ds() -> u16 {
    let v: u16;
    unsafe {
        core::arch::asm!("mov {0:x}, ds", out(reg) v, options(nomem, nostack, preserves_flags));
    }
    v
}

#[inline]
fn read_es() -> u16 {
    let v: u16;
    unsafe {
        core::arch::asm!("mov {0:x}, es", out(reg) v, options(nomem, nostack, preserves_flags));
    }
    v
}

#[inline]
fn read_fs() -> u16 {
    let v: u16;
    unsafe {
        core::arch::asm!("mov {0:x}, fs", out(reg) v, options(nomem, nostack, preserves_flags));
    }
    v
}

#[inline]
fn read_gs() -> u16 {
    let v: u16;
    unsafe {
        core::arch::asm!("mov {0:x}, gs", out(reg) v, options(nomem, nostack, preserves_flags));
    }
    v
}

#[inline]
fn read_ss() -> u16 {
    let v: u16;
    unsafe {
        core::arch::asm!("mov {0:x}, ss", out(reg) v, options(nomem, nostack, preserves_flags));
    }
    v
}

/// Read TR via `str`.
#[inline]
fn read_tr() -> u16 {
    let v: u16;
    unsafe {
        core::arch::asm!("str {0:x}", out(reg) v, options(nomem, nostack, preserves_flags));
    }
    v
}

// ---------------------------------------------------------------------------
// B.5 — Per-CPU exit stack allocation
// ---------------------------------------------------------------------------

/// Number of pages in the per-CPU VMX exit stack. 2 pages = 8 KiB,
/// matches the kernel-stack convention; same shape as the IST stacks
/// the GDT module allocates for #PF/#GP/#DF.
const VMX_EXIT_STACK_PAGES: usize = 2;

/// Allocate a 2-page exit stack for the current CPU and store the top
/// (high address) in `PerCpu::vmx_exit_stack_top`. Idempotent: if the
/// stack is already allocated, returns Ok immediately.
///
/// Called once per CPU after `enable_on_current_cpu()` succeeds, before
/// any VMCS on this CPU has its `HOST_RSP` populated.
pub fn alloc_exit_stack_for_current_cpu() -> Result<u64, VmxError> {
    let pc = percpu::current_percpu();
    if pc.vmx_exit_stack_top != 0 {
        return Ok(pc.vmx_exit_stack_top);
    }
    let base = mm::alloc_contiguous(VMX_EXIT_STACK_PAGES).ok_or(VmxError::OutOfFrames)?;
    let virt = base.addr() + mm::hhdm_offset();
    let top = virt + (VMX_EXIT_STACK_PAGES as u64) * 4096;
    pc.vmx_exit_stack_top = top;
    Ok(top)
}

// ---------------------------------------------------------------------------
// B.4/B.5 — Host + control state setup helpers (no guest state yet,
// that's the test payload's job in B.5)
// ---------------------------------------------------------------------------

use crate::arch::x86_64::gdt;

/// Populate the **host** state fields of a VMCS so that on every
/// VM-exit the CPU restores the kernel's current execution context.
///
/// Must be called with `vmcs_phys` already loaded as the active VMCS
/// (i.e. after `vmcs_load`). Reads the *current* CR0/CR3/CR4/segments/
/// MSRs/GDTR/IDTR/TR — so the kernel state captured here is whatever
/// the calling thread sees at the moment of the call.
///
/// `host_rip` is the address of the asm exit trampoline.
/// `host_rsp` is the per-CPU exit stack top (must be DISTINCT from any
/// thread kernel stack — see #PF/IST gotcha).
pub fn setup_host_state(vmcs_phys: u64, host_rsp: u64, host_rip: u64) -> Result<(), VmxError> {
    // Control registers — read live, never hardcoded.
    vmwrite(VMCS_HOST_CR0, read_cr0(), vmcs_phys)?;
    vmwrite(VMCS_HOST_CR3, read_cr3(), vmcs_phys)?;
    vmwrite(VMCS_HOST_CR4, read_cr4(), vmcs_phys)?;

    // RSP / RIP — caller-supplied.
    vmwrite(VMCS_HOST_RSP, host_rsp, vmcs_phys)?;
    vmwrite(VMCS_HOST_RIP, host_rip, vmcs_phys)?;

    // Segment selectors. Per Intel SDM Vol 3C 26.2.3, host selectors
    // must have RPL=0 and TI=0 — we read live values which already
    // satisfy this in kernel mode.
    vmwrite(VMCS_HOST_CS_SELECTOR, (read_cs() & 0xFFF8) as u64, vmcs_phys)?;
    vmwrite(VMCS_HOST_SS_SELECTOR, (read_ss() & 0xFFF8) as u64, vmcs_phys)?;
    vmwrite(VMCS_HOST_DS_SELECTOR, (read_ds() & 0xFFF8) as u64, vmcs_phys)?;
    vmwrite(VMCS_HOST_ES_SELECTOR, (read_es() & 0xFFF8) as u64, vmcs_phys)?;
    vmwrite(VMCS_HOST_FS_SELECTOR, (read_fs() & 0xFFF8) as u64, vmcs_phys)?;
    vmwrite(VMCS_HOST_GS_SELECTOR, (read_gs() & 0xFFF8) as u64, vmcs_phys)?;
    vmwrite(VMCS_HOST_TR_SELECTOR, (read_tr() & 0xFFF8) as u64, vmcs_phys)?;

    // Descriptor table bases.
    vmwrite(VMCS_HOST_GDTR_BASE, read_gdtr_base(), vmcs_phys)?;
    vmwrite(VMCS_HOST_IDTR_BASE, read_idtr_base(), vmcs_phys)?;

    // FS_BASE / GS_BASE come from MSRs (kernel uses GS_BASE for the
    // PerCpu pointer; FS_BASE is normally 0 in kernel).
    vmwrite(VMCS_HOST_FS_BASE, rdmsr(IA32_FS_BASE), vmcs_phys)?;
    vmwrite(VMCS_HOST_GS_BASE, rdmsr(IA32_GS_BASE), vmcs_phys)?;

    // TR base — for our setup, the per-CPU TSS pointer in PerCpu is
    // the kernel virtual address of the TSS, which is what the GDT
    // descriptor encodes too. Reading from PerCpu avoids parsing the
    // GDT descriptor format.
    let tss_ptr = percpu::current_percpu().tss as u64;
    vmwrite(VMCS_HOST_TR_BASE, tss_ptr, vmcs_phys)?;

    // SYSENTER MSRs (rarely used in kernel — sotOS uses SYSCALL — but
    // the VMCS requires them).
    vmwrite(
        VMCS_HOST_IA32_SYSENTER_CS,
        rdmsr(IA32_SYSENTER_CS) & 0xFFFF_FFFF,
        vmcs_phys,
    )?;
    vmwrite(
        VMCS_HOST_IA32_SYSENTER_ESP,
        rdmsr(IA32_SYSENTER_ESP),
        vmcs_phys,
    )?;
    vmwrite(
        VMCS_HOST_IA32_SYSENTER_EIP,
        rdmsr(IA32_SYSENTER_EIP),
        vmcs_phys,
    )?;

    // IA32_EFER — host stays in long mode, save the live value.
    let efer = rdmsr(IA32_EFER);
    vmwrite(VMCS_HOST_IA32_EFER, efer, vmcs_phys)?;

    Ok(())
}

/// Populate the VMCS execution control fields (pin/proc/exit/entry +
/// secondary). Applies the fixed-bit MSR adjustments so the values
/// the CPU sees are always legal for this microarchitecture.
///
/// EPTP is filled separately by the caller (it depends on a per-VM
/// EPT root, not host state).
pub fn setup_controls(vmcs_phys: u64) -> Result<(), VmxError> {
    // Pin-based: external interrupts cause exits, NMIs cause exits.
    let pin = adjust_controls(
        (1 << 0) | (1 << 3), // EXTINT_EXIT | NMI_EXIT
        IA32_VMX_TRUE_PINBASED_CTLS,
    );
    vmwrite(VMCS_PIN_BASED_CTLS, pin as u64, vmcs_phys)?;

    // Primary proc-based: HLT exit (so HLT terminates), MSR bitmaps
    // disabled (so RDMSR/WRMSR always exit), and secondary controls
    // enabled.
    let proc1 = adjust_controls(
        (1 << 7) | (1 << 31), // HLT_EXIT | SECONDARY
        IA32_VMX_TRUE_PROCBASED_CTLS,
    );
    vmwrite(VMCS_PROC_BASED_CTLS, proc1 as u64, vmcs_phys)?;

    // Secondary: EPT, VPID, unrestricted guest. Adjusted against
    // IA32_VMX_PROCBASED_CTLS2 (no "true" variant).
    let proc2 = adjust_controls(
        (1 << 1) | (1 << 5) | (1 << 7), // EPT | VPID | UNRESTRICTED_GUEST
        IA32_VMX_PROCBASED_CTLS2,
    );
    vmwrite(VMCS_PROC_BASED_CTLS2, proc2 as u64, vmcs_phys)?;

    // VM-exit: host runs in 64-bit (HOST_ADDR_SPACE bit 9).
    let exit = adjust_controls(1 << 9, IA32_VMX_TRUE_EXIT_CTLS);
    vmwrite(VMCS_EXIT_CTLS, exit as u64, vmcs_phys)?;

    // VM-entry: 32-bit guest for the test payload (no IA32E_GUEST).
    let entry = adjust_controls(0, IA32_VMX_TRUE_ENTRY_CTLS);
    vmwrite(VMCS_ENTRY_CTLS, entry as u64, vmcs_phys)?;

    // Exception bitmap = 0 (no exceptions cause exits — we let the
    // guest handle its own faults).
    vmwrite(VMCS_EXCEPTION_BITMAP, 0, vmcs_phys)?;

    // VPID = 1 for this VM (Phase B has only one VM at a time, so
    // hardcoding is fine; Phase C will allocate per-VM).
    vmwrite(VMCS_VPID, 1, vmcs_phys)?;

    // VMCS link pointer must be all-ones (Intel SDM 26.4.2).
    vmwrite(VMCS_VMCS_LINK_POINTER, !0u64, vmcs_phys)?;

    Ok(())
}

/// Populate guest state for a 32-bit protected-mode flat guest. The
/// guest enters with CR0.PE=1, CR0.PG=0 (no paging — EPT alone provides
/// translation), flat 32-bit code/data segments, RIP at `entry_gpa`.
///
/// Used by the Phase B test payload to run a `mov eax, 1; cpuid; hlt`
/// sequence at a known guest physical address (which the EPT then maps
/// to the host frame holding those bytes).
pub fn setup_guest_state(
    vmcs_phys: u64,
    entry_gpa: u64,
    stack_gpa: u64,
) -> Result<(), VmxError> {
    // CR0: PE=1, NE=1, fixed bits applied. No paging.
    let cr0 = adjust_cr(0x21, IA32_VMX_CR0_FIXED0, IA32_VMX_CR0_FIXED1);
    vmwrite(VMCS_GUEST_CR0, cr0, vmcs_phys)?;
    vmwrite(VMCS_GUEST_CR3, 0, vmcs_phys)?;
    let cr4 = adjust_cr(0, IA32_VMX_CR4_FIXED0, IA32_VMX_CR4_FIXED1);
    vmwrite(VMCS_GUEST_CR4, cr4, vmcs_phys)?;

    // Flat 32-bit code segment, DPL=0, granularity=4K, default size=32-bit.
    // access_rights: present(7) + S(4) + type=10/Code-Read/Acc(0xB) = 0x9B,
    // db(14)=1 32-bit, g(15)=1 4K granularity → 0xC09B
    vmwrite(VMCS_GUEST_CS_SELECTOR, 0x08, vmcs_phys)?;
    vmwrite(VMCS_GUEST_CS_BASE, 0, vmcs_phys)?;
    vmwrite(VMCS_GUEST_CS_LIMIT, 0xFFFFFFFF, vmcs_phys)?;
    vmwrite(VMCS_GUEST_CS_ACCESS_RIGHTS, 0xC09B, vmcs_phys)?;

    // Flat 32-bit data segments (DS/ES/SS/FS/GS).
    let data_ar = 0xC093u64;
    for (sel_field, base_field, limit_field, ar_field) in [
        (
            VMCS_GUEST_DS_SELECTOR,
            VMCS_GUEST_DS_BASE,
            VMCS_GUEST_DS_LIMIT,
            VMCS_GUEST_DS_ACCESS_RIGHTS,
        ),
        (
            VMCS_GUEST_ES_SELECTOR,
            VMCS_GUEST_ES_BASE,
            VMCS_GUEST_ES_LIMIT,
            VMCS_GUEST_ES_ACCESS_RIGHTS,
        ),
        (
            VMCS_GUEST_SS_SELECTOR,
            VMCS_GUEST_SS_BASE,
            VMCS_GUEST_SS_LIMIT,
            VMCS_GUEST_SS_ACCESS_RIGHTS,
        ),
        (
            VMCS_GUEST_FS_SELECTOR,
            VMCS_GUEST_FS_BASE,
            VMCS_GUEST_FS_LIMIT,
            VMCS_GUEST_FS_ACCESS_RIGHTS,
        ),
        (
            VMCS_GUEST_GS_SELECTOR,
            VMCS_GUEST_GS_BASE,
            VMCS_GUEST_GS_LIMIT,
            VMCS_GUEST_GS_ACCESS_RIGHTS,
        ),
    ] {
        vmwrite(sel_field, 0x10, vmcs_phys)?;
        vmwrite(base_field, 0, vmcs_phys)?;
        vmwrite(limit_field, 0xFFFFFFFF, vmcs_phys)?;
        vmwrite(ar_field, data_ar, vmcs_phys)?;
    }

    // LDTR: unusable. access_rights bit 16 (unusable) = 0x10000.
    vmwrite(VMCS_GUEST_LDTR_SELECTOR, 0, vmcs_phys)?;
    vmwrite(VMCS_GUEST_LDTR_BASE, 0, vmcs_phys)?;
    vmwrite(VMCS_GUEST_LDTR_LIMIT, 0xFFFF, vmcs_phys)?;
    vmwrite(VMCS_GUEST_LDTR_ACCESS_RIGHTS, 0x10082, vmcs_phys)?;

    // TR: must be present even with no real TSS. type=11 (busy 32-bit TSS).
    vmwrite(VMCS_GUEST_TR_SELECTOR, 0, vmcs_phys)?;
    vmwrite(VMCS_GUEST_TR_BASE, 0, vmcs_phys)?;
    vmwrite(VMCS_GUEST_TR_LIMIT, 0xFFFF, vmcs_phys)?;
    vmwrite(VMCS_GUEST_TR_ACCESS_RIGHTS, 0x008B, vmcs_phys)?;

    // GDTR / IDTR: minimal (the guest doesn't use them in our payload).
    vmwrite(VMCS_GUEST_GDTR_BASE, 0, vmcs_phys)?;
    vmwrite(VMCS_GUEST_GDTR_LIMIT, 0xFFFF, vmcs_phys)?;
    vmwrite(VMCS_GUEST_IDTR_BASE, 0, vmcs_phys)?;
    vmwrite(VMCS_GUEST_IDTR_LIMIT, 0xFFFF, vmcs_phys)?;

    // RIP / RSP / RFLAGS.
    vmwrite(VMCS_GUEST_RIP, entry_gpa, vmcs_phys)?;
    vmwrite(VMCS_GUEST_RSP, stack_gpa, vmcs_phys)?;
    // RFLAGS: bit 1 (reserved, always 1), interrupts disabled.
    vmwrite(VMCS_GUEST_RFLAGS, 0x0000_0002, vmcs_phys)?;

    // Activity state = 0 (active), interruptibility = 0.
    vmwrite(VMCS_GUEST_INTERRUPTIBILITY_STATE, 0, vmcs_phys)?;
    vmwrite(VMCS_GUEST_ACTIVITY_STATE, 0, vmcs_phys)?;

    Ok(())
}

// ---------------------------------------------------------------------------
// B.5 — Minimal EPT (just enough to identity-map a few pages)
// ---------------------------------------------------------------------------

/// EPT entry flags: read | write | execute, memory type WB.
const EPT_LEAF_FLAGS: u64 = 0x37; // R(1) | W(2) | X(4) | (WB(6) << 3)
/// EPT entry flags for non-leaf entries: read | write | execute.
const EPT_NONLEAF_FLAGS: u64 = 0x07;

/// A minimal 4-level EPT root. Holds the PML4 frame plus pre-allocated
/// PDPT/PD/PT frames so we can identity-map a contiguous low-memory
/// region without dynamic allocation in the hot path.
///
/// **Phase B only.** Phase D will replace this with a real lazy-fault
/// EPT that grows as the guest touches new pages.
pub struct MiniEpt {
    pub pml4_phys: u64,
    pub pdpt_phys: u64,
    pub pd_phys: u64,
    pub pt_phys: u64,
}

impl MiniEpt {
    /// Allocate a 4-level EPT covering guest physical addresses
    /// `[0 .. 2 MiB)` via 4 KiB leaf entries. Each level except the
    /// PT has exactly one entry; the PT has 512 entries, all initially
    /// zero (not present). Use `map_4k` to install a leaf.
    pub fn allocate() -> Result<Self, VmxError> {
        let pml4 = mm::alloc_frame().ok_or(VmxError::OutOfFrames)?;
        let pdpt = mm::alloc_frame().ok_or(VmxError::OutOfFrames)?;
        let pd = mm::alloc_frame().ok_or(VmxError::OutOfFrames)?;
        let pt = mm::alloc_frame().ok_or(VmxError::OutOfFrames)?;

        let hhdm = mm::hhdm_offset();
        // Zero all four pages, then thread them together.
        unsafe {
            for &p in &[pml4.addr(), pdpt.addr(), pd.addr(), pt.addr()] {
                core::ptr::write_bytes((p + hhdm) as *mut u8, 0, 4096);
            }
            // PML4[0] -> PDPT
            *((pml4.addr() + hhdm) as *mut u64) = pdpt.addr() | EPT_NONLEAF_FLAGS;
            // PDPT[0] -> PD
            *((pdpt.addr() + hhdm) as *mut u64) = pd.addr() | EPT_NONLEAF_FLAGS;
            // PD[0] -> PT
            *((pd.addr() + hhdm) as *mut u64) = pt.addr() | EPT_NONLEAF_FLAGS;
        }

        Ok(Self {
            pml4_phys: pml4.addr(),
            pdpt_phys: pdpt.addr(),
            pd_phys: pd.addr(),
            pt_phys: pt.addr(),
        })
    }

    /// Identity-map a 4 KiB guest physical page to the given host
    /// frame. `gpa` must be in `[0 .. 2 MiB)` (the range covered by
    /// the single PT this MiniEpt allocated).
    pub fn map_4k(&self, gpa: u64, host_phys: u64) -> Result<(), VmxError> {
        let pt_idx = ((gpa >> 12) & 0x1FF) as usize;
        if (gpa >> 21) != 0 {
            return Err(VmxError::OutOfFrames); // outside 2 MiB window
        }
        let pt_virt = self.pt_phys + mm::hhdm_offset();
        // SAFETY: pt_phys is a valid 4 KiB frame allocated above; we
        // write one u64 entry within bounds.
        unsafe {
            let entry_ptr = (pt_virt as *mut u64).add(pt_idx);
            *entry_ptr = host_phys | EPT_LEAF_FLAGS;
        }
        Ok(())
    }

    /// Build the EPTP value for the VMCS field.
    ///
    /// Format: pml4_phys | (page-walk-length-1 << 3) | memory-type
    /// = pml4_phys | (3 << 3) | 6 (WB)
    /// = pml4_phys | 0x1E
    pub fn eptp(&self) -> u64 {
        self.pml4_phys | (3 << 3) | 6
    }
}

// ---------------------------------------------------------------------------
// B.5 — VM-exit trampoline + vCPU run loop
// ---------------------------------------------------------------------------
//
// `vmx_exit_trampoline` is the host RIP target for every VM-exit in
// Phase B. The CPU jumps here with HOST_RSP = vmx_exit_stack_top - 8
// (the [-8] slot holds the Rust `vmx_run` return address that we
// pushed before vmlaunch).
//
// Trampoline contract:
//   1. Save guest GPRs into `state.gprs` (state pointer is in gs:[104])
//   2. Call `vm_exit_handler_rust(state)` — Rust dispatcher
//   3. Read return value (ExitAction) from eax:
//        0 = Resume → reload guest GPRs, vmresume → loop on next exit
//        1 = Terminate → ret (pops Rust return address, control returns
//            to vmx_run after the vmlaunch/vmresume instruction)
//
// The `state.gprs` field is at offset 0 of `KernelVCpuState` (load-bearing
// `#[repr(C)]` ordering — see `vm/mod.rs` doc comment).

extern "C" {
    /// Asm exit trampoline. Defined below via `global_asm!`. Address
    /// is what we write into `VMCS_HOST_RIP`.
    pub fn vmx_exit_trampoline();

    /// Naked-ish helper that performs the actual `vmlaunch` /
    /// `vmresume` and returns when the trampoline does `ret`.
    /// Returns `()`; `state.halted` indicates whether the dispatcher
    /// terminated the vCPU.
    fn vmx_run_inner(state: *mut crate::vm::KernelVCpuState);
}

/// C-ABI dispatcher entry point invoked by the asm exit trampoline.
/// `state` is a pointer to the `KernelVCpuState` whose VMCS is currently
/// active. Returns `0` to resume, `1` to terminate.
#[no_mangle]
extern "C" fn vm_exit_handler_rust(state: *mut crate::vm::KernelVCpuState) -> u32 {
    // SAFETY: the trampoline passed us a pointer to the
    // currently-active vCPU's KernelVCpuState. The caller (Rust
    // `vmx_run`) holds the only mutable reference to it for the
    // duration of this VM execution.
    let state_ref = unsafe { &mut *state };
    let vm_handle = crate::vm::current_vm_for_dispatch();
    let action = match vm_handle {
        Some(h) => {
            // Look up the VM's profile by handle, dispatch, return.
            // We re-borrow the pool's profile via a copy so we don't
            // hold the pool lock across the dispatcher.
            let profile = crate::vm::profile_for(h);
            crate::vm::exit::dispatch(state_ref, &profile)
        }
        None => {
            crate::kprintln!(
                "  vmx: VM-exit on cpu {} with no active VM — terminating",
                percpu::current_percpu().cpu_index
            );
            crate::vm::exit::ExitAction::Terminate
        }
    };
    match action {
        crate::vm::exit::ExitAction::Resume => 0,
        crate::vm::exit::ExitAction::Terminate => 1,
    }
}

core::arch::global_asm!(
    ".global vmx_exit_trampoline",
    "vmx_exit_trampoline:",
    // Entry: just took a VM-exit. RSP = vmx_exit_stack_top - 8.
    // [rsp] = saved Rust return address from vmx_run_inner.
    // All GPRs are guest values; we have to save them before doing
    // anything else.
    //
    // Find the active KernelVCpuState via gs:[104]. RAX is currently
    // a guest value, but we need a scratch register. Save it on the
    // exit stack first.
    "    push rax",
    "    mov rax, gs:[104]",        // rax = &KernelVCpuState (gprs at offset 0)
    "    mov [rax + 8], rbx",       // gprs.rbx
    "    mov [rax + 16], rcx",      // gprs.rcx
    "    mov [rax + 24], rdx",      // gprs.rdx
    "    mov [rax + 32], rsi",      // gprs.rsi
    "    mov [rax + 40], rdi",      // gprs.rdi
    "    mov [rax + 48], rbp",      // gprs.rbp
    "    mov [rax + 56], r8",       // gprs.r8
    "    mov [rax + 64], r9",       // gprs.r9
    "    mov [rax + 72], r10",      // gprs.r10
    "    mov [rax + 80], r11",      // gprs.r11
    "    mov [rax + 88], r12",      // gprs.r12
    "    mov [rax + 96], r13",      // gprs.r13
    "    mov [rax + 104], r14",     // gprs.r14
    "    mov [rax + 112], r15",     // gprs.r15
    // Now save the original guest rax (currently on the stack) into gprs.rax.
    "    pop rcx",                  // rcx = original guest rax
    "    mov [rax], rcx",           // gprs.rax
    // Call the C-ABI dispatcher with rdi = &KernelVCpuState
    "    mov rdi, rax",
    "    call vm_exit_handler_rust",
    // eax now holds the action: 0 = Resume, 1 = Terminate
    "    test eax, eax",
    "    jne 2f",                   // non-zero → terminate
    // === Resume ===
    // Reload guest GPRs from state.gprs (state ptr is back in gs:[104]).
    "    mov rax, gs:[104]",
    "    mov rbx, [rax + 8]",
    "    mov rcx, [rax + 16]",
    "    mov rdx, [rax + 24]",
    "    mov rsi, [rax + 32]",
    "    mov rdi, [rax + 40]",
    "    mov rbp, [rax + 48]",
    "    mov r8,  [rax + 56]",
    "    mov r9,  [rax + 64]",
    "    mov r10, [rax + 72]",
    "    mov r11, [rax + 80]",
    "    mov r12, [rax + 88]",
    "    mov r13, [rax + 96]",
    "    mov r14, [rax + 104]",
    "    mov r15, [rax + 112]",
    "    mov rax, [rax]",           // rax LAST so we don't clobber the base
    "    vmresume",
    // vmresume falls through ONLY on failure (CF or ZF set). Treat
    // failure as Terminate.
    "2:",
    // === Terminate ===
    // RSP at this point is wherever we left it after the dispatcher
    // call: that's vmx_exit_stack_top - 8 (the slot containing the
    // Rust return address). `ret` pops it back into rip and returns
    // to vmx_run_inner.
    "    ret",
);

core::arch::global_asm!(
    ".global vmx_run_inner",
    "vmx_run_inner:",
    // Args: rdi = &KernelVCpuState
    // Save callee-saved regs onto the kernel stack (we need rbx/rbp/
    // r12-r15 preserved across the entire VM execution).
    "    push rbp",
    "    push rbx",
    "    push r12",
    "    push r13",
    "    push r14",
    "    push r15",
    // Stash the state pointer in PerCpu so the trampoline can find it.
    "    mov gs:[104], rdi",
    // Push our return address (the post-vmlaunch label) onto the
    // vmx_exit_stack so the trampoline's terminate path can `ret`
    // back here. The exit stack lives in PerCpu at offset 96.
    "    mov rax, gs:[96]",        // rax = vmx_exit_stack_top
    "    sub rax, 8",
    "    lea rcx, [rip + 3f]",     // rcx = address of post_vmlaunch label
    "    mov [rax], rcx",          // store return address at exit_stack_top - 8
    // Load guest GPRs from state.gprs into CPU registers.
    "    mov rbx, [rdi + 8]",
    "    mov rcx, [rdi + 16]",
    "    mov rdx, [rdi + 24]",
    "    mov rsi, [rdi + 32]",
    "    mov rbp, [rdi + 48]",
    "    mov r8,  [rdi + 56]",
    "    mov r9,  [rdi + 64]",
    "    mov r10, [rdi + 72]",
    "    mov r11, [rdi + 80]",
    "    mov r12, [rdi + 88]",
    "    mov r13, [rdi + 96]",
    "    mov r14, [rdi + 104]",
    "    mov r15, [rdi + 112]",
    // launched flag is at offset 120+8+1 = 129 in KernelVCpuState
    // (gprs[120] + vmcs[8] + idx[1] + launched)
    // Read launched into al.
    "    mov al, [rdi + 129]",
    "    test al, al",
    // Now load rax and rdi (the last GPRs we still needed for indexing).
    "    mov rax, [rdi]",
    "    mov rdi, [rdi + 40]",
    "    jne 4f",                  // launched != 0 → vmresume
    "    vmlaunch",
    "    jmp 3f",                  // vmlaunch falls through on failure
    "4:",
    "    vmresume",
    "3:",
    // post_vmlaunch — either vmlaunch/vmresume failed (immediate
    // fall-through) OR the trampoline `ret`ed back here on terminate.
    "    pop r15",
    "    pop r14",
    "    pop r13",
    "    pop r12",
    "    pop rbx",
    "    pop rbp",
    "    ret",
);

/// Run the given vCPU until it terminates.
///
/// Sets up the active VMCS, populates host state, and enters the
/// asm `vmx_run_inner` which executes `vmlaunch` (or `vmresume`).
/// Returns when the dispatcher in the asm trampoline decides to
/// terminate (HLT, unhandled exit, etc.).
///
/// **Caller must hold the vCPU as `&mut`** so the asm trampoline's
/// in-place mutation of `state.gprs` is sound.
pub fn vmx_run(state: &mut crate::vm::KernelVCpuState) -> Result<(), VmxError> {
    // Make this vCPU's VMCS the active one on this CPU. The first
    // vmptrld of a freshly-allocated VMCS must be preceded by vmclear.
    if !state.launched {
        vmcs_clear(&state.vmcs)?;
    }
    vmcs_load(&state.vmcs)?;

    // Populate host state with `vmx_exit_trampoline` as HOST_RIP.
    let exit_top = alloc_exit_stack_for_current_cpu()?;
    setup_host_state(
        state.vmcs.phys,
        exit_top - 8,
        vmx_exit_trampoline as *const () as u64,
    )?;

    // SAFETY: state is borrowed mutably for the duration of this call,
    // so the asm side has exclusive access. The trampoline finds it
    // via `gs:[104]` which we set inside `vmx_run_inner`.
    unsafe {
        vmx_run_inner(state as *mut _);
    }

    // Mark launched so the next call uses vmresume.
    state.launched = true;
    Ok(())
}
