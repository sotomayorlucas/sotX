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
