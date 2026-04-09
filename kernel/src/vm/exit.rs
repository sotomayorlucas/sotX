//! VM-exit dispatcher.
//!
//! Called from the asm exit trampoline (Phase B.5) on every VM-exit
//! with a mutable reference to the `KernelVCpuState` whose VMCS is
//! currently active. Reads `VM_EXIT_REASON` from the VMCS, dispatches
//! to the matching arm, mutates `state.gprs` for any spoofed values,
//! and returns an `ExitAction` telling the caller whether to VMRESUME
//! or terminate the vCPU.
//!
//! Phase B coverage:
//! - **CPUID** (reason 10): consult deception profile, write spoofed
//!   eax/ebx/ecx/edx into `state.gprs`, advance RIP past the cpuid
//!   instruction (2 bytes), VMRESUME.
//! - **HLT** (reason 12): mark `state.halted = true`, return
//!   `Terminate`. The vCPU thread exits the run loop.
//! - **RDMSR** (reason 31): consult deception profile; if spoofed,
//!   write the value into rax/rdx and advance RIP (2 bytes), VMRESUME.
//!   If not spoofed, inject #GP (Phase B.5+ TODO; for now Terminate).
//! - **WRMSR** (reason 32): silently swallow (no spoofing yet),
//!   advance RIP, VMRESUME.
//!
//! Anything else: log + Terminate. Phases B.4+ (host state) and the
//! Linux boot work in Phase F will fill in EPT_VIOLATION,
//! IO_INSTRUCTION, EXTERNAL_INTERRUPT, etc.

use super::KernelVCpuState;
use crate::arch::x86_64::vmx;
use crate::kprintln;

/// What the vCPU run loop should do after `dispatch` returns.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExitAction {
    /// Resume the guest with `vmresume`.
    Resume,
    /// Stop running this vCPU. The thread exits the run loop.
    Terminate,
}

// VM-exit reason encodings (Intel SDM Vol 3C Appendix C). Only the
// reasons we handle in Phase B are spelled out; the rest fall through
// to the catchall `Terminate` arm with a kprintln.

#[allow(dead_code)] const REASON_EXCEPTION_OR_NMI: u16 = 0;
#[allow(dead_code)] const REASON_EXTERNAL_INTERRUPT: u16 = 1;
#[allow(dead_code)] const REASON_TRIPLE_FAULT: u16 = 2;
const REASON_CPUID: u16 = 10;
const REASON_HLT: u16 = 12;
#[allow(dead_code)] const REASON_INVLPG: u16 = 14;
const REASON_RDMSR: u16 = 31;
const REASON_WRMSR: u16 = 32;
#[allow(dead_code)] const REASON_VM_ENTRY_FAILURE_GUEST_STATE: u16 = 33;
#[allow(dead_code)] const REASON_EPT_VIOLATION: u16 = 48;
#[allow(dead_code)] const REASON_EPT_MISCONFIG: u16 = 49;
#[allow(dead_code)] const REASON_IO_INSTRUCTION: u16 = 30;

/// VMCS field encodings we read inside the dispatcher. Imported from
/// the vmx module so the constants live in one place.
use crate::arch::x86_64::vmx::{
    VMCS_GUEST_RIP, VMCS_VM_EXIT_REASON,
};

/// Length of the `cpuid` and `rdmsr`/`wrmsr` instructions in bytes.
/// Used to advance GUEST_RIP past the trapping instruction so the next
/// VMRESUME doesn't immediately re-fault on the same `cpuid`.
const INSN_LEN_CPUID: u64 = 2;
const INSN_LEN_RDMSR: u64 = 2;
const INSN_LEN_WRMSR: u64 = 2;

/// Read VMCS exit reason. Bits [15:0] are the basic exit reason; bits
/// 31..28 hold flags we don't currently look at.
fn read_exit_reason(vmcs_phys: u64) -> u16 {
    match vmx::vmread(VMCS_VM_EXIT_REASON, vmcs_phys) {
        Ok(r) => (r & 0xFFFF) as u16,
        Err(e) => {
            kprintln!("  vm/exit: vmread(EXIT_REASON) failed: {:?}", e);
            0xFFFF
        }
    }
}

/// Advance `GUEST_RIP` by `bytes`. Used after handling instruction
/// exits like CPUID/RDMSR/WRMSR so the next VMRESUME picks up the
/// instruction *after* the trap.
fn advance_rip(vmcs_phys: u64, bytes: u64) {
    match vmx::vmread(VMCS_GUEST_RIP, vmcs_phys) {
        Ok(rip) => {
            if let Err(e) = vmx::vmwrite(VMCS_GUEST_RIP, rip + bytes, vmcs_phys) {
                kprintln!("  vm/exit: vmwrite(GUEST_RIP) failed: {:?}", e);
            }
        }
        Err(e) => kprintln!("  vm/exit: vmread(GUEST_RIP) failed: {:?}", e),
    }
}

/// Top-level dispatcher. Called from the asm exit trampoline (B.5)
/// with a mut ref to the vCPU state whose VMCS is currently active on
/// this CPU. The trampoline has already saved guest GPRs into
/// `state.gprs`; the dispatcher mutates them in place and the
/// trampoline reloads them into the CPU before VMRESUME.
///
/// `profile` is borrowed from the parent `VmObject`; the caller
/// resolves it once before this function so we don't re-lock the VM
/// pool inside the hot exit path.
pub fn dispatch(
    state: &mut KernelVCpuState,
    profile: &super::deception::KernelDeceptionProfile,
) -> ExitAction {
    kprintln!("  dispatch: enter");
    let vmcs_phys = state.vmcs.phys;
    let reason = read_exit_reason(vmcs_phys);
    kprintln!("  dispatch: reason={}", reason);

    match reason {
        REASON_CPUID => handle_cpuid(state, profile, vmcs_phys),
        REASON_HLT => handle_hlt(state),
        REASON_RDMSR => handle_rdmsr(state, profile, vmcs_phys),
        REASON_WRMSR => handle_wrmsr(state, vmcs_phys),
        other => {
            kprintln!(
                "  vm/exit: unhandled exit reason {} on vcpu {} — terminating",
                other,
                state.idx
            );
            ExitAction::Terminate
        }
    }
}

fn handle_cpuid(
    state: &mut KernelVCpuState,
    profile: &super::deception::KernelDeceptionProfile,
    vmcs_phys: u64,
) -> ExitAction {
    let leaf = state.gprs.rax as u32;
    let subleaf = state.gprs.rcx as u32;
    if let Some((eax, ebx, ecx, edx)) = profile.handle_cpuid(leaf, subleaf) {
        state.gprs.rax = eax as u64;
        state.gprs.rbx = ebx as u64;
        state.gprs.rcx = ecx as u64;
        state.gprs.rdx = edx as u64;
    } else {
        // Passthrough: execute cpuid on the host and return the real
        // values. Most leaves are passthrough; the deception profile
        // only overrides leaves 0, 1, and 0x40000000 by default.
        let r = core::arch::x86_64::__cpuid_count(leaf, subleaf);
        state.gprs.rax = r.eax as u64;
        state.gprs.rbx = r.ebx as u64;
        state.gprs.rcx = r.ecx as u64;
        state.gprs.rdx = r.edx as u64;
    }
    advance_rip(vmcs_phys, INSN_LEN_CPUID);
    ExitAction::Resume
}

fn handle_hlt(state: &mut KernelVCpuState) -> ExitAction {
    state.halted = true;
    ExitAction::Terminate
}

fn handle_rdmsr(
    state: &mut KernelVCpuState,
    profile: &super::deception::KernelDeceptionProfile,
    vmcs_phys: u64,
) -> ExitAction {
    let msr = state.gprs.rcx as u32;
    if let Some(value) = profile.handle_msr_read(msr) {
        state.gprs.rax = value & 0xFFFF_FFFF;
        state.gprs.rdx = value >> 32;
        advance_rip(vmcs_phys, INSN_LEN_RDMSR);
        ExitAction::Resume
    } else {
        // No spoof entry — terminate for now. Phase B.5+ will inject
        // #GP into the guest instead, matching real CPU semantics for
        // unsupported MSRs.
        kprintln!(
            "  vm/exit: unhandled rdmsr({:#x}) on vcpu {} — terminating",
            msr,
            state.idx
        );
        ExitAction::Terminate
    }
}

fn handle_wrmsr(state: &mut KernelVCpuState, vmcs_phys: u64) -> ExitAction {
    let msr = state.gprs.rcx as u32;
    let _value = (state.gprs.rax & 0xFFFF_FFFF) | (state.gprs.rdx << 32);
    // Phase B: silently swallow guest WRMSRs. Real implementation in
    // a later phase will validate against an MSR write whitelist and
    // either passthrough, spoof, or inject #GP.
    let _ = msr;
    advance_rip(vmcs_phys, INSN_LEN_WRMSR);
    ExitAction::Resume
}
