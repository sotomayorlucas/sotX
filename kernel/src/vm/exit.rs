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

use super::{KernelVCpuState, VmIntrospectEvent};
use crate::arch::x86_64::vmx::{self, VMCS_GUEST_PHYSICAL_ADDRESS};
use crate::kprintln;
use crate::pool::PoolHandle;

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
const REASON_EXTERNAL_INTERRUPT: u16 = 1;
#[allow(dead_code)] const REASON_TRIPLE_FAULT: u16 = 2;
const REASON_CPUID: u16 = 10;
const REASON_HLT: u16 = 12;
#[allow(dead_code)] const REASON_INVLPG: u16 = 14;
const REASON_RDMSR: u16 = 31;
const REASON_WRMSR: u16 = 32;
#[allow(dead_code)] const REASON_VM_ENTRY_FAILURE_GUEST_STATE: u16 = 33;
const REASON_EPT_VIOLATION: u16 = 48;
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
    vm_handle: Option<PoolHandle>,
) -> ExitAction {
    let vmcs_phys = state.vmcs.phys;
    let reason = read_exit_reason(vmcs_phys);

    match reason {
        REASON_CPUID => handle_cpuid(state, profile, vmcs_phys, vm_handle),
        REASON_HLT => handle_hlt(state, vm_handle),
        REASON_RDMSR => handle_rdmsr(state, profile, vmcs_phys, vm_handle),
        REASON_WRMSR => handle_wrmsr(state, vmcs_phys, vm_handle),
        REASON_EXTERNAL_INTERRUPT => handle_external_interrupt(),
        REASON_EPT_VIOLATION => handle_ept_violation(state, vmcs_phys, vm_handle),
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

/// Convenience: push an introspection event into the parent VM's ring.
/// No-op if `vm_handle` is `None` (e.g. unit-test hot-path).
fn record(vm_handle: Option<PoolHandle>, event: VmIntrospectEvent) {
    if let Some(h) = vm_handle {
        super::push_introspect_event(h, event);
    }
}

fn handle_cpuid(
    state: &mut KernelVCpuState,
    profile: &super::deception::KernelDeceptionProfile,
    vmcs_phys: u64,
    vm_handle: Option<PoolHandle>,
) -> ExitAction {
    let leaf = state.gprs.rax as u32;
    let subleaf = state.gprs.rcx as u32;
    if let Some((eax, ebx, ecx, edx)) = profile.handle_cpuid(leaf, subleaf) {
        state.gprs.rax = eax as u64;
        state.gprs.rbx = ebx as u64;
        state.gprs.rcx = ecx as u64;
        state.gprs.rdx = edx as u64;
        // Phase C: spoofed CPUID exits go into the introspection ring
        // so the userspace caller can prove the kernel did the spoof
        // (rather than userspace's old in-process `handle_cpuid`).
        record(
            vm_handle,
            VmIntrospectEvent {
                kind: VmIntrospectEvent::KIND_CPUID,
                _pad: 0,
                a: ((subleaf as u64) << 32) | (leaf as u64),
                b: ((ebx as u64) << 32) | (eax as u64),
                c: ((edx as u64) << 32) | (ecx as u64),
                d: 0,
            },
        );
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

fn handle_hlt(state: &mut KernelVCpuState, vm_handle: Option<PoolHandle>) -> ExitAction {
    state.halted = true;
    record(
        vm_handle,
        VmIntrospectEvent {
            kind: VmIntrospectEvent::KIND_HLT,
            _pad: 0,
            a: 0,
            b: 0,
            c: 0,
            d: 0,
        },
    );
    ExitAction::Terminate
}

fn handle_rdmsr(
    state: &mut KernelVCpuState,
    profile: &super::deception::KernelDeceptionProfile,
    vmcs_phys: u64,
    vm_handle: Option<PoolHandle>,
) -> ExitAction {
    let msr = state.gprs.rcx as u32;
    if let Some(value) = profile.handle_msr_read(msr) {
        state.gprs.rax = value & 0xFFFF_FFFF;
        state.gprs.rdx = value >> 32;
        record(
            vm_handle,
            VmIntrospectEvent {
                kind: VmIntrospectEvent::KIND_RDMSR,
                _pad: 0,
                a: msr as u64,
                b: value,
                c: 0,
                d: 0,
            },
        );
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

/// Phase D — handle a guest EPT_VIOLATION (reason 48). The guest
/// touched a guest-physical page that has no leaf in the VM's EPT;
/// we lazily allocate a fresh host frame, install a 4 KiB leaf, and
/// `Resume` the guest. The dispatcher records the GPA + new HPA in
/// the introspection ring so userspace can verify the lazy-fault
/// counter at the end of the test.
///
/// Returns `Terminate` (and the vCPU bails out of the run loop) if
/// the per-VM `mem_pages_limit` budget is exhausted or the host
/// frame allocator is empty — those are unrecoverable for the
/// current guest.
fn handle_ept_violation(
    state: &mut KernelVCpuState,
    vmcs_phys: u64,
    vm_handle: Option<PoolHandle>,
) -> ExitAction {
    let gpa = match vmx::vmread(VMCS_GUEST_PHYSICAL_ADDRESS, vmcs_phys) {
        Ok(v) => v,
        Err(e) => {
            kprintln!("  vm/exit: ept_violation: vmread(GUEST_PA) failed: {:?}", e);
            return ExitAction::Terminate;
        }
    };
    let handle = match vm_handle {
        Some(h) => h,
        None => {
            kprintln!("  vm/exit: ept_violation with no active VM handle");
            return ExitAction::Terminate;
        }
    };
    match super::handle_ept_lazy_fault(handle, gpa) {
        Ok(()) => {
            // Look up the new mem_pages_used so the introspection
            // event records the post-alloc count (handy for the
            // Phase D test's "exactly N pages" assertion). Walking
            // the EPT to recover the host frame would be redundant
            // because we just installed it; we leave `b` as the GPA's
            // page-aligned value because that's the user-visible
            // address space.
            let pages = super::mem_pages_used(handle) as u64;
            super::push_introspect_event(
                handle,
                VmIntrospectEvent {
                    kind: VmIntrospectEvent::KIND_EPT_VIOLATION,
                    _pad: 0,
                    a: gpa & !0xFFF,
                    b: 0, // host phys is intentionally hidden from userspace
                    c: pages,
                    d: 0,
                },
            );
            let _ = state;
            ExitAction::Resume
        }
        Err(e) => {
            kprintln!(
                "  vm/exit: ept_violation lazy-fault failed at gpa={:#x}: {:?} — terminating",
                gpa,
                e
            );
            ExitAction::Terminate
        }
    }
}

/// Handle a host external-interrupt VM-exit (reason 1).
///
/// We set `PIN_BASED.EXTINT_EXIT` so the LAPIC timer (and any other
/// host interrupt) preempts the guest cleanly. The CPU did NOT
/// acknowledge the interrupt because we leave EXIT_CTLS bit 15
/// ("Acknowledge interrupt on exit") cleared, which means the host's
/// LAPIC still has the vector pending. Briefly enabling IF lets the
/// host IDT deliver it via the normal interrupt path; we then return
/// `Resume` so the trampoline `vmresume`s back into the guest at the
/// same RIP it was preempted on.
///
/// `sti; nop; cli` is the canonical "interrupt window" pattern: `sti`
/// has a one-instruction delay before interrupts can fire, the `nop`
/// is that one instruction, and `cli` re-disables IF before we return
/// to the dispatcher's caller. The pending vector — if there is one —
/// fires between the `nop` and the `cli`.
fn handle_external_interrupt() -> ExitAction {
    // SAFETY: only modifies the IF bit. The kernel exit-stack we are
    // running on is distinct from any thread's kernel stack and the
    // host IDT is loaded; an IRQ delivered through the IDT here is
    // identical to one taken from the kernel idle loop.
    unsafe {
        core::arch::asm!(
            "sti",
            "nop",
            "cli",
            options(nomem, nostack, preserves_flags),
        );
    }
    ExitAction::Resume
}

fn handle_wrmsr(
    state: &mut KernelVCpuState,
    vmcs_phys: u64,
    vm_handle: Option<PoolHandle>,
) -> ExitAction {
    let msr = state.gprs.rcx as u32;
    let value = (state.gprs.rax & 0xFFFF_FFFF) | (state.gprs.rdx << 32);
    // Phase B/C: silently swallow guest WRMSRs but record them for the
    // introspection ring. Real implementation in a later phase will
    // validate against an MSR write whitelist and either passthrough,
    // spoof, or inject #GP.
    record(
        vm_handle,
        VmIntrospectEvent {
            kind: VmIntrospectEvent::KIND_WRMSR,
            _pad: 0,
            a: msr as u64,
            b: value & 0xFFFF_FFFF,
            c: value >> 32,
            d: 0,
        },
    );
    advance_rip(vmcs_phys, INSN_LEN_WRMSR);
    ExitAction::Resume
}
