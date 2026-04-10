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

use super::devmodel::{self, IoAccess, IoDir, IoResult};
use super::{KernelVCpuState, VmIntrospectEvent};
use crate::arch::x86_64::vmx::{self, VMCS_EXIT_QUALIFICATION, VMCS_GUEST_PHYSICAL_ADDRESS};
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

const REASON_EXCEPTION_OR_NMI: u16 = 0;
const REASON_EXTERNAL_INTERRUPT: u16 = 1;
const REASON_TRIPLE_FAULT: u16 = 2;
const REASON_CPUID: u16 = 10;
const REASON_HLT: u16 = 12;
#[allow(dead_code)] const REASON_INVLPG: u16 = 14;
const REASON_IO_INSTRUCTION: u16 = 30;
const REASON_RDMSR: u16 = 31;
const REASON_WRMSR: u16 = 32;
#[allow(dead_code)] const REASON_VM_ENTRY_FAILURE_GUEST_STATE: u16 = 33;
const REASON_EPT_VIOLATION: u16 = 48;
#[allow(dead_code)] const REASON_EPT_MISCONFIG: u16 = 49;

/// VMCS field encodings we read inside the dispatcher. Imported from
/// the vmx module so the constants live in one place.
use crate::arch::x86_64::vmx::{
    VMCS_GUEST_CR0, VMCS_GUEST_CR3, VMCS_GUEST_CR4, VMCS_GUEST_CS_BASE,
    VMCS_GUEST_CS_SELECTOR, VMCS_GUEST_IA32_EFER, VMCS_GUEST_RFLAGS, VMCS_GUEST_RIP,
    VMCS_GUEST_RSP, VMCS_IDT_VECTORING_ERROR_CODE, VMCS_IDT_VECTORING_INFO_FIELD,
    VMCS_VM_EXIT_INTR_ERROR_CODE, VMCS_VM_EXIT_INTR_INFO, VMCS_VM_EXIT_REASON,
};

/// Length of the `cpuid` and `rdmsr`/`wrmsr` instructions in bytes.
/// Used to advance GUEST_RIP past the trapping instruction so the next
/// VMRESUME doesn't immediately re-fault on the same `cpuid`.
const INSN_LEN_CPUID: u64 = 2;
const INSN_LEN_RDMSR: u64 = 2;
const INSN_LEN_WRMSR: u64 = 2;

/// Read the VM-exit instruction length from VMCS field 0x440C. The
/// CPU populates this on every "instruction exit" reason (CPUID,
/// IO_INSTRUCTION, etc.) so we don't have to hard-code per-instruction
/// sizes for variable-length encodings like `out dx, al` (1 byte) vs
/// `in eax, dx` (1 byte) vs `outsb` (1 byte). For F.2's hand-crafted
/// payload all I/O instructions are 1 byte, but using the VMCS field
/// keeps the dispatcher correct for any future payload.
const VMCS_VM_EXIT_INSTRUCTION_LENGTH: u64 = 0x440C;

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
        REASON_IO_INSTRUCTION => handle_io_instruction(state, vmcs_phys, vm_handle),
        REASON_TRIPLE_FAULT => handle_triple_fault(state, vmcs_phys, vm_handle),
        REASON_EXCEPTION_OR_NMI => handle_exception_or_nmi(state, vmcs_phys, vm_handle),
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
        // values. Phase F.4 records these too so we can see what
        // leaves Linux is probing during boot. The kernel still
        // hides the hypervisor bit because the host CPUID we
        // execute happens INSIDE the L0 host where that bit is set;
        // for the leaf-1 ECX value we mask bit 31 explicitly.
        let r = core::arch::x86_64::__cpuid_count(leaf, subleaf);
        let mut ecx_out = r.ecx;
        if leaf == 1 {
            ecx_out &= !(1u32 << 31); // hide hypervisor bit
        }
        state.gprs.rax = r.eax as u64;
        state.gprs.rbx = r.ebx as u64;
        state.gprs.rcx = ecx_out as u64;
        state.gprs.rdx = r.edx as u64;
        record(
            vm_handle,
            VmIntrospectEvent {
                kind: VmIntrospectEvent::KIND_CPUID,
                _pad: 0,
                a: ((subleaf as u64) << 32) | (leaf as u64),
                b: ((r.ebx as u64) << 32) | (r.eax as u64),
                c: ((r.edx as u64) << 32) | (ecx_out as u64),
                d: 0,
            },
        );
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

    // F.5.4 — three-tier MSR read handling:
    //   1. spoof table (highest priority — deception profile)
    //   2. VMCS-backed MSRs (EFER / FS_BASE / GS_BASE etc. live in
    //      the VMCS guest area, return them directly so Linux sees
    //      what we just installed at VMENTER)
    //   3. fall through to 0 (instead of terminating) so Linux's
    //      probing of "is this MSR there?" doesn't kill the guest.
    //      Real impl will inject #GP per SDM, but for F.5 we just
    //      want Linux to make progress.
    let value: u64 = if let Some(v) = profile.handle_msr_read(msr) {
        v
    } else {
        match msr {
            // IA32_EFER — guest's saved EFER (this was the unblocker
            // for F.5 — Linux reads EFER very early in head_64.S to
            // confirm long mode is active before installing its high
            // half mapping).
            0xC000_0080 => vmx::vmread(vmx::VMCS_GUEST_IA32_EFER, vmcs_phys).unwrap_or(0),
            // FS_BASE
            0xC000_0100 => vmx::vmread(vmx::VMCS_GUEST_FS_BASE, vmcs_phys).unwrap_or(0),
            // GS_BASE
            0xC000_0101 => vmx::vmread(vmx::VMCS_GUEST_GS_BASE, vmcs_phys).unwrap_or(0),
            // KERNEL_GS_BASE — no dedicated VMCS field; the guest's
            // earlier WRMSR was silently swallowed so we just return
            // 0 until F.6 wires WRMSR-to-VMCS.
            0xC000_0102 => 0,
            // IA32_PAT — VMCS guest PAT
            0x0277 => vmx::vmread(vmx::VMCS_GUEST_IA32_PAT, vmcs_phys).unwrap_or(0),
            // IA32_APIC_BASE — fake "BSP, x2APIC disabled, APIC enabled,
            // physical address 0xFEE00000".
            0x001B => 0xFEE0_0900,
            // IA32_MTRRCAP — 8 variable MTRRs, fixed MTRRs supported,
            // write-combining supported.
            0x00FE => 0x0000_0508,
            // IA32_MTRR_DEF_TYPE — WB default, fixed MTRRs enabled,
            // MTRRs enabled.
            0x02FF => 0x0000_0C06,
            // Fixed MTRRs (0x250..0x26F): all WB.
            0x0250..=0x026F => 0x0606_0606_0606_0606,
            // Variable MTRR base/mask (0x200..0x20F): unmapped.
            0x0200..=0x020F => 0,
            // Anything else: return 0 instead of terminating.
            _ => 0,
        }
    };

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
    let rip = vmx::vmread(VMCS_GUEST_RIP, vmcs_phys).unwrap_or(0);
    match super::handle_ept_lazy_fault(handle, gpa) {
        Ok(()) => {
            // Look up the new mem_pages_used so the introspection
            // event records the post-alloc count (handy for the
            // Phase D test's "exactly N pages" assertion). Walking
            // the EPT to recover the host frame would be redundant
            // because we just installed it; we leave `b` as the
            // guest RIP at the time of the fault — useful for
            // userspace correlation in F.5+.
            let pages = super::mem_pages_used(handle) as u64;
            super::push_introspect_event(
                handle,
                VmIntrospectEvent {
                    kind: VmIntrospectEvent::KIND_EPT_VIOLATION,
                    _pad: 0,
                    a: gpa & !0xFFF,
                    b: rip,
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

/// Phase F.1 — handle a guest IN/OUT instruction trapped via
/// `PROC_BASED.UNCONDITIONAL_IO_EXIT` (reason 30).
///
/// The CPU populates `EXIT_QUALIFICATION` (Intel SDM Vol 3C 27.2.1
/// Table 27-5) with the decoded I/O access:
///
///   bits 0..2  Width-1 (0=1B, 1=2B, 3=4B)
///   bit  3     Direction (0 = OUT, 1 = IN)
///   bit  4     String op (INS/OUTS)        — Phase F.1 rejects
///   bit  5     REP prefix                  — Phase F.1 rejects
///   bit  6     Operand encoding            — 0=DX, 1=imm
///   bits 16..31 Port (16 bits)
///
/// On success the dispatcher writes any `IN` result back into
/// `state.gprs.rax` and advances `GUEST_RIP` by the VMCS-supplied
/// instruction length, then returns `Resume`.
fn handle_io_instruction(
    state: &mut KernelVCpuState,
    vmcs_phys: u64,
    vm_handle: Option<PoolHandle>,
) -> ExitAction {
    let qual = match vmx::vmread(VMCS_EXIT_QUALIFICATION, vmcs_phys) {
        Ok(v) => v,
        Err(e) => {
            kprintln!("  vm/exit: io: vmread(EXIT_QUAL) failed: {:?}", e);
            return ExitAction::Terminate;
        }
    };
    let insn_len = match vmx::vmread(VMCS_VM_EXIT_INSTRUCTION_LENGTH, vmcs_phys) {
        Ok(v) => v,
        Err(e) => {
            kprintln!("  vm/exit: io: vmread(INSN_LEN) failed: {:?}", e);
            return ExitAction::Terminate;
        }
    };

    let width = match (qual & 0x7) as u8 {
        0 => 1,
        1 => 2,
        3 => 4,
        _ => {
            kprintln!("  vm/exit: io: bad width encoding qual={:#x}", qual);
            return ExitAction::Terminate;
        }
    };
    let direction = if (qual >> 3) & 1 == 1 {
        IoDir::In
    } else {
        IoDir::Out
    };
    if (qual >> 4) & 1 == 1 || (qual >> 5) & 1 == 1 {
        kprintln!(
            "  vm/exit: io: string/REP not supported (qual={:#x}) — terminating",
            qual
        );
        return ExitAction::Terminate;
    }
    let port = ((qual >> 16) & 0xFFFF) as u16;
    let value = match width {
        1 => (state.gprs.rax & 0xFF) as u32,
        2 => (state.gprs.rax & 0xFFFF) as u32,
        4 => (state.gprs.rax & 0xFFFF_FFFF) as u32,
        _ => 0,
    };

    let access = IoAccess { port, width, direction, value };
    match devmodel::handle_io(state, vm_handle, access) {
        IoResult::Ok { value: read_value } => {
            if direction == IoDir::In {
                let mask = match width {
                    1 => 0xFFu64,
                    2 => 0xFFFFu64,
                    4 => 0xFFFF_FFFFu64,
                    _ => 0,
                };
                state.gprs.rax = (state.gprs.rax & !mask) | (read_value as u64 & mask);
            }
            advance_rip(vmcs_phys, insn_len);
            ExitAction::Resume
        }
        IoResult::Unhandled => {
            kprintln!(
                "  vm/exit: io: unhandled port={:#x} width={} dir={:?} value={:#x} — terminating",
                port,
                width,
                direction,
                value
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

/// Phase F.5 — handle a guest triple fault (exit reason 2). The CPU
/// has given up on the guest because three fault levels nested
/// (e.g. #PF -> #DF -> #TF). The IDT_VECTORING_INFO_FIELD VMCS slot
/// remembers the *original* exception that started the chain, which
/// is the most useful single number we can hand to userspace.
///
/// We snapshot every register that's likely to localize the failure
/// — RIP / CS / RFLAGS / RSP / CR0 / CR3 / CR4 / EFER plus the two
/// VECTORING_INFO fields — and emit them both to the kernel serial
/// log and to the introspection ring as `KIND_TRIPLE_FAULT`. The
/// vCPU run loop bails out via `Terminate`.
fn handle_triple_fault(
    state: &mut KernelVCpuState,
    vmcs_phys: u64,
    vm_handle: Option<PoolHandle>,
) -> ExitAction {
    // Helper: read a VMCS field, returning 0 on error so the dump
    // shows up even if one read fails. The whole point of this
    // handler is "don't lose any signal on the way down".
    let r = |field: u64| vmx::vmread(field, vmcs_phys).unwrap_or(0);

    let rip = r(VMCS_GUEST_RIP);
    let cs_sel = r(VMCS_GUEST_CS_SELECTOR);
    let cs_base = r(VMCS_GUEST_CS_BASE);
    let cr0 = r(VMCS_GUEST_CR0);
    let cr3 = r(VMCS_GUEST_CR3);
    let cr4 = r(VMCS_GUEST_CR4);
    let rflags = r(VMCS_GUEST_RFLAGS);
    let rsp = r(VMCS_GUEST_RSP);
    let efer = r(VMCS_GUEST_IA32_EFER);
    let idt_vec = r(VMCS_IDT_VECTORING_INFO_FIELD);
    let idt_err = r(VMCS_IDT_VECTORING_ERROR_CODE);
    let intr = r(VMCS_VM_EXIT_INTR_INFO);
    let intr_err = r(VMCS_VM_EXIT_INTR_ERROR_CODE);

    kprintln!("  vm/exit: TRIPLE_FAULT on vcpu {}", state.idx);
    kprintln!(
        "    rip={:#x} cs={:#x}/{:#x} rflags={:#x} rsp={:#x}",
        rip, cs_sel, cs_base, rflags, rsp
    );
    kprintln!(
        "    cr0={:#x} cr3={:#x} cr4={:#x} efer={:#x}",
        cr0, cr3, cr4, efer
    );
    kprintln!(
        "    idt_vec={:#x} idt_err={:#x} intr={:#x} intr_err={:#x}",
        idt_vec, idt_err, intr, intr_err
    );
    // F.5 — dump 32 bytes around RIP via EPT walk so we can disassemble
    // exactly what Linux was about to execute (or had just executed)
    // when the fault chain started. Skip if no vm_handle (e.g. unit test).
    if let Some(handle) = vm_handle {
        let mut buf = [0u8; 32];
        let n = super::vm_read_gpa(handle, rip & !0xFFF, &mut buf);
        if n > 0 {
            let off_in_page = (rip & 0xFFF) as usize;
            kprintln!("    bytes@page+{:#x}:", off_in_page);
            // Print 32 bytes from page start (so we have context).
            for chunk_idx in 0..(n / 16) {
                let base = chunk_idx * 16;
                kprintln!(
                    "      +{:04x}: {:02x}{:02x}{:02x}{:02x} {:02x}{:02x}{:02x}{:02x} {:02x}{:02x}{:02x}{:02x} {:02x}{:02x}{:02x}{:02x}",
                    base,
                    buf[base+0],  buf[base+1],  buf[base+2],  buf[base+3],
                    buf[base+4],  buf[base+5],  buf[base+6],  buf[base+7],
                    buf[base+8],  buf[base+9],  buf[base+10], buf[base+11],
                    buf[base+12], buf[base+13], buf[base+14], buf[base+15]
                );
            }
        } else {
            kprintln!("    rip page UNMAPPED in EPT");
        }
        // Also dump bytes AT the rip (and 16 before) for the exact
        // failing instruction.
        let mut around = [0u8; 32];
        let start = rip.saturating_sub(16);
        let n2 = super::vm_read_gpa(handle, start, &mut around);
        if n2 > 0 {
            kprintln!("    bytes around rip ({:#x}..):", start);
            for chunk_idx in 0..(n2 / 16) {
                let base = chunk_idx * 16;
                kprintln!(
                    "      {:#010x}: {:02x}{:02x}{:02x}{:02x} {:02x}{:02x}{:02x}{:02x} {:02x}{:02x}{:02x}{:02x} {:02x}{:02x}{:02x}{:02x}",
                    start + base as u64,
                    around[base+0],  around[base+1],  around[base+2],  around[base+3],
                    around[base+4],  around[base+5],  around[base+6],  around[base+7],
                    around[base+8],  around[base+9],  around[base+10], around[base+11],
                    around[base+12], around[base+13], around[base+14], around[base+15]
                );
            }
        }
    }

    record(
        vm_handle,
        VmIntrospectEvent {
            kind: VmIntrospectEvent::KIND_TRIPLE_FAULT,
            _pad: 0,
            a: rip,
            b: cs_sel,
            c: cr3,
            d: idt_vec,
        },
    );
    ExitAction::Terminate
}

/// Phase F.5 — handle a guest exception or NMI VM-exit (reason 0).
/// This fires for any vector in the VMCS exception bitmap (we don't
/// trap any specifically, so this only fires for things the CPU
/// thinks should always exit to root mode — typically a real
/// hardware NMI).
///
/// `VM_EXIT_INTR_INFO` (Intel SDM Vol 3C 25.9.2 Table 25-17) decodes
/// as:
///
///   bits  0..7   Vector
///   bits  8..10  Interruption type (3 = hardware exception, etc.)
///   bit   11     Error code valid
///   bit   31     Valid (1 if this VMCS field has meaningful data)
///
/// `EXIT_QUALIFICATION` carries CR2 for #PF (vector 14).
fn handle_exception_or_nmi(
    state: &mut KernelVCpuState,
    vmcs_phys: u64,
    vm_handle: Option<PoolHandle>,
) -> ExitAction {
    let r = |field: u64| vmx::vmread(field, vmcs_phys).unwrap_or(0);

    let intr = r(VMCS_VM_EXIT_INTR_INFO);
    let intr_err = r(VMCS_VM_EXIT_INTR_ERROR_CODE);
    let rip = r(VMCS_GUEST_RIP);
    let cr2 = r(VMCS_EXIT_QUALIFICATION); // #PF parks CR2 here

    let vector = (intr & 0xFF) as u8;
    let kind = ((intr >> 8) & 0x7) as u8;
    kprintln!(
        "  vm/exit: exception vec={} kind={} err={:#x} rip={:#x} qual={:#x} on vcpu {}",
        vector, kind, intr_err, rip, cr2, state.idx
    );

    record(
        vm_handle,
        VmIntrospectEvent {
            kind: VmIntrospectEvent::KIND_EXCEPTION,
            _pad: 0,
            a: vector as u64,
            b: intr_err,
            c: rip,
            d: cr2,
        },
    );
    ExitAction::Terminate
}
