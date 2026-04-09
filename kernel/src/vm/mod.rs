//! Kernel-side VM object pool and vCPU state.
//!
//! This module owns the kernel data plane for the bhyve VT-x backend:
//! `VmObject` (one per guest), `KernelVCpuState` (one per vCPU thread),
//! and the deception profile that drives in-kernel CPUID/MSR spoofing
//! on every VM-exit.
//!
//! Userspace `personality/bsd/bhyve::VmDomain` is the *control plane*;
//! it speaks to this module via `SYS_VM_*` syscalls (Phase C). The
//! deception policy lives in the kernel for performance — Linux boot
//! issues hundreds of CPUIDs and tens of thousands of EPT violations,
//! and bouncing each one through userspace would be a context-switch
//! disaster (see plan critique).
//!
//! Phase B status: scaffolding only. No syscall surface yet (Phase C);
//! no EPT (Phase D); no IO-port emulation (Phase F). The CPUID and
//! RDMSR exit arms route through `KernelDeceptionProfile` and the HLT
//! exit terminates the vCPU.

pub mod deception;
pub mod exit;

use crate::arch::x86_64::vmx::{self, VmcsRegion, VmxError};
use crate::pool::{Pool, PoolHandle};
use deception::KernelDeceptionProfile;
use spin::Mutex;

/// Maximum simultaneous guest VMs the kernel supports. Static cap
/// because the `Pool<VmObject>` is statically sized to avoid an
/// allocator dependency for VM creation.
pub const MAX_VMS: usize = 16;

/// Maximum vCPUs per VM. Matches `personality/bsd/bhyve::VmDomain`.
pub const MAX_VCPUS_PER_VM: usize = 16;

/// Errors from the VM control plane. Translated to `SysError` at the
/// syscall boundary in Phase C.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VmObjError {
    /// `Pool<VmObject>` is full.
    PoolFull,
    /// VM id does not refer to a live `VmObject`.
    NotFound,
    /// `vcpu_count` was 0 or > `MAX_VCPUS_PER_VM`.
    BadVcpuCount,
    /// VMX backend reported an error during vCPU bringup.
    Vmx(VmxError),
}

impl From<VmxError> for VmObjError {
    fn from(e: VmxError) -> Self {
        Self::Vmx(e)
    }
}

/// Saved guest GPRs at the moment a VM-exit occurred. RSP is in the
/// VMCS (`GUEST_RSP`), not in this struct, since the CPU saves it
/// automatically. RIP is also in the VMCS (`GUEST_RIP`).
///
/// `#[repr(C)]` so the asm exit trampoline can index by fixed offset:
///   rax = +0, rbx = +8, rcx = +16, rdx = +24, rsi = +32, rdi = +40,
///   rbp = +48, r8 = +56, r9 = +64, r10 = +72, r11 = +80, r12 = +88,
///   r13 = +96, r14 = +104, r15 = +112. Total size 120 bytes.
///
/// `KernelVCpuState` puts `gprs` at offset 0 specifically so the
/// trampoline can do `mov [rdi + N], reg` with no extra base add.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct GuestGprs {
    pub rax: u64,
    pub rbx: u64,
    pub rcx: u64,
    pub rdx: u64,
    pub rsi: u64,
    pub rdi: u64,
    pub rbp: u64,
    pub r8: u64,
    pub r9: u64,
    pub r10: u64,
    pub r11: u64,
    pub r12: u64,
    pub r13: u64,
    pub r14: u64,
    pub r15: u64,
}

/// Per-vCPU kernel state. One per vCPU per VM.
///
/// **`#[repr(C)]` is load-bearing**: the asm exit trampoline reaches
/// into this struct via fixed offsets computed by `core::mem::offset_of!`
/// and `const` operands in the inline asm. Reordering fields here
/// silently breaks the trampoline.
#[repr(C)]
pub struct KernelVCpuState {
    /// `gprs` first so it's at offset 0 — the asm trampoline indexes
    /// into it as the hot path on every VM-exit, and a 0-offset save
    /// is one fewer add instruction per exit.
    pub gprs: GuestGprs,
    /// Backing VMCS region (4 KiB phys frame, revision id at offset 0).
    pub vmcs: VmcsRegion,
    /// vCPU index inside the owning VM (0..vcpu_count).
    pub idx: u8,
    /// Whether this vCPU has been launched at least once. The first
    /// entry uses `vmlaunch`; subsequent entries use `vmresume`.
    pub launched: bool,
    /// Set by the dispatcher when the guest executed HLT or otherwise
    /// terminated. The vCPU thread checks this after the dispatcher
    /// returns and exits the run loop.
    pub halted: bool,
}

impl KernelVCpuState {
    /// Allocate a fresh VMCS for this vCPU. Caller must subsequently
    /// `vmcs_clear` + `vmcs_load` it on whichever CPU will run this
    /// vCPU before populating fields.
    pub fn allocate(idx: u8) -> Result<Self, VmxError> {
        Ok(Self {
            idx,
            vmcs: VmcsRegion::allocate()?,
            gprs: GuestGprs::default(),
            launched: false,
            halted: false,
        })
    }

    /// Diagnostic accessor — read the backing VMCS phys for use in
    /// post-mortem `vmread` calls (e.g. VM_INSTRUCTION_ERROR after a
    /// vmlaunch failure).
    pub fn vcps_phys_for_diag(&self) -> u64 {
        self.vmcs.phys
    }
}

/// One guest VM. Owns its vCPUs and the deception profile that drives
/// CPUID / MSR spoofing on every exit.
pub struct VmObject {
    pub id: u32,
    pub vcpu_count: u8,
    pub vcpus: [Option<KernelVCpuState>; MAX_VCPUS_PER_VM],
    pub profile: KernelDeceptionProfile,
    pub mem_pages_used: u32,
    pub mem_pages_limit: u32,
    /// Once set, the run loop will not re-enter the guest. Used by
    /// `destroy()` and by terminal exits (triple fault, etc.).
    pub destroyed: bool,
}

impl VmObject {
    /// Construct a new VM with `vcpu_count` vCPUs and a budget of
    /// `mem_pages_limit` 4 KiB physical pages. Each vCPU gets a
    /// freshly-allocated VMCS region.
    pub fn create(
        id: u32,
        vcpu_count: u8,
        mem_pages_limit: u32,
    ) -> Result<Self, VmObjError> {
        if vcpu_count == 0 || vcpu_count as usize > MAX_VCPUS_PER_VM {
            return Err(VmObjError::BadVcpuCount);
        }
        const NONE_VCPU: Option<KernelVCpuState> = None;
        let mut vcpus = [NONE_VCPU; MAX_VCPUS_PER_VM];
        for i in 0..vcpu_count as usize {
            vcpus[i] = Some(KernelVCpuState::allocate(i as u8)?);
        }
        Ok(Self {
            id,
            vcpu_count,
            vcpus,
            profile: KernelDeceptionProfile::bare_metal_intel(),
            mem_pages_used: 0,
            mem_pages_limit,
            destroyed: false,
        })
    }

    /// Borrow a vCPU mutably by index.
    pub fn vcpu_mut(&mut self, idx: u8) -> Option<&mut KernelVCpuState> {
        self.vcpus.get_mut(idx as usize)?.as_mut()
    }
}

/// Monotonic VM id counter, separate from pool slot indices so the
/// caller-visible id is stable across slot recycling. KARL-randomised
/// in Phase C; for Phase B it's a plain counter starting at 1.
static NEXT_VM_ID: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(1);

/// Global pool of all live VMs. `Mutex` because creation/destruction
/// is rare and the per-VM hot path holds direct references rather than
/// re-locking. (Phase C will revisit if contention shows up.)
static VM_POOL: Mutex<Pool<VmObject>> = Mutex::new(Pool::new());

/// Initialise the VM subsystem. Called once from `kmain` after
/// `vmx::init_bsp`. Currently a no-op since `Pool::new()` is `const`,
/// but kept as the integration point for any future setup.
pub fn init() {
    // Pool is already initialised at static-init time. Nothing to do
    // for Phase B; Phase C will register VM-related syscalls here.
}

/// Create a new VM. Returns an opaque pool handle on success; the
/// handle is later passed to `vcpu_thread_entry` (Phase B.5) and to
/// the syscall layer (Phase C).
pub fn create_vm(vcpu_count: u8, mem_pages_limit: u32) -> Result<PoolHandle, VmObjError> {
    if !vmx::cpu_has_vmx() {
        return Err(VmObjError::Vmx(VmxError::NotSupported));
    }
    let id = NEXT_VM_ID.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
    let vm = VmObject::create(id, vcpu_count, mem_pages_limit)?;
    let mut pool = VM_POOL.lock();
    Ok(pool.alloc(vm))
}

/// Destroy a VM by handle. Marks it `destroyed` and frees the slot.
/// vCPU threads (when they exist in B.5) check `destroyed` after each
/// exit and bail out of the run loop.
#[allow(dead_code)]
pub fn destroy_vm(handle: PoolHandle) -> Result<(), VmObjError> {
    let mut pool = VM_POOL.lock();
    let vm = pool.get_mut(handle).ok_or(VmObjError::NotFound)?;
    vm.destroyed = true;
    pool.free(handle);
    Ok(())
}

// ---------------------------------------------------------------------------
// Per-CPU "currently-dispatching VM" tracker
// ---------------------------------------------------------------------------
//
// The asm exit trampoline has a `&mut KernelVCpuState` (via `gs:[104]`),
// but the dispatcher also needs the parent VM's deception profile.
// Threading the profile through is tricky because the dispatcher is
// entered from asm. Cleanest solution: stash the *VM handle* in a
// per-CPU slot before calling `vmx::vmx_run`, read it from the
// dispatcher, and look up the profile via the VM_POOL.
//
// We can't put another field on PerCpu (the offset would conflict
// with the existing `current_vcpu_state` at 104), so we use a
// separate per-CPU array indexed by `cpu_index`.

use sotos_common::MAX_CPUS;

static CURRENT_VM: [core::sync::atomic::AtomicU32; MAX_CPUS] = {
    const ZERO: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);
    [ZERO; MAX_CPUS]
};

// We store `handle.raw() + 1` so that the value 0 unambiguously means
// "no active VM". Without this offset, the first allocated VM (slot 0,
// generation 0 → raw == 0) would collide with the empty sentinel and
// the dispatcher would think there's no active VM.

/// Set the active VM handle for this CPU before entering `vmx::vmx_run`.
fn set_current_vm(handle: PoolHandle) {
    let cpu = crate::arch::x86_64::percpu::current_percpu().cpu_index as usize;
    CURRENT_VM[cpu].store(
        handle.raw().wrapping_add(1),
        core::sync::atomic::Ordering::Release,
    );
}

/// Clear the active VM handle for this CPU after the run loop exits.
fn clear_current_vm() {
    let cpu = crate::arch::x86_64::percpu::current_percpu().cpu_index as usize;
    CURRENT_VM[cpu].store(0, core::sync::atomic::Ordering::Release);
}

/// Read the active VM handle for this CPU. Called from
/// `vm_exit_handler_rust` to find which VM's profile to dispatch with.
pub fn current_vm_for_dispatch() -> Option<PoolHandle> {
    let cpu = crate::arch::x86_64::percpu::current_percpu().cpu_index as usize;
    let stored = CURRENT_VM[cpu].load(core::sync::atomic::Ordering::Acquire);
    if stored == 0 {
        None
    } else {
        Some(PoolHandle::from_raw(stored - 1))
    }
}

/// Look up a VM's deception profile by handle. Returns a copy so the
/// caller doesn't need to hold the VM_POOL lock across the dispatcher.
/// Returns the default `bare_metal_intel` profile if the handle is
/// stale (defensive — should never happen in normal operation).
pub fn profile_for(handle: PoolHandle) -> deception::KernelDeceptionProfile {
    let pool = VM_POOL.lock();
    pool.get(handle)
        .map(|vm| vm.profile)
        .unwrap_or_else(deception::KernelDeceptionProfile::bare_metal_intel)
}

// ---------------------------------------------------------------------------
// Phase B test path — create a VM, run a tiny `cpuid; hlt` payload,
// observe the spoofed CPUID, terminate cleanly.
// ---------------------------------------------------------------------------

use crate::arch::x86_64::vmx::MiniEpt;

/// Hand-assembled `mov eax, 1; cpuid; hlt` payload (8 bytes).
///
/// On entry the guest CR0.PE=1 / PG=0, flat 32-bit segments, RIP at
/// the start of these bytes. Executes:
///   B8 01 00 00 00   mov eax, 1
///   0F A2            cpuid       ← VM-exit (reason 10), profile spoof fires
///   F4               hlt         ← VM-exit (reason 12), state.halted = true
const TEST_PAYLOAD: [u8; 8] = [
    0xB8, 0x01, 0x00, 0x00, 0x00, // mov eax, 1
    0x0F, 0xA2, // cpuid
    0xF4, // hlt
];

/// Phase B end-to-end test. Allocates a VM, builds an EPT mapping
/// from GPA 0x1000 to a host frame containing `TEST_PAYLOAD`, sets
/// up host/guest/control state, and calls `vmx::vmx_run`.
///
/// Expected sequence:
///   1. `vmlaunch` enters guest at GPA 0x1000
///   2. `mov eax, 1` executes (no exit)
///   3. `cpuid` traps → exit reason 10 → dispatcher writes spoofed
///      Cascade Lake values from `bare_metal_intel`
///   4. `vmresume` reloads guest GPRs, advances RIP +2, resumes
///   5. `hlt` traps → exit reason 12 → dispatcher sets `state.halted`
///   6. Trampoline `ret`s back to `vmx_run`
///
/// On success, prints
///   `vmx-test: guest CPUID spoofed, HLT exit caught, vCPU terminated cleanly`
/// On failure, prints the `VmxError` and continues.
pub fn run_phase_b_test() {
    if !vmx::cpu_has_vmx() {
        return;
    }
    if let Err(e) = run_phase_b_test_inner() {
        crate::kprintln!("  vmx-test: FAILED: {:?}", e);
    }
}

fn run_phase_b_test_inner() -> Result<(), VmObjError> {
    // 1. Allocate the test VM.
    let vm_handle = create_vm(1, 16)?;

    // 2. Allocate a host frame for the payload, copy the bytes in.
    let payload_frame =
        crate::mm::alloc_frame().ok_or(VmObjError::Vmx(VmxError::OutOfFrames))?;
    let payload_phys = payload_frame.addr();
    let payload_virt = payload_phys + crate::mm::hhdm_offset();
    // SAFETY: freshly-allocated frame, HHDM-mapped writable.
    unsafe {
        core::ptr::copy_nonoverlapping(TEST_PAYLOAD.as_ptr(), payload_virt as *mut u8, TEST_PAYLOAD.len());
    }

    // 3. Allocate a stack frame at GPA 0x2000 (separate from code).
    let stack_frame =
        crate::mm::alloc_frame().ok_or(VmObjError::Vmx(VmxError::OutOfFrames))?;

    // 4. KVM nested-VMX forces the guest to run in 64-bit mode. That
    //    requires CR0.PG=1, so we need a guest page table that maps
    //    the payload + stack into the guest virtual address space.
    //    Allocate 3 frames for a minimal 4-level table that uses a
    //    single 2 MiB leaf to identity-map guest virt 0..2 MiB →
    //    guest phys 0..2 MiB:
    //      PML4[0] -> PDPT
    //      PDPT[0] -> PD
    //      PD[0]   -> 2 MiB leaf at GPA 0
    let pml4_frame = crate::mm::alloc_frame().ok_or(VmObjError::Vmx(VmxError::OutOfFrames))?;
    let pdpt_frame = crate::mm::alloc_frame().ok_or(VmObjError::Vmx(VmxError::OutOfFrames))?;
    let pd_frame = crate::mm::alloc_frame().ok_or(VmObjError::Vmx(VmxError::OutOfFrames))?;
    let pml4_phys = pml4_frame.addr();
    let pdpt_phys = pdpt_frame.addr();
    let pd_phys = pd_frame.addr();
    let hhdm = crate::mm::hhdm_offset();
    // SAFETY: each frame is freshly allocated, HHDM-mapped writable,
    // not aliased. We zero them and write one entry per page.
    //
    // Guest PT entry flags: P=1 W=1 = 0x3.
    // PD entry with PS=1 (2 MiB leaf): P=1 W=1 PS=1 = 0x83.
    unsafe {
        core::ptr::write_bytes((pml4_phys + hhdm) as *mut u8, 0, 4096);
        core::ptr::write_bytes((pdpt_phys + hhdm) as *mut u8, 0, 4096);
        core::ptr::write_bytes((pd_phys + hhdm) as *mut u8, 0, 4096);
        // GUEST page table entries use GUEST physical addresses. Since
        // EPT is identity-mapped over 0..2 MiB, GPA = HPA for these.
        // BUT — pml4/pdpt/pd are at HPAs that may be outside 0..2 MiB,
        // so we need DIFFERENT GPAs for them and let EPT translate.
        //
        // Use this scheme:
        //   GPA 0x1000 = payload (host frame `payload_phys`)
        //   GPA 0x2000 = stack   (host frame `stack_frame.addr()`)
        //   GPA 0x10000 = pml4   (host frame `pml4_phys`)
        //   GPA 0x11000 = pdpt   (host frame `pdpt_phys`)
        //   GPA 0x12000 = pd     (host frame `pd_phys`)
        // Guest CR3 = GPA 0x10000 = pml4's guest physical.
        //
        // Then PML4[0] holds GPA 0x11000 (pdpt's GPA), PDPT[0] holds
        // GPA 0x12000 (pd's GPA), PD[0] holds GPA 0 with PS=1
        // (2 MiB leaf mapping guest virt 0..2 MiB to guest phys 0..2 MiB).
        *((pml4_phys + hhdm) as *mut u64) = 0x11000 | 0x3;
        *((pdpt_phys + hhdm) as *mut u64) = 0x12000 | 0x3;
        *((pd_phys + hhdm) as *mut u64) = 0x0 | 0x83;
    }

    // 5. Build the minimal EPT and map all 5 GPAs into it.
    let ept = MiniEpt::allocate().map_err(VmObjError::Vmx)?;
    ept.map_4k(0x1000, payload_phys).map_err(VmObjError::Vmx)?;
    ept.map_4k(0x2000, stack_frame.addr()).map_err(VmObjError::Vmx)?;
    ept.map_4k(0x10000, pml4_phys).map_err(VmObjError::Vmx)?;
    ept.map_4k(0x11000, pdpt_phys).map_err(VmObjError::Vmx)?;
    ept.map_4k(0x12000, pd_phys).map_err(VmObjError::Vmx)?;

    // 6. Configure the vCPU's VMCS and run.
    set_current_vm(vm_handle);
    let result = run_one_vcpu(vm_handle, &ept);
    clear_current_vm();

    // 6. Inspect the result and print the milestone marker.
    match result {
        Ok(()) => {
            // Look up the vCPU again to read state.halted.
            let halted = {
                let mut pool = VM_POOL.lock();
                pool.get_mut(vm_handle)
                    .and_then(|vm| vm.vcpu_mut(0))
                    .map(|v| v.halted)
                    .unwrap_or(false)
            };
            if halted {
                crate::kprintln!(
                    "  vmx-test: guest CPUID spoofed, HLT exit caught, vCPU terminated cleanly"
                );
            } else {
                // Try to read VM-instruction-error from the VMCS so we
                // know what entry check failed. The VMCS may not still
                // be the active one on this CPU; vmread will return
                // VmFailInvalid in that case.
                let mut pool = VM_POOL.lock();
                let vmcs_phys = pool
                    .get_mut(vm_handle)
                    .and_then(|vm| vm.vcpu_mut(0))
                    .map(|v| v.vcps_phys_for_diag())
                    .unwrap_or(0);
                drop(pool);
                let err = vmx::vmread(vmx::VMCS_VM_INSTRUCTION_ERROR, vmcs_phys);
                crate::kprintln!(
                    "  vmx-test: vmx_run returned but vCPU not halted; vm_instruction_error={:?}",
                    err
                );
                // Post-run field dump so we can see whether the controls
                // and host state survived the vmx_run path.
                let pin = vmx::vmread(vmx::VMCS_PIN_BASED_CTLS, vmcs_phys);
                let p1 = vmx::vmread(vmx::VMCS_PROC_BASED_CTLS, vmcs_phys);
                let p2 = vmx::vmread(vmx::VMCS_PROC_BASED_CTLS2, vmcs_phys);
                let h_cr0 = vmx::vmread(vmx::VMCS_HOST_CR0, vmcs_phys);
                let h_cr3 = vmx::vmread(vmx::VMCS_HOST_CR3, vmcs_phys);
                let h_cr4 = vmx::vmread(vmx::VMCS_HOST_CR4, vmcs_phys);
                let h_rip = vmx::vmread(vmx::VMCS_HOST_RIP, vmcs_phys);
                let g_cr0 = vmx::vmread(vmx::VMCS_GUEST_CR0, vmcs_phys);
                let g_rip = vmx::vmread(vmx::VMCS_GUEST_RIP, vmcs_phys);
                crate::kprintln!(
                    "  vmx-test POST: pin={:?} p1={:?} p2={:?} hcr0={:?} hcr3={:?} hcr4={:?} hrip={:?} gcr0={:?} grip={:?}",
                    pin, p1, p2, h_cr0, h_cr3, h_cr4, h_rip, g_cr0, g_rip
                );
            }
        }
        Err(e) => {
            crate::kprintln!("  vmx-test: vmx_run error: {:?}", e);
        }
    }

    let _ = destroy_vm(vm_handle);
    Ok(())
}

fn run_one_vcpu(vm_handle: PoolHandle, ept: &MiniEpt) -> Result<(), VmxError> {
    let mut pool = VM_POOL.lock();
    let vm = pool.get_mut(vm_handle).ok_or(VmxError::VmFailInvalid)?;
    let vcpu = vm.vcpu_mut(0).ok_or(VmxError::VmFailInvalid)?;
    let vmcs_phys = vcpu.vmcs.phys;

    // Initial VMCS setup: clear, load, controls, EPTP, guest state.
    // Guest CR3 = GPA 0x10000 (the PML4's guest-physical address as
    // mapped via EPT in `run_phase_b_test_inner`).
    vmx::vmcs_clear(&vcpu.vmcs)?;
    vmx::vmcs_load(&vcpu.vmcs)?;
    vmx::setup_controls(vmcs_phys)?;
    vmx::vmwrite(vmx::VMCS_EPTP, ept.eptp(), vmcs_phys)?;
    vmx::setup_guest_state(vmcs_phys, 0x1000, 0x2FF0, 0x10000)?;

    // Diagnostic: read back the control fields the CPU actually accepted.
    // VM-instruction-error 7 ("invalid control field") means one of these
    // is bad — printing them lets us identify which on the next boot.
    let pin = vmx::vmread(vmx::VMCS_PIN_BASED_CTLS, vmcs_phys);
    let p1 = vmx::vmread(vmx::VMCS_PROC_BASED_CTLS, vmcs_phys);
    let p2 = vmx::vmread(vmx::VMCS_PROC_BASED_CTLS2, vmcs_phys);
    let exit = vmx::vmread(vmx::VMCS_EXIT_CTLS, vmcs_phys);
    let entry = vmx::vmread(vmx::VMCS_ENTRY_CTLS, vmcs_phys);
    let eptp = vmx::vmread(vmx::VMCS_EPTP, vmcs_phys);
    crate::kprintln!(
        "  vmx-test: pin={:?} proc1={:?} proc2={:?} exit={:?} entry={:?} eptp={:?}",
        pin,
        p1,
        p2,
        exit,
        entry,
        eptp
    );

    // Comprehensive dump of fields that could be the source of error 7.
    // Read the bitmap addresses, the control-related fields, and the
    // host CR0/CR3/CR4 to verify they round-trip correctly.
    let msr_bm = vmx::vmread(vmx::VMCS_MSR_BITMAP, vmcs_phys);
    let io_a = vmx::vmread(vmx::VMCS_IO_BITMAP_A, vmcs_phys);
    let io_b = vmx::vmread(vmx::VMCS_IO_BITMAP_B, vmcs_phys);
    let vapic = vmx::vmread(vmx::VMCS_VIRT_APIC_ADDR, vmcs_phys);
    let tpr_thr = vmx::vmread(vmx::VMCS_TPR_THRESHOLD, vmcs_phys);
    let vpid = vmx::vmread(vmx::VMCS_VPID, vmcs_phys);
    let link = vmx::vmread(vmx::VMCS_VMCS_LINK_POINTER, vmcs_phys);
    crate::kprintln!(
        "  vmx-test: msr_bm={:?} io_a={:?} io_b={:?} vapic={:?} tpr={:?} vpid={:?} link={:?}",
        msr_bm,
        io_a,
        io_b,
        vapic,
        tpr_thr,
        vpid,
        link
    );

    let h_cr0 = vmx::vmread(vmx::VMCS_HOST_CR0, vmcs_phys);
    let h_cr3 = vmx::vmread(vmx::VMCS_HOST_CR3, vmcs_phys);
    let h_cr4 = vmx::vmread(vmx::VMCS_HOST_CR4, vmcs_phys);
    let h_rsp = vmx::vmread(vmx::VMCS_HOST_RSP, vmcs_phys);
    let h_rip = vmx::vmread(vmx::VMCS_HOST_RIP, vmcs_phys);
    let h_efer = vmx::vmread(vmx::VMCS_HOST_IA32_EFER, vmcs_phys);
    let h_pat = vmx::vmread(vmx::VMCS_HOST_IA32_PAT, vmcs_phys);
    crate::kprintln!(
        "  vmx-test: host cr0={:?} cr3={:?} cr4={:?} rsp={:?} rip={:?} efer={:?} pat={:?}",
        h_cr0,
        h_cr3,
        h_cr4,
        h_rsp,
        h_rip,
        h_efer,
        h_pat
    );

    let g_cr0 = vmx::vmread(vmx::VMCS_GUEST_CR0, vmcs_phys);
    let g_cr3 = vmx::vmread(vmx::VMCS_GUEST_CR3, vmcs_phys);
    let g_cr4 = vmx::vmread(vmx::VMCS_GUEST_CR4, vmcs_phys);
    let g_rip = vmx::vmread(vmx::VMCS_GUEST_RIP, vmcs_phys);
    let g_rsp = vmx::vmread(vmx::VMCS_GUEST_RSP, vmcs_phys);
    let g_rfl = vmx::vmread(vmx::VMCS_GUEST_RFLAGS, vmcs_phys);
    let g_efer = vmx::vmread(vmx::VMCS_GUEST_IA32_EFER, vmcs_phys);
    crate::kprintln!(
        "  vmx-test: guest cr0={:?} cr3={:?} cr4={:?} rip={:?} rsp={:?} rfl={:?} efer={:?}",
        g_cr0,
        g_cr3,
        g_cr4,
        g_rip,
        g_rsp,
        g_rfl,
        g_efer
    );

    let g_cs_sel = vmx::vmread(vmx::VMCS_GUEST_CS_SELECTOR, vmcs_phys);
    let g_cs_ar = vmx::vmread(vmx::VMCS_GUEST_CS_ACCESS_RIGHTS, vmcs_phys);
    let g_tr_ar = vmx::vmread(vmx::VMCS_GUEST_TR_ACCESS_RIGHTS, vmcs_phys);
    let g_ldtr_ar = vmx::vmread(vmx::VMCS_GUEST_LDTR_ACCESS_RIGHTS, vmcs_phys);
    crate::kprintln!(
        "  vmx-test: guest cs_sel={:?} cs_ar={:?} tr_ar={:?} ldtr_ar={:?}",
        g_cs_sel,
        g_cs_ar,
        g_tr_ar,
        g_ldtr_ar
    );

    // Drop the pool lock before entering the VMX hot path — vmx_run
    // calls back into the dispatcher which re-locks the pool.
    drop(pool);

    // Re-borrow the vCPU mutably for vmx_run. We can't keep the pool
    // lock because the asm dispatcher needs to lock it too. This is
    // safe in Phase B because there's only one VM and one caller.
    let mut pool = VM_POOL.lock();
    let vm = pool.get_mut(vm_handle).ok_or(VmxError::VmFailInvalid)?;
    let vcpu = vm.vcpu_mut(0).ok_or(VmxError::VmFailInvalid)?;
    let vcpu_ptr = vcpu as *mut KernelVCpuState;
    drop(pool);

    // SAFETY: Phase B has a single VM and serial execution; nothing
    // else holds a reference to this vCPU.
    unsafe {
        let state = &mut *vcpu_ptr;
        vmx::vmx_run(state)
    }
}

