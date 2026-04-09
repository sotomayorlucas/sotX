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
/// Layout matches the order the exit trampoline pushes / pops in
/// reverse — `rax` at offset 0 so the trampoline can use a small
/// constant offset to find each register.
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
pub struct KernelVCpuState {
    /// vCPU index inside the owning VM (0..vcpu_count).
    pub idx: u8,
    /// Backing VMCS region (4 KiB phys frame, revision id at offset 0).
    pub vmcs: VmcsRegion,
    /// Guest GPRs as of the last VM-exit. Updated by the exit trampoline
    /// before calling the Rust dispatcher; consumed by the dispatcher
    /// (e.g. CPUID writes spoofed values back here).
    pub gprs: GuestGprs,
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
