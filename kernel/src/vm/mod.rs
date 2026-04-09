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
pub mod devmodel;
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

/// Capacity of the per-VM introspection ring. Sized for the Phase B/C
/// `cpuid; hlt` test (only a handful of events) plus headroom for the
/// Phase F Linux boot's hot-path of CPUID / RDMSR / WRMSR exits.
pub const INTROSPECT_RING_CAP: usize = 256;

/// One introspection event captured by the kernel exit dispatcher.
/// Mirrors the userspace `sotos_common::VmIntrospectEvent` layout.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct VmIntrospectEvent {
    pub kind: u32,
    pub _pad: u32,
    pub a: u64,
    pub b: u64,
    pub c: u64,
    pub d: u64,
}

impl VmIntrospectEvent {
    pub const KIND_CPUID: u32 = 1;
    pub const KIND_RDMSR: u32 = 2;
    pub const KIND_WRMSR: u32 = 3;
    pub const KIND_HLT: u32 = 4;
    /// Phase D: lazy EPT fault. `a` = guest physical address (page
    /// aligned), `b` = host physical address backing it after the
    /// alloc, `c` = post-fault `mem_pages_used`.
    pub const KIND_EPT_VIOLATION: u32 = 5;
    /// Phase F: guest OUT instruction trapped via UNCONDITIONAL_IO_EXIT.
    /// `a` = port, `b` = width (1/2/4), `c` = value written, `d` = 0.
    pub const KIND_IO_OUT: u32 = 6;
    /// Phase F: guest IN instruction. `a` = port, `b` = width,
    /// `c` = 0, `d` = value the dispatcher returned to the guest.
    pub const KIND_IO_IN: u32 = 7;
}

/// Lock-free SPSC ring of introspection events. Single producer is the
/// vCPU thread inside `vm::exit::dispatch`; single consumer is whoever
/// calls `SYS_VM_INTROSPECT_DRAIN`.
///
/// Phase C runs everything serially on the BSP so a plain head/tail
/// `usize` pair behind the parent VM's pool lock is enough; Phase F
/// will replace this with a real lock-free ring once vCPU threads run
/// concurrently with the userspace drainer.
pub struct IntrospectRing {
    pub events: [VmIntrospectEvent; INTROSPECT_RING_CAP],
    pub head: usize,
    pub tail: usize,
    /// Lifetime count of pushes (including drops on overflow). Useful
    /// for the Tier 4 demo's "we observed N CPUIDs" assertion when the
    /// ring would otherwise wrap.
    pub total_pushed: u64,
}

impl IntrospectRing {
    pub const fn new() -> Self {
        const ZERO: VmIntrospectEvent = VmIntrospectEvent {
            kind: 0, _pad: 0, a: 0, b: 0, c: 0, d: 0,
        };
        Self {
            events: [ZERO; INTROSPECT_RING_CAP],
            head: 0,
            tail: 0,
            total_pushed: 0,
        }
    }

    /// Push an event. Drops the oldest entry on overflow (and bumps
    /// `total_pushed` regardless, so consumers can detect drops).
    pub fn push(&mut self, ev: VmIntrospectEvent) {
        self.events[self.head] = ev;
        self.head = (self.head + 1) % INTROSPECT_RING_CAP;
        if self.head == self.tail {
            // Overflow — drop oldest.
            self.tail = (self.tail + 1) % INTROSPECT_RING_CAP;
        }
        self.total_pushed = self.total_pushed.wrapping_add(1);
    }

    /// Pop the oldest event, or `None` if the ring is empty.
    pub fn pop(&mut self) -> Option<VmIntrospectEvent> {
        if self.head == self.tail {
            return None;
        }
        let ev = self.events[self.tail];
        self.tail = (self.tail + 1) % INTROSPECT_RING_CAP;
        Some(ev)
    }

    /// Drain at most `out.len()` events into `out`, returning N written.
    pub fn drain_into(&mut self, out: &mut [VmIntrospectEvent]) -> usize {
        let mut n = 0;
        while n < out.len() {
            match self.pop() {
                Some(ev) => {
                    out[n] = ev;
                    n += 1;
                }
                None => break,
            }
        }
        n
    }
}

/// One guest VM. Owns its vCPUs and the deception profile that drives
/// CPUID / MSR spoofing on every exit.
pub struct VmObject {
    pub id: u32,
    pub vcpu_count: u8,
    pub vcpus: [Option<KernelVCpuState>; MAX_VCPUS_PER_VM],
    pub profile: KernelDeceptionProfile,
    /// Number of host frames currently backing this VM's guest memory.
    /// Incremented by `vm::exit::handle_ept_violation` on each lazy
    /// fault, decremented (well, dropped wholesale) when the VM is
    /// destroyed and `leaf_frames` is freed.
    pub mem_pages_used: u32,
    pub mem_pages_limit: u32,
    /// Once set, the run loop will not re-enter the guest. Used by
    /// `destroy()` and by terminal exits (triple fault, etc.).
    pub destroyed: bool,
    /// Per-VM introspection ring. Filled by `vm::exit::dispatch`,
    /// drained by userspace via `SYS_VM_INTROSPECT_DRAIN`.
    pub introspect: IntrospectRing,
    /// Phase D — real EPT root. Allocated lazily on the first
    /// `vm_run` call so VMs that never run don't waste a PML4 frame.
    pub ept_root: Option<crate::arch::x86_64::ept::EptRoot>,
    /// Host physical frames the EPT exit dispatcher allocated for
    /// this VM via the lazy fault path. Phase D-only ownership: the
    /// frames are owned by the `VmObject` and freed in `Drop` after
    /// the EPT itself has been torn down (so we don't free a frame
    /// that's still referenced by a leaf entry).
    pub leaf_frames: alloc::vec::Vec<u64>,
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
            introspect: IntrospectRing::new(),
            ept_root: None,
            leaf_frames: alloc::vec::Vec::new(),
        })
    }

    /// Borrow a vCPU mutably by index.
    pub fn vcpu_mut(&mut self, idx: u8) -> Option<&mut KernelVCpuState> {
        self.vcpus.get_mut(idx as usize)?.as_mut()
    }
}

impl Drop for VmObject {
    /// Tear down the VM in the right order:
    ///   1. Drop the EPT root (frees PML4 + intermediate PDPT/PD/PT
    ///      table frames).
    ///   2. Free every leaf frame this VM allocated via the lazy
    ///      fault path. Order matters because step 1 still has live
    ///      references to step 2's frames via the leaf entries.
    fn drop(&mut self) {
        // Step 1: drop the EPT (kills the table frames + invalidates
        // every leaf entry pointing at our `leaf_frames`).
        let _ = self.ept_root.take();
        // Step 2: return guest leaf frames to the allocator.
        for &phys in &self.leaf_frames {
            crate::mm::free_frame(crate::mm::PhysFrame::from_addr(phys));
        }
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

/// Push an introspection event into a VM's per-VM ring. Briefly locks
/// `VM_POOL`; safe to call from the kernel-side exit dispatcher because
/// the dispatcher itself does not hold the pool lock (we deliberately
/// release it in `run_one_vcpu` before entering `vmx_run`).
pub fn push_introspect_event(handle: PoolHandle, event: VmIntrospectEvent) {
    let mut pool = VM_POOL.lock();
    if let Some(vm) = pool.get_mut(handle) {
        vm.introspect.push(event);
    }
}

/// Drain at most `out.len()` events from a VM's introspection ring into
/// `out`. Returns the number of events written. Used by the
/// `SYS_VM_INTROSPECT_DRAIN` syscall handler.
pub fn drain_introspect_events(handle: PoolHandle, out: &mut [VmIntrospectEvent]) -> usize {
    let mut pool = VM_POOL.lock();
    match pool.get_mut(handle) {
        Some(vm) => vm.introspect.drain_into(out),
        None => 0,
    }
}

/// Total number of events pushed into a VM's ring (including overflow
/// drops). Used by the Tier 4 demo to assert "we observed >= N CPUIDs"
/// in environments where the ring would otherwise wrap.
pub fn introspect_total_pushed(handle: PoolHandle) -> u64 {
    let pool = VM_POOL.lock();
    pool.get(handle).map(|vm| vm.introspect.total_pushed).unwrap_or(0)
}

/// Number of host frames currently backing this VM's guest memory.
/// Used by the Phase D demo to assert "we lazily allocated exactly N
/// pages for the test payload".
pub fn mem_pages_used(handle: PoolHandle) -> u32 {
    let pool = VM_POOL.lock();
    pool.get(handle).map(|vm| vm.mem_pages_used).unwrap_or(0)
}

/// Phase D — handle an EPT_VIOLATION VM-exit by lazily allocating a
/// fresh host frame, mapping it into the VM's EPT at `gpa`, and
/// recording the new leaf frame so it gets freed when the VM is torn
/// down.
///
/// Returns:
///   `Ok(())`  — page successfully mapped, dispatcher should `Resume`
///   `Err(_)`  — EPT alloc failed or budget exhausted, terminate vCPU
pub fn handle_ept_lazy_fault(handle: PoolHandle, gpa: u64) -> Result<(), VmObjError> {
    let mut pool = VM_POOL.lock();
    let vm = pool.get_mut(handle).ok_or(VmObjError::NotFound)?;

    // Budget check: refuse to grow beyond the declared per-VM cap.
    if vm.mem_pages_used >= vm.mem_pages_limit {
        return Err(VmObjError::Vmx(VmxError::OutOfFrames));
    }

    // Allocate a fresh host frame for the new guest page.
    let frame = crate::mm::alloc_frame().ok_or(VmObjError::Vmx(VmxError::OutOfFrames))?;
    let host_phys = frame.addr();

    // Zero the guest-visible page so we don't leak host memory.
    // SAFETY: freshly-allocated frame, HHDM-mapped writable, no other
    // reference to this physical page.
    unsafe {
        core::ptr::write_bytes(
            (host_phys + crate::mm::hhdm_offset()) as *mut u8,
            0,
            4096,
        );
    }

    // Install the leaf in the VM's EPT. The EPT root must already
    // exist by this point — `vm_run` allocates it before invoking
    // `vmlaunch`, so any EPT violation we see comes from a VM whose
    // EPT root is initialised.
    let ept = vm.ept_root.as_mut().ok_or(VmObjError::NotFound)?;
    if let Err(e) = ept.map_4k(
        gpa & !0xFFF,
        host_phys,
        crate::arch::x86_64::ept::EPT_LEAF_RWX_WB,
    ) {
        // Roll back the frame allocation if the EPT walk failed.
        crate::mm::free_frame(frame);
        return Err(VmObjError::Vmx(match e {
            crate::arch::x86_64::ept::EptError::OutOfFrames => VmxError::OutOfFrames,
            _ => VmxError::VmFailInvalid,
        }));
    }

    vm.leaf_frames.push(host_phys);
    vm.mem_pages_used += 1;
    Ok(())
}

/// Pre-map a guest physical page into the VM's EPT under direct
/// control of the kernel. Used to install the canned Phase B/C test
/// payload + page tables before the guest starts running. Returns
/// the host physical address that was mapped.
///
/// Unlike `handle_ept_lazy_fault`, this does NOT count against the
/// `mem_pages_used` budget — these are kernel-controlled init pages
/// the userspace caller never sees and didn't ask for.
#[allow(dead_code)]
pub fn ept_premap(handle: PoolHandle, gpa: u64, host_phys: u64) -> Result<(), VmObjError> {
    let mut pool = VM_POOL.lock();
    let vm = pool.get_mut(handle).ok_or(VmObjError::NotFound)?;
    let ept = vm.ept_root.as_mut().ok_or(VmObjError::NotFound)?;
    ept.map_4k(
        gpa & !0xFFF,
        host_phys & !0xFFF,
        crate::arch::x86_64::ept::EPT_LEAF_RWX_WB,
    )
    .map_err(|e| match e {
        crate::arch::x86_64::ept::EptError::OutOfFrames => VmObjError::Vmx(VmxError::OutOfFrames),
        _ => VmObjError::Vmx(VmxError::VmFailInvalid),
    })
}

/// Install a fresh `EptRoot` into the VM if one is not already
/// present. Idempotent. Called by `vm_run` before entering the
/// guest.
pub fn ensure_ept_root(handle: PoolHandle) -> Result<(), VmObjError> {
    let mut pool = VM_POOL.lock();
    let vm = pool.get_mut(handle).ok_or(VmObjError::NotFound)?;
    if vm.ept_root.is_none() {
        let ept =
            crate::arch::x86_64::ept::EptRoot::new().map_err(|_| VmObjError::Vmx(VmxError::OutOfFrames))?;
        vm.ept_root = Some(ept);
    }
    Ok(())
}

/// Read the EPTP value to write into VMCS. Returns 0 if the VM has
/// no EPT root yet (caller should treat that as a programming bug).
pub fn ept_pointer(handle: PoolHandle) -> u64 {
    let pool = VM_POOL.lock();
    pool.get(handle)
        .and_then(|vm| vm.ept_root.as_ref().map(|e| e.eptp()))
        .unwrap_or(0)
}

// ---------------------------------------------------------------------------
// Phase B test path — create a VM, run a tiny `cpuid; hlt` payload,
// observe the spoofed CPUID, terminate cleanly. Phase D moved EPT
// management out of `MiniEpt` and into the per-VM `EptRoot` so the
// dispatcher can lazy-fault new pages on demand; the test now drives
// `ept_premap` to install its 5 init pages.
// ---------------------------------------------------------------------------

/// Hand-assembled test payload — exercises Phase B (CPUID spoofing
/// + HLT), Phase D (lazy EPT fault), AND Phase F.2 (COM1 TX through
/// the in-kernel device model) in a single run.
///
/// On entry the guest is in 64-bit mode with CR3 → 2 MiB identity
/// PD, RIP at GPA `0x1000`, RSP at GPA `0x2FF0`. Both 0x1000 and
/// 0x2000 are pre-mapped via EPT in `run_phase_b_test_inner_on_handle`.
/// The 4 memory stores target GPAs `0x3000..0x6000` which are NOT
/// pre-mapped — each one triggers an EPT_VIOLATION. The 4 OUT
/// instructions hit COM1 (port 0x3F8) which the in-kernel devmodel
/// pipes through to the host serial console with a `[GUEST]` prefix.
///
///   B8 01 00 00 00                  mov eax, 1
///   0F A2                           cpuid                         ; Phase B
///   B0 42                           mov al, 0x42
///   A2 00 30 00 00 00 00 00 00      mov [0x3000], al              ; Phase D
///   A2 00 40 00 00 00 00 00 00      mov [0x4000], al              ; Phase D
///   A2 00 50 00 00 00 00 00 00      mov [0x5000], al              ; Phase D
///   A2 00 60 00 00 00 00 00 00      mov [0x6000], al              ; Phase D
///   66 BA F8 03                     mov dx, 0x3F8                 ; COM1 base
///   B0 46                           mov al, 'F'
///   EE                              out dx, al                    ; Phase F.2
///   B0 78                           mov al, 'x'
///   EE                              out dx, al                    ; Phase F.2
///   B0 0A                           mov al, '\n'
///   EE                              out dx, al                    ; flush
///   F4                              hlt
///
/// Total: 59 bytes. Still fits in the 4 KiB payload page at GPA
/// 0x1000.
const TEST_PAYLOAD: [u8; 59] = [
    // mov eax, 1; cpuid (Phase B path)
    0xB8, 0x01, 0x00, 0x00, 0x00,
    0x0F, 0xA2,
    // mov al, 0x42
    0xB0, 0x42,
    // mov [0x3000], al — Phase D lazy fault #1
    0xA2, 0x00, 0x30, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    // mov [0x4000], al — #2
    0xA2, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    // mov [0x5000], al — #3
    0xA2, 0x00, 0x50, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    // mov [0x6000], al — #4
    0xA2, 0x00, 0x60, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    // mov dx, 0x3F8 (16-bit operand-size override 0x66 + opcode BA + imm16)
    0x66, 0xBA, 0xF8, 0x03,
    // mov al, 'F'; out dx, al
    0xB0, 0x46,
    0xEE,
    // mov al, 'x'; out dx, al
    0xB0, 0x78,
    0xEE,
    // mov al, '\n'; out dx, al
    0xB0, 0x0A,
    0xEE,
    // hlt
    0xF4,
];

/// Number of EPT lazy-fault pages the canned payload above touches.
/// `tier4_demo::run_bhyve` asserts `mem_pages_used == EXPECTED_LAZY_PAGES`
/// after `SYS_VM_RUN` returns.
pub const EXPECTED_LAZY_PAGES: u32 = 4;

/// Number of COM1 TX writes the canned payload performs. Userspace
/// asserts the introspection ring contains exactly this many
/// `KIND_IO_OUT` events.
pub const EXPECTED_IO_OUT_EVENTS: u32 = 3;

/// Phase C — execute the canned `cpuid; hlt` test payload on an
/// already-allocated `VmObject`. Public so the syscall layer
/// (`syscall::vm::sys_vm_run`) can reach it; the Phase B in-kernel
/// test path now goes through this same helper.
///
/// `vcpu_idx` is currently unused (Phase B/C only support vCPU 0) but
/// is part of the syscall ABI so we keep it in the signature.
pub fn run_payload_on_vm(vm_handle: PoolHandle, _vcpu_idx: u8) -> Result<(), VmObjError> {
    run_phase_b_test_inner_on_handle(vm_handle)
}

/// Phase B end-to-end test, kept for direct kernel invocation in case
/// we want a self-contained smoke test (currently unused — kmain stops
/// driving the test at boot once Phase C lands the syscall path).
#[allow(dead_code)]
pub fn run_phase_b_test() {
    if !vmx::cpu_has_vmx() {
        return;
    }
    let handle = match create_vm(1, 16) {
        Ok(h) => h,
        Err(e) => {
            crate::kprintln!("  vmx-test: create_vm failed: {:?}", e);
            return;
        }
    };
    if let Err(e) = run_phase_b_test_inner_on_handle(handle) {
        crate::kprintln!("  vmx-test: FAILED: {:?}", e);
    }
    let _ = destroy_vm(handle);
}

fn run_phase_b_test_inner_on_handle(vm_handle: PoolHandle) -> Result<(), VmObjError> {
    // 1. Make sure the VM has an EPT root. Phase D allocates this
    //    lazily so VMs that never run don't waste a PML4 frame.
    ensure_ept_root(vm_handle)?;

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
    let stack_phys = stack_frame.addr();

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
        // GUEST page table entries use GUEST physical addresses.
        //   GPA 0x1000  = payload
        //   GPA 0x2000  = stack
        //   GPA 0x10000 = pml4
        //   GPA 0x11000 = pdpt
        //   GPA 0x12000 = pd
        // Guest CR3 = GPA 0x10000.
        // PD[0] is a 2 MiB PS=1 leaf identity-mapping guest virt
        // 0..2 MiB to guest phys 0..2 MiB; the EPT then maps GPA
        // 0x1000..0x2000 to the host payload frame and the rest of
        // the 2 MiB window can be lazy-faulted in if the guest ever
        // touches it.
        *((pml4_phys + hhdm) as *mut u64) = 0x11000 | 0x3;
        *((pdpt_phys + hhdm) as *mut u64) = 0x12000 | 0x3;
        *((pd_phys + hhdm) as *mut u64) = 0x0 | 0x83;
    }

    // 5. Pre-map the 5 init pages into the VM's EPT. Phase D's lazy
    //    fault handler will fill in any other GPA the guest touches
    //    (the test payload only touches 0x1000 and 0x2FF0, both of
    //    which are pre-mapped here, so we never actually exercise
    //    the lazy path in this test — the dedicated Phase D test
    //    payload below does).
    ept_premap(vm_handle, 0x1000, payload_phys)?;
    ept_premap(vm_handle, 0x2000, stack_phys)?;
    ept_premap(vm_handle, 0x10000, pml4_phys)?;
    ept_premap(vm_handle, 0x11000, pdpt_phys)?;
    ept_premap(vm_handle, 0x12000, pd_phys)?;

    // 6. Run the vCPU. Phase C runs this from a userspace thread via
    // SYS_VM_RUN, so we keep the noise low — diagnostics are gated
    // behind `kdebug!` and only fire under the `verbose` feature.
    set_current_vm(vm_handle);
    let result = run_one_vcpu(vm_handle);
    clear_current_vm();

    if let Err(e) = result {
        crate::kprintln!("  vmx-test: vmx_run error: {:?}", e);
        return Err(VmObjError::Vmx(e));
    }

    // Check the vCPU actually halted (sanity — the dispatcher only
    // returns Terminate after a HLT exit in the canned payload). If
    // it didn't, dump the VM-instruction-error so the boot log shows
    // what went wrong instead of just silently passing.
    let halted = {
        let mut pool = VM_POOL.lock();
        pool.get_mut(vm_handle)
            .and_then(|vm| vm.vcpu_mut(0))
            .map(|v| v.halted)
            .unwrap_or(false)
    };
    if !halted {
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
        return Err(VmObjError::Vmx(VmxError::VmFailInvalid));
    }

    Ok(())
}

fn run_one_vcpu(vm_handle: PoolHandle) -> Result<(), VmxError> {
    // Phase D: read the VM's EPTP first (under a brief pool lock) so
    // we can drop the lock before vmcs_load — `run_one_vcpu` is the
    // hot path and we want to keep it lock-free past the VMCS setup.
    let eptp_value = ept_pointer(vm_handle);
    if eptp_value == 0 {
        return Err(VmxError::VmFailInvalid);
    }

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
    vmx::vmwrite(vmx::VMCS_EPTP, eptp_value, vmcs_phys)?;
    vmx::setup_guest_state(vmcs_phys, 0x1000, 0x2FF0, 0x10000)?;

    // Diagnostic dumps from Phase B's bringup. Gated behind `kdebug!`
    // so they only fire under the `verbose` feature; the production
    // boot path stays quiet on the serial console.
    crate::kdebug!(
        "  vmx-test: pin={:?} proc1={:?} proc2={:?} exit={:?} entry={:?}",
        vmx::vmread(vmx::VMCS_PIN_BASED_CTLS, vmcs_phys),
        vmx::vmread(vmx::VMCS_PROC_BASED_CTLS, vmcs_phys),
        vmx::vmread(vmx::VMCS_PROC_BASED_CTLS2, vmcs_phys),
        vmx::vmread(vmx::VMCS_EXIT_CTLS, vmcs_phys),
        vmx::vmread(vmx::VMCS_ENTRY_CTLS, vmcs_phys),
    );
    crate::kdebug!(
        "  vmx-test: host cr0={:?} cr3={:?} cr4={:?} rip={:?} efer={:?}",
        vmx::vmread(vmx::VMCS_HOST_CR0, vmcs_phys),
        vmx::vmread(vmx::VMCS_HOST_CR3, vmcs_phys),
        vmx::vmread(vmx::VMCS_HOST_CR4, vmcs_phys),
        vmx::vmread(vmx::VMCS_HOST_RIP, vmcs_phys),
        vmx::vmread(vmx::VMCS_HOST_IA32_EFER, vmcs_phys),
    );
    crate::kdebug!(
        "  vmx-test: guest cr0={:?} cr4={:?} rip={:?} rsp={:?} efer={:?}",
        vmx::vmread(vmx::VMCS_GUEST_CR0, vmcs_phys),
        vmx::vmread(vmx::VMCS_GUEST_CR4, vmcs_phys),
        vmx::vmread(vmx::VMCS_GUEST_RIP, vmcs_phys),
        vmx::vmread(vmx::VMCS_GUEST_RSP, vmcs_phys),
        vmx::vmread(vmx::VMCS_GUEST_IA32_EFER, vmcs_phys),
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

