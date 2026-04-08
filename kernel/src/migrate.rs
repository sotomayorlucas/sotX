//! Live process migration — checkpoint/restore infrastructure.
//!
//! Provides the ability to serialize a thread's entire state (registers,
//! memory mappings, IPC state) into a portable checkpoint that can be
//! transferred to another node and restored.
//!
//! This is the foundation for distributed scheduling and fault tolerance:
//! a process can be checkpointed on one node and restored on another
//! without the process being aware of the migration.

use crate::mm::paging::{self, AddressSpace};
use crate::sched::{self, ThreadState, SCHEDULER};

/// Maximum number of memory regions in a checkpoint.
pub const MAX_REGIONS: usize = 32;

/// Serialized size of the checkpoint header (without memory data).
pub const CHECKPOINT_HEADER_SIZE: usize = core::mem::size_of::<ThreadCheckpoint>();

/// A memory region descriptor for migration.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct MemRegion {
    /// Virtual address of the region.
    pub vaddr: u64,
    /// Size in bytes.
    pub size: u64,
    /// Page flags (present, writable, user, NX, etc.).
    pub flags: u64,
    /// Offset into the migration data buffer where this region's content starts.
    pub data_offset: u64,
}

impl MemRegion {
    pub const fn zeroed() -> Self {
        Self {
            vaddr: 0,
            size: 0,
            flags: 0,
            data_offset: 0,
        }
    }
}

/// Thread checkpoint: complete serialized state for migration.
///
/// Contains everything needed to recreate a thread on a target node:
/// - Register state (instruction pointer, stack pointer)
/// - Address space identifier (CR3)
/// - Scheduling parameters (priority, compute target)
/// - IPC state snapshot
/// - Memory region descriptors (actual data is in a separate buffer)
#[repr(C)]
#[derive(Clone, Copy)]
pub struct ThreadCheckpoint {
    /// Thread ID on the source node.
    pub tid: u32,
    /// User-mode instruction pointer.
    pub user_rip: u64,
    /// User-mode stack pointer.
    pub user_rsp: u64,
    /// Physical address of PML4 (for reference; target will create new page tables).
    pub cr3: u64,
    /// Scheduling priority (0 = highest, 255 = lowest).
    pub priority: u8,
    /// Compute target (0=CPU, 1=GPU, 2=NPU).
    pub compute_target: u8,
    /// Padding for alignment.
    pub _pad: [u8; 2],
    /// Serialized IPC state (endpoint ID, role, message registers).
    pub ipc_state: [u8; 128],
    /// Memory region descriptors.
    pub memory_regions: [MemRegion; MAX_REGIONS],
    /// Number of valid memory regions.
    pub region_count: usize,
}

impl ThreadCheckpoint {
    pub const fn zeroed() -> Self {
        Self {
            tid: 0,
            user_rip: 0,
            user_rsp: 0,
            cr3: 0,
            priority: 128,
            compute_target: 0,
            _pad: [0; 2],
            ipc_state: [0; 128],
            memory_regions: [MemRegion::zeroed(); MAX_REGIONS],
            region_count: 0,
        }
    }
}

/// Checkpoint a thread's state for migration.
///
/// Captures the thread's register state, scheduling parameters, IPC state,
/// and enumerates its memory regions. The actual memory content must be
/// copied separately using the region descriptors.
///
/// The thread must be in a Blocked or Ready state (not Running).
/// Returns `None` if the thread doesn't exist or is currently running.
pub fn checkpoint(tid: u32) -> Option<ThreadCheckpoint> {
    let sched = SCHEDULER.lock();
    let thread_id = sched::ThreadId(tid);

    let slot = sched.slot_of(thread_id)?;
    let t = sched.threads.get_by_index(slot)?;

    // Can only checkpoint threads that aren't actively running.
    if t.state == ThreadState::Running {
        return None;
    }

    let mut cp = ThreadCheckpoint::zeroed();
    cp.tid = tid;
    cp.user_rip = t.user_rip;
    cp.user_rsp = t.user_rsp;
    cp.cr3 = t.cr3;
    cp.priority = t.priority;
    cp.compute_target = match t.compute_target {
        sched::ComputeTarget::Cpu => 0,
        sched::ComputeTarget::Gpu => 1,
        sched::ComputeTarget::Npu => 2,
    };

    // Serialize IPC state into the fixed-size buffer.
    serialize_ipc_state(t, &mut cp.ipc_state);

    // Enumerate memory regions from the thread's page tables.
    // Walk the PML4 at cr3 to find mapped user pages.
    if t.cr3 != 0 {
        cp.region_count = enumerate_regions(t.cr3, &mut cp.memory_regions);
    }

    Some(cp)
}

/// Restore a thread from a checkpoint on the target node.
///
/// Creates a new thread with the checkpointed register state and
/// scheduling parameters. Memory regions must be mapped separately
/// after restoration.
///
/// `memory_data` contains the raw memory content referenced by the
/// checkpoint's region descriptors (via `data_offset` fields).
///
/// Returns the new thread ID, or `None` if restoration fails.
pub fn restore(checkpoint: &ThreadCheckpoint, _memory_data: &[u8]) -> Option<u32> {
    // Create a new address space for the restored thread.
    let addr_space = AddressSpace::new_user();
    let cr3 = addr_space.cr3();

    // Map memory regions into the new address space.
    let hhdm = crate::mm::hhdm_offset();
    for i in 0..checkpoint.region_count {
        let region = &checkpoint.memory_regions[i];
        if region.size == 0 {
            continue;
        }

        // Allocate physical frames for this region.
        let page_count = ((region.size + 4095) / 4096) as usize;
        for page_idx in 0..page_count {
            let frame = crate::mm::alloc_frame()?;
            let vaddr = region.vaddr + (page_idx as u64) * 4096;
            addr_space.map_page(vaddr, frame.addr(), region.flags);

            // Copy memory content from the migration buffer if available.
            let src_offset = region.data_offset as usize + page_idx * 4096;
            let dst_ptr = (frame.addr() + hhdm) as *mut u8;
            if src_offset + 4096 <= _memory_data.len() {
                unsafe {
                    core::ptr::copy_nonoverlapping(
                        _memory_data.as_ptr().add(src_offset),
                        dst_ptr,
                        4096,
                    );
                }
            } else {
                // Zero-fill if no data available.
                unsafe {
                    core::ptr::write_bytes(dst_ptr, 0, 4096);
                }
            }
        }
    }

    // Spawn a new user thread with the restored state.
    let new_tid = sched::spawn_user(checkpoint.user_rip, checkpoint.user_rsp, cr3);

    // Apply scheduling parameters.
    {
        let mut sched_lock = SCHEDULER.lock();
        if let Some(slot) = sched_lock.slot_of(new_tid) {
            if let Some(t) = sched_lock.threads.get_mut_by_index(slot) {
                t.priority = checkpoint.priority;
                t.compute_target = match checkpoint.compute_target {
                    0 => sched::ComputeTarget::Cpu,
                    1 => sched::ComputeTarget::Gpu,
                    2 => sched::ComputeTarget::Npu,
                    _ => sched::ComputeTarget::Cpu,
                };

                // Restore IPC state.
                deserialize_ipc_state(&checkpoint.ipc_state, t);
            }
        }
    }

    Some(new_tid.0)
}

/// Serialize a checkpoint to bytes for network transfer.
///
/// Writes the checkpoint header into the provided buffer.
/// Returns the number of bytes written.
pub fn serialize(checkpoint: &ThreadCheckpoint, buf: &mut [u8]) -> usize {
    let size = core::mem::size_of::<ThreadCheckpoint>();
    if buf.len() < size {
        return 0;
    }

    unsafe {
        let src = checkpoint as *const ThreadCheckpoint as *const u8;
        core::ptr::copy_nonoverlapping(src, buf.as_mut_ptr(), size);
    }

    size
}

/// Deserialize a checkpoint from bytes received over the network.
///
/// Returns `None` if the buffer is too small.
pub fn deserialize(data: &[u8]) -> Option<ThreadCheckpoint> {
    let size = core::mem::size_of::<ThreadCheckpoint>();
    if data.len() < size {
        return None;
    }

    let mut cp = ThreadCheckpoint::zeroed();
    unsafe {
        let dst = &mut cp as *mut ThreadCheckpoint as *mut u8;
        core::ptr::copy_nonoverlapping(data.as_ptr(), dst, size);
    }

    // Basic validation.
    if cp.region_count > MAX_REGIONS {
        return None;
    }

    Some(cp)
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Serialize a thread's IPC state into a fixed-size buffer.
///
/// Layout: [endpoint_id: u32][role: u8][pad: 3][tag: u64][regs: 8×u64][cap: u32]
fn serialize_ipc_state(t: &crate::sched::thread::Thread, buf: &mut [u8; 128]) {
    let mut offset = 0;

    // Endpoint ID (4 bytes).
    let ep_id = t.ipc_endpoint.unwrap_or(0);
    buf[offset..offset + 4].copy_from_slice(&ep_id.to_le_bytes());
    offset += 4;

    // IPC role (1 byte).
    buf[offset] = match t.ipc_role {
        sched::IpcRole::None => 0,
        sched::IpcRole::Sender => 1,
        sched::IpcRole::Receiver => 2,
        sched::IpcRole::Caller => 3,
    };
    offset += 1;

    // Padding (3 bytes).
    buf[offset..offset + 3].fill(0);
    offset += 3;

    // Message tag (8 bytes).
    buf[offset..offset + 8].copy_from_slice(&t.ipc_msg.tag.to_le_bytes());
    offset += 8;

    // Message registers (8 x 8 bytes = 64 bytes).
    for i in 0..crate::ipc::endpoint::MSG_REGS {
        buf[offset..offset + 8].copy_from_slice(&t.ipc_msg.regs[i].to_le_bytes());
        offset += 8;
    }

    // Cap transfer (4 bytes).
    let cap = t.ipc_msg.cap_transfer.unwrap_or(0);
    buf[offset..offset + 4].copy_from_slice(&cap.to_le_bytes());
    // offset += 4;

    // Remaining bytes are zero (already initialized).
}

/// Deserialize IPC state from a buffer into a thread.
fn deserialize_ipc_state(buf: &[u8; 128], t: &mut crate::sched::thread::Thread) {
    let mut offset = 0;

    // Endpoint ID.
    let mut ep_bytes = [0u8; 4];
    ep_bytes.copy_from_slice(&buf[offset..offset + 4]);
    let ep_id = u32::from_le_bytes(ep_bytes);
    t.ipc_endpoint = if ep_id != 0 { Some(ep_id) } else { None };
    offset += 4;

    // IPC role.
    t.ipc_role = match buf[offset] {
        1 => sched::IpcRole::Sender,
        2 => sched::IpcRole::Receiver,
        3 => sched::IpcRole::Caller,
        _ => sched::IpcRole::None,
    };
    offset += 1;

    // Padding.
    offset += 3;

    // Message tag.
    let mut tag_bytes = [0u8; 8];
    tag_bytes.copy_from_slice(&buf[offset..offset + 8]);
    t.ipc_msg.tag = u64::from_le_bytes(tag_bytes);
    offset += 8;

    // Message registers.
    for i in 0..crate::ipc::endpoint::MSG_REGS {
        let mut reg_bytes = [0u8; 8];
        reg_bytes.copy_from_slice(&buf[offset..offset + 8]);
        t.ipc_msg.regs[i] = u64::from_le_bytes(reg_bytes);
        offset += 8;
    }

    // Cap transfer.
    let mut cap_bytes = [0u8; 4];
    cap_bytes.copy_from_slice(&buf[offset..offset + 4]);
    let cap = u32::from_le_bytes(cap_bytes);
    t.ipc_msg.cap_transfer = if cap != 0 { Some(cap) } else { None };
}

/// Enumerate mapped user-space memory regions from a page table.
///
/// Walks the 4-level page table at `cr3` and records mapped regions.
/// Returns the number of regions found (up to MAX_REGIONS).
fn enumerate_regions(cr3: u64, regions: &mut [MemRegion; MAX_REGIONS]) -> usize {
    let hhdm = crate::mm::hhdm_offset();
    let pml4_phys = cr3 & !0xFFF;
    let pml4_virt = pml4_phys + hhdm;
    let pml4 = unsafe { &*(pml4_virt as *const [u64; 512]) };

    let mut count = 0usize;
    let mut current_start: u64 = 0;
    let mut current_end: u64 = 0;
    let mut current_flags: u64 = 0;
    let mut data_offset: u64 = 0;
    let mut in_region = false;

    // Only scan the lower half of the address space (user pages: PML4 entries 0-255).
    for pml4_idx in 0..256u64 {
        if pml4[pml4_idx as usize] & paging::PAGE_PRESENT == 0 {
            if in_region && count < MAX_REGIONS {
                regions[count] = MemRegion {
                    vaddr: current_start,
                    size: current_end - current_start,
                    flags: current_flags,
                    data_offset,
                };
                data_offset += current_end - current_start;
                count += 1;
                in_region = false;
            }
            continue;
        }

        let pdpt_phys = pml4[pml4_idx as usize] & 0x000F_FFFF_FFFF_F000;
        let pdpt = unsafe { &*((pdpt_phys + hhdm) as *const [u64; 512]) };

        for pdpt_idx in 0..512u64 {
            if pdpt[pdpt_idx as usize] & paging::PAGE_PRESENT == 0 {
                if in_region && count < MAX_REGIONS {
                    regions[count] = MemRegion {
                        vaddr: current_start,
                        size: current_end - current_start,
                        flags: current_flags,
                        data_offset,
                    };
                    data_offset += current_end - current_start;
                    count += 1;
                    in_region = false;
                }
                continue;
            }

            let pd_phys = pdpt[pdpt_idx as usize] & 0x000F_FFFF_FFFF_F000;
            let pd = unsafe { &*((pd_phys + hhdm) as *const [u64; 512]) };

            for pd_idx in 0..512u64 {
                if pd[pd_idx as usize] & paging::PAGE_PRESENT == 0 {
                    if in_region && count < MAX_REGIONS {
                        regions[count] = MemRegion {
                            vaddr: current_start,
                            size: current_end - current_start,
                            flags: current_flags,
                            data_offset,
                        };
                        data_offset += current_end - current_start;
                        count += 1;
                        in_region = false;
                    }
                    continue;
                }

                let pt_phys = pd[pd_idx as usize] & 0x000F_FFFF_FFFF_F000;
                let pt = unsafe { &*((pt_phys + hhdm) as *const [u64; 512]) };

                for pt_idx in 0..512u64 {
                    let entry = pt[pt_idx as usize];
                    let vaddr =
                        (pml4_idx << 39) | (pdpt_idx << 30) | (pd_idx << 21) | (pt_idx << 12);

                    if entry & paging::PAGE_PRESENT != 0 {
                        let flags = entry & 0x8000_0000_0000_001F; // P, W, U, WT, CD, NX
                        if in_region && vaddr == current_end && flags == current_flags {
                            // Extend current region.
                            current_end = vaddr + 4096;
                        } else {
                            // Close previous region.
                            if in_region && count < MAX_REGIONS {
                                regions[count] = MemRegion {
                                    vaddr: current_start,
                                    size: current_end - current_start,
                                    flags: current_flags,
                                    data_offset,
                                };
                                data_offset += current_end - current_start;
                                count += 1;
                            }
                            // Start new region.
                            current_start = vaddr;
                            current_end = vaddr + 4096;
                            current_flags = flags;
                            in_region = true;
                        }
                    } else if in_region {
                        if count < MAX_REGIONS {
                            regions[count] = MemRegion {
                                vaddr: current_start,
                                size: current_end - current_start,
                                flags: current_flags,
                                data_offset,
                            };
                            data_offset += current_end - current_start;
                            count += 1;
                        }
                        in_region = false;
                    }
                }
            }
        }
    }

    // Close final region if open.
    if in_region && count < MAX_REGIONS {
        regions[count] = MemRegion {
            vaddr: current_start,
            size: current_end - current_start,
            flags: current_flags,
            data_offset,
        };
        count += 1;
    }

    count
}
