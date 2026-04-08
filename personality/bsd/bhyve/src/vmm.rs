//! Virtual Machine Monitor core -- guest VM lifecycle and SOT domain
//! capabilities.

use crate::deception::VmDeceptionProfile;
use crate::vcpu::{VCpu, VCpuState};

/// VM lifecycle state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VmState {
    Created,
    Running,
    Paused,
    Halted,
}

/// SOT capabilities held by a VM domain.
#[derive(Debug, Clone, Copy)]
pub struct VmCaps {
    /// Capability to guest physical memory.
    pub memory_cap: u64,
    /// Capabilities to emulated I/O devices.
    pub io_caps: [u64; 8],
    /// Capability to inject interrupts.
    pub irq_cap: u64,
}

impl VmCaps {
    pub const fn empty() -> Self {
        Self {
            memory_cap: 0,
            io_caps: [0; 8],
            irq_cap: 0,
        }
    }
}

/// A guest VM running in a SOT domain.
pub struct VmDomain {
    pub id: u32,
    pub vcpu_count: u8,
    pub vcpus: [Option<VCpu>; 16],
    /// Pages of guest physical memory (4 KiB each).
    pub memory_pages: u32,
    pub state: VmState,
    /// SOT capabilities held by this VM domain.
    pub caps: VmCaps,
    pub deception_profile: Option<VmDeceptionProfile>,
}

/// Errors returned by VM lifecycle operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VmError {
    InvalidVcpuCount,
    InvalidState,
    VcpuNotFound,
}

const NONE_VCPU: Option<VCpu> = None;

impl VmDomain {
    /// Create a new VM domain.
    ///
    /// `vcpu_count` is clamped to 16. `memory_pages` is the number of
    /// 4 KiB pages allocated to the guest.
    pub fn create(id: u32, vcpu_count: u8, memory_pages: u32) -> Result<Self, VmError> {
        let clamped = if vcpu_count > 16 { 16 } else { vcpu_count };
        if clamped == 0 {
            return Err(VmError::InvalidVcpuCount);
        }

        let mut vcpus = [NONE_VCPU; 16];
        for i in 0..clamped as usize {
            vcpus[i] = Some(VCpu::new(i as u8));
        }

        Ok(Self {
            id,
            vcpu_count: clamped,
            vcpus,
            memory_pages,
            state: VmState::Created,
            caps: VmCaps::empty(),
            deception_profile: None,
        })
    }

    /// Start all vCPUs and transition to Running.
    pub fn start(&mut self) -> Result<(), VmError> {
        if self.state != VmState::Created && self.state != VmState::Paused {
            return Err(VmError::InvalidState);
        }
        for slot in self.vcpus.iter_mut().flatten() {
            slot.run();
        }
        self.state = VmState::Running;
        Ok(())
    }

    /// Pause all vCPUs.
    pub fn pause(&mut self) -> Result<(), VmError> {
        if self.state != VmState::Running {
            return Err(VmError::InvalidState);
        }
        for slot in self.vcpus.iter_mut().flatten() {
            slot.exit();
        }
        self.state = VmState::Paused;
        Ok(())
    }

    /// Resume from paused state (alias for start from Paused).
    pub fn resume(&mut self) -> Result<(), VmError> {
        if self.state != VmState::Paused {
            return Err(VmError::InvalidState);
        }
        self.start()
    }

    /// Destroy the VM: halt every vCPU and mark Halted.
    pub fn destroy(&mut self) {
        for slot in self.vcpus.iter_mut().flatten() {
            slot.halt();
        }
        self.state = VmState::Halted;
    }

    /// Whether deception is currently active.
    pub fn deception_active(&self) -> bool {
        self.deception_profile.is_some()
    }

    /// Enable deception with a specific profile.
    pub fn enable_deception(&mut self, profile: VmDeceptionProfile) {
        self.deception_profile = Some(profile);
    }

    /// Disable deception.
    pub fn disable_deception(&mut self) {
        self.deception_profile = None;
    }

    /// Look up a vCPU by id.
    pub fn vcpu(&self, id: u8) -> Result<&VCpu, VmError> {
        let idx = id as usize;
        if idx >= 16 {
            return Err(VmError::VcpuNotFound);
        }
        self.vcpus[idx].as_ref().ok_or(VmError::VcpuNotFound)
    }

    /// Look up a vCPU mutably.
    pub fn vcpu_mut(&mut self, id: u8) -> Result<&mut VCpu, VmError> {
        let idx = id as usize;
        if idx >= 16 {
            return Err(VmError::VcpuNotFound);
        }
        self.vcpus[idx].as_mut().ok_or(VmError::VcpuNotFound)
    }

    /// Count of vCPUs currently in a given state.
    pub fn vcpus_in_state(&self, state: VCpuState) -> usize {
        self.vcpus
            .iter()
            .flatten()
            .filter(|v| v.state == state)
            .count()
    }
}
