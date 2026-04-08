//! Virtual CPU management.

use crate::vmcs::VmcsConfig;

/// Virtual CPU state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VCpuState {
    /// Created but not yet started.
    Idle,
    /// Executing guest code.
    Running,
    /// Exited to host for handling.
    Exited,
    /// Halted (HLT instruction).
    Halted,
}

/// General-purpose and control registers for one vCPU.
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct VCpuRegs {
    pub rax: u64,
    pub rbx: u64,
    pub rcx: u64,
    pub rdx: u64,
    pub rsi: u64,
    pub rdi: u64,
    pub rbp: u64,
    pub rsp: u64,
    pub r8: u64,
    pub r9: u64,
    pub r10: u64,
    pub r11: u64,
    pub r12: u64,
    pub r13: u64,
    pub r14: u64,
    pub r15: u64,
    pub rip: u64,
    pub rflags: u64,
    pub cr0: u64,
    pub cr3: u64,
    pub cr4: u64,
}

impl VCpuRegs {
    /// Zeroed register file.
    pub const fn new() -> Self {
        Self {
            rax: 0,
            rbx: 0,
            rcx: 0,
            rdx: 0,
            rsi: 0,
            rdi: 0,
            rbp: 0,
            rsp: 0,
            r8: 0,
            r9: 0,
            r10: 0,
            r11: 0,
            r12: 0,
            r13: 0,
            r14: 0,
            r15: 0,
            rip: 0,
            rflags: 0x0000_0000_0000_0002, // Reserved bit 1 always set
            cr0: 0,
            cr3: 0,
            cr4: 0,
        }
    }
}

/// A single virtual CPU inside a guest VM.
pub struct VCpu {
    pub id: u8,
    pub state: VCpuState,
    pub regs: VCpuRegs,
    pub vmcs: VmcsConfig,
}

impl VCpu {
    /// Create a vCPU in the idle state with default VMCS controls.
    pub fn new(id: u8) -> Self {
        Self {
            id,
            state: VCpuState::Idle,
            regs: VCpuRegs::new(),
            vmcs: VmcsConfig::default_intel(),
        }
    }

    /// Reset the vCPU to power-on state (real-mode entry at 0xFFF0).
    pub fn reset(&mut self) {
        self.regs = VCpuRegs::new();
        self.regs.rip = 0x0000_FFF0;
        self.regs.cr0 = 0x0000_0010; // ET bit (x87 present)
        self.regs.rflags = 0x0000_0002;
        self.state = VCpuState::Idle;
    }

    /// Transition to running.  Returns `false` if already running.
    pub fn run(&mut self) -> bool {
        if self.state == VCpuState::Running {
            return false;
        }
        self.state = VCpuState::Running;
        true
    }

    /// Record a VM-exit and park the vCPU.
    pub fn exit(&mut self) {
        self.state = VCpuState::Exited;
    }

    /// Mark halted (guest executed HLT).
    pub fn halt(&mut self) {
        self.state = VCpuState::Halted;
    }
}
