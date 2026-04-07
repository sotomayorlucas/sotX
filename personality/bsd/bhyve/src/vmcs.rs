//! VMCS (Virtual Machine Control Structure) abstractions for Intel VT-x.

// --- Pin-based VM-execution controls (SDM Vol 3, Table 24-5) ---
pub const PIN_EXTINT_EXIT: u32 = 1 << 0;
pub const PIN_NMI_EXIT: u32 = 1 << 3;
pub const PIN_VIRTUAL_NMIS: u32 = 1 << 5;
pub const PIN_PREEMPTION_TIMER: u32 = 1 << 6;

// --- Primary processor-based controls (SDM Vol 3, Table 24-6) ---
pub const PROC_HLT_EXIT: u32 = 1 << 7;
pub const PROC_INVLPG_EXIT: u32 = 1 << 9;
pub const PROC_MWAIT_EXIT: u32 = 1 << 10;
pub const PROC_RDPMC_EXIT: u32 = 1 << 11;
pub const PROC_RDTSC_EXIT: u32 = 1 << 12;
pub const PROC_CR3_LOAD_EXIT: u32 = 1 << 15;
pub const PROC_CR3_STORE_EXIT: u32 = 1 << 16;
pub const PROC_CR8_LOAD_EXIT: u32 = 1 << 19;
pub const PROC_CR8_STORE_EXIT: u32 = 1 << 20;
pub const PROC_MOV_DR_EXIT: u32 = 1 << 23;
pub const PROC_IO_EXIT: u32 = 1 << 24;
pub const PROC_MSR_BITMAPS: u32 = 1 << 28;
pub const PROC_SECONDARY: u32 = 1 << 31;

// --- Secondary processor-based controls (SDM Vol 3, Table 24-7) ---
pub const PROC2_EPT: u32 = 1 << 1;
pub const PROC2_RDTSCP: u32 = 1 << 3;
pub const PROC2_VPID: u32 = 1 << 5;
pub const PROC2_UNRESTRICTED: u32 = 1 << 7;
pub const PROC2_INVPCID: u32 = 1 << 12;
pub const PROC2_XSAVES: u32 = 1 << 20;

// --- VM-exit controls ---
pub const EXIT_HOST_ADDR_SPACE: u32 = 1 << 9; // 64-bit host
pub const EXIT_ACK_INTERRUPT: u32 = 1 << 15;

// --- VM-entry controls ---
pub const ENTRY_IA32E_GUEST: u32 = 1 << 9; // 64-bit guest

/// VMCS field configuration for one vCPU.
#[derive(Debug, Clone, Copy)]
pub struct VmcsConfig {
    pub pin_based_controls: u32,
    pub proc_based_controls: u32,
    pub proc_based_controls2: u32,
    pub exit_controls: u32,
    pub entry_controls: u32,
    /// Bitmap of exceptions that cause VM-exits (bit N = vector N).
    pub exception_bitmap: u32,
    pub cr0_mask: u64,
    pub cr4_mask: u64,
    /// Host-physical address of the MSR bitmap page (4 KiB).
    pub msr_bitmap_addr: u64,
}

impl VmcsConfig {
    /// Sensible defaults for a 64-bit Intel guest with EPT.
    pub fn default_intel() -> Self {
        Self {
            pin_based_controls: PIN_EXTINT_EXIT | PIN_NMI_EXIT | PIN_VIRTUAL_NMIS,
            proc_based_controls: PROC_HLT_EXIT
                | PROC_IO_EXIT
                | PROC_MSR_BITMAPS
                | PROC_SECONDARY,
            proc_based_controls2: PROC2_EPT | PROC2_VPID | PROC2_UNRESTRICTED | PROC2_RDTSCP,
            exit_controls: EXIT_HOST_ADDR_SPACE | EXIT_ACK_INTERRUPT,
            entry_controls: ENTRY_IA32E_GUEST,
            exception_bitmap: 0,
            cr0_mask: 0,
            cr4_mask: 0,
            msr_bitmap_addr: 0,
        }
    }

    /// Minimal controls -- only mandatory exits.
    pub fn minimal() -> Self {
        Self {
            pin_based_controls: PIN_EXTINT_EXIT | PIN_NMI_EXIT,
            proc_based_controls: PROC_SECONDARY,
            proc_based_controls2: PROC2_EPT | PROC2_VPID,
            exit_controls: EXIT_HOST_ADDR_SPACE,
            entry_controls: ENTRY_IA32E_GUEST,
            exception_bitmap: 0,
            cr0_mask: 0,
            cr4_mask: 0,
            msr_bitmap_addr: 0,
        }
    }

    /// Enable RDTSC exits (needed for timing deception).
    pub fn with_rdtsc_exit(mut self) -> Self {
        self.proc_based_controls |= PROC_RDTSC_EXIT;
        self
    }

    /// Trap all I/O port accesses.
    pub fn with_io_exit(mut self) -> Self {
        self.proc_based_controls |= PROC_IO_EXIT;
        self
    }

    /// Set the exception bitmap (bit per vector).
    pub fn with_exception_bitmap(mut self, bitmap: u32) -> Self {
        self.exception_bitmap = bitmap;
        self
    }

    /// Set the MSR-bitmap host-physical address.
    pub fn with_msr_bitmap(mut self, addr: u64) -> Self {
        self.msr_bitmap_addr = addr;
        self.proc_based_controls |= PROC_MSR_BITMAPS;
        self
    }

    /// Check whether a specific pin-based control is set.
    pub fn has_pin(&self, bit: u32) -> bool {
        self.pin_based_controls & bit != 0
    }

    /// Check whether a specific primary proc-based control is set.
    pub fn has_proc(&self, bit: u32) -> bool {
        self.proc_based_controls & bit != 0
    }

    /// Check whether a specific secondary proc-based control is set.
    pub fn has_proc2(&self, bit: u32) -> bool {
        self.proc_based_controls2 & bit != 0
    }
}
