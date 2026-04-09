//! Kernel-local mirror of `personality/bsd/bhyve::deception`.
//!
//! The userspace types in `sot-bhyve` cannot be linked into the kernel
//! directly (separate workspace, host-test build mode), so the kernel
//! holds its own copy of the spoofing tables and the `bare_metal_intel`
//! profile. Phase C will add a `#[repr(C)]` ABI struct in
//! `libs/sotos-common::vm` that both sides agree on, plus a
//! `SYS_VM_SET_PROFILE` syscall to copy a profile from userspace
//! into the kernel-side `VmObject`.
//!
//! For Phase B every new `VmObject` is hardcoded to `bare_metal_intel`.
//!
//! ## Why kernel-side
//!
//! VM-exits dispatch lookups happen on every guest CPUID, every guest
//! RDMSR, and every EPT violation. Linux boot issues hundreds of CPUIDs
//! and tens of thousands of EPT violations, so a userspace bounce per
//! exit would be catastrophically slow. The plan agent's critique
//! flagged this as the single biggest design risk; we land on the
//! "in-kernel data plane, userspace control plane" split.

/// A single CPUID leaf override. `subleaf` is `0xFFFF_FFFF` to mean
/// "match any subleaf".
#[derive(Debug, Clone, Copy, Default)]
pub struct CpuidSpoof {
    pub leaf: u32,
    pub subleaf: u32,
    pub eax: u32,
    pub ebx: u32,
    pub ecx: u32,
    pub edx: u32,
}

const MAX_CPUID_SPOOFS: usize = 32;

/// Fixed-size CPUID spoof table.
#[derive(Debug, Clone, Copy)]
pub struct CpuidSpoofTable {
    entries: [Option<CpuidSpoof>; MAX_CPUID_SPOOFS],
    count: usize,
}

impl CpuidSpoofTable {
    pub const fn new() -> Self {
        Self {
            entries: [None; MAX_CPUID_SPOOFS],
            count: 0,
        }
    }

    pub fn add(&mut self, spoof: CpuidSpoof) -> bool {
        if self.count >= MAX_CPUID_SPOOFS {
            return false;
        }
        self.entries[self.count] = Some(spoof);
        self.count += 1;
        true
    }

    /// O(n) lookup over `count` populated entries. n ≤ 32 — fine in a
    /// VM-exit handler.
    pub fn lookup(&self, leaf: u32, subleaf: u32) -> Option<&CpuidSpoof> {
        for entry in self.entries[..self.count].iter().flatten() {
            if entry.leaf == leaf
                && (entry.subleaf == subleaf || entry.subleaf == 0xFFFF_FFFF)
            {
                return Some(entry);
            }
        }
        None
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub struct MsrSpoof {
    pub msr: u32,
    pub value: u64,
}

const MAX_MSR_SPOOFS: usize = 16;

#[derive(Debug, Clone, Copy)]
pub struct MsrSpoofTable {
    entries: [Option<MsrSpoof>; MAX_MSR_SPOOFS],
    count: usize,
}

impl MsrSpoofTable {
    pub const fn new() -> Self {
        Self {
            entries: [None; MAX_MSR_SPOOFS],
            count: 0,
        }
    }

    pub fn add(&mut self, spoof: MsrSpoof) -> bool {
        if self.count >= MAX_MSR_SPOOFS {
            return false;
        }
        self.entries[self.count] = Some(spoof);
        self.count += 1;
        true
    }

    pub fn lookup(&self, msr: u32) -> Option<u64> {
        for entry in self.entries[..self.count].iter().flatten() {
            if entry.msr == msr {
                return Some(entry.value);
            }
        }
        None
    }
}

/// Complete deception profile attached to a VM. Mirrors
/// `sot-bhyve::deception::VmDeceptionProfile` field-for-field.
#[derive(Debug, Clone, Copy)]
pub struct KernelDeceptionProfile {
    pub cpuid_spoofs: CpuidSpoofTable,
    pub msr_spoofs: MsrSpoofTable,
    /// Hide the hypervisor bit in CPUID leaf 1, ECX bit 31.
    pub hide_hypervisor: bool,
    /// Offset added to RDTSC results to defeat timing-based detection.
    /// Unused in Phase B (no RDTSC trap yet); Phase B.5+ will wire it.
    pub timing_offset: u64,
}

impl KernelDeceptionProfile {
    /// Mirror of `sot-bhyve::deception::bare_metal_intel`. Cascade Lake
    /// Xeon Platinum 8280, hypervisor bit OFF, hypervisor leaf zero,
    /// `IA32_FEATURE_CONTROL` reports locked-and-disabled.
    pub fn bare_metal_intel() -> Self {
        let mut cpuid = CpuidSpoofTable::new();
        let mut msr = MsrSpoofTable::new();

        // Helper: pack 4 ASCII bytes into a u32 (little-endian register order).
        const fn pack4(a: u8, b: u8, c: u8, d: u8) -> u32 {
            (a as u32) | (b as u32) << 8 | (c as u32) << 16 | (d as u32) << 24
        }

        // Leaf 0: vendor = "GenuineIntel", max leaf = 0x1F
        cpuid.add(CpuidSpoof {
            leaf: 0,
            subleaf: 0,
            eax: 0x0000_001F,
            ebx: pack4(b'G', b'e', b'n', b'u'),
            edx: pack4(b'i', b'n', b'e', b'I'),
            ecx: pack4(b'n', b't', b'e', b'l'),
        });

        // Leaf 1: family/model/stepping for Xeon Platinum 8280 (Cascade Lake)
        // ECX bit 31 (hypervisor) cleared.
        cpuid.add(CpuidSpoof {
            leaf: 1,
            subleaf: 0,
            eax: 0x0005_0657, // Family 6, Model 85, Stepping 7
            ebx: 0x0010_0800,
            ecx: 0x7FFA_3203, // bit 31 OFF
            edx: 0xBFEB_FBFF,
        });

        // Leaf 0x40000000: zeroed (hide hypervisor leaves entirely)
        cpuid.add(CpuidSpoof {
            leaf: 0x4000_0000,
            subleaf: 0,
            eax: 0,
            ebx: 0,
            ecx: 0,
            edx: 0,
        });

        // IA32_FEATURE_CONTROL — locked, VMX-outside-SMX disabled (the
        // attacker should think this box has VT-x off in BIOS).
        msr.add(MsrSpoof {
            msr: 0x3A,
            value: 0x0000_0001,
        });

        // IA32_MISC_ENABLE (0x1A0) — Linux reads this very early in
        // boot to detect speedstep / no-execute / monitor support.
        // The value below matches Cascade Lake Xeon defaults: bits 0
        // (Fast strings), 3 (TM1), 7 (PEBS), 11 (BTS), 12 (PEBS),
        // 16 (Enhanced SpeedStep), 18 (MONITOR/MWAIT), 22 (xTPR
        // disable). Returning this lets Linux's early CPU detection
        // proceed past the rdmsr.
        msr.add(MsrSpoof {
            msr: 0x1A0,
            value: 0x0000_0000_0085_0089,
        });

        // IA32_PLATFORM_ID (0x17) — read by Linux for microcode
        // selection. Cascade Lake reports platform ID = 1 in bits
        // 50..52. We return 0x14_0000_0000_0000 (= bit 52 set).
        msr.add(MsrSpoof {
            msr: 0x17,
            value: 0x0014_0000_0000_0000,
        });

        // IA32_BIOS_SIGN_ID (0x8B) — microcode revision. Linux reads
        // this and prints "microcode: revision 0x..." Cascade Lake
        // ucode rev 0x500003c is current at the time of writing.
        msr.add(MsrSpoof {
            msr: 0x8B,
            value: 0x0500_003c_0000_0000,
        });

        // IA32_TSC (0x10) — read for time calibration. Returning 0
        // is fine; Linux uses RDTSC directly for the hot path.
        msr.add(MsrSpoof {
            msr: 0x10,
            value: 0,
        });

        Self {
            cpuid_spoofs: cpuid,
            msr_spoofs: msr,
            hide_hypervisor: true,
            timing_offset: 0,
        }
    }

    /// Handle a CPUID VM-exit. Returns `Some((eax, ebx, ecx, edx))` if
    /// a spoof entry matched; the caller writes those into the guest
    /// GPRs and resumes. `None` falls through to passthrough.
    pub fn handle_cpuid(&self, leaf: u32, subleaf: u32) -> Option<(u32, u32, u32, u32)> {
        self.cpuid_spoofs
            .lookup(leaf, subleaf)
            .map(|e| (e.eax, e.ebx, e.ecx, e.edx))
    }

    /// Handle an RDMSR VM-exit. Returns the spoofed value, or `None`
    /// to passthrough to host MSR (or inject #GP).
    pub fn handle_msr_read(&self, msr: u32) -> Option<u64> {
        self.msr_spoofs.lookup(msr)
    }
}
