//! VM-level deception: CPUID spoofing, MSR spoofing, and built-in
//! profiles that make the guest believe it runs on real hardware.

/// A single CPUID leaf override.
#[derive(Debug, Clone, Copy)]
pub struct CpuidSpoof {
    pub leaf: u32,
    pub subleaf: u32,
    pub eax: u32,
    pub ebx: u32,
    pub ecx: u32,
    pub edx: u32,
}

/// Table of CPUID overrides applied on every CPUID VM-exit.
pub struct CpuidSpoofTable {
    pub entries: [Option<CpuidSpoof>; 32],
    pub count: usize,
}

impl CpuidSpoofTable {
    pub const fn new() -> Self {
        Self {
            entries: [None; 32],
            count: 0,
        }
    }

    /// Insert a spoof entry. Returns `false` if the table is full.
    pub fn add(&mut self, spoof: CpuidSpoof) -> bool {
        if self.count >= self.entries.len() {
            return false;
        }
        self.entries[self.count] = Some(spoof);
        self.count += 1;
        true
    }

    /// Look up an override for the given leaf/subleaf.
    pub fn lookup(&self, leaf: u32, subleaf: u32) -> Option<&CpuidSpoof> {
        for entry in &self.entries[..self.count] {
            if let Some(e) = entry {
                if e.leaf == leaf && e.subleaf == subleaf {
                    return Some(e);
                }
            }
        }
        None
    }
}

/// A single MSR override.
#[derive(Debug, Clone, Copy)]
pub struct MsrSpoof {
    pub msr: u32,
    pub value: u64,
}

/// Table of MSR overrides applied on RDMSR VM-exits.
pub struct MsrSpoofTable {
    pub entries: [Option<MsrSpoof>; 16],
    pub count: usize,
}

impl MsrSpoofTable {
    pub const fn new() -> Self {
        Self {
            entries: [None; 16],
            count: 0,
        }
    }

    /// Insert a spoof entry. Returns `false` if the table is full.
    pub fn add(&mut self, spoof: MsrSpoof) -> bool {
        if self.count >= self.entries.len() {
            return false;
        }
        self.entries[self.count] = Some(spoof);
        self.count += 1;
        true
    }

    /// Look up an override for the given MSR index.
    pub fn lookup(&self, msr: u32) -> Option<u64> {
        for entry in &self.entries[..self.count] {
            if let Some(e) = entry {
                if e.msr == msr {
                    return Some(e.value);
                }
            }
        }
        None
    }
}

/// Complete deception profile attached to a VM domain.
pub struct VmDeceptionProfile {
    pub cpuid_spoofs: CpuidSpoofTable,
    pub msr_spoofs: MsrSpoofTable,
    /// Hide hypervisor bit in CPUID leaf 1, ECX bit 31.
    pub hide_hypervisor: bool,
    /// Offset added to RDTSC to prevent timing-based detection.
    pub timing_offset: u64,
    /// Fake BIOS vendor string returned via SMBIOS/CPUID.
    pub bios_vendor: [u8; 32],
    pub bios_vendor_len: usize,
}

// Helper: write a byte slice into a fixed-size array, returning length.
fn fill_vendor(buf: &mut [u8; 32], src: &[u8]) -> usize {
    let len = if src.len() > 32 { 32 } else { src.len() };
    let mut i = 0;
    while i < len {
        buf[i] = src[i];
        i += 1;
    }
    len
}

// Helper: pack 4 ASCII bytes into a u32 (little-endian register order).
const fn pack4(a: u8, b: u8, c: u8, d: u8) -> u32 {
    (a as u32) | (b as u32) << 8 | (c as u32) << 16 | (d as u32) << 24
}

impl VmDeceptionProfile {
    // --- Built-in profiles ---------------------------------------------------

    /// Looks like a physical Intel Xeon Platinum running bare-metal.
    pub fn bare_metal_intel() -> Self {
        let mut cpuid = CpuidSpoofTable::new();
        let mut msr = MsrSpoofTable::new();

        // Leaf 0: vendor = "GenuineIntel", max leaf = 0x1F
        cpuid.add(CpuidSpoof {
            leaf: 0,
            subleaf: 0,
            eax: 0x0000_001F,
            ebx: pack4(b'G', b'e', b'n', b'u'),
            edx: pack4(b'i', b'n', b'e', b'I'),
            ecx: pack4(b'n', b't', b'e', b'l'),
        });

        // Leaf 1: family/model/stepping for Xeon Platinum 8280
        // ECX: clear bit 31 (hypervisor), set SSE4.2/AVX/etc.
        cpuid.add(CpuidSpoof {
            leaf: 1,
            subleaf: 0,
            eax: 0x0005_0657, // Family 6, Model 85, Stepping 7 (Cascade Lake)
            ebx: 0x0010_0800, // 1 logical proc, CLFLUSH 8, APIC id 0
            ecx: 0x7FFA_3203, // SSE3, SSE4.1/2, AVX, AES, PCLMUL -- bit 31 OFF
            edx: 0xBFEB_FBFF,
        });

        // Leaf 0x40000000: return 0 (no hypervisor leaves)
        cpuid.add(CpuidSpoof {
            leaf: 0x4000_0000,
            subleaf: 0,
            eax: 0,
            ebx: 0,
            ecx: 0,
            edx: 0,
        });

        // IA32_FEATURE_CONTROL -- locked, VMX outside SMX disabled
        msr.add(MsrSpoof {
            msr: 0x3A,
            value: 0x0000_0001,
        });

        let mut bios_vendor = [0u8; 32];
        let len = fill_vendor(&mut bios_vendor, b"Intel Corporation");

        Self {
            cpuid_spoofs: cpuid,
            msr_spoofs: msr,
            hide_hypervisor: true,
            timing_offset: 0,
            bios_vendor,
            bios_vendor_len: len,
        }
    }

    /// Looks like a physical AMD EPYC 7763 running bare-metal.
    pub fn bare_metal_amd() -> Self {
        let mut cpuid = CpuidSpoofTable::new();
        let mut msr = MsrSpoofTable::new();

        // Leaf 0: vendor = "AuthenticAMD", max leaf = 0x10
        cpuid.add(CpuidSpoof {
            leaf: 0,
            subleaf: 0,
            eax: 0x0000_0010,
            ebx: pack4(b'A', b'u', b't', b'h'),
            edx: pack4(b'e', b'n', b't', b'i'),
            ecx: pack4(b'c', b'A', b'M', b'D'),
        });

        // Leaf 1: family/model for EPYC 7763 (Zen 3, Milan)
        cpuid.add(CpuidSpoof {
            leaf: 1,
            subleaf: 0,
            eax: 0x00A0_0F11, // Family 0x19, Model 0x01
            ebx: 0x0010_0800,
            ecx: 0x7EDA_3209, // bit 31 OFF
            edx: 0x178B_FBFF,
        });

        cpuid.add(CpuidSpoof {
            leaf: 0x4000_0000,
            subleaf: 0,
            eax: 0,
            ebx: 0,
            ecx: 0,
            edx: 0,
        });

        // AMD-specific: SYSCFG MSR
        msr.add(MsrSpoof {
            msr: 0xC001_0010,
            value: 0x0000_0000_0014_0000,
        });

        let mut bios_vendor = [0u8; 32];
        let len = fill_vendor(&mut bios_vendor, b"AMD Corporation");

        Self {
            cpuid_spoofs: cpuid,
            msr_spoofs: msr,
            hide_hypervisor: true,
            timing_offset: 0,
            bios_vendor,
            bios_vendor_len: len,
        }
    }

    /// Nested deception: looks like the guest is inside VMware.
    pub fn vmware_guest() -> Self {
        let mut cpuid = CpuidSpoofTable::new();

        // Leaf 0: still Intel vendor
        cpuid.add(CpuidSpoof {
            leaf: 0,
            subleaf: 0,
            eax: 0x0000_0016,
            ebx: pack4(b'G', b'e', b'n', b'u'),
            edx: pack4(b'i', b'n', b'e', b'I'),
            ecx: pack4(b'n', b't', b'e', b'l'),
        });

        // Leaf 1: hypervisor bit SET (bit 31 of ECX)
        cpuid.add(CpuidSpoof {
            leaf: 1,
            subleaf: 0,
            eax: 0x0005_0657,
            ebx: 0x0010_0800,
            ecx: 0xFFFA_3203, // bit 31 ON
            edx: 0xBFEB_FBFF,
        });

        // Leaf 0x40000000: VMware hypervisor identification
        cpuid.add(CpuidSpoof {
            leaf: 0x4000_0000,
            subleaf: 0,
            eax: 0x4000_000A, // max hypervisor leaf
            ebx: pack4(b'V', b'M', b'w', b'a'),
            ecx: pack4(b'r', b'e', b'V', b'M'),
            edx: pack4(b'w', b'a', b'r', b'e'),
        });

        // Leaf 0x40000010: VMware timing info (TSC freq, bus freq)
        cpuid.add(CpuidSpoof {
            leaf: 0x4000_0010,
            subleaf: 0,
            eax: 3000, // TSC kHz / 1000
            ebx: 1000, // bus kHz / 1000
            ecx: 0,
            edx: 0,
        });

        let mut bios_vendor = [0u8; 32];
        let len = fill_vendor(&mut bios_vendor, b"Phoenix Technologies");

        Self {
            cpuid_spoofs: cpuid,
            msr_spoofs: MsrSpoofTable::new(),
            hide_hypervisor: false, // hypervisor bit intentionally ON
            timing_offset: 0,
            bios_vendor,
            bios_vendor_len: len,
        }
    }

    /// Handle a CPUID VM-exit: apply spoofing if a matching entry exists.
    /// Returns `Some((eax, ebx, ecx, edx))` when spoofed, `None` to
    /// pass through to real hardware.
    pub fn handle_cpuid(&self, leaf: u32, subleaf: u32) -> Option<(u32, u32, u32, u32)> {
        if let Some(e) = self.cpuid_spoofs.lookup(leaf, subleaf) {
            return Some((e.eax, e.ebx, e.ecx, e.edx));
        }
        None
    }

    /// Handle an RDMSR VM-exit: return spoofed value if present.
    pub fn handle_msr_read(&self, msr: u32) -> Option<u64> {
        self.msr_spoofs.lookup(msr)
    }
}
