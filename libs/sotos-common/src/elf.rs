//! Userspace ELF64 parser.
//!
//! Parses ELF64 headers and program headers without loading — the caller
//! is responsible for mapping segments into the target address space.

/// Information about a parsed ELF binary.
pub struct ElfInfo {
    /// Entry point virtual address.
    pub entry: u64,
    /// Program header offset in the ELF data.
    pub phoff: usize,
    /// Size of each program header entry.
    pub phentsize: usize,
    /// Number of program headers.
    pub phnum: usize,
    /// ELF type: 2 = ET_EXEC, 3 = ET_DYN.
    pub elf_type: u16,
}

/// A single PT_LOAD segment.
pub struct LoadSegment {
    /// File offset of segment data.
    pub offset: usize,
    /// Virtual address to load at.
    pub vaddr: u64,
    /// Size of data in the file.
    pub filesz: usize,
    /// Size in memory (may be > filesz for BSS).
    pub memsz: usize,
    /// Segment flags (PF_X=1, PF_W=2, PF_R=4).
    pub flags: u32,
}

// ELF64 header offsets.
const EI_MAG: usize = 0;
const EI_CLASS: usize = 4;
const EI_DATA: usize = 5;
const E_TYPE: usize = 16;
const E_MACHINE: usize = 18;
const E_ENTRY: usize = 24;
const E_PHOFF: usize = 32;
const E_PHENTSIZE: usize = 54;
const E_PHNUM: usize = 56;

// Program header offsets (relative to phdr start).
const P_TYPE: usize = 0;
const P_FLAGS: usize = 4;
const P_OFFSET: usize = 8;
const P_VADDR: usize = 16;
const P_FILESZ: usize = 32;
const P_MEMSZ: usize = 40;

const PT_LOAD: u32 = 1;
const PT_DYNAMIC: u32 = 2;

fn read_u16(data: &[u8], off: usize) -> u16 {
    u16::from_le_bytes([data[off], data[off + 1]])
}

fn read_u32(data: &[u8], off: usize) -> u32 {
    u32::from_le_bytes([data[off], data[off + 1], data[off + 2], data[off + 3]])
}

fn read_u64(data: &[u8], off: usize) -> u64 {
    u64::from_le_bytes([
        data[off], data[off + 1], data[off + 2], data[off + 3],
        data[off + 4], data[off + 5], data[off + 6], data[off + 7],
    ])
}

/// Parse an ELF64 binary. Accepts ET_EXEC (type 2) and ET_DYN (type 3).
pub fn parse(data: &[u8]) -> Result<ElfInfo, &'static str> {
    if data.len() < 64 {
        return Err("ELF too small");
    }
    if &data[EI_MAG..EI_MAG + 4] != b"\x7fELF" {
        return Err("bad ELF magic");
    }
    if data[EI_CLASS] != 2 {
        return Err("not ELF64");
    }
    if data[EI_DATA] != 1 {
        return Err("not little-endian");
    }
    let elf_type = read_u16(data, E_TYPE);
    if elf_type != 2 && elf_type != 3 {
        return Err("not ET_EXEC or ET_DYN");
    }
    if read_u16(data, E_MACHINE) != 62 {
        return Err("not x86_64");
    }

    Ok(ElfInfo {
        entry: read_u64(data, E_ENTRY),
        phoff: read_u64(data, E_PHOFF) as usize,
        phentsize: read_u16(data, E_PHENTSIZE) as usize,
        phnum: read_u16(data, E_PHNUM) as usize,
        elf_type,
    })
}

/// Maximum number of PT_LOAD segments we support.
pub const MAX_LOAD_SEGMENTS: usize = 8;

/// Extract all PT_LOAD segments from a parsed ELF.
/// Returns the number of segments written to `out`.
pub fn load_segments(data: &[u8], info: &ElfInfo, out: &mut [LoadSegment; MAX_LOAD_SEGMENTS]) -> usize {
    let mut count = 0;
    for i in 0..info.phnum {
        let ph = info.phoff + i * info.phentsize;
        if ph + info.phentsize > data.len() {
            break;
        }
        let p_type = read_u32(data, ph + P_TYPE);
        if p_type != PT_LOAD {
            continue;
        }
        if count >= MAX_LOAD_SEGMENTS {
            break;
        }
        out[count] = LoadSegment {
            offset: read_u64(data, ph + P_OFFSET) as usize,
            vaddr: read_u64(data, ph + P_VADDR),
            filesz: read_u64(data, ph + P_FILESZ) as usize,
            memsz: read_u64(data, ph + P_MEMSZ) as usize,
            flags: read_u32(data, ph + P_FLAGS),
        };
        count += 1;
    }
    count
}

/// Dynamic linking information parsed from PT_DYNAMIC.
pub struct DynamicInfo {
    /// DT_RELA: offset of .rela.dyn section.
    pub rela: u64,
    /// DT_RELASZ: size of .rela.dyn in bytes.
    pub relasz: u64,
    /// DT_RELAENT: size of each Rela entry (typically 24).
    pub relaent: u64,
    /// DT_JMPREL: offset of .rela.plt section.
    pub jmprel: u64,
    /// DT_PLTRELSZ: size of .rela.plt in bytes.
    pub pltrelsz: u64,
    /// DT_SYMTAB: address of .dynsym.
    pub symtab: u64,
    /// DT_STRTAB: address of .dynstr.
    pub strtab: u64,
    /// DT_STRSZ: size of .dynstr.
    pub strsz: u64,
    /// DT_GNU_HASH: address of GNU hash table.
    pub gnu_hash: u64,
    /// DT_INIT_ARRAY: address of init function array.
    pub init_array: u64,
    /// DT_INIT_ARRAYSZ: size of init array in bytes.
    pub init_arraysz: u64,
}

impl DynamicInfo {
    pub const fn empty() -> Self {
        Self {
            rela: 0, relasz: 0, relaent: 0,
            jmprel: 0, pltrelsz: 0,
            symtab: 0, strtab: 0, strsz: 0,
            gnu_hash: 0,
            init_array: 0, init_arraysz: 0,
        }
    }
}

// DT_* tag values.
const DT_NULL: u64 = 0;
const DT_RELA: u64 = 7;
const DT_RELASZ: u64 = 8;
const DT_RELAENT: u64 = 9;
const DT_STRTAB: u64 = 5;
const DT_SYMTAB: u64 = 6;
const DT_STRSZ: u64 = 10;
const DT_JMPREL: u64 = 23;
const DT_PLTRELSZ: u64 = 2;
const DT_GNU_HASH: u64 = 0x6ffffef5;
const DT_INIT_ARRAY: u64 = 25;
const DT_INIT_ARRAYSZ: u64 = 27;

/// Parse the PT_DYNAMIC segment to extract dynamic linking info.
/// `data` is the full ELF file, `info` is the parsed header.
/// Returns None if no PT_DYNAMIC segment exists.
pub fn parse_dynamic(data: &[u8], info: &ElfInfo) -> Option<DynamicInfo> {
    // Find the PT_DYNAMIC program header.
    let mut dyn_offset = 0usize;
    let mut dyn_size = 0usize;
    let mut found = false;

    for i in 0..info.phnum {
        let ph = info.phoff + i * info.phentsize;
        if ph + info.phentsize > data.len() {
            break;
        }
        if read_u32(data, ph + P_TYPE) == PT_DYNAMIC {
            dyn_offset = read_u64(data, ph + P_OFFSET) as usize;
            dyn_size = read_u64(data, ph + P_FILESZ) as usize;
            found = true;
            break;
        }
    }

    if !found {
        return None;
    }

    let mut dinfo = DynamicInfo::empty();
    let entry_size = 16; // sizeof(Elf64_Dyn) = 8 (tag) + 8 (val)
    let mut pos = dyn_offset;
    let end = dyn_offset + dyn_size;

    while pos + entry_size <= end && pos + entry_size <= data.len() {
        let tag = read_u64(data, pos);
        let val = read_u64(data, pos + 8);
        match tag {
            DT_NULL => break,
            DT_RELA => dinfo.rela = val,
            DT_RELASZ => dinfo.relasz = val,
            DT_RELAENT => dinfo.relaent = val,
            DT_STRTAB => dinfo.strtab = val,
            DT_SYMTAB => dinfo.symtab = val,
            DT_STRSZ => dinfo.strsz = val,
            DT_JMPREL => dinfo.jmprel = val,
            DT_PLTRELSZ => dinfo.pltrelsz = val,
            DT_GNU_HASH => dinfo.gnu_hash = val,
            DT_INIT_ARRAY => dinfo.init_array = val,
            DT_INIT_ARRAYSZ => dinfo.init_arraysz = val,
            _ => {}
        }
        pos += entry_size;
    }

    Some(dinfo)
}
