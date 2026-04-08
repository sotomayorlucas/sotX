//! HAMMER2 volume header and block reference types.

/// Block type in the HAMMER2 B-tree.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlockType {
    Volume,
    Freemap,
    Inode,
    Data,
    IndirectBlock,
}

/// Block reference in the HAMMER2 B-tree.
#[derive(Debug, Clone, Copy)]
pub struct BlockRef {
    /// Physical offset of the data on disk.
    pub data_offset: u64,
    /// Lookup key for this block reference.
    pub key: u64,
    /// Transaction ID that last wrote this block.
    pub mirror_tid: u64,
    /// Block type.
    pub block_type: BlockType,
    /// Compression method (0 = none).
    pub methods: u8,
    /// Checksum algorithm (0 = none, 1 = xxhash64, 2 = sha256).
    pub check_algo: u8,
}

impl BlockRef {
    /// Create an empty (zeroed) block reference.
    pub fn empty() -> Self {
        Self {
            data_offset: 0,
            key: 0,
            mirror_tid: 0,
            block_type: BlockType::Data,
            methods: 0,
            check_algo: 0,
        }
    }
}

/// HAMMER2 volume -- CoW B-tree filesystem with instant snapshots.
pub struct Hammer2Volume {
    pub name: [u8; 32],
    pub name_len: usize,
    /// SOT capability for the underlying block device.
    pub block_cap: u64,
    /// Root of the B-tree.
    pub root_blockref: BlockRef,
    /// Number of free blocks.
    pub free_count: u64,
    /// Total number of blocks.
    pub total_count: u64,
    /// Number of snapshots.
    pub snapshot_count: u32,
}

impl Hammer2Volume {
    /// Create a new volume with the given name and block device capability.
    pub fn new(name_bytes: &[u8], block_cap: u64, total_blocks: u64) -> Self {
        let mut name = [0u8; 32];
        let name_len = name_bytes.len().min(32);
        name[..name_len].copy_from_slice(&name_bytes[..name_len]);

        Self {
            name,
            name_len,
            block_cap,
            root_blockref: BlockRef {
                data_offset: 0,
                key: 0,
                mirror_tid: 1,
                block_type: BlockType::Volume,
                methods: 0,
                check_algo: 1,
            },
            free_count: total_blocks,
            total_count: total_blocks,
            snapshot_count: 0,
        }
    }

    /// Return the volume name as a byte slice.
    pub fn name(&self) -> &[u8] {
        &self.name[..self.name_len]
    }

    /// Advance the root mirror_tid (transaction ID).
    pub fn advance_tid(&mut self) -> u64 {
        self.root_blockref.mirror_tid += 1;
        self.root_blockref.mirror_tid
    }

    /// Allocate `count` blocks. Returns false if insufficient free blocks.
    pub fn alloc_blocks(&mut self, count: u64) -> bool {
        if count > self.free_count {
            return false;
        }
        self.free_count -= count;
        true
    }

    /// Free `count` blocks.
    pub fn free_blocks(&mut self, count: u64) {
        self.free_count = (self.free_count + count).min(self.total_count);
    }
}
