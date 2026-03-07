#!/usr/bin/env python3
"""Create a sotOS ObjectStore v5 disk image.

Modes:
  - Default (no --rootfs): Creates a small empty formatted disk.
  - With --rootfs <dir>: Injects directory tree into the disk as ObjectStore entries.

Layout (v5):
  Sector 0:        Superblock
  Sector 1:        WAL header
  Sectors 2-5:     WAL payload (4 sectors)
  Sectors 6-133:   Bitmap (128 sectors = 65536 bytes)
  Sectors 134-645: Directory (512 sectors = 2048 entries)
  Sectors 646-661: Refcount (16 sectors = 8192 entries)
  Sectors 662-665: Snap meta (4 sectors)
  Sectors 666-2713:  Snap dirs (4 x 512 sectors)
  Sectors 2714-3225: Snap bitmaps (4 x 128 sectors)
  Sector 3226+:    Data region

Usage:
  python scripts/mkdisk.py [--output target/disk.img] [--size 256] [--rootfs ./rootfs]
"""

import argparse
import os
import struct
import time

# ── Layout constants (must match layout.rs v5) ──────────────────────────
SECTOR_SIZE        = 512
FS_VERSION         = 5
SUPERBLOCK_MAGIC   = 0x534F544F_53465321  # "SOTOS_FS!"
WAL_MAGIC          = 0x57414C48           # "WALH"

SECTOR_SUPERBLOCK  = 0
SECTOR_WAL_HEADER  = 1
SECTOR_WAL_PAYLOAD = 2
WAL_MAX_ENTRIES    = 4
SECTOR_BITMAP      = 6
BITMAP_SECTORS     = 128
SECTOR_DIR         = 134
DIR_SECTORS        = 512
DIR_ENTRIES_PER_SECTOR = 4
DIR_ENTRY_COUNT    = DIR_SECTORS * DIR_ENTRIES_PER_SECTOR  # 2048
SECTOR_REFCOUNT    = 646
REFCOUNT_SECTORS   = 16
REFCOUNT_ENTRIES   = REFCOUNT_SECTORS * SECTOR_SIZE       # 8192
SECTOR_SNAP_META   = 662
MAX_SNAPSHOTS      = 4
SECTOR_SNAP_DIR    = 666
SECTOR_SNAP_BMP    = 2714
SECTOR_DATA        = 3226

BITMAP_BYTES       = BITMAP_SECTORS * SECTOR_SIZE         # 65536
MAX_NAME_LEN       = 48
FLAG_DIR           = 1
ROOT_OID           = 1
DEFAULT_DIR_PERMS  = 0o755
DEFAULT_FILE_PERMS = 0o644

# DirEntry layout (128 bytes, #[repr(C)]):
#   0: oid (u64)
#   8: name ([u8; 48])
#  56: size (u64)
#  64: sector_start (u32)
#  68: sector_count (u32)
#  72: flags (u32)
#  76: created_time (u64)
#  84: modified_time (u64)
#  92: accessed_time (u64)
# 100: parent_oid (u64)
# 108: permissions (u32)
# 112: owner_uid (u16)
# 114: owner_gid (u16)
# 116: _pad (12 bytes)
DIRENTRY_FMT = '<Q48sQIIIQQQQIHH8s'
DIRENTRY_SIZE = 128

# Superblock layout (512 bytes):
#   0: magic (u64)
#   8: version (u32)
#  12: total_sectors (u32)
#  16: data_start (u32)
#  20: data_count (u32)
#  24: bitmap_start (u32)
#  28: dir_start (u32)
#  32: dir_sectors (u32)
#  36: next_oid (u64)
#  44: obj_count (u32)
#  48: _pad (464 bytes)
SUPERBLOCK_FMT = '<QIIIIIIQIH'  # note: padding after obj_count is manual


def sectors_for(size):
    """Number of 512-byte sectors needed for `size` bytes."""
    return (size + SECTOR_SIZE - 1) // SECTOR_SIZE


def make_direntry(oid, name_bytes, size, sector_start, sector_count,
                  flags, parent_oid, permissions, uid=0, gid=0):
    """Pack a 128-byte DirEntry matching #[repr(C)] layout."""
    buf = bytearray(DIRENTRY_SIZE)
    name = name_bytes[:MAX_NAME_LEN - 1]
    now = int(time.time())
    struct.pack_into('<Q', buf, 0, oid)
    buf[8:8 + len(name)] = name
    struct.pack_into('<Q', buf, 56, size)
    struct.pack_into('<I', buf, 64, sector_start)
    struct.pack_into('<I', buf, 68, sector_count)
    struct.pack_into('<I', buf, 72, flags)
    # 4 bytes implicit padding at 76 (align u64 created_time)
    struct.pack_into('<Q', buf, 80, now)
    struct.pack_into('<Q', buf, 88, now)
    struct.pack_into('<Q', buf, 96, now)
    struct.pack_into('<Q', buf, 104, parent_oid)
    struct.pack_into('<I', buf, 112, permissions)
    struct.pack_into('<H', buf, 116, uid)
    struct.pack_into('<H', buf, 118, gid)
    # 8 bytes _pad at 120 (already zeroed)
    return bytes(buf)


def make_superblock(total_sectors, data_count, next_oid, obj_count):
    """Pack a 512-byte Superblock matching #[repr(C)] layout."""
    sb = bytearray(SECTOR_SIZE)
    struct.pack_into('<Q', sb, 0, SUPERBLOCK_MAGIC)
    struct.pack_into('<I', sb, 8, FS_VERSION)
    struct.pack_into('<I', sb, 12, total_sectors)
    struct.pack_into('<I', sb, 16, SECTOR_DATA)
    struct.pack_into('<I', sb, 20, data_count)
    struct.pack_into('<I', sb, 24, SECTOR_BITMAP)
    struct.pack_into('<I', sb, 28, SECTOR_DIR)
    struct.pack_into('<I', sb, 32, DIR_SECTORS)
    struct.pack_into('<Q', sb, 36, next_oid)
    struct.pack_into('<I', sb, 44, obj_count)
    return bytes(sb)


def make_wal_header():
    """Pack a 512-byte WAL header (empty)."""
    wal = bytearray(SECTOR_SIZE)
    struct.pack_into('<I', wal, 0, WAL_MAGIC)
    return bytes(wal)


class DiskBuilder:
    """Builds a raw disk image in ObjectStore v5 format."""

    def __init__(self, disk_size_mb):
        self.disk_size = disk_size_mb * 1024 * 1024
        self.total_sectors = self.disk_size // SECTOR_SIZE
        self.data_count = self.total_sectors - SECTOR_DATA
        self.data = bytearray(self.disk_size)

        # In-memory metadata
        self.dir_entries = []   # list of 128-byte packed entries
        self.next_oid = 2       # 1 reserved for root
        self.obj_count = 1      # root counts
        self.bitmap = bytearray(BITMAP_BYTES)
        self.next_block = 0     # next free data block

        # Create root directory entry
        root = make_direntry(
            oid=ROOT_OID, name_bytes=b'/', size=0,
            sector_start=0, sector_count=0, flags=FLAG_DIR,
            parent_oid=0, permissions=DEFAULT_DIR_PERMS
        )
        self.dir_entries.append(root)

    def alloc_blocks(self, count):
        """Allocate contiguous data blocks. Returns start block index."""
        if count == 0:
            return 0
        start = self.next_block
        if start + count > self.data_count:
            raise RuntimeError(f"Disk full: need {count} blocks at {start}, "
                               f"only {self.data_count} total")
        # Mark bitmap
        for b in range(start, start + count):
            byte_idx = b // 8
            bit_idx = b % 8
            self.bitmap[byte_idx] |= (1 << bit_idx)
        self.next_block = start + count
        return start

    def write_data(self, block_start, file_data):
        """Write file data to the data region."""
        abs_sector = SECTOR_DATA + block_start
        offset = abs_sector * SECTOR_SIZE
        # Write full sectors, zero-pad last
        for i in range(0, len(file_data), SECTOR_SIZE):
            chunk = file_data[i:i + SECTOR_SIZE]
            self.data[offset:offset + len(chunk)] = chunk
            offset += SECTOR_SIZE

    def add_file(self, name, file_data, parent_oid, permissions=DEFAULT_FILE_PERMS,
                 uid=0, gid=0):
        """Add a file to the filesystem. Returns OID."""
        if len(self.dir_entries) >= DIR_ENTRY_COUNT:
            raise RuntimeError(f"Directory full ({DIR_ENTRY_COUNT} entries)")

        name_bytes = name.encode('utf-8') if isinstance(name, str) else name
        if len(name_bytes) >= MAX_NAME_LEN:
            # Truncate — filesystem limitation
            name_bytes = name_bytes[:MAX_NAME_LEN - 1]

        size = len(file_data)
        count = sectors_for(size)
        start = self.alloc_blocks(count)
        if size > 0:
            self.write_data(start, file_data)

        oid = self.next_oid
        self.next_oid += 1
        self.obj_count += 1

        entry = make_direntry(
            oid=oid, name_bytes=name_bytes, size=size,
            sector_start=start, sector_count=count, flags=0,
            parent_oid=parent_oid, permissions=permissions,
            uid=uid, gid=gid
        )
        self.dir_entries.append(entry)
        return oid

    def add_dir(self, name, parent_oid, permissions=DEFAULT_DIR_PERMS):
        """Add a directory entry. Returns OID."""
        if len(self.dir_entries) >= DIR_ENTRY_COUNT:
            raise RuntimeError(f"Directory full ({DIR_ENTRY_COUNT} entries)")

        name_bytes = name.encode('utf-8') if isinstance(name, str) else name
        if len(name_bytes) >= MAX_NAME_LEN:
            name_bytes = name_bytes[:MAX_NAME_LEN - 1]

        oid = self.next_oid
        self.next_oid += 1
        self.obj_count += 1

        entry = make_direntry(
            oid=oid, name_bytes=name_bytes, size=0,
            sector_start=0, sector_count=0, flags=FLAG_DIR,
            parent_oid=parent_oid, permissions=permissions
        )
        self.dir_entries.append(entry)
        return oid

    def inject_rootfs(self, rootfs_path):
        """Recursively inject a directory tree into the filesystem."""
        rootfs_path = os.path.normpath(rootfs_path)
        # Map from host directory path → OID
        dir_oids = {rootfs_path: ROOT_OID}

        total_files = 0
        total_bytes = 0
        skipped = 0

        for dirpath, dirnames, filenames in os.walk(rootfs_path):
            parent_oid = dir_oids.get(dirpath, ROOT_OID)

            # Create subdirectories
            for dname in sorted(dirnames):
                full = os.path.join(dirpath, dname)
                try:
                    oid = self.add_dir(dname, parent_oid)
                    dir_oids[full] = oid
                except RuntimeError:
                    skipped += 1
                    # Remove from dirnames to prevent os.walk from descending
                    dirnames.remove(dname)

            # Create files
            for fname in sorted(filenames):
                full = os.path.join(dirpath, fname)
                # Skip symlinks — resolve to target if possible
                if os.path.islink(full):
                    target = os.readlink(full)
                    # Store symlink as a small file containing the target path
                    target_bytes = target.encode('utf-8')
                    try:
                        self.add_file(fname, target_bytes, parent_oid,
                                      permissions=0o777)
                        total_files += 1
                        total_bytes += len(target_bytes)
                    except RuntimeError:
                        skipped += 1
                    continue

                try:
                    with open(full, 'rb') as f:
                        data = f.read()
                except (PermissionError, OSError):
                    skipped += 1
                    continue

                try:
                    self.add_file(fname, data, parent_oid)
                    total_files += 1
                    total_bytes += len(data)
                except RuntimeError:
                    skipped += 1

        print(f"  Injected: {total_files} files, {len(dir_oids)-1} dirs, "
              f"{total_bytes:,} bytes data")
        if skipped:
            print(f"  Skipped: {skipped} (directory full or read error)")

    def finalize(self):
        """Write all metadata to the disk image."""
        # Superblock
        sb = make_superblock(self.total_sectors, self.data_count,
                             self.next_oid, self.obj_count)
        self.data[0:SECTOR_SIZE] = sb

        # WAL header
        wal = make_wal_header()
        self.data[SECTOR_SIZE:2 * SECTOR_SIZE] = wal

        # Bitmap
        bmp_offset = SECTOR_BITMAP * SECTOR_SIZE
        self.data[bmp_offset:bmp_offset + BITMAP_BYTES] = self.bitmap

        # Directory entries
        dir_offset = SECTOR_DIR * SECTOR_SIZE
        for i, entry in enumerate(self.dir_entries):
            off = dir_offset + i * DIRENTRY_SIZE
            self.data[off:off + DIRENTRY_SIZE] = entry
        # Zero remaining entries
        remaining = DIR_ENTRY_COUNT - len(self.dir_entries)
        if remaining > 0:
            off = dir_offset + len(self.dir_entries) * DIRENTRY_SIZE
            end = dir_offset + DIR_ENTRY_COUNT * DIRENTRY_SIZE
            self.data[off:end] = b'\x00' * (end - off)

        # Refcount (set 1 for all allocated blocks)
        rc_offset = SECTOR_REFCOUNT * SECTOR_SIZE
        for i in range(min(self.next_block, REFCOUNT_ENTRIES)):
            self.data[rc_offset + i] = 1

        # Snap meta (zeroed)
        # Already zeroed from bytearray init.

        # ── Embed FAT32 test partition at end of disk ──────────────
        # MBR partition table (bytes 446-511) doesn't overlap ObjectStore
        # superblock (bytes 0-48), so both coexist in sector 0.
        fat32_sectors = 131072  # 64 MiB
        fat32_start = self.total_sectors - fat32_sectors
        if fat32_start > SECTOR_DATA + 10000:
            self._embed_fat32(fat32_start, fat32_sectors)

    def _embed_fat32(self, part_start, part_sectors):
        """Write MBR partition entry + minimal FAT32 filesystem at end of disk."""
        # MBR partition entry 1 (bytes 446-461 of sector 0)
        e = bytearray(16)
        e[4] = 0x0C  # FAT32 LBA
        struct.pack_into('<I', e, 8, part_start)
        struct.pack_into('<I', e, 12, part_sectors)
        self.data[446:462] = e
        self.data[510] = 0x55
        self.data[511] = 0xAA

        reserved = 32
        num_fats = 2
        spc = 1  # 1 sector/cluster → guaranteed FAT32 (>65525 clusters)
        total = part_sectors
        # FAT size: 4 bytes per cluster entry
        fat_sectors = ((total - reserved) * 4 // (512 * spc + 4 * num_fats)) + 1
        clusters = (total - reserved - fat_sectors * num_fats) // spc

        off = part_start * SECTOR_SIZE

        # BPB
        bpb = bytearray(512)
        bpb[0:3] = b'\xEB\x58\x90'
        bpb[3:11] = b'sotOS   '
        struct.pack_into('<H', bpb, 11, 512)       # bytes/sector
        bpb[13] = spc
        struct.pack_into('<H', bpb, 14, reserved)   # reserved sectors
        bpb[16] = num_fats
        bpb[21] = 0xF8                              # media
        struct.pack_into('<H', bpb, 24, 63)          # sectors/track
        struct.pack_into('<H', bpb, 26, 255)         # heads
        struct.pack_into('<I', bpb, 28, part_start)  # hidden sectors
        struct.pack_into('<I', bpb, 32, total)       # total sectors
        struct.pack_into('<I', bpb, 36, fat_sectors) # FAT size
        struct.pack_into('<I', bpb, 44, 2)           # root cluster
        struct.pack_into('<H', bpb, 48, 1)           # FSInfo
        struct.pack_into('<H', bpb, 50, 6)           # backup boot
        bpb[66] = 0x29
        struct.pack_into('<I', bpb, 67, 0x534F5453)  # serial
        bpb[71:82] = b'SOTOS_FAT  '
        bpb[82:90] = b'FAT32   '
        bpb[510] = 0x55
        bpb[511] = 0xAA
        self.data[off:off+512] = bpb

        # FSInfo at sector 1
        fsi = bytearray(512)
        struct.pack_into('<I', fsi, 0, 0x41615252)
        struct.pack_into('<I', fsi, 484, 0x61417272)
        struct.pack_into('<I', fsi, 488, clusters - 1)
        struct.pack_into('<I', fsi, 492, 3)
        fsi[508] = 0x00; fsi[509] = 0x00; fsi[510] = 0x55; fsi[511] = 0xAA
        self.data[off+512:off+1024] = fsi

        # Backup boot sector at sector 6
        self.data[off+6*512:off+7*512] = bpb

        # FAT1 and FAT2
        fat = bytearray(fat_sectors * 512)
        struct.pack_into('<I', fat, 0, 0x0FFFFFF8)   # media
        struct.pack_into('<I', fat, 4, 0x0FFFFFFF)   # reserved
        struct.pack_into('<I', fat, 8, 0x0FFFFFFF)   # root cluster 2 (end)
        struct.pack_into('<I', fat, 12, 0x0FFFFFFF)  # cluster 3 (README.TXT, end)

        fat1_off = off + reserved * 512
        fat2_off = fat1_off + fat_sectors * 512
        self.data[fat1_off:fat1_off + len(fat)] = fat
        self.data[fat2_off:fat2_off + len(fat)] = fat

        # Root directory at cluster 2
        data_start_off = off + (reserved + fat_sectors * num_fats) * 512
        # Volume label entry
        vlabel = bytearray(32)
        vlabel[0:11] = b'SOTOS_FAT  '
        vlabel[11] = 0x08
        self.data[data_start_off:data_start_off+32] = vlabel
        # README.TXT entry → cluster 3
        entry = bytearray(32)
        entry[0:8] = b'README  '
        entry[8:11] = b'TXT'
        entry[11] = 0x20  # archive
        content = b'Hello from FAT32 on sotOS!\n'
        struct.pack_into('<H', entry, 26, 3)  # first cluster lo
        struct.pack_into('<I', entry, 28, len(content))
        self.data[data_start_off+32:data_start_off+64] = entry

        # File content at cluster 3 (data_start + 1 sector)
        file_off = data_start_off + spc * 512
        self.data[file_off:file_off+len(content)] = content

    def write(self, path):
        """Write the disk image to a file."""
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        with open(path, 'wb') as f:
            f.write(self.data)


def main():
    parser = argparse.ArgumentParser(description="Create a sotOS ObjectStore disk image")
    parser.add_argument("--output", default="target/disk.img",
                        help="Output disk image path")
    parser.add_argument("--size", type=int, default=256,
                        help="Disk size in MiB (default: 256)")
    parser.add_argument("--rootfs", type=str, default=None,
                        help="Directory to inject as rootfs (recursive)")
    args = parser.parse_args()

    builder = DiskBuilder(args.size)

    if args.rootfs:
        if not os.path.isdir(args.rootfs):
            print(f"Error: {args.rootfs} is not a directory")
            return 1
        print(f"Injecting rootfs from: {args.rootfs}")
        builder.inject_rootfs(args.rootfs)

    builder.finalize()
    builder.write(args.output)

    sectors = builder.disk_size // SECTOR_SIZE
    used_blocks = builder.next_block
    used_mb = (used_blocks * SECTOR_SIZE) / (1024 * 1024)
    print(f"Created {args.output}: {builder.disk_size:,} bytes ({sectors} sectors)")
    print(f"  {builder.obj_count} objects, {used_blocks} data blocks ({used_mb:.1f} MiB used)")
    return 0


if __name__ == "__main__":
    exit(main())
