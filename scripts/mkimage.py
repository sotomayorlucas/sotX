#!/usr/bin/env python3
"""
Build a bootable disk image for sotOS.

Creates an MBR-partitioned disk with a FAT32 partition containing the
Limine BIOS bootloader, kernel, and boot config. Then runs `limine.exe
bios-install` to make it bootable.

Usage:
    python scripts/mkimage.py [--kernel PATH] [--output PATH] [--size SIZE_MB]
"""

import argparse
import struct
import subprocess
import sys
from pathlib import Path

SECTOR = 512
PART_START_LBA = 2048  # 1 MiB alignment (standard)


_sfn_counter = {}  # Track numeric tails per directory level


def needs_lfn(name: str) -> bool:
    """Check if a filename requires Long File Name entries."""
    upper = name.upper()
    if '.' in upper:
        base, ext = upper.rsplit('.', 1)
    else:
        base, ext = upper, ''
    if len(base) > 8 or len(ext) > 3:
        return True
    # Also need LFN if the name contains lowercase (FAT stores uppercase in SFN)
    if name != upper:
        return True
    return False


def make_sfn(name: str) -> bytes:
    """Generate an 8.3 short file name. Uses ~N suffix for truncated names."""
    upper = name.upper()
    if '.' in upper:
        base, ext = upper.rsplit('.', 1)
    else:
        base, ext = upper, ''
    ext = ext[:3]

    if len(base) <= 8 and len(ext) <= 3 and name == upper:
        return base.ljust(8).encode() + ext.ljust(3).encode()

    # Need numeric tail
    # Strip invalid chars and truncate
    clean = ''.join(c for c in base if c.isalnum() or c in '_-')
    key = clean[:6]
    n = _sfn_counter.get(key, 0) + 1
    _sfn_counter[key] = n
    tail = f"~{n}"
    sfn_base = clean[:8 - len(tail)] + tail
    return sfn_base.ljust(8).encode() + ext[:3].ljust(3).encode()


def lfn_checksum(sfn: bytes) -> int:
    """Compute checksum for LFN entries from the 8.3 name."""
    s = 0
    for b in sfn:
        s = ((s >> 1) + ((s & 1) << 7) + b) & 0xFF
    return s


def make_lfn_entries(long_name: str, sfn: bytes) -> bytes:
    """Create LFN directory entries for a long filename."""
    chk = lfn_checksum(sfn)
    # Encode as UCS-2
    ucs2 = long_name.encode('utf-16-le')
    # Pad to fill the last LFN slot (13 chars per entry)
    chars = []
    for i in range(0, len(ucs2), 2):
        chars.append(ucs2[i:i+2])
    # Add null terminator
    chars.append(b'\x00\x00')
    # Pad remaining with 0xFFFF
    while len(chars) % 13 != 0:
        chars.append(b'\xFF\xFF')

    num_entries = len(chars) // 13
    entries = bytearray()

    # LFN entries are stored in reverse order (highest seq first)
    for seq in range(num_entries, 0, -1):
        e = bytearray(32)
        idx = (seq - 1) * 13
        e[0] = seq | (0x40 if seq == num_entries else 0)  # sequence, last flag
        # Characters 1-5 (bytes 1-10)
        for j in range(5):
            ci = idx + j
            if ci < len(chars):
                e[1 + j*2:3 + j*2] = chars[ci]
            else:
                e[1 + j*2:3 + j*2] = b'\xFF\xFF'
        e[11] = 0x0F  # LFN attribute
        e[12] = 0     # type
        e[13] = chk   # checksum
        # Characters 6-11 (bytes 14-25)
        for j in range(6):
            ci = idx + 5 + j
            if ci < len(chars):
                e[14 + j*2:16 + j*2] = chars[ci]
            else:
                e[14 + j*2:16 + j*2] = b'\xFF\xFF'
        e[26:28] = b'\x00\x00'  # first cluster (always 0)
        # Characters 12-13 (bytes 28-31)
        for j in range(2):
            ci = idx + 11 + j
            if ci < len(chars):
                e[28 + j*2:30 + j*2] = chars[ci]
            else:
                e[28 + j*2:30 + j*2] = b'\xFF\xFF'
        entries += e

    return bytes(entries)


class Fat32:
    """Minimal FAT32 filesystem builder."""

    def __init__(self, size_bytes: int, hidden_sectors: int = 0):
        self.data = bytearray(size_bytes)
        self.total_sectors = size_bytes // SECTOR
        self.spc = 1  # 1 sector per cluster = 512 bytes/cluster → many clusters → real FAT32
        self.reserved = 32
        self.num_fats = 2
        self.hidden = hidden_sectors

        # FAT sizing: each cluster needs 4 bytes in the FAT
        usable = self.total_sectors - self.reserved
        # Rough estimate of clusters, then compute exact FAT size
        est_clusters = usable // self.spc
        self.fat_sectors = ((est_clusters + 2) * 4 + SECTOR - 1) // SECTOR

        self.data_lba = self.reserved + self.num_fats * self.fat_sectors
        data_sectors = self.total_sectors - self.data_lba
        self.num_clusters = data_sectors // self.spc

        # In-memory FAT (will be written twice at the end)
        self.fat = bytearray(self.fat_sectors * SECTOR)
        self._fat_set(0, 0x0FFFFFF8)  # media descriptor
        self._fat_set(1, 0x0FFFFFFF)  # EOC
        self._fat_set(2, 0x0FFFFFFF)  # root dir

        self.next_cluster = 3
        self._write_bpb()
        self._write_fsinfo()

    def _fat_set(self, cluster, value):
        struct.pack_into('<I', self.fat, cluster * 4, value & 0x0FFFFFFF)

    def _write_bpb(self):
        b = bytearray(SECTOR)
        b[0:3] = b'\xEB\x58\x90'                           # jmp short + nop
        b[3:11] = b'MSWIN4.1'                               # OEM (widely compatible)
        struct.pack_into('<H', b, 11, SECTOR)               # bytes/sector
        b[13] = self.spc                                     # sectors/cluster
        struct.pack_into('<H', b, 14, self.reserved)        # reserved sectors
        b[16] = self.num_fats                                # num FATs
        # b[17:19] = 0 (root entry count, 0 for FAT32)
        # b[19:21] = 0 (total sectors 16, 0 for FAT32)
        b[21] = 0xF8                                         # media type: hard disk
        # b[22:24] = 0 (fat16 size, 0 for FAT32)
        struct.pack_into('<H', b, 24, 63)                   # sectors/track
        struct.pack_into('<H', b, 26, 255)                  # heads
        struct.pack_into('<I', b, 28, self.hidden)          # hidden sectors!
        struct.pack_into('<I', b, 32, self.total_sectors)   # total sectors 32
        # --- FAT32-specific fields ---
        struct.pack_into('<I', b, 36, self.fat_sectors)     # FAT size 32
        # b[40:42] = 0 (ext flags)
        # b[42:44] = 0 (version)
        struct.pack_into('<I', b, 44, 2)                    # root cluster
        struct.pack_into('<H', b, 48, 1)                    # FSInfo sector
        struct.pack_into('<H', b, 50, 6)                    # backup boot sector
        # b[52:64] = reserved zeros
        b[64] = 0x80                                         # drive number: HDD
        b[66] = 0x29                                         # extended boot sig
        struct.pack_into('<I', b, 67, 0xDEAD1337)          # volume serial
        b[71:82] = b'SOTOS BOOT '                           # volume label
        b[82:90] = b'FAT32   '                              # FS type hint
        b[510] = 0x55; b[511] = 0xAA                        # boot sig
        self.data[0:SECTOR] = b
        self.data[6*SECTOR:7*SECTOR] = b  # backup at sector 6

    def _write_fsinfo(self):
        f = bytearray(SECTOR)
        struct.pack_into('<I', f, 0, 0x41615252)            # lead sig
        struct.pack_into('<I', f, 484, 0x61417272)          # struct sig
        struct.pack_into('<I', f, 488, self.num_clusters)   # free cluster count
        struct.pack_into('<I', f, 492, 3)                   # next free hint
        f[510] = 0x55; f[511] = 0xAA
        self.data[SECTOR:2*SECTOR] = f

    def _cluster_off(self, c):
        return self.data_lba * SECTOR + (c - 2) * self.spc * SECTOR

    def _alloc(self, blob: bytes) -> int:
        """Allocate cluster chain, write data, return first cluster."""
        if not blob:
            return 0
        csz = self.spc * SECTOR
        n = (len(blob) + csz - 1) // csz
        first = self.next_cluster
        for i in range(n):
            c = self.next_cluster
            self.next_cluster += 1
            self._fat_set(c, c + 1 if i < n - 1 else 0x0FFFFFFF)
            off = self._cluster_off(c)
            chunk = blob[i*csz:(i+1)*csz]
            self.data[off:off+len(chunk)] = chunk
        return first

    def _write_chain(self, first_cluster: int, data: bytes):
        """Write data into cluster chain starting at first_cluster, extending as needed."""
        csz = self.spc * SECTOR
        off = self._cluster_off(first_cluster)
        if len(data) <= csz:
            self.data[off:off+len(data)] = data
        else:
            self.data[off:off+csz] = data[:csz]
            rest = data[csz:]
            prev = first_cluster
            while rest:
                nc = self.next_cluster
                self.next_cluster += 1
                self._fat_set(prev, nc)
                self._fat_set(nc, 0x0FFFFFFF)
                o2 = self._cluster_off(nc)
                chunk = rest[:csz]
                self.data[o2:o2+len(chunk)] = chunk
                rest = rest[csz:]
                prev = nc

    def _dir_entry(self, name83: bytes, cluster: int, size: int, is_dir: bool) -> bytes:
        e = bytearray(32)
        e[0:11] = name83
        e[11] = 0x10 if is_dir else 0x20
        struct.pack_into('<H', e, 20, (cluster >> 16) & 0xFFFF)
        struct.pack_into('<H', e, 26, cluster & 0xFFFF)
        struct.pack_into('<I', e, 28, 0 if is_dir else size)
        return bytes(e)

    def _emit_entry(self, raw: bytearray, name: str, cluster: int, size: int, is_dir: bool):
        """Emit LFN entries (if needed) + SFN entry into raw."""
        sfn = make_sfn(name)
        if needs_lfn(name):
            raw += make_lfn_entries(name, sfn)
        raw += self._dir_entry(sfn, cluster, size, is_dir)

    def _build_dir(self, entries: dict, self_c: int, parent_c: int) -> bytes:
        """Build directory data from {name: bytes|dict} tree."""
        raw = bytearray()
        if self_c != 2:
            raw += self._dir_entry(b'.          ', self_c, 0, True)
            raw += self._dir_entry(b'..         ', parent_c, 0, True)

        for name in sorted(entries):
            val = entries[name]
            if isinstance(val, dict):
                dc = self.next_cluster
                self.next_cluster += 1
                self._fat_set(dc, 0x0FFFFFFF)
                child = self._build_dir(val, dc, self_c)
                self._write_chain(dc, child)
                self._emit_entry(raw, name, dc, 0, True)
            else:
                fc = self._alloc(val)
                self._emit_entry(raw, name, fc, len(val), False)
        return bytes(raw)

    def add_files(self, files: dict):
        """Add files. Keys are paths like 'boot/limine.conf'."""
        tree = {}
        for path, data in files.items():
            parts = path.replace('\\', '/').split('/')
            node = tree
            for p in parts[:-1]:
                node = node.setdefault(p, {})
            node[parts[-1]] = data

        root = self._build_dir(tree, 2, 0)
        self._write_chain(2, root)

    def finish(self) -> bytes:
        """Write FATs and return the partition data."""
        off1 = self.reserved * SECTOR
        off2 = off1 + len(self.fat)
        self.data[off1:off1+len(self.fat)] = self.fat
        self.data[off2:off2+len(self.fat)] = self.fat
        return bytes(self.data)


def write_mbr(disk: bytearray, disk_sectors: int, part_start: int):
    """Write an MBR with one active FAT32-LBA partition."""
    part_sectors = disk_sectors - part_start
    # Partition entry at offset 446
    e = bytearray(16)
    e[0] = 0x80              # active/bootable
    e[4] = 0x0C              # FAT32 LBA
    struct.pack_into('<I', e, 8, part_start)
    struct.pack_into('<I', e, 12, part_sectors)
    disk[446:462] = e
    disk[510] = 0x55
    disk[511] = 0xAA


def build_image(kernel_path: str, output_path: str, size_mb: int, initrd_path: str = None):
    root = Path(__file__).parent.parent

    bootx64 = (root / "limine" / "BOOTX64.EFI").read_bytes()
    bios_sys = (root / "limine" / "limine-bios.sys").read_bytes()
    kernel = Path(kernel_path).read_bytes()
    conf = (root / "boot" / "limine.conf").read_bytes()

    print(f"  Kernel:         {len(kernel):>10,} bytes")
    print(f"  limine-bios.sys:{len(bios_sys):>10,} bytes")
    print(f"  BOOTX64.EFI:   {len(bootx64):>10,} bytes")

    disk_bytes = size_mb * 1024 * 1024
    disk_sectors = disk_bytes // SECTOR
    disk = bytearray(disk_bytes)

    write_mbr(disk, disk_sectors, PART_START_LBA)

    part_bytes = (disk_sectors - PART_START_LBA) * SECTOR
    fat = Fat32(part_bytes, hidden_sectors=PART_START_LBA)
    files = {
        # Limine BIOS
        "limine-bios.sys": bios_sys,
        # Limine UEFI (for dual-boot support)
        "EFI/BOOT/BOOTX64.EFI": bootx64,
        # Config and kernel
        "boot/limine.conf": conf,
        "boot/sotos-kernel": kernel,
        # Also place config at root for maximum compatibility
        "limine.conf": conf,
    }

    if initrd_path and Path(initrd_path).exists():
        initrd_data = Path(initrd_path).read_bytes()
        files["boot/initrd.img"] = initrd_data
        print(f"  initrd.img:     {len(initrd_data):>10,} bytes")

    fat.add_files(files)
    part_data = fat.finish()
    off = PART_START_LBA * SECTOR
    disk[off:off+len(part_data)] = part_data

    Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    Path(output_path).write_bytes(disk)
    print(f"  Disk image:     {output_path} ({size_mb} MiB)")

    # Install Limine BIOS bootloader
    limine_exe = root / "limine" / "limine.exe"
    if limine_exe.exists():
        print("  Installing Limine BIOS bootloader...")
        r = subprocess.run(
            [str(limine_exe), "bios-install", str(output_path)],
            capture_output=True, text=True
        )
        if r.returncode == 0:
            print("  Limine BIOS installed successfully.")
        else:
            print(f"  Warning: limine bios-install failed: {r.stderr.strip()}")
            print("  BIOS boot may not work. UEFI boot should still work.")
    else:
        print(f"  Warning: {limine_exe} not found. Run 'limine bios-install' manually.")


def main():
    root = Path(__file__).parent.parent
    default_kernel = root / "target" / "x86_64-unknown-none" / "debug" / "sotos-kernel"
    default_output = root / "target" / "sotos.img"

    p = argparse.ArgumentParser(description="Build sotOS bootable disk image")
    p.add_argument("--kernel", default=str(default_kernel))
    p.add_argument("--output", "-o", default=str(default_output))
    p.add_argument("--size", type=int, default=64, help="Disk size in MiB")
    p.add_argument("--initrd", default=None, help="Initramfs image to include")
    args = p.parse_args()

    if not Path(args.kernel).exists():
        print(f"Error: kernel not found at {args.kernel}")
        print("Run 'cargo build --package sotos-kernel' first.")
        return 1

    print("Building sotOS disk image...")
    build_image(args.kernel, args.output, args.size, args.initrd)
    print("Done.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
