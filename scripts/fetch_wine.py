#!/usr/bin/env python3
"""Download Wine64 minimal files for running 'wine64 --version' on sotOS.

Only 5 files needed:
  /bin/wine64          - ELF loader (dynamically linked)
  /bin/ntdll.so        - Wine ntdll Unix-side library (loaded via dlopen)
  /lib/ld-linux-x86-64.so.2  - glibc dynamic linker
  /lib/libc.so.6       - glibc
  /lib/libunwind.so.8  - required by ntdll.so

Flow: wine64 -> dlopen("ntdll.so") -> __wine_main() -> check_command_line()
      -> printf(wine_build) -> exit(0)

No wineserver, no PE DLLs, no Windows environment needed for --version.

Usage:
  python scripts/fetch_wine.py              # download wine + deps
  python scripts/fetch_wine.py --disk       # download + create disk image
"""

import argparse
import os
import struct
import sys
import tarfile
import urllib.request

CACHE_DIR = "target/wine-cache"
SYSROOT = "target/wine-sysroot"

# Debian Bookworm (glibc 2.36, Wine 8.0 — stable, well-tested)
WINE_DEB_URL = "http://deb.debian.org/debian/pool/main/w/wine/"
LIBUNWIND_DEB_URL = "http://deb.debian.org/debian/pool/main/libu/libunwind/"

# We'll fetch package listings to find exact filenames
PACKAGES_URL = "http://deb.debian.org/debian/dists/bookworm/main/binary-amd64/Packages.gz"


def download(url, output_path):
    """Download a file if not cached."""
    if os.path.isfile(output_path):
        sz = os.path.getsize(output_path)
        print(f"  Cached: {os.path.basename(output_path)} ({sz:,} bytes)")
        return True

    os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
    print(f"  Downloading: {url}")

    try:
        req = urllib.request.Request(url, headers={"User-Agent": "sotOS-fetch/1.0"})
        with urllib.request.urlopen(req, timeout=120) as resp:
            total = resp.headers.get('Content-Length')
            total = int(total) if total else None
            with open(output_path + ".tmp", 'wb') as f:
                downloaded = 0
                while True:
                    chunk = resp.read(65536)
                    if not chunk:
                        break
                    f.write(chunk)
                    downloaded += len(chunk)
                    if total:
                        pct = downloaded * 100 // total
                        sys.stdout.write(f"\r  {downloaded / (1024*1024):.1f} MiB ({pct}%)")
                        sys.stdout.flush()

            if total:
                print()
            print(f"  Downloaded: {downloaded:,} bytes")

        os.replace(output_path + ".tmp", output_path)
        return True
    except Exception as e:
        print(f"\n  Error: {e}")
        tmp = output_path + ".tmp"
        if os.path.exists(tmp):
            os.remove(tmp)
        return False


def extract_deb_data(deb_path):
    """Extract data.tar from a .deb file (ar archive format)."""
    with open(deb_path, 'rb') as f:
        # ar header: "!<arch>\n" (8 bytes)
        magic = f.read(8)
        if magic != b'!<arch>\n':
            print(f"  Error: {deb_path} is not an ar archive")
            return None

        while True:
            # ar entry header: 60 bytes
            header = f.read(60)
            if len(header) < 60:
                break

            name = header[0:16].strip()
            size = int(header[48:58].strip())

            # Look for data.tar*
            name_str = name.decode('ascii', errors='replace').rstrip('/')
            if name_str.startswith('data.tar'):
                data = f.read(size)
                return data, name_str

            # Skip this entry (+ padding to even boundary)
            f.seek(size + (size % 2), 1)

    return None


def extract_files_from_deb(deb_path, file_patterns, output_dir):
    """Extract specific files from a .deb package."""
    result = extract_deb_data(deb_path)
    if result is None:
        print(f"  Error: no data.tar found in {deb_path}")
        return {}

    data, tar_name = result
    extracted = {}

    # Determine compression
    if tar_name.endswith('.xz'):
        import lzma
        data = lzma.decompress(data)
    elif tar_name.endswith('.gz'):
        import gzip
        data = gzip.decompress(data)
    elif tar_name.endswith('.zst'):
        print(f"  Error: zstd compression not supported by stdlib")
        return {}

    tf = tarfile.open(fileobj=__import__('io').BytesIO(data), mode='r:')

    for member in tf.getmembers():
        path = member.name.lstrip('./')
        if not path:
            continue

        for pattern, out_name in file_patterns:
            if path == pattern or (path.endswith('/' + pattern.split('/')[-1]) and out_name not in extracted):
                if member.isfile() or member.issym():
                    # For symlinks, try to get the target
                    if member.issym():
                        target = member.linkname
                        if not target.startswith('/'):
                            resolved = os.path.normpath(
                                os.path.join(os.path.dirname(path), target)).replace('\\', '/')
                        else:
                            resolved = target.lstrip('/')
                        # Try to extract the target
                        for try_path in [resolved, './' + resolved]:
                            try:
                                tm = tf.getmember(try_path)
                                if tm.isfile():
                                    fobj = tf.extractfile(tm)
                                    if fobj:
                                        out_path = os.path.join(output_dir, out_name)
                                        os.makedirs(os.path.dirname(out_path), exist_ok=True)
                                        file_data = fobj.read()
                                        with open(out_path, 'wb') as out:
                                            out.write(file_data)
                                        extracted[out_name] = len(file_data)
                                        break
                            except KeyError:
                                continue
                    else:
                        fobj = tf.extractfile(member)
                        if fobj:
                            out_path = os.path.join(output_dir, out_name)
                            os.makedirs(os.path.dirname(out_path), exist_ok=True)
                            file_data = fobj.read()
                            with open(out_path, 'wb') as out:
                                out.write(file_data)
                            extracted[out_name] = len(file_data)

    tf.close()
    return extracted


def extract_nls_from_deb(deb_path, output_dir):
    """Extract all NLS files from a .deb package to share/wine/nls/."""
    result = extract_deb_data(deb_path)
    if result is None:
        return {}

    data, tar_name = result
    if tar_name.endswith('.xz'):
        import lzma
        data = lzma.decompress(data)
    elif tar_name.endswith('.gz'):
        import gzip
        data = gzip.decompress(data)

    extracted = {}
    tf = tarfile.open(fileobj=__import__('io').BytesIO(data), mode='r:')
    nls_dir = os.path.join(output_dir, "usr", "share", "wine", "nls")
    os.makedirs(nls_dir, exist_ok=True)

    for member in tf.getmembers():
        path = member.name.lstrip('./')
        if path.endswith('.nls') and member.isfile():
            fobj = tf.extractfile(member)
            if fobj:
                fname = os.path.basename(path)
                out_path = os.path.join(nls_dir, fname)
                file_data = fobj.read()
                with open(out_path, 'wb') as out:
                    out.write(file_data)
                rel = f"usr/share/wine/nls/{fname}"
                extracted[rel] = len(file_data)
                print(f"    NLS: {fname} ({len(file_data):,} bytes)")

    tf.close()
    return extracted


def extract_wine_tree_from_deb(deb_path, output_dir):
    """Extract essential Wine DLLs preserving directory structure.

    Extracts from usr/lib/x86_64-linux-gnu/wine/ to x86_64-linux-gnu/wine/
    so Wine finds them at /bin/../x86_64-linux-gnu/wine/x86_64-unix/ntdll.so etc.
    Only extracts core DLLs needed for basic PE execution to fit in 512MB disk.
    """
    # Core files needed for PE loading (basename only)
    ESSENTIAL = {
        # Unix-side drivers
        'ntdll.so', 'win32u.so', 'winebus.so',
        'libwine.so.1', 'libwine.so.1.0',
        # PE-side core
        'ntdll.dll', 'start.exe', 'conhost.exe',
        'kernel32.dll', 'kernelbase.dll',
        'ucrtbase.dll', 'msvcrt.dll',
        'advapi32.dll', 'sechost.dll',
        'bcrypt.dll', 'bcryptprimitives.dll',
        'user32.dll', 'gdi32.dll', 'win32u.dll',
        'ws2_32.dll', 'nsi.dll', 'iphlpapi.dll',
        'ole32.dll', 'oleaut32.dll', 'rpcrt4.dll',
        'combase.dll', 'shell32.dll', 'shlwapi.dll',
        'setupapi.dll', 'version.dll', 'cfgmgr32.dll',
        'imm32.dll', 'winex11.drv',
        'apisetschema.dll',
    }

    result = extract_deb_data(deb_path)
    if result is None:
        return {}

    data, tar_name = result
    if tar_name.endswith('.xz'):
        import lzma
        data = lzma.decompress(data)
    elif tar_name.endswith('.gz'):
        import gzip
        data = gzip.decompress(data)

    extracted = {}
    tf = tarfile.open(fileobj=__import__('io').BytesIO(data), mode='r:')

    WINE_PREFIX = "usr/lib/x86_64-linux-gnu/wine/"
    STRIP = "usr/lib/"

    def try_extract(member_or_path, rel_out):
        """Extract a file (or resolve symlink) to output."""
        m = member_or_path if not isinstance(member_or_path, str) else None
        if m and m.issym():
            target = m.linkname
            if not target.startswith('/'):
                resolved = os.path.normpath(
                    os.path.join(os.path.dirname(m.name.lstrip('./')), target)).replace('\\', '/')
            else:
                resolved = target.lstrip('/')
            for try_path in [resolved, './' + resolved]:
                try:
                    tm = tf.getmember(try_path)
                    if tm.isfile():
                        fobj = tf.extractfile(tm)
                        if fobj:
                            out_path = os.path.join(output_dir, rel_out)
                            os.makedirs(os.path.dirname(out_path), exist_ok=True)
                            file_data = fobj.read()
                            with open(out_path, 'wb') as out:
                                out.write(file_data)
                            extracted[rel_out] = len(file_data)
                            return True
                except KeyError:
                    continue
            return False

        if m and m.isfile():
            fobj = tf.extractfile(m)
            if fobj:
                out_path = os.path.join(output_dir, rel_out)
                os.makedirs(os.path.dirname(out_path), exist_ok=True)
                file_data = fobj.read()
                with open(out_path, 'wb') as out:
                    out.write(file_data)
                extracted[rel_out] = len(file_data)
                return True
        return False

    for member in tf.getmembers():
        path = member.name.lstrip('./')
        if not path.startswith(WINE_PREFIX):
            continue
        if not (member.isfile() or member.issym()):
            continue

        basename = os.path.basename(path)
        if basename not in ESSENTIAL:
            continue

        rel = path[len(STRIP):]
        try_extract(member, rel)

    tf.close()
    count = len(extracted)
    total_mb = sum(extracted.values()) / (1024 * 1024)
    print(f"    Extracted {count} essential Wine DLLs ({total_mb:.1f} MiB)")
    return extracted


def build_hello_exe(output_path):
    """Build a minimal PE32+ executable that prints 'Hello from Wine!' and exits."""
    # Minimal PE32+ with kernel32.dll import (WriteFile + ExitProcess)
    # Layout: DOS header + PE header + .text section + .idata section
    import struct

    # x86_64 machine code for:
    #   sub rsp, 40          ; shadow space
    #   mov ecx, -11         ; STD_OUTPUT_HANDLE
    #   call [GetStdHandle]
    #   mov rcx, rax         ; hFile
    #   lea rdx, [rip+msg]   ; lpBuffer
    #   mov r8d, msglen      ; nBytesToWrite
    #   lea r9, [rsp+32]     ; lpNumberOfBytesWritten
    #   push 0               ; lpOverlapped
    #   call [WriteFile]
    #   xor ecx, ecx         ; exit code 0
    #   call [ExitProcess]
    # msg: "Hello from Wine!\n"
    #
    # We'll use a simpler approach: just call ExitProcess(42) as proof of concept
    # The output will be the exit code, verifiable by Wine

    IMAGE_BASE = 0x140000000

    # --- DOS Header (64 bytes) ---
    dos = bytearray(64)
    dos[0:2] = b'MZ'
    struct.pack_into('<I', dos, 0x3c, 64)  # e_lfanew = 64

    # --- PE Signature (4 bytes) ---
    pe_sig = b'PE\x00\x00'

    # --- COFF Header (20 bytes) ---
    coff = bytearray(20)
    struct.pack_into('<H', coff, 0, 0x8664)   # Machine: AMD64
    struct.pack_into('<H', coff, 2, 2)         # NumberOfSections: 2 (.text, .idata)
    struct.pack_into('<H', coff, 16, 0xF0)     # SizeOfOptionalHeader: 240
    struct.pack_into('<H', coff, 18, 0x22)     # Characteristics: EXECUTABLE_IMAGE | LARGE_ADDRESS_AWARE

    # --- Optional Header PE32+ (240 bytes) ---
    opt = bytearray(0xF0)
    struct.pack_into('<H', opt, 0, 0x20B)      # Magic: PE32+
    opt[2] = 14; opt[3] = 0                    # Linker version
    struct.pack_into('<I', opt, 4, 0x200)      # SizeOfCode
    struct.pack_into('<I', opt, 16, 0x1000)    # AddressOfEntryPoint (.text RVA)
    struct.pack_into('<Q', opt, 24, IMAGE_BASE) # ImageBase
    struct.pack_into('<I', opt, 32, 0x1000)    # SectionAlignment
    struct.pack_into('<I', opt, 36, 0x200)     # FileAlignment
    struct.pack_into('<H', opt, 40, 6)         # MajorOSVersion
    struct.pack_into('<H', opt, 44, 6)         # MajorSubsystemVersion
    struct.pack_into('<I', opt, 56, 0x4000)    # SizeOfImage
    struct.pack_into('<I', opt, 60, 0x200)     # SizeOfHeaders
    struct.pack_into('<H', opt, 68, 3)         # Subsystem: CONSOLE
    struct.pack_into('<H', opt, 70, 0x8160)    # DllCharacteristics: NX|DYNAMIC_BASE|HIGH_ENTROPY_VA|TERMINAL_SERVER_AWARE
    struct.pack_into('<Q', opt, 72, 0x100000)  # SizeOfStackReserve
    struct.pack_into('<Q', opt, 80, 0x1000)    # SizeOfStackCommit
    struct.pack_into('<Q', opt, 88, 0x100000)  # SizeOfHeapReserve
    struct.pack_into('<Q', opt, 96, 0x1000)    # SizeOfHeapCommit
    struct.pack_into('<I', opt, 108, 16)       # NumberOfRvaAndSizes

    # Data directories (16 entries, 8 bytes each = 128 bytes, starting at offset 112)
    # Entry 1 (Import Table): RVA=0x2000, Size=...
    struct.pack_into('<I', opt, 112 + 1*8, 0x2000)     # Import Table RVA
    struct.pack_into('<I', opt, 112 + 1*8 + 4, 40)     # Import Table Size

    # --- Section Headers (2 * 40 bytes) ---
    # .text section
    text_hdr = bytearray(40)
    text_hdr[0:6] = b'.text\x00'
    struct.pack_into('<I', text_hdr, 8, 0x200)    # VirtualSize
    struct.pack_into('<I', text_hdr, 12, 0x1000)   # VirtualAddress
    struct.pack_into('<I', text_hdr, 16, 0x200)    # SizeOfRawData
    struct.pack_into('<I', text_hdr, 20, 0x200)    # PointerToRawData
    struct.pack_into('<I', text_hdr, 36, 0x60000020) # Characteristics: CODE|EXECUTE|READ

    # .idata section
    idata_hdr = bytearray(40)
    idata_hdr[0:7] = b'.idata\x00'
    struct.pack_into('<I', idata_hdr, 8, 0x200)    # VirtualSize
    struct.pack_into('<I', idata_hdr, 12, 0x2000)   # VirtualAddress
    struct.pack_into('<I', idata_hdr, 16, 0x200)    # SizeOfRawData
    struct.pack_into('<I', idata_hdr, 20, 0x400)    # PointerToRawData
    struct.pack_into('<I', idata_hdr, 36, 0xC0000040) # Characteristics: INITIALIZED_DATA|READ|WRITE

    # --- Assemble headers ---
    headers = dos + pe_sig + coff + opt + text_hdr + idata_hdr
    # Pad headers to FileAlignment (0x200)
    headers += b'\x00' * (0x200 - len(headers))

    # --- .text section (at file offset 0x200) ---
    # Machine code for:
    #   sub rsp, 0x28           ; 48 83 EC 28
    #   mov ecx, 0xFFFFFFF5     ; B9 F5 FF FF FF    (-11 = STD_OUTPUT_HANDLE)
    #   call [rip + GetStdHandle_IAT]  ; FF 15 xx xx xx xx
    #   mov rcx, rax            ; 48 89 C1
    #   lea rdx, [rip + msg]    ; 48 8D 15 xx xx xx xx
    #   mov r8d, MSGLEN         ; 41 B8 xx 00 00 00
    #   lea r9, [rsp+0x20]      ; 4C 8D 4C 24 20
    #   xor eax, eax            ; 31 C0
    #   push rax                ; 50  (lpOverlapped = NULL)
    #   sub rsp, 0x20           ; 48 83 EC 20  (shadow space for WriteFile)
    #   call [rip + WriteFile_IAT]  ; FF 15 xx xx xx xx
    #   add rsp, 0x28           ; 48 83 C4 28
    #   xor ecx, ecx            ; 31 C9
    #   call [rip + ExitProcess_IAT]; FF 15 xx xx xx xx

    msg = b"Hello from Wine!\n"
    msglen = len(msg)  # 17

    text = bytearray(0x200)

    # We need to know offsets. Let's build instruction by instruction.
    # .text starts at RVA 0x1000, .idata at RVA 0x2000
    # IAT entries in .idata at known offsets (we'll set up):
    #   GetStdHandle  at RVA 0x2080
    #   WriteFile     at RVA 0x2088
    #   ExitProcess   at RVA 0x2090

    code = bytearray()
    # sub rsp, 0x28
    code += b'\x48\x83\xEC\x28'
    # mov ecx, -11 (STD_OUTPUT_HANDLE)
    code += b'\xB9\xF5\xFF\xFF\xFF'
    # call [rip + offset_to_GetStdHandle_IAT]
    # RIP after this instruction = 0x1000 + len(code) + 6
    # Target = 0x2080
    rip_after = 0x1000 + len(code) + 6
    rel = 0x2080 - rip_after
    code += b'\xFF\x15' + struct.pack('<i', rel)
    # mov rcx, rax
    code += b'\x48\x89\xC1'
    # lea rdx, [rip + msg_offset]
    # msg will be at end of code in .text
    # We'll place msg at offset 0x100 within .text (RVA 0x1100)
    rip_after_lea = 0x1000 + len(code) + 7
    msg_rva = 0x1100
    rel_msg = msg_rva - rip_after_lea
    code += b'\x48\x8D\x15' + struct.pack('<i', rel_msg)
    # mov r8d, msglen
    code += b'\x41\xB8' + struct.pack('<I', msglen)
    # lea r9, [rsp+0x20]
    code += b'\x4C\x8D\x4C\x24\x20'
    # xor eax, eax
    code += b'\x31\xC0'
    # push rax (lpOverlapped = NULL)
    code += b'\x50'
    # sub rsp, 0x20
    code += b'\x48\x83\xEC\x20'
    # call [rip + WriteFile_IAT]
    rip_after2 = 0x1000 + len(code) + 6
    rel2 = 0x2088 - rip_after2
    code += b'\xFF\x15' + struct.pack('<i', rel2)
    # add rsp, 0x28
    code += b'\x48\x83\xC4\x28'
    # xor ecx, ecx
    code += b'\x31\xC9'
    # call [rip + ExitProcess_IAT]
    rip_after3 = 0x1000 + len(code) + 6
    rel3 = 0x2090 - rip_after3
    code += b'\xFF\x15' + struct.pack('<i', rel3)

    text[0:len(code)] = code
    # Place message at offset 0x100
    text[0x100:0x100+msglen] = msg

    # --- .idata section (at file offset 0x400) ---
    idata = bytearray(0x200)

    # Import Directory Table (at RVA 0x2000, file offset 0x400)
    # One entry for kernel32.dll + null terminator
    # Each entry: 20 bytes (OriginalFirstThunk, TimeDateStamp, ForwarderChain, Name, FirstThunk)
    # kernel32.dll entry:
    ilt_rva = 0x2060   # Import Lookup Table
    name_rva = 0x20A0  # DLL name
    iat_rva = 0x2080   # Import Address Table

    struct.pack_into('<I', idata, 0, ilt_rva)     # OriginalFirstThunk
    struct.pack_into('<I', idata, 12, name_rva)    # Name
    struct.pack_into('<I', idata, 16, iat_rva)     # FirstThunk (IAT)
    # Null terminator entry (20 bytes of zeros) is already there

    # Import Lookup Table at offset 0x60 (RVA 0x2060)
    # 3 entries: GetStdHandle, WriteFile, ExitProcess + null terminator
    # Each is 8 bytes (PE32+), pointing to Hint/Name entries
    hint_GetStdHandle = 0x20C0
    hint_WriteFile = 0x20E0
    hint_ExitProcess = 0x2100
    struct.pack_into('<Q', idata, 0x60, hint_GetStdHandle)
    struct.pack_into('<Q', idata, 0x68, hint_WriteFile)
    struct.pack_into('<Q', idata, 0x70, hint_ExitProcess)
    # null terminator at 0x78 (already zeros)

    # Import Address Table at offset 0x80 (RVA 0x2080) — same as ILT initially
    struct.pack_into('<Q', idata, 0x80, hint_GetStdHandle)
    struct.pack_into('<Q', idata, 0x88, hint_WriteFile)
    struct.pack_into('<Q', idata, 0x90, hint_ExitProcess)

    # DLL name at offset 0xA0 (RVA 0x20A0)
    dll_name = b'kernel32.dll\x00'
    idata[0xA0:0xA0+len(dll_name)] = dll_name

    # Hint/Name entries
    # GetStdHandle at offset 0xC0 (RVA 0x20C0): Hint(2) + Name
    struct.pack_into('<H', idata, 0xC0, 0)
    idata[0xC2:0xC2+15] = b'GetStdHandle\x00\x00\x00'

    # WriteFile at offset 0xE0 (RVA 0x20E0)
    struct.pack_into('<H', idata, 0xE0, 0)
    idata[0xE2:0xE2+10] = b'WriteFile\x00'

    # ExitProcess at offset 0x100 (RVA 0x2100)
    struct.pack_into('<H', idata, 0x100, 0)
    idata[0x102:0x102+13] = b'ExitProcess\x00\x00'

    # --- Assemble final PE ---
    pe = headers + text + idata

    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, 'wb') as f:
        f.write(pe)
    print(f"  Built hello.exe: {len(pe)} bytes")
    return len(pe)


def find_deb_url(packages_data, pkg_name):
    """Find the download URL for a package from Packages index."""
    current_pkg = None
    filename = None
    for line in packages_data.split('\n'):
        if line.startswith('Package: '):
            current_pkg = line[9:].strip()
            filename = None
        elif line.startswith('Filename: '):
            filename = line[10:].strip()
        elif line == '' and current_pkg == pkg_name and filename:
            return f"http://deb.debian.org/debian/{filename}"
    return None


def main():
    parser = argparse.ArgumentParser(description="Fetch Wine64 for sotOS")
    parser.add_argument("--disk", action="store_true",
                        help="Also create disk image with Wine sysroot")
    parser.add_argument("--disk-size", type=int, default=512,
                        help="Disk size in MiB (default: 512)")
    args = parser.parse_args()

    os.makedirs(CACHE_DIR, exist_ok=True)
    os.makedirs(SYSROOT, exist_ok=True)

    print("=== sotOS Wine64 Sysroot Builder ===\n")

    # Step 1: Download Packages index to find exact .deb URLs
    print("[1/4] Fetching Debian package index...")
    packages_gz_path = os.path.join(CACHE_DIR, "Packages.gz")
    if not download(PACKAGES_URL, packages_gz_path):
        print("  Error: could not download package index")
        return 1

    import gzip
    with gzip.open(packages_gz_path, 'rt', encoding='utf-8', errors='replace') as f:
        packages_data = f.read()

    # Find URLs for our packages
    needed_pkgs = {
        'wine64': 'wine64',
        'libwine': 'libwine',
        'libunwind8': 'libunwind8',
        'liblzma5': 'liblzma5',
    }

    deb_paths = {}
    for pkg_name, label in needed_pkgs.items():
        url = find_deb_url(packages_data, pkg_name)
        if not url:
            print(f"  Warning: {pkg_name} not found in Packages index")
            # Try direct URLs as fallback
            continue
        deb_file = os.path.join(CACHE_DIR, os.path.basename(url))
        deb_paths[label] = (url, deb_file)

    # Step 2: Download .deb packages
    print("\n[2/4] Downloading Wine packages...")
    for label, (url, deb_file) in deb_paths.items():
        print(f"  [{label}]")
        if not download(url, deb_file):
            print(f"  Error downloading {label}")
            return 1

    # Step 3: Extract needed files
    print("\n[3/4] Extracting Wine binaries...")

    all_extracted = {}

    # From wine64 package: wine64 loader + wineserver
    if 'wine64' in deb_paths:
        print("  Extracting wine64 loader + wineserver...")
        files = extract_files_from_deb(deb_paths['wine64'][1], [
            ("usr/lib/wine/wine64", "bin/wine64"),
            ("usr/lib/wine/wineserver64", "bin/wineserver64"),
            ("usr/lib/wine/wineserver64", "bin/wineserver"),
        ], SYSROOT)
        all_extracted.update(files)

    # From libwine package: Wine DLLs (Unix + PE) + NLS files
    if 'libwine' in deb_paths:
        print("  Extracting Wine DLL tree + NLS files...")
        # Keep bin/ntdll.so for backward compat, and also place at real Wine path
        files = extract_files_from_deb(deb_paths['libwine'][1], [
            ("usr/lib/x86_64-linux-gnu/wine/x86_64-unix/ntdll.so", "bin/ntdll.so"),
            ("x86_64-unix/ntdll.so", "bin/ntdll.so"),
        ], SYSROOT)
        all_extracted.update(files)

        # Extract full Wine DLL tree at correct paths (wine64 looks here)
        wine_files = extract_wine_tree_from_deb(deb_paths['libwine'][1], SYSROOT)
        all_extracted.update(wine_files)

        # Extract ALL NLS files from the package
        nls_files = extract_nls_from_deb(deb_paths['libwine'][1], SYSROOT)
        for name, size in nls_files.items():
            all_extracted[name] = size

        # Wine also looks at /share/wine/nls/ (from /bin/../../share/wine/nls/)
        # Copy NLS files there too
        import shutil as _sh
        share_nls = os.path.join(SYSROOT, "share", "wine", "nls")
        usr_nls = os.path.join(SYSROOT, "usr", "share", "wine", "nls")
        if os.path.isdir(usr_nls):
            os.makedirs(share_nls, exist_ok=True)
            for f in os.listdir(usr_nls):
                src = os.path.join(usr_nls, f)
                dst = os.path.join(share_nls, f)
                if not os.path.isfile(dst):
                    _sh.copy2(src, dst)

    # From libunwind8 package: libunwind.so.8
    if 'libunwind8' in deb_paths:
        print("  Extracting libunwind.so.8...")
        files = extract_files_from_deb(deb_paths['libunwind8'][1], [
            ("usr/lib/x86_64-linux-gnu/libunwind.so.8", "lib/libunwind.so.8"),
            ("usr/lib/x86_64-linux-gnu/libunwind-x86_64.so.8", "lib/libunwind-x86_64.so.8"),
        ], SYSROOT)
        all_extracted.update(files)

    # From liblzma5 package: liblzma.so.5 (dependency of libunwind)
    if 'liblzma5' in deb_paths:
        print("  Extracting liblzma.so.5...")
        files = extract_files_from_deb(deb_paths['liblzma5'][1], [
            ("usr/lib/x86_64-linux-gnu/liblzma.so.5", "lib/liblzma.so.5"),
            ("lib/x86_64-linux-gnu/liblzma.so.5", "lib/liblzma.so.5"),
        ], SYSROOT)
        all_extracted.update(files)

    # Copy existing glibc files from project root
    import shutil
    for fname, dest in [
        ("ld-linux-x86-64.so.2", "lib/ld-linux-x86-64.so.2"),
        ("libc.so.6", "lib/libc.so.6"),
        ("libgcc_s.so.1", "lib/libgcc_s.so.1"),
    ]:
        src = os.path.join(".", fname)
        if os.path.isfile(src):
            dst = os.path.join(SYSROOT, dest)
            os.makedirs(os.path.dirname(dst), exist_ok=True)
            shutil.copy2(src, dst)
            all_extracted[dest] = os.path.getsize(src)
            print(f"  Copied {fname} -> {dest} ({os.path.getsize(src):,} bytes)")

    # Also ensure lib64 symlink equivalent
    lib64_dir = os.path.join(SYSROOT, "lib64")
    os.makedirs(lib64_dir, exist_ok=True)
    ld_src = os.path.join(SYSROOT, "lib/ld-linux-x86-64.so.2")
    ld_dst = os.path.join(lib64_dir, "ld-linux-x86-64.so.2")
    if os.path.isfile(ld_src) and not os.path.isfile(ld_dst):
        shutil.copy2(ld_src, ld_dst)

    # Wine looks for wineserver at /usr/lib/wine/wineserver64
    # Copy from /bin/wineserver64 so Wine finds it at both locations
    wine_lib_dir = os.path.join(SYSROOT, "usr", "lib", "wine")
    os.makedirs(wine_lib_dir, exist_ok=True)
    ws_src = os.path.join(SYSROOT, "bin", "wineserver64")
    ws_dst = os.path.join(wine_lib_dir, "wineserver64")
    if os.path.isfile(ws_src) and not os.path.isfile(ws_dst):
        shutil.copy2(ws_src, ws_dst)
        print(f"  Copied wineserver64 -> usr/lib/wine/wineserver64")

    # Summary
    print(f"\n  Sysroot contents ({SYSROOT}):")
    for root, dirs, files in os.walk(SYSROOT):
        for fname in sorted(files):
            full = os.path.join(root, fname)
            rel = os.path.relpath(full, SYSROOT).replace('\\', '/')
            sz = os.path.getsize(full)
            print(f"    /{rel}: {sz:,} bytes")

    # Build minimal PE32+ hello.exe
    print("  Building hello.exe (minimal PE32+)...")
    hello_size = build_hello_exe(os.path.join(SYSROOT, "bin", "hello.exe"))
    all_extracted["bin/hello.exe"] = hello_size

    # Verify we have the critical files
    critical = ["bin/wine64", "bin/ntdll.so", "bin/hello.exe", "lib/ld-linux-x86-64.so.2", "lib/libc.so.6"]
    missing = [f for f in critical if not os.path.isfile(os.path.join(SYSROOT, f))]
    if missing:
        print(f"\n  WARNING: Missing critical files: {missing}")
        print("  wine64 --version will not work without these.")
    else:
        print(f"\n  All critical files present!")

    # Step 4: Create disk image
    if args.disk:
        print(f"\n[4/4] Creating disk image...")
        import subprocess

        # Create tarball from sysroot
        sysroot_tar = "target/wine-sysroot.tar.gz"
        print(f"  Creating tarball: {sysroot_tar}")
        with tarfile.open(sysroot_tar, 'w:gz') as tf:
            for root, dirs, files in os.walk(SYSROOT):
                for d in sorted(dirs):
                    full = os.path.join(root, d)
                    arcname = os.path.relpath(full, SYSROOT).replace('\\', '/')
                    tf.add(full, arcname=arcname, recursive=False)
                for f in sorted(files):
                    full = os.path.join(root, f)
                    arcname = os.path.relpath(full, SYSROOT).replace('\\', '/')
                    tf.add(full, arcname=arcname)

        cmd = [
            sys.executable, "scripts/mkdisk.py",
            "--size", str(args.disk_size),
            "--tarball", sysroot_tar,
        ]
        print(f"  Running: {' '.join(cmd)}")
        result = subprocess.run(cmd)
        if result.returncode != 0:
            print("  Disk creation failed.")
            return 1

    print("\nDone!")
    return 0


if __name__ == "__main__":
    sys.exit(main())
