# LKL (Linux Kernel Library) for sotX

LKL compiles the real Linux kernel as a static userspace library (`liblkl.a`).
sotX will link against it to get production-grade filesystem, networking, and
block-device support without re-implementing those subsystems.

## Prerequisites

The build runs inside **WSL2** (Ubuntu or Debian).  Install the toolchain:

```bash
sudo apt-get update
sudo apt-get install -y gcc make flex bison bc libelf-dev git
```

## Build

From the repo root on Windows (uses `just`):

```
just build-lkl
```

Or manually inside WSL:

```bash
cd lkl/
bash build-lkl.sh
```

The script will:

1. Clone `lkl/linux` at tag `lkl-4.19-rc3` (shallow, ~200 MB).
2. Apply `lkl_defconfig` (minimal: tmpfs, ext4, virtio-blk/net, no modules,
   no /proc, no debug info, size-optimized).
3. Build with `make ARCH=lkl tools/lkl/`.
4. Copy artifacts to `lkl/output/`.

## Output

```
lkl/output/
  liblkl.a          -- static library to link into sotX userspace
  include/           -- LKL public headers (lkl.h, lkl_host.h, ...)
```

## Configuration

Edit `lkl_defconfig` to enable/disable kernel features.  After changes, re-run
`just build-lkl` (or `bash build-lkl.sh`).  Key options:

| Option               | Default | Purpose                    |
|----------------------|---------|----------------------------|
| CONFIG_EXT4_FS       | y       | ext4 filesystem            |
| CONFIG_TMPFS         | y       | in-memory tmpfs            |
| CONFIG_VIRTIO_BLK    | y       | virtio block device        |
| CONFIG_VIRTIO_NET    | y       | virtio network device      |
| CONFIG_MODULES       | n       | no loadable modules        |
| CONFIG_PROC_FS       | n       | no /proc (emulated by init)|
| CONFIG_DEBUG_INFO    | n       | no DWARF -- smaller binary |

## Pinned version

The build script clones tag `lkl-4.19-rc3`.  To update, change `LKL_TAG` in
`build-lkl.sh` and verify the build still succeeds.
