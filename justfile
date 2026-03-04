# sotOS Build System
# Requires: rust nightly, python3, QEMU

QEMU := if os() == "windows" { "C:/Program Files/qemu/qemu-system-x86_64.exe" } else { "qemu-system-x86_64" }
KERNEL := "target/x86_64-unknown-none/debug/sotos-kernel"
IMAGE := "target/sotos.img"
USER_INIT := "services/init/target/x86_64-unknown-none/debug/sotos-init"
INITRD := "target/initrd.img"

# Default: build and run
default: run

# Build userspace programs (CARGO_ENCODED_RUSTFLAGS overrides parent .cargo/config.toml)
build-user:
    cd services/init && CARGO_ENCODED_RUSTFLAGS="$(printf '%s\x1f%s' '-Clink-arg=-Tlinker.ld' '-Crelocation-model=static')" cargo build

# Build the kernel
build:
    cargo build --package sotos-kernel

# Build in release mode
release:
    cargo build --package sotos-kernel --release

# Create CPIO initrd from userspace binaries
initrd: build-user
    python scripts/mkinitrd.py --output {{INITRD}} --file init={{USER_INIT}}

# Create the bootable disk image (BIOS + Limine)
image: build initrd
    python scripts/mkimage.py --kernel {{KERNEL}} --initrd {{INITRD}} --output {{IMAGE}}

# Build and run in QEMU (serial output to terminal)
run: image
    "{{QEMU}}" \
        -drive format=raw,file={{IMAGE}} \
        -serial stdio \
        -display none \
        -no-reboot \
        -m 256M

# Run with SMP (4 CPUs)
run-smp: image
    "{{QEMU}}" \
        -drive format=raw,file={{IMAGE}} \
        -serial stdio \
        -display none \
        -no-reboot \
        -m 256M \
        -smp 4

# Run with QEMU display window (for framebuffer/Limine menu)
run-gui: image
    "{{QEMU}}" \
        -drive format=raw,file={{IMAGE}} \
        -serial stdio \
        -no-reboot \
        -m 256M

# Run with GDB server for debugging (connect with gdb -ex "target remote :1234")
debug: image
    "{{QEMU}}" \
        -drive format=raw,file={{IMAGE}} \
        -serial stdio \
        -display none \
        -no-reboot \
        -m 256M \
        -s -S

# Create a 1 MiB test disk for virtio-blk
create-test-disk:
    python scripts/mkdisk.py

# Run with virtio-blk test disk
run-blk: image create-test-disk
    "{{QEMU}}" \
        -drive format=raw,file={{IMAGE}} \
        -drive if=none,format=raw,file=target/disk.img,id=disk0 \
        -device virtio-blk-pci,drive=disk0,disable-modern=on \
        -serial stdio \
        -display none \
        -no-reboot \
        -m 256M

# Clean build artifacts
clean:
    cargo clean

# Check without building (fast feedback)
check:
    cargo check --package sotos-kernel

# Run clippy
lint:
    cargo clippy --package sotos-kernel -- -W clippy::all
