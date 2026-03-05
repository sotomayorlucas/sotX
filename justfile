# sotOS Build System
# Requires: rust nightly, python3, QEMU

set shell := ["C:/Program Files/Git/bin/bash.exe", "-c"]

QEMU := if os() == "windows" { "C:/Program Files/qemu/qemu-system-x86_64.exe" } else { "qemu-system-x86_64" }
KERNEL := "target/x86_64-unknown-none/debug/sotos-kernel"
IMAGE := "target/sotos.img"
USER_INIT := "services/init/target/x86_64-unknown-none/debug/sotos-init"
USER_SHELL := "services/lucas-shell/target/x86_64-unknown-none/debug/sotos-lucas-shell"
USER_KBD := "services/kbd/target/x86_64-unknown-none/debug/sotos-kbd"
USER_NET := "services/net/target/x86_64-unknown-none/debug/sotos-net-svc"
USER_VMM := "services/vmm/target/x86_64-unknown-none/debug/sotos-vmm"
USER_HELLO := "services/hello/target/x86_64-unknown-none/debug/sotos-hello"
TESTLIB := "target/libtest.so"
INITRD := "target/initrd.img"

# Default: build and run
default: run

# Build userspace init
build-user:
    cd services/init && CARGO_ENCODED_RUSTFLAGS="$(printf '%s\x1f%s\x1f%s' '-Clink-arg=-Tlinker.ld' '-Crelocation-model=static' '-Zstack-protector=strong')" cargo build

# Build LUCAS shell (Linux-ABI guest binary)
build-shell:
    cd services/lucas-shell && CARGO_ENCODED_RUSTFLAGS="$(printf '%s\x1f%s\x1f%s' '-Clink-arg=-Tlinker.ld' '-Crelocation-model=static' '-Zstack-protector=strong')" cargo build

# Build keyboard driver (separate process)
build-kbd:
    cd services/kbd && CARGO_ENCODED_RUSTFLAGS="$(printf '%s\x1f%s\x1f%s' '-Clink-arg=-Tlinker.ld' '-Crelocation-model=static' '-Zstack-protector=strong')" cargo build

# Build network driver (separate process)
build-net:
    cd services/net && CARGO_ENCODED_RUSTFLAGS="$(printf '%s\x1f%s\x1f%s' '-Clink-arg=-Tlinker.ld' '-Crelocation-model=static' '-Zstack-protector=strong')" cargo build

# Build VMM server (separate process)
build-vmm:
    cd services/vmm && CARGO_ENCODED_RUSTFLAGS="$(printf '%s\x1f%s\x1f%s' '-Clink-arg=-Tlinker.ld' '-Crelocation-model=static' '-Zstack-protector=strong')" cargo build

# Build hello test process (spawned from userspace)
build-hello:
    cd services/hello && CARGO_ENCODED_RUSTFLAGS="$(printf '%s\x1f%s\x1f%s' '-Clink-arg=-Tlinker.ld' '-Crelocation-model=static' '-Zstack-protector=strong')" cargo build

# Build test shared library (for dynamic linking)
build-testlib:
    cd libs/sotos-testlib && CARGO_ENCODED_RUSTFLAGS="$(printf '%s' '-Crelocation-model=pic')" cargo build
    python scripts/mksharedlib.py \
        --archive libs/sotos-testlib/target/x86_64-unknown-none/debug/libsotos_testlib.a \
        --linker-script libs/sotos-testlib/linker-so.ld \
        --output {{TESTLIB}}

# Build the kernel
build:
    cargo build --package sotos-kernel

# Build in release mode
release:
    cargo build --package sotos-kernel --release

# Create CPIO initrd from userspace binaries
initrd: build-user build-shell build-kbd build-net build-vmm build-hello build-testlib
    python scripts/mkinitrd.py --output {{INITRD}} --file init={{USER_INIT}} --file shell={{USER_SHELL}} --file kbd={{USER_KBD}} --file net={{USER_NET}} --file vmm={{USER_VMM}} --file hello={{USER_HELLO}} --file libtest.so={{TESTLIB}}

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
        -m 256M \
        -smp 4

# Run with SMP (4 CPUs)
run-smp: image
    "{{QEMU}}" \
        -drive format=raw,file={{IMAGE}} \
        -serial stdio \
        -display none \
        -no-reboot \
        -m 256M \
        -smp 4

# Run with QEMU display window (for framebuffer/keyboard)
run-gui: image create-test-disk
    "{{QEMU}}" \
        -drive format=raw,file={{IMAGE}} \
        -drive if=none,format=raw,file=target/disk.img,id=disk0 \
        -device virtio-blk-pci,drive=disk0,disable-modern=on \
        -serial stdio \
        -no-reboot \
        -m 256M \
        -smp 4

# Run with GDB server for debugging (connect with gdb -ex "target remote :1234")
debug: image
    "{{QEMU}}" \
        -drive format=raw,file={{IMAGE}} \
        -serial stdio \
        -display none \
        -no-reboot \
        -m 256M \
        -smp 4 \
        -s -S

# Create a 1 MiB test disk for virtio-blk
create-test-disk:
    python scripts/mkdisk.py

# Run with virtio-net (and virtio-blk)
run-net: image create-test-disk
    "{{QEMU}}" \
        -drive format=raw,file={{IMAGE}} \
        -drive if=none,format=raw,file=target/disk.img,id=disk0 \
        -device virtio-blk-pci,drive=disk0,disable-modern=on \
        -netdev user,id=net0,hostfwd=udp::5555-:5555,hostfwd=tcp::7777-:7 \
        -device virtio-net-pci,netdev=net0,disable-modern=on \
        -serial stdio \
        -no-reboot \
        -m 256M \
        -smp 4

# Run with virtio-net + Wireshark packet capture (pcap)
run-net-pcap: image create-test-disk
    "{{QEMU}}" \
        -drive format=raw,file={{IMAGE}} \
        -drive if=none,format=raw,file=target/disk.img,id=disk0 \
        -device virtio-blk-pci,drive=disk0,disable-modern=on \
        -netdev user,id=net0,hostfwd=udp::5555-:5555,hostfwd=tcp::7777-:7 \
        -device virtio-net-pci,netdev=net0,disable-modern=on \
        -object filter-dump,id=dump0,netdev=net0,file=target/net.pcap \
        -serial stdio \
        -no-reboot \
        -m 256M \
        -smp 4

# Run with virtio-blk test disk
run-blk: image create-test-disk
    "{{QEMU}}" \
        -drive format=raw,file={{IMAGE}} \
        -drive if=none,format=raw,file=target/disk.img,id=disk0 \
        -device virtio-blk-pci,drive=disk0,disable-modern=on \
        -serial stdio \
        -no-reboot \
        -m 256M \
        -smp 4

# Clean build artifacts
clean:
    cargo clean

# Check without building (fast feedback)
check:
    cargo check --package sotos-kernel

# Run clippy
lint:
    cargo clippy --package sotos-kernel -- -W clippy::all
