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
USER_NVME := "services/nvme/target/x86_64-unknown-none/debug/sotos-nvme-svc"
USER_XHCI := "services/xhci/target/x86_64-unknown-none/debug/sotos-xhci-svc"
USER_VMM := "services/vmm/target/x86_64-unknown-none/debug/sotos-vmm"
USER_HELLO := "services/hello/target/x86_64-unknown-none/debug/sotos-hello"
USER_HELLO_LINUX := "services/hello-linux/target/x86_64-unknown-none/debug/sotos-hello-linux"
USER_HELLO_MUSL := "target/hello-musl-raw"
USER_HELLO_DYNAMIC := "hello_dynamic"
MUSL_LD := "ld-musl-x86_64.so.1"
USER_NANO := "nano"
LIBNCURSESW := "libncursesw.so.6"
TERMINFO_XTERM := "xterm"
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

# Build NVMe driver (separate process)
build-nvme:
    cd services/nvme && CARGO_ENCODED_RUSTFLAGS="$(printf '%s\x1f%s\x1f%s' '-Clink-arg=-Tlinker.ld' '-Crelocation-model=static' '-Zstack-protector=strong')" cargo build

# Build xHCI USB driver (separate process)
build-xhci:
    cd services/xhci && CARGO_ENCODED_RUSTFLAGS="$(printf '%s\x1f%s\x1f%s' '-Clink-arg=-Tlinker.ld' '-Crelocation-model=static' '-Zstack-protector=strong')" cargo build

# Build hello-linux (Linux ABI test binary for LUCAS)
build-hello-linux:
    cd services/hello-linux && CARGO_ENCODED_RUSTFLAGS="$(printf '%s\x1f%s\x1f%s' '-Clink-arg=-Tlinker.ld' '-Crelocation-model=static' '-Zstack-protector=strong')" cargo build

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
initrd: build-user build-shell build-kbd build-net build-nvme build-xhci build-vmm build-hello build-hello-linux build-testlib
    python scripts/mkinitrd.py --output {{INITRD}} --file init={{USER_INIT}} --file shell={{USER_SHELL}} --file kbd={{USER_KBD}} --file net={{USER_NET}} --file nvme={{USER_NVME}} --file xhci={{USER_XHCI}} --file vmm={{USER_VMM}} --file hello={{USER_HELLO}} --file hello-linux={{USER_HELLO_LINUX}} --file hello-musl={{USER_HELLO_MUSL}} --file hello_dynamic={{USER_HELLO_DYNAMIC}} --file ld-musl-x86_64.so.1={{MUSL_LD}} --file nano={{USER_NANO}} --file libncursesw.so.6={{LIBNCURSESW}} --file xterm={{TERMINFO_XTERM}} --file libtest.so={{TESTLIB}}

# Create the bootable disk image (BIOS + Limine)
image: build initrd
    python scripts/mkimage.py --kernel {{KERNEL}} --initrd {{INITRD}} --output {{IMAGE}}

# Build and run in QEMU (serial output to terminal, single CPU)
run: image
    "{{QEMU}}" \
        -drive format=raw,file={{IMAGE}} \
        -serial stdio \
        -display none \
        -no-reboot \
        -m 256M

# Run with SMP (4 CPUs — may hang due to scheduler race, use for testing only)
run-smp: image
    "{{QEMU}}" \
        -drive format=raw,file={{IMAGE}} \
        -serial stdio \
        -display none \
        -no-reboot \
        -m 256M \
        -smp 4

# Run with QEMU display window (for framebuffer/keyboard/mouse)
# Uses -display sdl to get PS/2 mouse input. Click inside window to grab mouse;
# Ctrl+Alt+G to release mouse grab.
run-gui: image create-test-disk
    "{{QEMU}}" \
        -drive format=raw,file={{IMAGE}} \
        -drive if=none,format=raw,file=target/disk.img,id=disk0 \
        -device virtio-blk-pci,drive=disk0,disable-modern=on \
        -serial stdio \
        -no-reboot \
        -m 256M \
        -display sdl \
        -machine usb=off

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
        -m 256M

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
        -m 256M

# Run with virtio-blk test disk
run-blk: image create-test-disk
    "{{QEMU}}" \
        -drive format=raw,file={{IMAGE}} \
        -drive if=none,format=raw,file=target/disk.img,id=disk0 \
        -device virtio-blk-pci,drive=disk0,disable-modern=on \
        -serial stdio \
        -no-reboot \
        -m 256M

# Create a 64 MiB NVMe test disk
create-nvme-disk:
    python scripts/mknvmedisk.py

# Run with NVMe SSD (and virtio-blk for ObjectStore)
run-nvme: image create-test-disk create-nvme-disk
    "{{QEMU}}" \
        -drive format=raw,file={{IMAGE}} \
        -drive if=none,format=raw,file=target/disk.img,id=disk0 \
        -device virtio-blk-pci,drive=disk0,disable-modern=on \
        -drive file=target/nvme-disk.img,format=raw,if=none,id=nvme0 \
        -device nvme,serial=sotOS-NVMe,drive=nvme0 \
        -serial stdio \
        -no-reboot \
        -m 256M

# Run with xHCI USB controller (and virtio-blk for ObjectStore)
run-xhci: image create-test-disk
    "{{QEMU}}" \
        -drive format=raw,file={{IMAGE}} \
        -drive if=none,format=raw,file=target/disk.img,id=disk0 \
        -device virtio-blk-pci,drive=disk0,disable-modern=on \
        -device qemu-xhci,id=xhci \
        -device usb-kbd,bus=xhci.0 \
        -serial stdio \
        -no-reboot \
        -m 256M

# Run with ALL devices (virtio-blk, virtio-net, NVMe, xHCI USB kbd+mouse, AC97 audio, AHCI SATA, display)
run-full: image create-test-disk create-nvme-disk
    "{{QEMU}}" \
        -drive format=raw,file={{IMAGE}} \
        -drive if=none,format=raw,file=target/disk.img,id=disk0 \
        -device virtio-blk-pci,drive=disk0,disable-modern=on \
        -drive file=target/nvme-disk.img,format=raw,if=none,id=nvme0 \
        -device nvme,serial=sotOS-NVMe,drive=nvme0 \
        -netdev user,id=net0,hostfwd=udp::5555-:5555,hostfwd=tcp::7777-:7 \
        -device virtio-net-pci,netdev=net0,disable-modern=on \
        -device qemu-xhci,id=xhci \
        -device usb-kbd,bus=xhci.0 \
        -device usb-mouse,bus=xhci.0 \
        -device AC97 \
        -device ahci,id=ahci0 \
        -serial stdio \
        -no-reboot \
        -m 512M

# Flash sotOS image to a disk/USB drive (usage: just flash DISK=/dev/sdX)
flash DISK: image
    @echo "WARNING: This will OVERWRITE all data on {{DISK}}"
    @echo "Press Ctrl+C to cancel, or Enter to continue..."
    @read -r _
    dd if={{IMAGE}} of={{DISK}} bs=4M status=progress conv=fsync
    @echo "Flash complete. You can now boot from {{DISK}}."

# Clean build artifacts
clean:
    cargo clean

# Check without building (fast feedback)
check:
    cargo check --package sotos-kernel

# Run clippy
lint:
    cargo clippy --package sotos-kernel -- -W clippy::all
