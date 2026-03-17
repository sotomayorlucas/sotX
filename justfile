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
USER_NET_TEST := "services/net-test/target/x86_64-unknown-none/debug/sotos-net-test"
MUSL_LD := "ld-musl-x86_64.so.1"
USER_NANO := "nano"
USER_BUSYBOX := "busybox"
USER_LINKS := "links"
USER_HELLO_GLIBC := "hello_glibc"
GLIBC_LD := "ld-linux-x86-64.so.2"
GLIBC_LIBC := "libc.so.6"
LIBNCURSESW := "libncursesw.so.6"
TERMINFO_XTERM := "xterm"
TESTLIB := "target/libtest.so"
USER_TOYBOX := "toybox"
USER_JQ := "jq"
USER_BASH := "bash-static"
USER_GREP := "grep_alpine"
USER_SED := "sed_alpine"
USER_HELLO_GNU := "hello_gnu"
LIBGCC_S := "libgcc_s.so.1"
LIBSTDCPP := "libstdc++.so.6"
LIBZ := "libz.so.1"
USER_FASTFETCH := "fastfetch"
USER_APK := "apk"
USER_HTOP := "htop"
INITRD := "target/initrd.img"

# Default: build and run
default: run

# Build userspace init
build-user:
    cd services/init && CARGO_ENCODED_RUSTFLAGS="$(printf '%s\x1f%s\x1f%s\x1f%s' '-Clink-arg=-Tlinker.ld' '-Crelocation-model=static' '-Zstack-protector=strong' '-Zub-checks=no')" cargo build

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

# Build net-test (network socket proxy test for LUCAS)
build-net-test:
    cd services/net-test && CARGO_ENCODED_RUSTFLAGS="$(printf '%s\x1f%s\x1f%s' '-Clink-arg=-Tlinker.ld' '-Crelocation-model=static' '-Zstack-protector=strong')" cargo build

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
initrd: build-user build-shell build-kbd build-net build-nvme build-xhci build-vmm build-hello build-hello-linux build-net-test build-testlib
    python scripts/mkinitrd.py --output {{INITRD}} --file init={{USER_INIT}} --file shell={{USER_SHELL}} --file kbd={{USER_KBD}} --file net={{USER_NET}} --file nvme={{USER_NVME}} --file xhci={{USER_XHCI}} --file vmm={{USER_VMM}} --file hello={{USER_HELLO}} --file hello-linux={{USER_HELLO_LINUX}} --file hello-musl={{USER_HELLO_MUSL}} --file hello_dynamic={{USER_HELLO_DYNAMIC}} --file ld-musl-x86_64.so.1={{MUSL_LD}} --file nano={{USER_NANO}} --file libncursesw.so.6={{LIBNCURSESW}} --file xterm={{TERMINFO_XTERM}} --file libtest.so={{TESTLIB}} --file net-test={{USER_NET_TEST}} --file busybox={{USER_BUSYBOX}} --file links={{USER_LINKS}} --file hello_glibc={{USER_HELLO_GLIBC}} --file ld-linux-x86-64.so.2={{GLIBC_LD}} --file libc.so.6={{GLIBC_LIBC}} --file toybox={{USER_TOYBOX}} --file jq={{USER_JQ}} --file bash-static={{USER_BASH}} --file grep_alpine={{USER_GREP}} --file sed_alpine={{USER_SED}} --file hello_gnu={{USER_HELLO_GNU}} --file libgcc_s.so.1={{LIBGCC_S}} --file libstdc++.so.6={{LIBSTDCPP}} --file libz.so.1={{LIBZ}} --file fastfetch={{USER_FASTFETCH}} --file apk={{USER_APK}} --file htop={{USER_HTOP}}

# Create the bootable disk image (BIOS + Limine)
image: build initrd
    python scripts/mkimage.py --kernel {{KERNEL}} --initrd {{INITRD}} --output {{IMAGE}} --size 128

# Build and run in QEMU (serial output to terminal, single CPU)
run: image
    "{{QEMU}}" \
        -drive format=raw,file={{IMAGE}} \
        -serial stdio \
        -display none \
        -no-reboot \
        -m 1024M

# Run with SMP (4 CPUs — may hang due to scheduler race, use for testing only)
run-smp: image
    "{{QEMU}}" \
        -drive format=raw,file={{IMAGE}} \
        -serial stdio \
        -display none \
        -no-reboot \
        -m 1024M \
        -smp 4

# Run with QEMU display window (for framebuffer/keyboard testing)
run-gui: image create-test-disk
    "{{QEMU}}" \
        -drive format=raw,file={{IMAGE}} \
        -drive if=none,format=raw,file=target/disk.img,id=disk0 \
        -device virtio-blk-pci,drive=disk0,disable-modern=on \
        -serial stdio \
        -no-reboot \
        -m 1024M \
        -display sdl

# Run with GDB server for debugging (connect with gdb -ex "target remote :1234")
debug: image
    "{{QEMU}}" \
        -drive format=raw,file={{IMAGE}} \
        -serial stdio \
        -display none \
        -no-reboot \
        -m 1024M \
        -s -S

# Create a 256 MiB ObjectStore v5 disk (or inject rootfs if present)
create-test-disk:
    python scripts/mkdisk.py --size 256

# Create a rootfs-populated disk from an extracted rootfs directory
create-rootfs-disk ROOTFS="rootfs":
    python scripts/mkdisk.py --size 256 --rootfs {{ROOTFS}}

# Run with HTTPS proxy (auto-starts proxy on host, guest can download Alpine packages)
run-https: image
    @echo "Starting HTTPS proxy on port 8080..."
    python scripts/https_proxy.py -p 8080 &
    @sleep 1
    "{{QEMU}}" \
        -drive format=raw,file={{IMAGE}} \
        -device virtio-net-pci,netdev=n0 \
        -netdev user,id=n0 \
        -serial stdio \
        -display none \
        -no-reboot \
        -m 1024M; \
    kill %1 2>/dev/null || true

# Run with virtio-net (and virtio-blk)
run-net: image create-test-disk
    "{{QEMU}}" \
        -drive format=raw,file={{IMAGE}} \
        -drive if=none,format=raw,file=target/disk.img,id=disk0 \
        -device virtio-blk-pci,drive=disk0,disable-modern=on \
        -netdev user,id=net0,dns=8.8.8.8,hostfwd=udp::5555-:5555,hostfwd=tcp::7777-:7 \
        -device virtio-net-pci,netdev=net0,disable-modern=on \
        -serial stdio \
        -no-reboot \
        -m 1024M

# Run with virtio-net + Wireshark packet capture (pcap)
run-net-pcap: image create-test-disk
    "{{QEMU}}" \
        -drive format=raw,file={{IMAGE}} \
        -drive if=none,format=raw,file=target/disk.img,id=disk0 \
        -device virtio-blk-pci,drive=disk0,disable-modern=on \
        -netdev user,id=net0,dns=8.8.8.8,hostfwd=udp::5555-:5555,hostfwd=tcp::7777-:7 \
        -device virtio-net-pci,netdev=net0,disable-modern=on \
        -object filter-dump,id=dump0,netdev=net0,file=target/net.pcap \
        -serial stdio \
        -no-reboot \
        -m 1024M

# Run with virtio-blk test disk
run-blk: image create-test-disk
    "{{QEMU}}" \
        -drive format=raw,file={{IMAGE}} \
        -drive if=none,format=raw,file=target/disk.img,id=disk0 \
        -device virtio-blk-pci,drive=disk0,disable-modern=on \
        -serial stdio \
        -no-reboot \
        -m 1024M

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
        -m 1024M

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
        -m 1024M

# Run with ALL devices (virtio-blk, virtio-net, NVMe, xHCI USB kbd+mouse, AC97 audio, AHCI SATA, display)
run-full: image create-test-disk create-nvme-disk
    "{{QEMU}}" \
        -drive format=raw,file={{IMAGE}} \
        -drive if=none,format=raw,file=target/disk.img,id=disk0 \
        -device virtio-blk-pci,drive=disk0,disable-modern=on \
        -drive file=target/nvme-disk.img,format=raw,if=none,id=nvme0 \
        -device nvme,serial=sotOS-NVMe,drive=nvme0 \
        -netdev user,id=net0,dns=8.8.8.8,hostfwd=udp::5555-:5555,hostfwd=tcp::7777-:7 \
        -device virtio-net-pci,netdev=net0,disable-modern=on \
        -device qemu-xhci,id=xhci \
        -device usb-kbd,bus=xhci.0 \
        -device usb-mouse,bus=xhci.0 \
        -device AC97 \
        -device ahci,id=ahci0 \
        -serial stdio \
        -no-reboot \
        -m 1024M

# Automated validation: build everything, boot with 90s timeout, verify no panics
run-all: image create-test-disk
    @echo "=== sotOS run-all: automated build + boot validation ==="
    timeout 90 "{{QEMU}}" \
        -drive format=raw,file={{IMAGE}} \
        -drive if=none,format=raw,file=target/disk.img,id=disk0 \
        -device virtio-blk-pci,drive=disk0,disable-modern=on \
        -netdev user,id=net0,dns=8.8.8.8 \
        -device virtio-net-pci,netdev=net0,disable-modern=on \
        -serial stdio \
        -display none \
        -no-reboot \
        -m 1024M > target/test-output.log 2>&1; true
    @if grep -qiE "STACK.SMASH|PANIC" target/test-output.log; then \
        echo "FAIL: found panic/crash in output:"; \
        grep -iE "STACK.SMASH|PANIC" target/test-output.log; \
        exit 1; \
    fi
    @if ! grep -q "LUCAS" target/test-output.log; then \
        echo "FAIL: boot did not reach LUCAS shell"; \
        cat target/test-output.log | tail -20; \
        exit 1; \
    fi
    @echo "--- Key boot milestones ---"
    @grep -E "NET:.*MAC|DHCP.*IP=|PONG|async.*completed|FAT32-TEST:.*SUCCESS|LUCAS:.*starting" target/test-output.log || true
    @echo "=== PASS: sotOS booted successfully without panics ==="

# Run comprehensive test suite (boots QEMU, tests all features via serial)
test *ARGS: image
    python scripts/test_system.py {{ARGS}}

# Run tests with verbose output
test-verbose: image
    python scripts/test_system.py --verbose

# Flash sotOS image to a disk/USB drive (usage: just flash DISK=/dev/sdX)
flash DISK: image
    @echo "WARNING: This will OVERWRITE all data on {{DISK}}"
    @echo "Press Ctrl+C to cancel, or Enter to continue..."
    @read -r _
    dd if={{IMAGE}} of={{DISK}} bs=4M status=progress conv=fsync
    @echo "Flash complete. You can now boot from {{DISK}}."

# Download Alpine + Ubuntu rootfs tarballs
fetch-rootfs:
    python scripts/fetch_rootfs.py

# Build a 1 GiB sysroot disk with Alpine (musl) + Ubuntu (glibc) rootfs
build-sysroot: fetch-rootfs
    python scripts/mkdisk.py --size 1024 --output target/sysroot.img \
        --tarball target/alpine.tar.gz \
        --tarball target/ubuntu-base.tar.gz

# Run with Linux sysroot disk (Alpine+Ubuntu rootfs)
run-linux: image build-sysroot
    "{{QEMU}}" \
        -drive format=raw,file={{IMAGE}} \
        -drive if=none,format=raw,file=target/sysroot.img,id=disk0 \
        -device virtio-blk-pci,drive=disk0,disable-modern=on \
        -netdev user,id=net0,dns=8.8.8.8 \
        -device virtio-net-pci,netdev=net0,disable-modern=on \
        -serial stdio \
        -no-reboot \
        -m 1024M

# Clean build artifacts
clean:
    cargo clean

# Run interactive cybersecurity demo (serial console, automated test sequence)
demo: image create-test-disk
    python scripts/interactive_test.py

# Check without building (fast feedback)
check:
    cargo check --package sotos-kernel

# Run clippy
lint:
    cargo clippy --package sotos-kernel -- -W clippy::all
