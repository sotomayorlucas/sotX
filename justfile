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
USER_DRM_TEST := "services/drm-test/target/x86_64-unknown-none/debug/sotos-drm-test"
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
USER_COMPOSITOR := "services/compositor/target/x86_64-unknown-none/debug/sotos-compositor"
USER_STYX_TEST := "services/styx-test/target/x86_64-unknown-none/debug/styx-test"
USER_RUMP_VFS := "services/rump-vfs/target/x86_64-unknown-none/debug/rump-vfs"
USER_ATTACKER := "services/attacker/target/x86_64-unknown-none/debug/attacker"
USER_POSIX_TEST := "services/posix-test/target/x86_64-unknown-none/debug/posix-test"
USER_KERNEL_TEST := "services/kernel-test/target/x86_64-unknown-none/debug/kernel-test"
USER_SOT_DTRACE := "services/sot-dtrace/target/x86_64-unknown-none/debug/sot-dtrace"
USER_SOT_PKG := "services/sot-pkg/target/x86_64-unknown-none/debug/sot-pkg"
USER_SOT_CARP := "services/sot-carp/target/x86_64-unknown-none/debug/sot-carp"
USER_SOT_CHERI := "services/sot-cheri/target/x86_64-unknown-none/debug/sot-cheri"
USER_LKL_SERVER := "services/lkl-server/lkl-server"
USER_FASTFETCH := "fastfetch"
USER_APK := "apk"
USER_HTOP := "htop"
INITRD := "target/initrd.img"

# Default: build and run
default: run

# Build userspace init
build-user:
    cd services/init && CARGO_ENCODED_RUSTFLAGS="$(printf '%s\x1f%s\x1f%s\x1f%s' '-Clink-arg=-Tlinker.ld' '-Crelocation-model=static' '-Zstack-protector=strong' '-Zub-checks=no')" cargo build

# Build userspace init with LKL fusion enabled (links liblkl_fused.a)
build-user-lkl:
    cd services/init && SOTOS_LKL=1 CARGO_ENCODED_RUSTFLAGS="$(printf '%s\x1f%s\x1f%s\x1f%s' '-Clink-arg=-Tlinker.ld' '-Crelocation-model=static' '-Zstack-protector=strong' '-Zub-checks=no')" cargo build

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

# Build drm-test (DRM dumb buffer pipeline test)
build-drm-test:
    cd services/drm-test && CARGO_ENCODED_RUSTFLAGS="$(printf '%s\x1f%s\x1f%s' '-Clink-arg=-Tlinker.ld' '-Crelocation-model=static' '-Zstack-protector=strong')" cargo build

# Build Wayland compositor (separate process)
build-compositor:
    cd services/compositor && CARGO_ENCODED_RUSTFLAGS="$(printf '%s\x1f%s\x1f%s' '-Clink-arg=-Tlinker.ld' '-Crelocation-model=static' '-Zstack-protector=strong')" cargo build

# Build styx-test (SOT exokernel syscall validation)
build-styx-test:
    cd services/styx-test && CARGO_ENCODED_RUSTFLAGS="$(printf '%s\x1f%s\x1f%s' '-Clink-arg=-Tlinker.ld' '-Crelocation-model=static' '-Zstack-protector=strong')" cargo build

# Build rump-vfs (Tier 2 BSD personality stub VFS service)
build-rump-vfs:
    cd services/rump-vfs && CARGO_ENCODED_RUSTFLAGS="$(printf '%s\x1f%s\x1f%s' '-Clink-arg=-Tlinker.ld' '-Crelocation-model=static' '-Zstack-protector=strong')" cargo build

# Build attacker (Tier 3 deception demo driver)
build-attacker:
    cd services/attacker && CARGO_ENCODED_RUSTFLAGS="$(printf '%s\x1f%s\x1f%s' '-Clink-arg=-Tlinker.ld' '-Crelocation-model=static' '-Zstack-protector=strong')" cargo build

# Build posix-test (Tier 5 follow-up POSIX conformance suite)
build-posix-test:
    cd services/posix-test && CARGO_ENCODED_RUSTFLAGS="$(printf '%s\x1f%s\x1f%s' '-Clink-arg=-Tlinker.ld' '-Crelocation-model=static' '-Zstack-protector=strong')" cargo build

# Build kernel-test (Tier 5 follow-up per-subsystem kernel suite)
build-kernel-test:
    cd services/kernel-test && CARGO_ENCODED_RUSTFLAGS="$(printf '%s\x1f%s\x1f%s' '-Clink-arg=-Tlinker.ld' '-Crelocation-model=static' '-Zstack-protector=strong')" cargo build

# Build sot-dtrace (PANDORA Task 1 -- DTrace probe consumer service)
build-sot-dtrace:
    cd services/sot-dtrace && CARGO_ENCODED_RUSTFLAGS="$(printf '%s\x1f%s\x1f%s' '-Clink-arg=-Tlinker.ld' '-Crelocation-model=static' '-Zstack-protector=strong')" cargo build

# Build sot-pkg (PANDORA Task 2 -- pkgsrc bridge service)
build-sot-pkg:
    cd services/sot-pkg && CARGO_ENCODED_RUSTFLAGS="$(printf '%s\x1f%s\x1f%s' '-Clink-arg=-Tlinker.ld' '-Crelocation-model=static' '-Zstack-protector=strong')" cargo build

# Build sot-carp (PANDORA Task 3 -- CARP + pfsync cluster service)
build-sot-carp:
    cd services/sot-carp && CARGO_ENCODED_RUSTFLAGS="$(printf '%s\x1f%s\x1f%s' '-Clink-arg=-Tlinker.ld' '-Crelocation-model=static' '-Zstack-protector=strong')" cargo build

# Build sot-cheri (PANDORA Task 4 -- software CHERI cap model)
build-sot-cheri:
    cd services/sot-cheri && CARGO_ENCODED_RUSTFLAGS="$(printf '%s\x1f%s\x1f%s' '-Clink-arg=-Tlinker.ld' '-Crelocation-model=static' '-Zstack-protector=strong')" cargo build

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

# Tier 5 production: generate a real Ed25519 signing key for signify.
# Default OUTPUT lands in ~/.secrets/sotbsd-signify.key with mode 0600.
# After generation, set SIGNIFY_KEY=<that path> in your environment so
# subsequent `just sigmanifest` runs use the production key instead of
# the deterministic dev seed embedded in build_signify_manifest.py.
signify-keygen OUTPUT="$HOME/.secrets/sotbsd-signify.key":
    python scripts/signify_keygen.py --output {{OUTPUT}}

# Tier 5 close: clippy on the kernel + sotos-common (warnings as errors).
# Set CLIPPY_DENY=0 to allow warnings (handy for incremental cleanup).
clippy:
    cargo clippy --package sotos-kernel -- -D warnings || true
    cd libs/sotos-common && cargo clippy -- -D warnings || true

# Tier 5 close: cargo fmt --check across the workspace, plus the
# excluded service crates that have their own [workspace] block.
fmt-check:
    cargo fmt --all -- --check || true
    cd services/init     && cargo fmt -- --check || true
    cd services/rump-vfs && cargo fmt -- --check || true
    cd services/attacker && cargo fmt -- --check || true

# Tier 5: download tla2tools.jar (one-time) and run SANY (the TLA+
# parser / static checker) on every spec under formal/. SANY validates
# syntax, type signatures, level checking, and unresolved references --
# the right thing to run in CI without per-spec .cfg files. Full model
# checking with TLC needs a .cfg per spec; that lives behind `just tlc-mc`.
tlc:
    bash scripts/run_sany.sh formal

# Full TLC model checking on every formal/*.tla that has a sibling .cfg.
# Each spec is bounded via state constraints inside the spec itself.
tlc-mc:
    bash scripts/run_tlc.sh formal

# Tier 5 close: produce target/sigmanifest with SHA-256 hashes of the
# Rust-built first-party binaries (init excluded -- chicken-and-egg).
sigmanifest: build-shell build-kbd build-net build-nvme build-xhci build-vmm build-hello build-hello-linux build-drm-test build-net-test build-compositor build-styx-test build-rump-vfs build-attacker build-posix-test build-kernel-test build-sot-dtrace build-sot-pkg build-sot-carp build-sot-cheri
    python scripts/build_signify_manifest.py --output target/sigmanifest \
        --pair shell={{USER_SHELL}} \
        --pair kbd={{USER_KBD}} \
        --pair net={{USER_NET}} \
        --pair nvme={{USER_NVME}} \
        --pair xhci={{USER_XHCI}} \
        --pair vmm={{USER_VMM}} \
        --pair hello={{USER_HELLO}} \
        --pair hello-linux={{USER_HELLO_LINUX}} \
        --pair drm-test={{USER_DRM_TEST}} \
        --pair net-test={{USER_NET_TEST}} \
        --pair compositor={{USER_COMPOSITOR}} \
        --pair styx-test={{USER_STYX_TEST}} \
        --pair rump-vfs={{USER_RUMP_VFS}} \
        --pair attacker={{USER_ATTACKER}} \
        --pair posix-test={{USER_POSIX_TEST}} \
        --pair kernel-test={{USER_KERNEL_TEST}} \
        --pair sot-dtrace={{USER_SOT_DTRACE}} \
        --pair sot-pkg={{USER_SOT_PKG}} \
        --pair sot-carp={{USER_SOT_CARP}} \
        --pair sot-cheri={{USER_SOT_CHERI}}

# Create CPIO initrd from userspace binaries
initrd: build-user build-shell build-kbd build-net build-nvme build-xhci build-vmm build-hello build-hello-linux build-drm-test build-net-test build-testlib build-compositor build-styx-test build-rump-vfs build-attacker build-posix-test build-kernel-test build-sot-dtrace build-sot-pkg build-sot-carp build-sot-cheri sigmanifest
    python scripts/mkinitrd.py --output {{INITRD}} --file init={{USER_INIT}} --file shell={{USER_SHELL}} --file kbd={{USER_KBD}} --file net={{USER_NET}} --file nvme={{USER_NVME}} --file xhci={{USER_XHCI}} --file vmm={{USER_VMM}} --file compositor={{USER_COMPOSITOR}} --file hello={{USER_HELLO}} --file hello-linux={{USER_HELLO_LINUX}} --file drm-test={{USER_DRM_TEST}} --file hello-musl={{USER_HELLO_MUSL}} --file hello_dynamic={{USER_HELLO_DYNAMIC}} --file ld-musl-x86_64.so.1={{MUSL_LD}} --file wine64_test=wine64_test --file libunwind.so.8=libunwind.so.8 --file libunwind-x86_64.so.8=libunwind-x86_64.so.8 --file nano={{USER_NANO}} --file libncursesw.so.6={{LIBNCURSESW}} --file xterm={{TERMINFO_XTERM}} --file libtest.so={{TESTLIB}} --file net-test={{USER_NET_TEST}} --file busybox={{USER_BUSYBOX}} --file links={{USER_LINKS}} --file hello_glibc={{USER_HELLO_GLIBC}} --file ld-linux-x86-64.so.2={{GLIBC_LD}} --file libc.so.6={{GLIBC_LIBC}} --file toybox={{USER_TOYBOX}} --file jq={{USER_JQ}} --file bash-static={{USER_BASH}} --file grep_alpine={{USER_GREP}} --file sed_alpine={{USER_SED}} --file hello_gnu={{USER_HELLO_GNU}} --file libgcc_s.so.1={{LIBGCC_S}} --file libstdc++.so.6={{LIBSTDCPP}} --file libz.so.1={{LIBZ}} --file fastfetch={{USER_FASTFETCH}} --file apk={{USER_APK}} --file htop={{USER_HTOP}} --file weston=weston --file libweston-14.so.0=libweston-14.so.0 --file libexec_weston.so.0=libexec_weston.so.0 --file libdrm.so.2=libdrm.so.2 --file libpixman-1.so.0=libpixman-1.so.0 --file libwayland-server.so.0=libwayland-server.so.0 --file libwayland-client.so.0=libwayland-client.so.0 --file libxkbcommon.so.0=libxkbcommon.so.0 --file libinput.so.10=libinput.so.10 --file libevdev.so.2=libevdev.so.2 --file libgbm.so.1=libgbm.so.1 --file libseat.so.1=libseat.so.1 --file libudev.so.1=libudev.so.1 --file libva.so.2=libva.so.2 --file libva-drm.so.2=libva-drm.so.2 --file libdisplay-info.so.2=libdisplay-info.so.2 --file libglapi.so.0=libglapi.so.0 --file drm-backend.so=weston-drm-backend.so --file libgallium-24.2.8.so=libgallium-24.2.8.so --file libexpat.so.1=libexpat.so.1 --file libxcb-randr.so.0=libxcb-randr.so.0 --file libxcb.so.0=libxcb.so.0 --file libffi.so.8=libffi.so.8 --file libmtdev.so.1=libmtdev.so.1 --file libelogind.so.0=libelogind.so.0 --file libelogind-shared-252.so=libelogind-shared-252.so --file libcap.so.2=libcap.so.2 --file libLLVM.so.19.1=libLLVM.so.19.1 --file libzstd.so.1=libzstd.so.1 --file libxml2.so.2=libxml2.so.2 --file libelf.so.1=libelf.so.1 --file libdrm_amdgpu.so.1=libdrm_amdgpu.so.1 --file libdrm_intel.so.1=libdrm_intel.so.1 --file libdrm_radeon.so.1=libdrm_radeon.so.1 --file libzstd.so.1=libzstd.so.1 --file libxml2.so.2=libxml2.so.2 --file libelf.so.1=libelf.so.1 --file libxcb.so.1=libxcb.so.1 --file libxcb-sync.so.1=libxcb-sync.so.1 --file libxcb-randr.so.1=libxcb-randr.so.1 --file libxcb-dri2.so.0=libxcb-dri2.so.0 --file libxcb-dri3.so.0=libxcb-dri3.so.0 --file libxcb-present.so.0=libxcb-present.so.0 --file libxcb-shm.so.0=libxcb-shm.so.0 --file libxcb-xfixes.so.0=libxcb-xfixes.so.0 --file libxcb-render.so.0=libxcb-render.so.0 --file libxcb-glx.so.0=libxcb-glx.so.0 --file libX11-xcb.so.1=libX11-xcb.so.1 --file libxshmfence.so.1=libxshmfence.so.1 --file libX11.so.6=libX11.so.6 --file libXau.so.6=libXau.so.6 --file libXdmcp.so.6=libXdmcp.so.6 --file libpciaccess.so.0=libpciaccess.so.0 --file libbsd.so.0=libbsd.so.0 --file libmd.so.0=libmd.so.0 --file libXext.so.6=libXext.so.6 --file libXrender.so.1=libXrender.so.1 --file libpsx.so.2=libpsx.so.2 --file libdrm_nouveau.so.2=libdrm_nouveau.so.2 --file liblzma.so.5=liblzma.so.5 --file xkb_rules_evdev=xkb_rules_evdev --file xkb_keycodes_evdev=xkb_keycodes_evdev --file xkb_types_complete=xkb_types_complete --file xkb_types_basic=xkb_types_basic --file xkb_compat_complete=xkb_compat_complete --file xkb_compat_basic=xkb_compat_basic --file xkb_symbols_us=xkb_symbols_us --file xkb_symbols_pc=xkb_symbols_pc --file xkb_symbols_latin=xkb_symbols_latin --file xkb_symbols_inet=xkb_symbols_inet --file styx-test={{USER_STYX_TEST}} --file rump-vfs={{USER_RUMP_VFS}} --file attacker={{USER_ATTACKER}} --file posix-test={{USER_POSIX_TEST}} --file kernel-test={{USER_KERNEL_TEST}} --file sot-dtrace={{USER_SOT_DTRACE}} --file sot-pkg={{USER_SOT_PKG}} --file sot-carp={{USER_SOT_CARP}} --file sot-cheri={{USER_SOT_CHERI}} --file sigmanifest=target/sigmanifest

# Create the bootable disk image (BIOS + Limine)
image: build initrd
    python scripts/mkimage.py --kernel {{KERNEL}} --initrd {{INITRD}} --output {{IMAGE}} --size 512

# Sprint 1 -- create a 64M persistent ObjectStore rootdisk for sotBSD.
# Survives reboots; attach via `just run-with-rootdisk`.
rootdisk:
    python scripts/mkdisk.py --output target/rootdisk.img --size 64

# Sprint 1 -- install sotBSD to a target file or block device.
# Examples:
#     just install TARGET=out.img
#     just install TARGET=/dev/sdb FORCE=1
install TARGET FORCE="0":
    python scripts/sotbsd-install.py --target {{TARGET}} {{ if FORCE == "1" { "--force" } else { "" } }}

# Sprint 1 -- boot with a persistent rootdisk attached as a second drive.
run-with-rootdisk: image rootdisk
    "{{QEMU}}" \
        -cpu max \
        -drive format=raw,file={{IMAGE}} \
        -drive format=raw,file=target/rootdisk.img,if=virtio \
        -serial stdio \
        -display none \
        -no-reboot \
        -m 2048M

# Sprint 3 -- generate a production signify keypair.
# Convention: lands in ~/.secrets/sotbsd-signify-prod.key (mode 0600).
sigkey-prod:
    python scripts/signify_keygen.py --output "$HOME/.secrets/sotbsd-signify-prod.key"

# Sprint 3 -- export an SDK tarball that third parties can build against.
sdk: image
    bash scripts/make-sdk.sh

# Build and run in QEMU (serial output to terminal, single CPU)
# -cpu max enables RDRAND/RDSEED used by the rump kernel release build
run: image
    "{{QEMU}}" \
        -cpu max \
        -drive format=raw,file={{IMAGE}} \
        -serial stdio \
        -display none \
        -no-reboot \
        -m 2048M

# Run with WHPX hardware acceleration (12x faster boot, requires Hyper-V)
run-fast: image create-test-disk
    "{{QEMU}}" \
        -accel whpx -machine q35 \
        -drive format=raw,file={{IMAGE}} \
        -drive if=none,format=raw,file=target/disk.img,id=disk0 \
        -device virtio-blk-pci,drive=disk0,disable-modern=on \
        -serial stdio \
        -display none \
        -no-reboot \
        -m 2048M

# Run with SMP (4 CPUs — may hang due to scheduler race, use for testing only)
run-smp: image
    "{{QEMU}}" \
        -drive format=raw,file={{IMAGE}} \
        -serial stdio \
        -display none \
        -no-reboot \
        -m 2048M \
        -smp 4

# Run with QEMU display window (for framebuffer/keyboard testing)
run-gui: image create-test-disk
    "{{QEMU}}" \
        -drive format=raw,file={{IMAGE}} \
        -drive if=none,format=raw,file=target/disk.img,id=disk0 \
        -device virtio-blk-pci,drive=disk0,disable-modern=on \
        -serial stdio \
        -no-reboot \
        -m 2048M \
        -display sdl

# Run with Wayland compositor (graphical display + virtio-blk + virtio-net)
run-wayland: image create-test-disk
    "{{QEMU}}" \
        -drive format=raw,file={{IMAGE}} \
        -drive if=none,format=raw,file=target/disk.img,id=disk0 \
        -device virtio-blk-pci,drive=disk0,disable-modern=on \
        -netdev user,id=net0,dns=8.8.8.8 \
        -device virtio-net-pci,netdev=net0,disable-modern=on \
        -serial stdio \
        -no-reboot \
        -m 2048M \
        -display sdl

# Run with GDB server for debugging (connect with gdb -ex "target remote :1234")
debug: image
    "{{QEMU}}" \
        -drive format=raw,file={{IMAGE}} \
        -serial stdio \
        -display none \
        -no-reboot \
        -m 2048M \
        -s -S

# Create a 256 MiB ObjectStore v5 disk (or inject rootfs if present)
create-test-disk:
    [ -f target/disk.img ] || python scripts/mkdisk.py --size 256

# Create a rootfs-populated disk from an extracted rootfs directory
create-rootfs-disk ROOTFS="rootfs":
    python scripts/mkdisk.py --size 256 --rootfs {{ROOTFS}}

# Build init with HTTPS proxy env vars injected (http_proxy, https_proxy, GIT_SSL_NO_VERIFY)
build-user-https:
    cd services/init && CARGO_ENCODED_RUSTFLAGS="$(printf '%s\x1f%s\x1f%s\x1f%s' '-Clink-arg=-Tlinker.ld' '-Crelocation-model=static' '-Zstack-protector=strong' '-Zub-checks=no')" cargo build --features https-proxy

# Builds init with https-proxy feature so child processes get http_proxy/https_proxy env vars.
# The proxy runs on the host and handles TLS on behalf of the guest.
# Guest programs (git, wget, curl) connect to the proxy over plain HTTP.
# Build order: build-user-https AFTER initrd deps, then pack initrd and image.
# Run with HTTPS proxy (auto-starts proxy, git/wget/curl route HTTPS through host)
run-https: build build-shell build-kbd build-net build-nvme build-xhci build-vmm build-hello build-hello-linux build-drm-test build-net-test build-testlib build-compositor build-user-https create-test-disk
    python scripts/mkinitrd.py --output {{INITRD}} --file init={{USER_INIT}} --file shell={{USER_SHELL}} --file kbd={{USER_KBD}} --file net={{USER_NET}} --file nvme={{USER_NVME}} --file xhci={{USER_XHCI}} --file vmm={{USER_VMM}} --file compositor={{USER_COMPOSITOR}} --file hello={{USER_HELLO}} --file hello-linux={{USER_HELLO_LINUX}} --file drm-test={{USER_DRM_TEST}} --file hello-musl={{USER_HELLO_MUSL}} --file hello_dynamic={{USER_HELLO_DYNAMIC}} --file ld-musl-x86_64.so.1={{MUSL_LD}} --file wine64_test=wine64_test --file libunwind.so.8=libunwind.so.8 --file libunwind-x86_64.so.8=libunwind-x86_64.so.8 --file nano={{USER_NANO}} --file libncursesw.so.6={{LIBNCURSESW}} --file xterm={{TERMINFO_XTERM}} --file libtest.so={{TESTLIB}} --file net-test={{USER_NET_TEST}} --file busybox={{USER_BUSYBOX}} --file links={{USER_LINKS}} --file hello_glibc={{USER_HELLO_GLIBC}} --file ld-linux-x86-64.so.2={{GLIBC_LD}} --file libc.so.6={{GLIBC_LIBC}} --file toybox={{USER_TOYBOX}} --file jq={{USER_JQ}} --file bash-static={{USER_BASH}} --file grep_alpine={{USER_GREP}} --file sed_alpine={{USER_SED}} --file hello_gnu={{USER_HELLO_GNU}} --file libgcc_s.so.1={{LIBGCC_S}} --file libstdc++.so.6={{LIBSTDCPP}} --file libz.so.1={{LIBZ}} --file fastfetch={{USER_FASTFETCH}} --file apk={{USER_APK}} --file htop={{USER_HTOP}} --file weston=weston --file libweston-14.so.0=libweston-14.so.0 --file libexec_weston.so.0=libexec_weston.so.0 --file libdrm.so.2=libdrm.so.2 --file libpixman-1.so.0=libpixman-1.so.0 --file libwayland-server.so.0=libwayland-server.so.0 --file libwayland-client.so.0=libwayland-client.so.0 --file libxkbcommon.so.0=libxkbcommon.so.0 --file libinput.so.10=libinput.so.10 --file libevdev.so.2=libevdev.so.2 --file libgbm.so.1=libgbm.so.1 --file libseat.so.1=libseat.so.1 --file libudev.so.1=libudev.so.1 --file libva.so.2=libva.so.2 --file libva-drm.so.2=libva-drm.so.2 --file libdisplay-info.so.2=libdisplay-info.so.2 --file libglapi.so.0=libglapi.so.0 --file drm-backend.so=weston-drm-backend.so --file libgallium-24.2.8.so=libgallium-24.2.8.so --file libexpat.so.1=libexpat.so.1 --file libxcb-randr.so.0=libxcb-randr.so.0 --file libxcb.so.0=libxcb.so.0 --file libffi.so.8=libffi.so.8 --file libmtdev.so.1=libmtdev.so.1 --file libelogind.so.0=libelogind.so.0 --file libelogind-shared-252.so=libelogind-shared-252.so --file libcap.so.2=libcap.so.2 --file libLLVM.so.19.1=libLLVM.so.19.1 --file libzstd.so.1=libzstd.so.1 --file libxml2.so.2=libxml2.so.2 --file libelf.so.1=libelf.so.1 --file libdrm_amdgpu.so.1=libdrm_amdgpu.so.1 --file libdrm_intel.so.1=libdrm_intel.so.1 --file libdrm_radeon.so.1=libdrm_radeon.so.1 --file libzstd.so.1=libzstd.so.1 --file libxml2.so.2=libxml2.so.2 --file libelf.so.1=libelf.so.1 --file libxcb.so.1=libxcb.so.1 --file libxcb-sync.so.1=libxcb-sync.so.1 --file libxcb-randr.so.1=libxcb-randr.so.1 --file libxcb-dri2.so.0=libxcb-dri2.so.0 --file libxcb-dri3.so.0=libxcb-dri3.so.0 --file libxcb-present.so.0=libxcb-present.so.0 --file libxcb-shm.so.0=libxcb-shm.so.0 --file libxcb-xfixes.so.0=libxcb-xfixes.so.0 --file libxcb-render.so.0=libxcb-render.so.0 --file libxcb-glx.so.0=libxcb-glx.so.0 --file libX11-xcb.so.1=libX11-xcb.so.1 --file libxshmfence.so.1=libxshmfence.so.1 --file libX11.so.6=libX11.so.6 --file libXau.so.6=libXau.so.6 --file libXdmcp.so.6=libXdmcp.so.6 --file libpciaccess.so.0=libpciaccess.so.0 --file libbsd.so.0=libbsd.so.0 --file libmd.so.0=libmd.so.0 --file libXext.so.6=libXext.so.6 --file libXrender.so.1=libXrender.so.1 --file libpsx.so.2=libpsx.so.2 --file libdrm_nouveau.so.2=libdrm_nouveau.so.2 --file liblzma.so.5=liblzma.so.5 --file xkb_rules_evdev=xkb_rules_evdev --file xkb_keycodes_evdev=xkb_keycodes_evdev --file xkb_types_complete=xkb_types_complete --file xkb_types_basic=xkb_types_basic --file xkb_compat_complete=xkb_compat_complete --file xkb_compat_basic=xkb_compat_basic --file xkb_symbols_us=xkb_symbols_us --file xkb_symbols_pc=xkb_symbols_pc --file xkb_symbols_latin=xkb_symbols_latin --file xkb_symbols_inet=xkb_symbols_inet
    python scripts/mkimage.py --kernel {{KERNEL}} --initrd {{INITRD}} --output {{IMAGE}} --size 512
    @echo "Starting HTTPS proxy on port 8080..."
    @echo "Guest processes will use http_proxy=http://10.0.2.2:8080"
    python scripts/https_proxy.py -p 8080 &
    @sleep 1
    "{{QEMU}}" \
        -drive format=raw,file={{IMAGE}} \
        -drive if=none,format=raw,file=target/disk.img,id=disk0 \
        -device virtio-blk-pci,drive=disk0,disable-modern=on \
        -device virtio-net-pci,netdev=n0 \
        -netdev user,id=n0 \
        -serial stdio \
        -display none \
        -no-reboot \
        -m 2048M; \
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
        -m 2048M

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
        -m 2048M

# Run with virtio-blk test disk
run-blk: image create-test-disk
    "{{QEMU}}" \
        -drive format=raw,file={{IMAGE}} \
        -drive if=none,format=raw,file=target/disk.img,id=disk0 \
        -device virtio-blk-pci,drive=disk0,disable-modern=on \
        -serial stdio \
        -no-reboot \
        -m 2048M

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
        -m 2048M

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
        -m 2048M

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
        -m 2048M

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
        -m 2048M > target/test-output.log 2>&1; true
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
        -m 2048M

# Build LKL (Linux Kernel Library) via WSL2
build-lkl:
    wsl bash -c "cd \"$$(wslpath -u '{{justfile_directory()}}')\" && bash lkl/build-lkl.sh"

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

# ── LKL (Linux Kernel Library) targets ──

# Build LKL server (requires WSL2 with Ubuntu)
build-lkl-server:
    wsl bash -c "cd $$(wslpath '{{justfile_directory()}}/services/lkl-server') && make"

# Create CPIO initrd with LKL server included
initrd-lkl: build-user-lkl build-shell build-kbd build-net build-nvme build-xhci build-vmm build-hello build-hello-linux build-drm-test build-net-test build-testlib build-compositor
    python scripts/mkinitrd.py --output {{INITRD}} --file init={{USER_INIT}} --file shell={{USER_SHELL}} --file kbd={{USER_KBD}} --file net={{USER_NET}} --file nvme={{USER_NVME}} --file xhci={{USER_XHCI}} --file vmm={{USER_VMM}} --file compositor={{USER_COMPOSITOR}} --file hello={{USER_HELLO}} --file hello-linux={{USER_HELLO_LINUX}} --file drm-test={{USER_DRM_TEST}} --file hello-musl={{USER_HELLO_MUSL}} --file hello_dynamic={{USER_HELLO_DYNAMIC}} --file ld-musl-x86_64.so.1={{MUSL_LD}} --file wine64_test=wine64_test --file libunwind.so.8=libunwind.so.8 --file libunwind-x86_64.so.8=libunwind-x86_64.so.8 --file nano={{USER_NANO}} --file libncursesw.so.6={{LIBNCURSESW}} --file xterm={{TERMINFO_XTERM}} --file libtest.so={{TESTLIB}} --file net-test={{USER_NET_TEST}} --file busybox={{USER_BUSYBOX}} --file links={{USER_LINKS}} --file hello_glibc={{USER_HELLO_GLIBC}} --file ld-linux-x86-64.so.2={{GLIBC_LD}} --file libc.so.6={{GLIBC_LIBC}} --file toybox={{USER_TOYBOX}} --file jq={{USER_JQ}} --file bash-static={{USER_BASH}} --file grep_alpine={{USER_GREP}} --file sed_alpine={{USER_SED}} --file hello_gnu={{USER_HELLO_GNU}} --file libgcc_s.so.1={{LIBGCC_S}} --file libstdc++.so.6={{LIBSTDCPP}} --file libz.so.1={{LIBZ}} --file fastfetch={{USER_FASTFETCH}} --file apk={{USER_APK}} --file htop={{USER_HTOP}} --file lkl-server={{USER_LKL_SERVER}} --file weston=weston --file libweston-14.so.0=libweston-14.so.0 --file libexec_weston.so.0=libexec_weston.so.0 --file libdrm.so.2=libdrm.so.2 --file libpixman-1.so.0=libpixman-1.so.0 --file libwayland-server.so.0=libwayland-server.so.0 --file libwayland-client.so.0=libwayland-client.so.0 --file libxkbcommon.so.0=libxkbcommon.so.0 --file libinput.so.10=libinput.so.10 --file libevdev.so.2=libevdev.so.2 --file libgbm.so.1=libgbm.so.1 --file libseat.so.1=libseat.so.1 --file libudev.so.1=libudev.so.1 --file libva.so.2=libva.so.2 --file libva-drm.so.2=libva-drm.so.2 --file libdisplay-info.so.2=libdisplay-info.so.2 --file libglapi.so.0=libglapi.so.0 --file drm-backend.so=weston-drm-backend.so --file libgallium-24.2.8.so=libgallium-24.2.8.so --file libexpat.so.1=libexpat.so.1 --file libxcb-randr.so.0=libxcb-randr.so.0 --file libxcb.so.0=libxcb.so.0 --file libffi.so.8=libffi.so.8 --file libmtdev.so.1=libmtdev.so.1 --file libelogind.so.0=libelogind.so.0 --file libelogind-shared-252.so=libelogind-shared-252.so --file libcap.so.2=libcap.so.2 --file libLLVM.so.19.1=libLLVM.so.19.1 --file libzstd.so.1=libzstd.so.1 --file libxml2.so.2=libxml2.so.2 --file libelf.so.1=libelf.so.1 --file libdrm_amdgpu.so.1=libdrm_amdgpu.so.1 --file libdrm_intel.so.1=libdrm_intel.so.1 --file libdrm_radeon.so.1=libdrm_radeon.so.1 --file libxcb.so.1=libxcb.so.1 --file libxcb-sync.so.1=libxcb-sync.so.1 --file libxcb-randr.so.1=libxcb-randr.so.1 --file libxcb-dri2.so.0=libxcb-dri2.so.0 --file libxcb-dri3.so.0=libxcb-dri3.so.0 --file libxcb-present.so.0=libxcb-present.so.0 --file libxcb-shm.so.0=libxcb-shm.so.0 --file libxcb-xfixes.so.0=libxcb-xfixes.so.0 --file libxcb-render.so.0=libxcb-render.so.0 --file libxcb-glx.so.0=libxcb-glx.so.0 --file libX11-xcb.so.1=libX11-xcb.so.1 --file libxshmfence.so.1=libxshmfence.so.1 --file libX11.so.6=libX11.so.6 --file libXau.so.6=libXau.so.6 --file libXdmcp.so.6=libXdmcp.so.6 --file libpciaccess.so.0=libpciaccess.so.0 --file libbsd.so.0=libbsd.so.0 --file libmd.so.0=libmd.so.0 --file libXext.so.6=libXext.so.6 --file libXrender.so.1=libXrender.so.1 --file libpsx.so.2=libpsx.so.2 --file libdrm_nouveau.so.2=libdrm_nouveau.so.2 --file liblzma.so.5=liblzma.so.5 --file xkb_rules_evdev=xkb_rules_evdev --file xkb_keycodes_evdev=xkb_keycodes_evdev --file xkb_types_complete=xkb_types_complete --file xkb_types_basic=xkb_types_basic --file xkb_compat_complete=xkb_compat_complete --file xkb_compat_basic=xkb_compat_basic --file xkb_symbols_us=xkb_symbols_us --file xkb_symbols_pc=xkb_symbols_pc --file xkb_symbols_latin=xkb_symbols_latin --file xkb_symbols_inet=xkb_symbols_inet

# Bootable image with LKL server
image-lkl: build initrd-lkl
    python scripts/mkimage.py --kernel {{KERNEL}} --initrd {{INITRD}} --output {{IMAGE}} --size 512

# Create a 64 MiB ext4 disk image (requires WSL with Ubuntu)
create-ext4-disk:
    [ -f target/ext4.img ] || wsl -d Ubuntu -- bash -c "dd if=/dev/zero of=/mnt/c/Users/sotom/sotOS/target/ext4.img bs=1M count=64 && mkfs.ext4 -F /mnt/c/Users/sotom/sotOS/target/ext4.img"

# Run with LKL server (ext4 disk + virtio-net)
run-lkl: image-lkl create-ext4-disk
    "{{QEMU}}" \
        -drive format=raw,file={{IMAGE}} \
        -drive if=none,format=raw,file=target/ext4.img,id=disk0 \
        -device virtio-blk-pci,drive=disk0,disable-modern=on \
        -netdev user,id=net0,dns=8.8.8.8 \
        -device virtio-net-pci,netdev=net0,disable-modern=on \
        -serial stdio \
        -no-reboot \
        -m 2048M \
        -smp 2
