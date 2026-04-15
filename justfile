# sotX Build System
# Requires: rust nightly, python3, QEMU

set shell := ["C:/Program Files/Git/bin/bash.exe", "-c"]

QEMU := if os() == "windows" { "C:/Program Files/qemu/qemu-system-x86_64.exe" } else { "qemu-system-x86_64" }
KERNEL := "target/x86_64-unknown-none/debug/sotos-kernel"
IMAGE := "target/sotx.img"
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
USER_HELLO_GUI := "services/hello-gui/target/x86_64-unknown-none/debug/sotos-hello-gui"
USER_SOTOS_TERM := "services/sotos-term/target/x86_64-unknown-none/debug/sotos-term"
USER_STYX_TEST := "services/styx-test/target/x86_64-unknown-none/debug/styx-test"
USER_RUMP_VFS := "services/rump-vfs/target/x86_64-unknown-none/debug/rump-vfs"
USER_ATTACKER := "services/attacker/target/x86_64-unknown-none/debug/attacker"
USER_POSIX_TEST := "services/posix-test/target/x86_64-unknown-none/debug/posix-test"
USER_KERNEL_TEST := "services/kernel-test/target/x86_64-unknown-none/debug/kernel-test"
USER_SOT_DTRACE := "services/sot-dtrace/target/x86_64-unknown-none/debug/sot-dtrace"
USER_SOT_PKG := "services/sot-pkg/target/x86_64-unknown-none/debug/sot-pkg"
USER_SOT_CARP := "services/sot-carp/target/x86_64-unknown-none/debug/sot-carp"
USER_SOT_CHERI := "services/sot-cheri/target/x86_64-unknown-none/debug/sot-cheri"
USER_SOT_STATUSBAR := "services/sot-statusbar/target/x86_64-unknown-none/debug/sot-statusbar"
USER_SOT_LAUNCHER := "services/sot-launcher/target/x86_64-unknown-none/debug/sot-launcher"
USER_SOT_NOTIFY := "services/sot-notify/target/x86_64-unknown-none/debug/sot-notify"
USER_ABI_FUZZ := "services/abi-fuzz/target/x86_64-unknown-none/debug/abi-fuzz"
USER_SOTFS := "services/sotfs/target/x86_64-unknown-none/debug/sotos-sotfs-svc"
USER_SOTSH := "services/sotsh/target/x86_64-unknown-none/debug/sotsh"
USER_CAP_ESC_TEST := "services/cap-escalation-test/target/x86_64-unknown-none/debug/cap-escalation-test"
USER_IPC_STORM := "services/ipc-storm/target/x86_64-unknown-none/debug/ipc-storm"
USER_SMP_STRESS := "services/smp-stress/target/x86_64-unknown-none/debug/smp-stress"
USER_LKL_SERVER := "services/lkl-server/lkl-server"
USER_FASTFETCH := "fastfetch"
USER_APK := "apk"
USER_HTOP := "htop"
WALLPAPER_TOKYO := "assets/wallpapers/tokyo-night.bmp"
WALLPAPER_LOGO := "assets/wallpapers/sotos-logo.bmp"
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

# Build sotSh (native sotOS shell, B1 port: no_std + x86_64-unknown-none)
build-sotsh:
    cd services/sotsh && CARGO_ENCODED_RUSTFLAGS="$(printf '%s\x1f%s\x1f%s' '-Clink-arg=-Tlinker.ld' '-Crelocation-model=static' '-Zstack-protector=strong')" cargo build

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

# Build sotFS graph-based filesystem service
build-sotfs:
    cd services/sotfs && CARGO_ENCODED_RUSTFLAGS="$(printf '%s\x1f%s' '-Clink-arg=-Tlinker.ld' '-Crelocation-model=static')" cargo build

# Build QA kernel test services
build-cap-escalation-test:
    cd services/cap-escalation-test && CARGO_ENCODED_RUSTFLAGS="$(printf '%s\x1f%s' '-Clink-arg=-Tlinker.ld' '-Crelocation-model=static')" cargo build

build-ipc-storm:
    cd services/ipc-storm && CARGO_ENCODED_RUSTFLAGS="$(printf '%s\x1f%s' '-Clink-arg=-Tlinker.ld' '-Crelocation-model=static')" cargo build

build-smp-stress:
    cd services/smp-stress && CARGO_ENCODED_RUSTFLAGS="$(printf '%s\x1f%s' '-Clink-arg=-Tlinker.ld' '-Crelocation-model=static')" cargo build

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

# Build sot-statusbar (G12 -- Tokyo Night layer-shell status bar client)
build-sot-statusbar:
    cd services/sot-statusbar && CARGO_ENCODED_RUSTFLAGS="$(printf '%s\x1f%s\x1f%s' '-Clink-arg=-Tlinker.ld' '-Crelocation-model=static' '-Zstack-protector=strong')" cargo build

# Build hello-gui (Wayland demo client: attaches to the compositor and shows
# a 400x300 blue window with a banner).
build-hello-gui:
    cd services/hello-gui && CARGO_ENCODED_RUSTFLAGS="$(printf '%s\x1f%s\x1f%s' '-Clink-arg=-Tlinker.ld' '-Crelocation-model=static' '-Zstack-protector=strong')" cargo build

# Build sotos-term (Unit 17 -- native Wayland terminal emulator running LUCAS)
build-sotos-term:
    cd services/sotos-term && CARGO_ENCODED_RUSTFLAGS="$(printf '%s\x1f%s\x1f%s' '-Clink-arg=-Tlinker.ld' '-Crelocation-model=static' '-Zstack-protector=strong')" cargo build
# Build sot-launcher (keyboard-driven app launcher Wayland client)
build-sot-launcher:
    cd services/sot-launcher && CARGO_ENCODED_RUSTFLAGS="$(printf '%s\x1f%s\x1f%s' '-Clink-arg=-Tlinker.ld' '-Crelocation-model=static' '-Zstack-protector=strong')" cargo build
# Build sot-notify (Unit 20 -- Tokyo Night notification daemon)
build-sot-notify:
    cd services/sot-notify && CARGO_ENCODED_RUSTFLAGS="$(printf '%s\x1f%s\x1f%s' '-Clink-arg=-Tlinker.ld' '-Crelocation-model=static' '-Zstack-protector=strong')" cargo build

# Build abi-fuzz (Unit 9 -- deterministic ABI fuzz harness)
build-abi-fuzz:
    cd services/abi-fuzz && CARGO_ENCODED_RUSTFLAGS="$(printf '%s\x1f%s\x1f%s' '-Clink-arg=-Tlinker.ld' '-Crelocation-model=static' '-Zstack-protector=strong')" cargo build

# Build net-test (network socket proxy test for LUCAS)
build-net-test:
    cd services/net-test && CARGO_ENCODED_RUSTFLAGS="$(printf '%s\x1f%s\x1f%s' '-Clink-arg=-Tlinker.ld' '-Crelocation-model=static' '-Zstack-protector=strong')" cargo build

# Build test shared library (for dynamic linking).
# Built in release mode to avoid pulling in debug-only `core::panicking::*`
# pointer-check imports, and with `initial-exec` so TLS accesses emit
# `R_X86_64_TPOFF64` (instead of dynamic `__tls_get_addr` calls).
build-testlib:
    cd libs/sotos-testlib && CARGO_ENCODED_RUSTFLAGS="$(printf '%s\x1f%s' '-Crelocation-model=pic' '-Ztls-model=initial-exec')" cargo build --release
    python scripts/mksharedlib.py \
        --archive libs/sotos-testlib/target/x86_64-unknown-none/release/libsotos_testlib.a \
        --linker-script libs/sotos-testlib/linker-so.ld \
        --output {{TESTLIB}}

# Build the kernel
build:
    cargo build --package sotos-kernel

# Build in release mode
release:
    cargo build --package sotos-kernel --release

# Tier 5 production: generate a real Ed25519 signing key for signify.
# Default OUTPUT lands in ~/.secrets/sotx-signify.key with mode 0600.
# After generation, set SIGNIFY_KEY=<that path> in your environment so
# subsequent `just sigmanifest` runs use the production key instead of
# the deterministic dev seed embedded in build_signify_manifest.py.
signify-keygen OUTPUT="$HOME/.secrets/sotx-signify.key":
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

# Meta-test: verify that the sched_smp spec is *sensitive* to R1 by
# running it under the legacy (buggy) config and checking that TLC
# produces a NoLostWake counterexample. If TLC reports "no error" here,
# the spec is vacuously true and not actually catching the bug.
#
# Run this in CI alongside `tlc-mc` to confirm the formal verification
# is meaningful: tlc-mc verifies the patched scheduler is safe;
# verify-r1-bug verifies the spec would have caught the original bug.
verify-r1-bug:
    cd formal && cp sched_smp.cfg sched_smp.cfg.bak && cp sched_smp_legacy.cfg sched_smp.cfg && \
        java -Xss64m -XX:+UseParallelGC -cp ../tools/tlc.jar tlc2.TLC -workers auto sched_smp 2>&1 | tee /tmp/r1.log; \
        mv sched_smp.cfg.bak sched_smp.cfg; \
        rm -rf states sched_smp_TTrace_*.tla sched_smp_TTrace_*.bin 2>/dev/null; \
        if grep -q 'Temporal property NoLostWake was violated' /tmp/r1.log; then \
            echo 'verify-r1-bug: OK -- spec correctly flags R1 under legacy config'; \
        else \
            echo 'verify-r1-bug: FAIL -- spec is vacuously true, R1 not exhibited'; \
            exit 1; \
        fi

# Tier 5 close: produce target/sigmanifest with SHA-256 hashes of the
# Rust-built first-party binaries (init excluded -- chicken-and-egg).
sigmanifest: build-shell build-kbd build-net build-nvme build-xhci build-vmm build-hello build-hello-linux build-drm-test build-net-test build-compositor build-hello-gui build-sotos-term build-styx-test build-rump-vfs build-attacker build-posix-test build-kernel-test build-sot-dtrace build-sot-pkg build-sot-carp build-sot-cheri build-sot-statusbar build-sot-launcher build-sot-notify build-abi-fuzz
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
        --pair sot-cheri={{USER_SOT_CHERI}} \
        --pair sot-statusbar={{USER_SOT_STATUSBAR}} \
        --pair sot-launcher={{USER_SOT_LAUNCHER}} \
        --pair sot-notify={{USER_SOT_NOTIFY}} \
        --pair abi-fuzz={{USER_ABI_FUZZ}}

# Generate BMP wallpapers for the compositor
gen-wallpapers:
    python scripts/gen_wallpapers.py --output-dir assets/wallpapers

# Create CPIO initrd from userspace binaries
initrd: build-user build-shell build-kbd build-net build-nvme build-xhci build-vmm build-hello build-hello-linux build-drm-test build-net-test build-testlib build-compositor build-styx-test build-rump-vfs build-attacker build-posix-test build-kernel-test build-sot-dtrace build-sot-pkg build-sot-carp build-sot-cheri build-sot-statusbar build-hello-gui build-sotos-term build-sot-launcher build-sot-notify build-abi-fuzz build-sotfs build-cap-escalation-test build-ipc-storm build-smp-stress sigmanifest
    python scripts/mkinitrd.py --output {{INITRD}} --file init={{USER_INIT}} --file shell={{USER_SHELL}} --file kbd={{USER_KBD}} --file net={{USER_NET}} --file nvme={{USER_NVME}} --file xhci={{USER_XHCI}} --file vmm={{USER_VMM}} --file compositor={{USER_COMPOSITOR}} --file hello-gui={{USER_HELLO_GUI}} --file sotos-term={{USER_SOTOS_TERM}} --file sot-launcher={{USER_SOT_LAUNCHER}} --file sot-notify={{USER_SOT_NOTIFY}} --file hello={{USER_HELLO}} --file hello-linux={{USER_HELLO_LINUX}} --file drm-test={{USER_DRM_TEST}} --file hello-musl={{USER_HELLO_MUSL}} --file hello_dynamic={{USER_HELLO_DYNAMIC}} --file ld-musl-x86_64.so.1={{MUSL_LD}} --file wine64_test=wine64_test --file libunwind.so.8=libunwind.so.8 --file libunwind-x86_64.so.8=libunwind-x86_64.so.8 --file nano={{USER_NANO}} --file libncursesw.so.6={{LIBNCURSESW}} --file xterm={{TERMINFO_XTERM}} --file libtest.so={{TESTLIB}} --file net-test={{USER_NET_TEST}} --file busybox={{USER_BUSYBOX}} --file links={{USER_LINKS}} --file hello_glibc={{USER_HELLO_GLIBC}} --file ld-linux-x86-64.so.2={{GLIBC_LD}} --file libc.so.6={{GLIBC_LIBC}} --file toybox={{USER_TOYBOX}} --file jq={{USER_JQ}} --file bash-static={{USER_BASH}} --file grep_alpine={{USER_GREP}} --file sed_alpine={{USER_SED}} --file hello_gnu={{USER_HELLO_GNU}} --file libgcc_s.so.1={{LIBGCC_S}} --file libstdc++.so.6={{LIBSTDCPP}} --file libz.so.1={{LIBZ}} --file fastfetch={{USER_FASTFETCH}} --file apk={{USER_APK}} --file htop={{USER_HTOP}} --file weston=weston --file libweston-14.so.0=libweston-14.so.0 --file libexec_weston.so.0=libexec_weston.so.0 --file libdrm.so.2=libdrm.so.2 --file libpixman-1.so.0=libpixman-1.so.0 --file libwayland-server.so.0=libwayland-server.so.0 --file libwayland-client.so.0=libwayland-client.so.0 --file libxkbcommon.so.0=libxkbcommon.so.0 --file libinput.so.10=libinput.so.10 --file libevdev.so.2=libevdev.so.2 --file libgbm.so.1=libgbm.so.1 --file libseat.so.1=libseat.so.1 --file libudev.so.1=libudev.so.1 --file libva.so.2=libva.so.2 --file libva-drm.so.2=libva-drm.so.2 --file libdisplay-info.so.2=libdisplay-info.so.2 --file libglapi.so.0=libglapi.so.0 --file drm-backend.so=weston-drm-backend.so --file libgallium-24.2.8.so=libgallium-24.2.8.so --file libexpat.so.1=libexpat.so.1 --file libxcb-randr.so.0=libxcb-randr.so.0 --file libxcb.so.0=libxcb.so.0 --file libffi.so.8=libffi.so.8 --file libmtdev.so.1=libmtdev.so.1 --file libelogind.so.0=libelogind.so.0 --file libelogind-shared-252.so=libelogind-shared-252.so --file libcap.so.2=libcap.so.2 --file libLLVM.so.19.1=libLLVM.so.19.1 --file libzstd.so.1=libzstd.so.1 --file libxml2.so.2=libxml2.so.2 --file libelf.so.1=libelf.so.1 --file libdrm_amdgpu.so.1=libdrm_amdgpu.so.1 --file libdrm_intel.so.1=libdrm_intel.so.1 --file libdrm_radeon.so.1=libdrm_radeon.so.1 --file libzstd.so.1=libzstd.so.1 --file libxml2.so.2=libxml2.so.2 --file libelf.so.1=libelf.so.1 --file libxcb.so.1=libxcb.so.1 --file libxcb-sync.so.1=libxcb-sync.so.1 --file libxcb-randr.so.1=libxcb-randr.so.1 --file libxcb-dri2.so.0=libxcb-dri2.so.0 --file libxcb-dri3.so.0=libxcb-dri3.so.0 --file libxcb-present.so.0=libxcb-present.so.0 --file libxcb-shm.so.0=libxcb-shm.so.0 --file libxcb-xfixes.so.0=libxcb-xfixes.so.0 --file libxcb-render.so.0=libxcb-render.so.0 --file libxcb-glx.so.0=libxcb-glx.so.0 --file libX11-xcb.so.1=libX11-xcb.so.1 --file libxshmfence.so.1=libxshmfence.so.1 --file libX11.so.6=libX11.so.6 --file libXau.so.6=libXau.so.6 --file libXdmcp.so.6=libXdmcp.so.6 --file libpciaccess.so.0=libpciaccess.so.0 --file libbsd.so.0=libbsd.so.0 --file libmd.so.0=libmd.so.0 --file libXext.so.6=libXext.so.6 --file libXrender.so.1=libXrender.so.1 --file libpsx.so.2=libpsx.so.2 --file libdrm_nouveau.so.2=libdrm_nouveau.so.2 --file liblzma.so.5=liblzma.so.5 --file xkb_rules_evdev=xkb_rules_evdev --file xkb_keycodes_evdev=xkb_keycodes_evdev --file xkb_types_complete=xkb_types_complete --file xkb_types_basic=xkb_types_basic --file xkb_compat_complete=xkb_compat_complete --file xkb_compat_basic=xkb_compat_basic --file xkb_symbols_us=xkb_symbols_us --file xkb_symbols_pc=xkb_symbols_pc --file xkb_symbols_latin=xkb_symbols_latin --file xkb_symbols_inet=xkb_symbols_inet --file styx-test={{USER_STYX_TEST}} --file rump-vfs={{USER_RUMP_VFS}} --file attacker={{USER_ATTACKER}} --file posix-test={{USER_POSIX_TEST}} --file kernel-test={{USER_KERNEL_TEST}} --file sot-dtrace={{USER_SOT_DTRACE}} --file sot-pkg={{USER_SOT_PKG}} --file sot-carp={{USER_SOT_CARP}} --file sot-cheri={{USER_SOT_CHERI}} --file sot-statusbar={{USER_SOT_STATUSBAR}} --file abi-fuzz={{USER_ABI_FUZZ}} --file sotfs={{USER_SOTFS}} --file cap-escalation-test={{USER_CAP_ESC_TEST}} --file ipc-storm={{USER_IPC_STORM}} --file smp-stress={{USER_SMP_STRESS}} --file sigmanifest=target/sigmanifest --file bzImage=target/bzImage --file guest-initramfs=target/guest-initramfs.cpio.gz --file usr/share/sotos/wallpapers/tokyo-night.bmp={{WALLPAPER_TOKYO}} --file usr/share/sotos/wallpapers/sotos-logo.bmp={{WALLPAPER_LOGO}}

# Create the bootable disk image (BIOS + Limine)
image: build initrd
    python scripts/mkimage.py --kernel {{KERNEL}} --initrd {{INITRD}} --output {{IMAGE}} --size 512

# Sprint 1 -- create a 64M persistent ObjectStore rootdisk for sotX.
# Survives reboots; attach via `just run-with-rootdisk`.
rootdisk:
    python scripts/mkdisk.py --output target/rootdisk.img --size 64

# Sprint 1 -- install sotX to a target file or block device.
# Examples:
#     just install TARGET=out.img
#     just install TARGET=/dev/sdb FORCE=1
install TARGET FORCE="0":
    python scripts/sotx-install.py --target {{TARGET}} {{ if FORCE == "1" { "--force" } else { "" } }}

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
# Convention: lands in ~/.secrets/sotx-signify-prod.key (mode 0600).
sigkey-prod:
    python scripts/signify_keygen.py --output "$HOME/.secrets/sotx-signify-prod.key"

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

# ── UEFI boot (OVMF firmware) — M0 of HP Pavilion bootstrap ──
#
# Downloads OVMF.fd (combined EDK2 OVMF firmware, ~3 MiB) from the retrage
# nightly mirror into tools/ovmf/. Only runs if the file is missing.
# See tools/ovmf/README.md for alternative sources and split-firmware setup.
fetch-ovmf:
    @mkdir -p tools/ovmf
    @if [ ! -f tools/ovmf/OVMF.fd ]; then \
        echo "Downloading OVMF.fd from retrage.github.io edk2-nightly..."; \
        curl -L --fail -o tools/ovmf/OVMF.fd \
            https://retrage.github.io/edk2-nightly/bin/RELEASEX64_OVMF.fd; \
        echo "OVMF.fd ready at tools/ovmf/OVMF.fd"; \
    else \
        echo "OVMF.fd already present at tools/ovmf/OVMF.fd"; \
    fi

# Boot the sotX image under QEMU with UEFI firmware (OVMF). Mirrors `run-fast`
# (WHPX acceleration, virtio-blk data disk) but routes through Limine's UEFI
# loader (BOOTX64.EFI) instead of the BIOS path. This is the iteration loop
# for HP Pavilion bring-up: every change should land green here before
# flashing a USB.
#
# WHPX default because TCG is ~8× slower (25s vs 230s to LUCAS prompt).
# Use `run-uefi-tcg` if you need to exercise a pure-software execution path.
run-uefi: image fetch-ovmf create-test-disk
    "{{QEMU}}" \
        -accel whpx -machine q35 \
        -bios tools/ovmf/OVMF.fd \
        -drive format=raw,file={{IMAGE}} \
        -drive if=none,format=raw,file=target/disk.img,id=disk0 \
        -device virtio-blk-pci,drive=disk0,disable-modern=on \
        -serial stdio \
        -display none \
        -no-reboot \
        -m 2048M

# Same as run-uefi but pure TCG. Slower but doesn't require Hyper-V.
run-uefi-tcg: image fetch-ovmf create-test-disk
    "{{QEMU}}" \
        -cpu max \
        -bios tools/ovmf/OVMF.fd \
        -drive format=raw,file={{IMAGE}} \
        -drive if=none,format=raw,file=target/disk.img,id=disk0 \
        -device virtio-blk-pci,drive=disk0,disable-modern=on \
        -serial stdio \
        -display none \
        -no-reboot \
        -m 2048M

# Like run-uefi but with an SDL window, so the framebuffer path is exercised.
# Use this once A.1 (kernel-side FB text) lands to validate rendering without
# relying on serial.
run-uefi-gui: image fetch-ovmf create-test-disk
    "{{QEMU}}" \
        -accel whpx -machine q35 \
        -bios tools/ovmf/OVMF.fd \
        -drive format=raw,file={{IMAGE}} \
        -drive if=none,format=raw,file=target/disk.img,id=disk0 \
        -device virtio-blk-pci,drive=disk0,disable-modern=on \
        -serial stdio \
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

# Run under KVM in WSL with nested VMX exposed.
#
# Required for the bhyve VT-x project (Phase B+) — WHPX does not expose
# nested virtualization to its guests, so VMXON inside sotX only works
# under KVM (Linux) where nested VMX is supported by default.
#
# Boots the same target/sotx.img via WSL+QEMU, with `-cpu host,+vmx`
# (full host CPU passthrough including VMX/EPT/VPID). Serial output is
# captured to bootlog_kvm.txt in the workspace root via /mnt/c.
#
# Prerequisites: WSL2 distro with qemu-system-x86 installed, user in
# the kvm group, /dev/kvm accessible.
run-kvm: image
    wsl -e bash -c "qemu-system-x86_64 \
        -accel kvm \
        -cpu host,+vmx \
        -machine q35 \
        -drive format=raw,file=/mnt/c/Users/sotom/sotX/{{IMAGE}} \
        -serial file:/mnt/c/Users/sotom/sotX/bootlog_kvm.txt \
        -display none \
        -no-reboot \
        -m 2048M"

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
    python scripts/mkinitrd.py --output {{INITRD}} --file init={{USER_INIT}} --file shell={{USER_SHELL}} --file kbd={{USER_KBD}} --file net={{USER_NET}} --file nvme={{USER_NVME}} --file xhci={{USER_XHCI}} --file vmm={{USER_VMM}} --file compositor={{USER_COMPOSITOR}} --file hello-gui={{USER_HELLO_GUI}} --file sotos-term={{USER_SOTOS_TERM}} --file hello={{USER_HELLO}} --file hello-linux={{USER_HELLO_LINUX}} --file drm-test={{USER_DRM_TEST}} --file hello-musl={{USER_HELLO_MUSL}} --file hello_dynamic={{USER_HELLO_DYNAMIC}} --file ld-musl-x86_64.so.1={{MUSL_LD}} --file wine64_test=wine64_test --file libunwind.so.8=libunwind.so.8 --file libunwind-x86_64.so.8=libunwind-x86_64.so.8 --file nano={{USER_NANO}} --file libncursesw.so.6={{LIBNCURSESW}} --file xterm={{TERMINFO_XTERM}} --file libtest.so={{TESTLIB}} --file net-test={{USER_NET_TEST}} --file busybox={{USER_BUSYBOX}} --file links={{USER_LINKS}} --file hello_glibc={{USER_HELLO_GLIBC}} --file ld-linux-x86-64.so.2={{GLIBC_LD}} --file libc.so.6={{GLIBC_LIBC}} --file toybox={{USER_TOYBOX}} --file jq={{USER_JQ}} --file bash-static={{USER_BASH}} --file grep_alpine={{USER_GREP}} --file sed_alpine={{USER_SED}} --file hello_gnu={{USER_HELLO_GNU}} --file libgcc_s.so.1={{LIBGCC_S}} --file libstdc++.so.6={{LIBSTDCPP}} --file libz.so.1={{LIBZ}} --file fastfetch={{USER_FASTFETCH}} --file apk={{USER_APK}} --file htop={{USER_HTOP}} --file weston=weston --file libweston-14.so.0=libweston-14.so.0 --file libexec_weston.so.0=libexec_weston.so.0 --file libdrm.so.2=libdrm.so.2 --file libpixman-1.so.0=libpixman-1.so.0 --file libwayland-server.so.0=libwayland-server.so.0 --file libwayland-client.so.0=libwayland-client.so.0 --file libxkbcommon.so.0=libxkbcommon.so.0 --file libinput.so.10=libinput.so.10 --file libevdev.so.2=libevdev.so.2 --file libgbm.so.1=libgbm.so.1 --file libseat.so.1=libseat.so.1 --file libudev.so.1=libudev.so.1 --file libva.so.2=libva.so.2 --file libva-drm.so.2=libva-drm.so.2 --file libdisplay-info.so.2=libdisplay-info.so.2 --file libglapi.so.0=libglapi.so.0 --file drm-backend.so=weston-drm-backend.so --file libgallium-24.2.8.so=libgallium-24.2.8.so --file libexpat.so.1=libexpat.so.1 --file libxcb-randr.so.0=libxcb-randr.so.0 --file libxcb.so.0=libxcb.so.0 --file libffi.so.8=libffi.so.8 --file libmtdev.so.1=libmtdev.so.1 --file libelogind.so.0=libelogind.so.0 --file libelogind-shared-252.so=libelogind-shared-252.so --file libcap.so.2=libcap.so.2 --file libLLVM.so.19.1=libLLVM.so.19.1 --file libzstd.so.1=libzstd.so.1 --file libxml2.so.2=libxml2.so.2 --file libelf.so.1=libelf.so.1 --file libdrm_amdgpu.so.1=libdrm_amdgpu.so.1 --file libdrm_intel.so.1=libdrm_intel.so.1 --file libdrm_radeon.so.1=libdrm_radeon.so.1 --file libzstd.so.1=libzstd.so.1 --file libxml2.so.2=libxml2.so.2 --file libelf.so.1=libelf.so.1 --file libxcb.so.1=libxcb.so.1 --file libxcb-sync.so.1=libxcb-sync.so.1 --file libxcb-randr.so.1=libxcb-randr.so.1 --file libxcb-dri2.so.0=libxcb-dri2.so.0 --file libxcb-dri3.so.0=libxcb-dri3.so.0 --file libxcb-present.so.0=libxcb-present.so.0 --file libxcb-shm.so.0=libxcb-shm.so.0 --file libxcb-xfixes.so.0=libxcb-xfixes.so.0 --file libxcb-render.so.0=libxcb-render.so.0 --file libxcb-glx.so.0=libxcb-glx.so.0 --file libX11-xcb.so.1=libX11-xcb.so.1 --file libxshmfence.so.1=libxshmfence.so.1 --file libX11.so.6=libX11.so.6 --file libXau.so.6=libXau.so.6 --file libXdmcp.so.6=libXdmcp.so.6 --file libpciaccess.so.0=libpciaccess.so.0 --file libbsd.so.0=libbsd.so.0 --file libmd.so.0=libmd.so.0 --file libXext.so.6=libXext.so.6 --file libXrender.so.1=libXrender.so.1 --file libpsx.so.2=libpsx.so.2 --file libdrm_nouveau.so.2=libdrm_nouveau.so.2 --file liblzma.so.5=liblzma.so.5 --file xkb_rules_evdev=xkb_rules_evdev --file xkb_keycodes_evdev=xkb_keycodes_evdev --file xkb_types_complete=xkb_types_complete --file xkb_types_basic=xkb_types_basic --file xkb_compat_complete=xkb_compat_complete --file xkb_compat_basic=xkb_compat_basic --file xkb_symbols_us=xkb_symbols_us --file xkb_symbols_pc=xkb_symbols_pc --file xkb_symbols_latin=xkb_symbols_latin --file xkb_symbols_inet=xkb_symbols_inet
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
        -device nvme,serial=sotX-NVMe,drive=nvme0 \
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
        -device nvme,serial=sotX-NVMe,drive=nvme0 \
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
    @echo "=== sotX run-all: automated build + boot validation ==="
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
    @echo "=== PASS: sotX booted successfully without panics ==="

# Run comprehensive test suite (boots QEMU, tests all features via serial)
test *ARGS: image
    python scripts/test_system.py {{ARGS}}

# Run tests with verbose output
test-verbose: image
    python scripts/test_system.py --verbose

# Flash sotX image to a disk/USB drive (usage: just flash DISK=/dev/sdX)
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
# Hardcoded WSL path works on PowerShell, cmd, and bash alike — avoids
# $$(wslpath) which PowerShell tries to interpolate as a subexpression.
build-lkl:
    wsl bash -c "cd /mnt/c/Users/sotom/sotOS && bash lkl/build-lkl.sh"

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
    wsl bash -c "cd /mnt/c/Users/sotom/sotOS/services/lkl-server && make"

# Create CPIO initrd with LKL server included
initrd-lkl: build-user-lkl build-shell build-sotsh build-kbd build-net build-nvme build-xhci build-vmm build-hello build-hello-linux build-drm-test build-net-test build-testlib build-compositor
    python scripts/mkinitrd.py --output {{INITRD}} --file init={{USER_INIT}} --file shell={{USER_SHELL}} --file sotsh={{USER_SOTSH}} --file kbd={{USER_KBD}} --file net={{USER_NET}} --file nvme={{USER_NVME}} --file xhci={{USER_XHCI}} --file vmm={{USER_VMM}} --file compositor={{USER_COMPOSITOR}} --file hello-gui={{USER_HELLO_GUI}} --file sotos-term={{USER_SOTOS_TERM}} --file hello={{USER_HELLO}} --file hello-linux={{USER_HELLO_LINUX}} --file drm-test={{USER_DRM_TEST}} --file hello-musl={{USER_HELLO_MUSL}} --file hello_dynamic={{USER_HELLO_DYNAMIC}} --file ld-musl-x86_64.so.1={{MUSL_LD}} --file wine64_test=wine64_test --file libunwind.so.8=libunwind.so.8 --file libunwind-x86_64.so.8=libunwind-x86_64.so.8 --file nano={{USER_NANO}} --file libncursesw.so.6={{LIBNCURSESW}} --file xterm={{TERMINFO_XTERM}} --file libtest.so={{TESTLIB}} --file net-test={{USER_NET_TEST}} --file busybox={{USER_BUSYBOX}} --file links={{USER_LINKS}} --file hello_glibc={{USER_HELLO_GLIBC}} --file ld-linux-x86-64.so.2={{GLIBC_LD}} --file libc.so.6={{GLIBC_LIBC}} --file toybox={{USER_TOYBOX}} --file jq={{USER_JQ}} --file bash-static={{USER_BASH}} --file grep_alpine={{USER_GREP}} --file sed_alpine={{USER_SED}} --file hello_gnu={{USER_HELLO_GNU}} --file libgcc_s.so.1={{LIBGCC_S}} --file libstdc++.so.6={{LIBSTDCPP}} --file libz.so.1={{LIBZ}} --file fastfetch={{USER_FASTFETCH}} --file apk={{USER_APK}} --file htop={{USER_HTOP}} --file lkl-server={{USER_LKL_SERVER}} --file weston=weston --file libweston-14.so.0=libweston-14.so.0 --file libexec_weston.so.0=libexec_weston.so.0 --file libdrm.so.2=libdrm.so.2 --file libpixman-1.so.0=libpixman-1.so.0 --file libwayland-server.so.0=libwayland-server.so.0 --file libwayland-client.so.0=libwayland-client.so.0 --file libxkbcommon.so.0=libxkbcommon.so.0 --file libinput.so.10=libinput.so.10 --file libevdev.so.2=libevdev.so.2 --file libgbm.so.1=libgbm.so.1 --file libseat.so.1=libseat.so.1 --file libudev.so.1=libudev.so.1 --file libva.so.2=libva.so.2 --file libva-drm.so.2=libva-drm.so.2 --file libdisplay-info.so.2=libdisplay-info.so.2 --file libglapi.so.0=libglapi.so.0 --file drm-backend.so=weston-drm-backend.so --file libgallium-24.2.8.so=libgallium-24.2.8.so --file libexpat.so.1=libexpat.so.1 --file libxcb-randr.so.0=libxcb-randr.so.0 --file libxcb.so.0=libxcb.so.0 --file libffi.so.8=libffi.so.8 --file libmtdev.so.1=libmtdev.so.1 --file libelogind.so.0=libelogind.so.0 --file libelogind-shared-252.so=libelogind-shared-252.so --file libcap.so.2=libcap.so.2 --file libLLVM.so.19.1=libLLVM.so.19.1 --file libzstd.so.1=libzstd.so.1 --file libxml2.so.2=libxml2.so.2 --file libelf.so.1=libelf.so.1 --file libdrm_amdgpu.so.1=libdrm_amdgpu.so.1 --file libdrm_intel.so.1=libdrm_intel.so.1 --file libdrm_radeon.so.1=libdrm_radeon.so.1 --file libxcb.so.1=libxcb.so.1 --file libxcb-sync.so.1=libxcb-sync.so.1 --file libxcb-randr.so.1=libxcb-randr.so.1 --file libxcb-dri2.so.0=libxcb-dri2.so.0 --file libxcb-dri3.so.0=libxcb-dri3.so.0 --file libxcb-present.so.0=libxcb-present.so.0 --file libxcb-shm.so.0=libxcb-shm.so.0 --file libxcb-xfixes.so.0=libxcb-xfixes.so.0 --file libxcb-render.so.0=libxcb-render.so.0 --file libxcb-glx.so.0=libxcb-glx.so.0 --file libX11-xcb.so.1=libX11-xcb.so.1 --file libxshmfence.so.1=libxshmfence.so.1 --file libX11.so.6=libX11.so.6 --file libXau.so.6=libXau.so.6 --file libXdmcp.so.6=libXdmcp.so.6 --file libpciaccess.so.0=libpciaccess.so.0 --file libbsd.so.0=libbsd.so.0 --file libmd.so.0=libmd.so.0 --file libXext.so.6=libXext.so.6 --file libXrender.so.1=libXrender.so.1 --file libpsx.so.2=libpsx.so.2 --file libdrm_nouveau.so.2=libdrm_nouveau.so.2 --file liblzma.so.5=liblzma.so.5 --file xkb_rules_evdev=xkb_rules_evdev --file xkb_keycodes_evdev=xkb_keycodes_evdev --file xkb_types_complete=xkb_types_complete --file xkb_types_basic=xkb_types_basic --file xkb_compat_complete=xkb_compat_complete --file xkb_compat_basic=xkb_compat_basic --file xkb_symbols_us=xkb_symbols_us --file xkb_symbols_pc=xkb_symbols_pc --file xkb_symbols_latin=xkb_symbols_latin --file xkb_symbols_inet=xkb_symbols_inet

# Bootable image with LKL server
image-lkl: build initrd-lkl
    python scripts/mkimage.py --kernel {{KERNEL}} --initrd {{INITRD}} --output {{IMAGE}} --size 512

# Create a 64 MiB ext4 disk image (requires WSL with Ubuntu)
create-ext4-disk:
    [ -f target/ext4.img ] || wsl -d Ubuntu -- bash -c "dd if=/dev/zero of=/mnt/c/Users/sotom/sotOS/target/ext4.img bs=1M count=64 && mkfs.ext4 -F /mnt/c/Users/sotom/sotOS/target/ext4.img"

# Create a 32 MiB blank disk for LKL's dedicated ext4 (Phase 6)
create-lkl-disk:
    [ -f target/lkl_ext4.img ] || wsl -d Ubuntu -- bash -c "dd if=/dev/zero of=/mnt/c/Users/sotom/sotOS/target/lkl_ext4.img bs=1M count=32 && mkfs.ext4 -F /mnt/c/Users/sotom/sotOS/target/lkl_ext4.img"

# Run with LKL server (ext4 disk + virtio-net + LKL-dedicated blk)
run-lkl: image-lkl create-ext4-disk create-lkl-disk
    "{{QEMU}}" \
        -drive format=raw,file={{IMAGE}} \
        -drive if=none,format=raw,file=target/ext4.img,id=disk0 \
        -device virtio-blk-pci,drive=disk0,disable-modern=on \
        -drive if=none,format=raw,file=target/lkl_ext4.img,id=disk1 \
        -device virtio-blk-pci,drive=disk1,disable-modern=on \
        -netdev user,id=net0,dns=8.8.8.8 \
        -device virtio-net-pci,netdev=net0,disable-modern=on \
        -serial stdio \
        -no-reboot \
        -m 2048M \
        -smp 1

# Run TDD boot verification suite (builds image, boots QEMU, checks all stages)
test-boot *ARGS: image
    python scripts/test_boot.py --no-build {{ARGS}}

# ── Unit 3: persistent rootdisk on second virtio-blk device ──

# Create a 64 MiB raw image for the rootdisk (init formats it on first boot)
create-rootdisk-disk:
    python scripts/mkrootdisk.py target/sotx-rootdisk.img

# Run with a primary virtio-blk (ObjectStore) and a SECOND virtio-blk
# acting as the persistent rootdisk that init mounts and writes /persist/boot_marker into.
run-rootdisk: image create-test-disk create-rootdisk-disk
    "{{QEMU}}" \
        -drive format=raw,file={{IMAGE}} \
        -drive if=none,format=raw,file=target/disk.img,id=disk0 \
        -device virtio-blk-pci,drive=disk0,disable-modern=on \
        -drive if=none,format=raw,file=target/sotx-rootdisk.img,id=root0 \
        -device virtio-blk-pci,drive=root0,disable-modern=on \
        -serial stdio \
        -display none \
        -no-reboot \
        -m 512M

# run-full-quick — TCG-friendly variant of `run-full` without USB devices.
# qemu-xhci + usb-kbd + usb-mouse historically triggered a USB enumeration
# busy-yield storm in libs/sotos-xhci that took ~13 minutes on TCG (the
# xHCI driver's submit_command() polled in a 10-million-iteration loop,
# each MMIO read ~1000 host cycles -> ~13 min round-robin context-switching
# with init). Units U1-U4 of the run-full deadlock fix wave bounded those
# loops, but `run-full-quick` is still useful for routine boot smoke when
# you don't care about the USB enumeration path. Use `run-full` to exercise
# the actual xHCI USB enumeration path on real hardware or after the fix.
run-full-quick: image create-test-disk create-nvme-disk
    "{{QEMU}}" \
        -drive format=raw,file={{IMAGE}} \
        -drive if=none,format=raw,file=target/disk.img,id=disk0 \
        -device virtio-blk-pci,drive=disk0,disable-modern=on \
        -drive file=target/nvme-disk.img,format=raw,if=none,id=nvme0 \
        -device nvme,serial=sotX-NVMe,drive=nvme0 \
        -netdev user,id=net0,dns=8.8.8.8,hostfwd=udp::5555-:5555,hostfwd=tcp::7777-:7 \
        -device virtio-net-pci,netdev=net0,disable-modern=on \
        -device AC97 \
        -device ahci,id=ahci0 \
        -serial stdio \
        -no-reboot \
        -m 2048M

# Build futex-stress (A4 regression test for LUCAS->LKL SYS_FUTEX routing).
# Produces a statically-linked x86_64 ELF suitable for the initrd.
# Runs under WSL so the host Linux gcc+pthread+static libs are available; the
# Windows MSVC toolchain cannot link -static -pthread.
build-futex-stress:
    wsl -- make -C services/futex-stress

# ---------------------------------------------------------------------------
# B5 -- default shell swap (sotsh primary, lucas-shell legacy opt-in)
# ---------------------------------------------------------------------------
# Post-B5, the default `just run` boots with sotsh as the SOLE shell. The
# legacy lucas-shell (Linux-ABI guest) is opt-in for the soak window via the
# `shell-lucas` cargo feature on init. Removal is planned once the soak
# window completes.
#
# Default path (sotsh only):
#     just run               # build + boot, sotsh is the only shell spawned
#     just image             # default image (sotsh primary, no extra features)
#     just build-user        # default init build (no shell features)
#
# Legacy path (boot lucas-shell as well):
#     just run-lucas         # build + boot with lucas-shell spawned alongside sotsh
#     just image-lucas       # build the lucas-enabled image
#     just build-user-lucas  # build init with `shell-lucas` feature
#
# Backward-compat (deprecated B3-era invocations):
#     just run-sotsh         # alias for `run-lucas` (the old shell-sotsh feature
#                            #   pulls in shell-lucas; sotsh now runs unconditionally)
#     image-sotsh / build-user-sotsh: likewise.
#
# Verify: grep `sotsh: spawned` on the serial log (fires on every boot now).

# Build init with the legacy `shell-lucas` feature enabled (spawns lucas-shell
# alongside the default sotsh).
build-user-lucas:
    cd services/init && CARGO_ENCODED_RUSTFLAGS="$(printf '%s\x1f%s\x1f%s\x1f%s' '-Clink-arg=-Tlinker.ld' '-Crelocation-model=static' '-Zstack-protector=strong' '-Zub-checks=no')" cargo build --features shell-lucas

# Initrd that bundles sotsh alongside the baseline LUCAS payload. Mirrors the
# `initrd` target's --file list but uses the lucas-enabled init and adds
# --file sotsh={{USER_SOTSH}}.
initrd-lucas: build-user-lucas build-shell build-sotsh build-kbd build-net build-nvme build-xhci build-vmm build-hello build-hello-linux build-drm-test build-net-test build-testlib build-compositor build-styx-test build-rump-vfs build-attacker build-posix-test build-kernel-test build-sot-dtrace build-sot-pkg build-sot-carp build-sot-cheri build-sot-statusbar build-hello-gui build-sotos-term build-sot-launcher build-sot-notify build-abi-fuzz build-sotfs build-cap-escalation-test build-ipc-storm build-smp-stress sigmanifest
    python scripts/mkinitrd.py --output {{INITRD}} --file init={{USER_INIT}} --file shell={{USER_SHELL}} --file sotsh={{USER_SOTSH}} --file kbd={{USER_KBD}} --file net={{USER_NET}} --file nvme={{USER_NVME}} --file xhci={{USER_XHCI}} --file vmm={{USER_VMM}} --file compositor={{USER_COMPOSITOR}} --file hello-gui={{USER_HELLO_GUI}} --file sotos-term={{USER_SOTOS_TERM}} --file sot-launcher={{USER_SOT_LAUNCHER}} --file sot-notify={{USER_SOT_NOTIFY}} --file hello={{USER_HELLO}} --file hello-linux={{USER_HELLO_LINUX}} --file drm-test={{USER_DRM_TEST}} --file net-test={{USER_NET_TEST}} --file libtest.so={{TESTLIB}} --file styx-test={{USER_STYX_TEST}} --file rump-vfs={{USER_RUMP_VFS}} --file attacker={{USER_ATTACKER}} --file posix-test={{USER_POSIX_TEST}} --file kernel-test={{USER_KERNEL_TEST}} --file sot-dtrace={{USER_SOT_DTRACE}} --file sot-pkg={{USER_SOT_PKG}} --file sot-carp={{USER_SOT_CARP}} --file sot-cheri={{USER_SOT_CHERI}} --file sot-statusbar={{USER_SOT_STATUSBAR}} --file abi-fuzz={{USER_ABI_FUZZ}} --file sotfs={{USER_SOTFS}} --file cap-escalation-test={{USER_CAP_ESC_TEST}} --file ipc-storm={{USER_IPC_STORM}} --file smp-stress={{USER_SMP_STRESS}} --file sigmanifest=target/sigmanifest

# Image with the lucas-enabled initrd (sotsh + lucas-shell both spawned).
image-lucas: build initrd-lucas
    python scripts/mkimage.py --kernel {{KERNEL}} --initrd {{INITRD}} --output {{IMAGE}} --size 512

# Boot QEMU with lucas-shell spawned alongside sotsh. Mirrors `run` but uses
# the lucas-enabled image. Serial stdio; grep `LUCAS:` and `sotsh: spawned`.
run-lucas: image-lucas
    "{{QEMU}}" \
        -cpu max \
        -drive format=raw,file={{IMAGE}} \
        -serial stdio \
        -display none \
        -no-reboot \
        -m 2048M

# --- Backward-compat aliases (deprecated, slated for removal) ---
# The old `shell-sotsh` cargo feature is now an alias for `shell-lucas`
# (post-B5 sotsh runs unconditionally; the historical `shell-sotsh` knob
# meant "spawn both"). Keep these targets so `just run-sotsh` still works.
build-user-sotsh:
    cd services/init && CARGO_ENCODED_RUSTFLAGS="$(printf '%s\x1f%s\x1f%s\x1f%s' '-Clink-arg=-Tlinker.ld' '-Crelocation-model=static' '-Zstack-protector=strong' '-Zub-checks=no')" cargo build --features shell-sotsh

initrd-sotsh: build-user-sotsh build-shell build-sotsh build-kbd build-net build-nvme build-xhci build-vmm build-hello build-hello-linux build-drm-test build-net-test build-testlib build-compositor build-styx-test build-rump-vfs build-attacker build-posix-test build-kernel-test build-sot-dtrace build-sot-pkg build-sot-carp build-sot-cheri build-sot-statusbar build-hello-gui build-sotos-term build-sot-launcher build-sot-notify build-abi-fuzz build-sotfs build-cap-escalation-test build-ipc-storm build-smp-stress sigmanifest
    python scripts/mkinitrd.py --output {{INITRD}} --file init={{USER_INIT}} --file shell={{USER_SHELL}} --file sotsh={{USER_SOTSH}} --file kbd={{USER_KBD}} --file net={{USER_NET}} --file nvme={{USER_NVME}} --file xhci={{USER_XHCI}} --file vmm={{USER_VMM}} --file compositor={{USER_COMPOSITOR}} --file hello-gui={{USER_HELLO_GUI}} --file sotos-term={{USER_SOTOS_TERM}} --file sot-launcher={{USER_SOT_LAUNCHER}} --file sot-notify={{USER_SOT_NOTIFY}} --file hello={{USER_HELLO}} --file hello-linux={{USER_HELLO_LINUX}} --file drm-test={{USER_DRM_TEST}} --file net-test={{USER_NET_TEST}} --file libtest.so={{TESTLIB}} --file styx-test={{USER_STYX_TEST}} --file rump-vfs={{USER_RUMP_VFS}} --file attacker={{USER_ATTACKER}} --file posix-test={{USER_POSIX_TEST}} --file kernel-test={{USER_KERNEL_TEST}} --file sot-dtrace={{USER_SOT_DTRACE}} --file sot-pkg={{USER_SOT_PKG}} --file sot-carp={{USER_SOT_CARP}} --file sot-cheri={{USER_SOT_CHERI}} --file sot-statusbar={{USER_SOT_STATUSBAR}} --file abi-fuzz={{USER_ABI_FUZZ}} --file sotfs={{USER_SOTFS}} --file cap-escalation-test={{USER_CAP_ESC_TEST}} --file ipc-storm={{USER_IPC_STORM}} --file smp-stress={{USER_SMP_STRESS}} --file sigmanifest=target/sigmanifest

image-sotsh: build initrd-sotsh
    python scripts/mkimage.py --kernel {{KERNEL}} --initrd {{INITRD}} --output {{IMAGE}} --size 512

run-sotsh: image-sotsh
    "{{QEMU}}" \
        -cpu max \
        -drive format=raw,file={{IMAGE}} \
        -serial stdio \
        -display none \
        -no-reboot \
        -m 2048M

# ---------------------------------------------------------------------------
# Minimal sotsh-only boot (serial, no GUI stack, no QA demos)
# ---------------------------------------------------------------------------
# Skips the entire phase-6 demo/test scaffold in init (hello, tier4-5-6 demos,
# deception demo, supervisor SMF, FMA, Crossbow, etc.). Only init, kbd, and
# sotsh are packed into the initrd so there's no compositor/weston/terminal
# chrome. Boots straight to sotsh on the serial console.
build-user-minimal:
    cd services/init && CARGO_ENCODED_RUSTFLAGS="$(printf '%s\x1f%s\x1f%s\x1f%s' '-Clink-arg=-Tlinker.ld' '-Crelocation-model=static' '-Zstack-protector=strong' '-Zub-checks=no')" cargo build --features minimal-boot

initrd-minimal: build-user-minimal build-kbd build-sotsh
    python scripts/mkinitrd.py --output {{INITRD}} --file init={{USER_INIT}} --file kbd={{USER_KBD}} --file sotsh={{USER_SOTSH}}

# Kernel with `trace-boot` — skips `fb_text::hand_off_to_init()` so the
# kernel's framebuffer text console stays live for the whole boot. Every
# `sys::debug_print` byte is tee'd onto the screen, which is how `sotsh`
# output becomes visible in the QEMU display (sotsh has no direct fb access
# of its own yet — it writes through `sys::debug_print`).
build-trace:
    cargo build --package sotos-kernel --features trace-boot

# Smaller disk (48 MiB) — just kernel (~9 MB) + initrd (~28 MB) + limine +
# FAT overhead fits. BIOS reads are O(disk size) for metadata scans, so
# keeping this tight shaves seconds off cold boot.
image-minimal: build-trace initrd-minimal
    python scripts/mkimage.py --kernel {{KERNEL}} --initrd {{INITRD}} --output {{IMAGE}} --size 48

# UEFI path is dramatically faster than BIOS INT 13h — OVMF exposes real
# block I/O to the firmware so Limine's reads hit host speeds instead of
# the emulated ~1 MB/s legacy channel. Use this by default; only fall back
# to the BIOS target (`run-sotsh-minimal-bios`) if OVMF can't be fetched.
# Uses TCG, not WHPX (WHPX+OVMF+virtio-blk injection fails). No `-machine
# q35` either: q35's PCIe topology puts virtio-blk-pci on a root-port
# bridge above bus 0, and init's PCI walker (libs/sotos-pci) only
# enumerates bus 0. Leaving the machine at the QEMU default (pc-i440fx)
# keeps virtio-blk on bus 0 slot N where the walker can see it. Matches
# the known-working `run-uefi` target.
run-sotsh-minimal: image-minimal create-test-disk fetch-ovmf
    "{{QEMU}}" \
        -drive if=pflash,format=raw,readonly=on,file=tools/ovmf/OVMF.fd \
        -drive format=raw,file={{IMAGE}} \
        -drive if=none,format=raw,file=target/disk.img,id=disk0 \
        -device virtio-blk-pci,drive=disk0,disable-modern=on \
        -serial stdio \
        -no-reboot \
        -m 2048M

# Legacy BIOS fallback (only use if OVMF.fd isn't available). Slow:
# BIOS INT 13h caps out around 1 MB/s in QEMU, so the 36 MB of kernel +
# initrd reads take ~30-60 s on cold boot. Kept for parity with the
# original target; prefer `run-sotsh-minimal`.
run-sotsh-minimal-bios: image-minimal create-test-disk
    "{{QEMU}}" \
        -accel whpx -machine q35 \
        -drive format=raw,file={{IMAGE}} \
        -drive if=none,format=raw,file=target/disk.img,id=disk0 \
        -device virtio-blk-pci,drive=disk0,disable-modern=on \
        -serial stdio \
        -no-reboot \
        -m 2048M
