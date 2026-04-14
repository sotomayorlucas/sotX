#![no_std]
#![no_main]

extern crate alloc;

use sotos_common::sys;
use sotos_linux_abi::lucas::LucasBackend;

/// Wave-1 seed of the LUCAS -> LKL migration: a type-marker backend so the
/// rest of the tree can hold a `&'static dyn sotos_linux_abi::LinuxBackend`.
/// Dispatch still runs through `child_handler` today -- see the adapter at
/// libs/sotos-linux-abi/src/lucas.rs.
pub(crate) static LUCAS_BACKEND: LucasBackend = LucasBackend;

// ======================================================================
// Bump allocator for goblin ELF parsing (128 KiB, resettable)
// ======================================================================
mod bump_alloc {
    use core::sync::atomic::{AtomicUsize, Ordering};

    const HEAP_SIZE: usize = 512 * 1024;
    static mut HEAP: [u8; HEAP_SIZE] = [0; HEAP_SIZE];
    static HEAP_POS: AtomicUsize = AtomicUsize::new(0);

    pub fn reset() {
        HEAP_POS.store(0, Ordering::Release);
    }

    struct BumpAlloc;

    unsafe impl core::alloc::GlobalAlloc for BumpAlloc {
        unsafe fn alloc(&self, layout: core::alloc::Layout) -> *mut u8 {
            let size = layout.size();
            let align = layout.align();
            loop {
                let pos = HEAP_POS.load(Ordering::Relaxed);
                let aligned = (pos + align - 1) & !(align - 1);
                let new_pos = aligned + size;
                if new_pos > HEAP_SIZE {
                    return core::ptr::null_mut();
                }
                if HEAP_POS
                    .compare_exchange_weak(pos, new_pos, Ordering::AcqRel, Ordering::Relaxed)
                    .is_ok()
                {
                    return unsafe { HEAP.as_mut_ptr().add(aligned) };
                }
            }
        }
        unsafe fn dealloc(&self, _ptr: *mut u8, _layout: core::alloc::Layout) {}
    }

    #[global_allocator]
    static ALLOCATOR: BumpAlloc = BumpAlloc;
}
use sotos_common::spsc;
use sotos_common::{BootInfo, BOOT_INFO_ADDR};
use sotos_pci::PciBus;
use sotos_virtio::blk::VirtioBlk;
use sotos_objstore::{ObjectStore, DirEntry};

use core::sync::atomic::{AtomicU64, Ordering};

#[macro_use]
mod trace;
mod vdso;
#[allow(dead_code)]
mod framebuffer;
#[allow(dead_code)]
mod framebuffer_palette;
#[allow(dead_code)]
mod process;
#[allow(dead_code)]
mod fd;
#[allow(dead_code)]
mod net;
mod exec;
#[allow(dead_code)]
mod syscall_log;
mod vma;
mod syscalls;
mod fd_ops;
mod fork;
mod virtual_files;
mod evdev;
mod drm;
mod xkb;
mod seatd;
mod udev;
mod child_handler;
mod lucas_handler;
mod lkl;
mod vfs_service;
mod wine_diag;
mod boot_tests;
mod sot_types;
mod sot_bridge;
mod crossbow_demo;
mod deception_demo;
mod deception_service;
mod fma_demo;
mod tier4_demo;
mod tier5_demo;
mod tier6_demo;
mod tier6b_demo;
mod tier6c_demo;
mod tier6d_demo;
mod supervisor;
mod signify;

use framebuffer::{print, print_u64, print_hex64, print_hex, fb_init};
use exec::MAP_WRITABLE;
use boot_tests::{test_dynamic_linking, test_wasm, run_linux_test, run_musl_test,
                 run_dynamic_test, run_busybox_test, producer,
                 run_phase_validation, run_benchmarks};

// ---------------------------------------------------------------------------
// Init address space layout:
//   0x68000000      ELF .text (init binary, above child regions)
//   0x510000        KB ring (shared, from sotos_common)
//   0x520000        Mouse ring (shared, from sotos_common)
//   0x900000        Stack (4 pages, ASLR offset)
//   0xA00000        SPSC ring + producer stack
//   0xB00000        BootInfo (RO)
//   0xC00000+       Virtio MMIO pages
//   0xD00000+       ObjectStore + VFS (320 pages = 1.25 MiB, ends ~0xE40000)
//   0xE50000        LUCAS guest stack (4 pages)
//   0xE60000        LUCAS handler stack (16 pages)
//   0xE70000        VirtioBlk storage (1 page)
//   0xE80000+       Child process stacks (0x2000 each)
//   0xEA0000..0xEA6000  ROOT_BLK (6 pages, second virtio-blk vaddrs from
//                       BlkVaddrs::sequential — persistent rootdisk)
//   0xEB0000..0xEB1000  ROOT_STORE (1 page, in-memory RootStore mini-fs)
//   0x1000000       Shell ELF
//   0x2000000       brk heap (BRK_LIMIT = 1 MiB)
//   0x3000000       mmap region
//   0x4000000       Framebuffer (UC)
//   0x5000000       Spawn buffer (128 pages)
//   0x5200000       DL buffer (32 pages)
//   0x5400000       Exec buffer (128 pages)
//   0x6000000       Dynamic linker load base
//   0xB80000        vDSO page (forged ELF, R+X)
// ---------------------------------------------------------------------------

/// Shared memory page for the SPSC ring buffer.
const RING_ADDR: u64 = 0xA00000;
/// Producer thread stack base (1 page).
const PRODUCER_STACK_BASE: u64 = 0xA10000;
/// Producer thread stack top.
const PRODUCER_STACK_TOP: u64 = PRODUCER_STACK_BASE + 0x1000;
/// Number of messages to send through the ring.
const MSG_COUNT: u64 = 1000;

// ---------------------------------------------------------------------------
// LUCAS — Linux-ABI User Compatibility Shim
// ---------------------------------------------------------------------------

/// LUCAS guest stack (4 pages).
const LUCAS_GUEST_STACK: u64 = 0xE50000;
const LUCAS_GUEST_STACK_PAGES: u64 = 4;
/// LUCAS handler stack (16 pages = 64KB, large due to VFS/ObjectStore locals).
const LUCAS_HANDLER_STACK: u64 = 0xE60000;
const LUCAS_HANDLER_STACK_PAGES: u64 = 16;

/// LUCAS endpoint cap — shared between handler and _start via atomic.
pub(crate) static LUCAS_EP_CAP: AtomicU64 = AtomicU64::new(0);

/// Net service IPC endpoint cap — looked up via svc_lookup("net").
pub(crate) static NET_EP_CAP: AtomicU64 = AtomicU64::new(0);


// ---------------------------------------------------------------------------
// Root capability indices (must match kernel create_init_caps() order)
// ---------------------------------------------------------------------------
const CAP_PCI: usize = 0;

// ---------------------------------------------------------------------------
// LUCAS handler setup
// ---------------------------------------------------------------------------

/// Address where VirtioBlk is stored for the LUCAS handler (1 page).
pub(crate) const LUCAS_BLK_STORE: u64 = 0xE70000;

/// Flag: VirtioBlk stored and ready at LUCAS_BLK_STORE.
pub(crate) static LUCAS_VFS_READY: AtomicU64 = AtomicU64::new(0);

/// Shared ObjectStore pointer — set by lucas_handler after mount, read by child_handlers.
pub(crate) static SHARED_STORE_PTR: AtomicU64 = AtomicU64::new(0);
/// Spinlock protecting shared ObjectStore access (0=free, 1=held).
static VFS_LOCK_INNER: AtomicU64 = AtomicU64::new(0);

pub(crate) fn vfs_lock() {
    while VFS_LOCK_INNER.compare_exchange(0, 1, Ordering::AcqRel, Ordering::Relaxed).is_err() {
        sys::yield_now();
    }
}
pub(crate) fn vfs_unlock() {
    VFS_LOCK_INNER.store(0, Ordering::Release);
}

/// Get a mutable reference to the shared ObjectStore (caller MUST hold VFS_LOCK).
pub(crate) unsafe fn shared_store() -> Option<&'static mut sotos_objstore::ObjectStore> {
    let ptr = SHARED_STORE_PTR.load(Ordering::Acquire);
    if ptr == 0 { None } else { Some(&mut *(ptr as *mut sotos_objstore::ObjectStore)) }
}

// ---------------------------------------------------------------------------
// Userspace process spawning
// ---------------------------------------------------------------------------

/// Temporary buffer region for reading ELF data from initrd (from sotos-common).
use sotos_common::SPAWN_BUF_BASE;
/// Max ELF size we support for spawning (512 KiB = 128 pages).
const SPAWN_BUF_PAGES: u64 = 3328; // 13MB — enough for lkl-server (12MB)

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    // --- Phase 1: Read BootInfo ---
    let boot_info = unsafe { &*(BOOT_INFO_ADDR as *const BootInfo) };
    let cap_count = if boot_info.is_valid() {
        boot_info.cap_count
    } else {
        0
    };

    // --- Initialize framebuffer text console ---
    //
    // The old `fb_init_gui` painted a simulated "LUCAS Terminal" window
    // chrome directly onto the Limine framebuffer and routed a text
    // console inside that chrome. That was a stand-in for a real window
    // manager. Now the native Wayland compositor + sotos-term client
    // (see `services/sotos-term/`) provide the same UX as real clients,
    // so we suppress the fake chrome -- the compositor takes ownership of
    // the framebuffer and draws real windows instead. The plain serial-
    // synced text console (`fb_init`) still runs so kernel panics and
    // early-boot logs remain visible on the framebuffer before the
    // compositor finishes coming up.
    #[cfg(not(feature = "minimal-boot"))]
    if boot_info.fb_addr != 0 {
        unsafe { fb_init(boot_info); }
        // Draw Tokyo Night desktop GUI (positions terminal in window)
        unsafe { framebuffer::fb_init_gui(); }
        // Replay any kernel boot messages that were buffered in the console ring
        // before init had its framebuffer ready.
        unsafe { framebuffer::drain_console_ring(); }

        // Hand the framebuffer off to the compositor only if a compositor
        // service will actually come up (`gui-boot` kernel feature). On a
        // console-only build the init-side FB text console is what LUCAS
        // shell renders into — suspending it would leave the user with a
        // blank screen and no interactive shell.
        //
        // Detection: try to look up the compositor service. It's spawned by
        // the kernel before init runs when `gui-boot` is set. The service
        // registers its IPC endpoint during its own startup, so allow a few
        // yields for it to appear before we decide.
        for _ in 0..500 { sys::yield_now(); }
        let compositor_name = b"compositor";
        if sys::svc_lookup(
            compositor_name.as_ptr() as u64,
            compositor_name.len() as u64,
        ).is_ok() {
            framebuffer::suspend();
        }
    }

    // Clear kernel boot splash on serial and show Tokyo Night init header.
    // Box-drawing uses ASCII-safe substitutes (+, -, |) for maximum
    // terminal compatibility (serial consoles may not have Unicode).
    #[cfg(not(feature = "minimal-boot"))]
    {
        fn serial_str(s: &[u8]) {
            for &b in s { sys::debug_print(b); }
        }
        // Clear screen + cursor home
        serial_str(b"\x1b[2J\x1b[H");
        // Tokyo Night blue + bold
        serial_str(b"\x1b[1;38;2;122;162;247m");
        // Top border
        serial_str(b"+------------------------------------+\r\n");
        serial_str(b"|  sotX init -- Tokyo Night         |\r\n");
        serial_str(b"+------------------------------------+\r\n");
        // Reset
        serial_str(b"\x1b[0m");
    }

    print(b"INIT: boot complete, ");
    print_u64(cap_count);
    print(b" caps received\n");

    // Store init's own AS cap for CoW fork support.
    if boot_info.self_as_cap != 0 {
        crate::process::INIT_SELF_AS_CAP.store(boot_info.self_as_cap, core::sync::atomic::Ordering::Release);
        print(b"INIT: self_as_cap=");
        print_u64(boot_info.self_as_cap);
        print(b"\n");
    }

    // Wave-1 seed of the LUCAS -> LKL migration: observable-only marker
    // confirming the LucasBackend adapter (LUCAS_BACKEND, static) linked.
    // Dispatch still runs through child_handler today.
    let _ = &LUCAS_BACKEND;
    print(b"LinuxBackend: LucasBackend registered\n");

    // --- Phase 2/3: SPSC test + benchmarks ---
    {
        let ring_frame = sys::frame_alloc().unwrap_or_else(|_| panic_halt());
        sys::map(RING_ADDR, ring_frame, MAP_WRITABLE).unwrap_or_else(|_| panic_halt());
        let empty_cap = sys::notify_create().unwrap_or_else(|_| panic_halt());
        let full_cap = sys::notify_create().unwrap_or_else(|_| panic_halt());
        let ring = unsafe {
            spsc::SpscRing::init(RING_ADDR as *mut u8, 128, empty_cap as u32, full_cap as u32)
        };
        let stack_frame = sys::frame_alloc().unwrap_or_else(|_| panic_halt());
        sys::map(PRODUCER_STACK_BASE, stack_frame, MAP_WRITABLE).unwrap_or_else(|_| panic_halt());
        let _thread_cap = sys::thread_create(producer as *const () as u64, PRODUCER_STACK_TOP)
            .unwrap_or_else(|_| panic_halt());
        let mut sum: u64 = 0;
        for _ in 0..MSG_COUNT {
            sum += spsc::recv(ring);
        }
        print(b"SPSC: sum=");
        print_u64(sum);
        print(b"\n");
        run_benchmarks(ring);
    }

    // --- Phase 4: Virtio-BLK + Object Store ---
    let mut blk = init_block_storage(boot_info);

    // --- Phase 4b (Unit 3): persistent rootdisk on the SECOND virtio-blk ---
    // Safe no-op when only one drive is present (e.g. plain `just run`).
    mount_or_format_root(boot_info);

    // --- Phase 5: Look up net service endpoint ---
    for _ in 0..50 { sys::yield_now(); }
    let net_name = b"net";
    match sys::svc_lookup(net_name.as_ptr() as u64, net_name.len() as u64) {
        Ok(cap) => {
            NET_EP_CAP.store(cap, Ordering::Release);
            print(b"INIT: net service endpoint cap = ");
            print_u64(cap);
            print(b"\n");
        }
        Err(_) => {
            // Net service not available — networking disabled for this boot config.
        }
    }

    // --- Phase 5b: LKL (Linux 6.6 kernel as in-process backend) ---
    // LKL fusion requires SMP (-smp 2+) — kernel threads starve on single CPU.
    // On single CPU, LKL stays dormant (LKL_READY=false, all syscalls go to LUCAS).
    // To enable: boot with -smp 2 and LKL auto-activates when kernel finishes booting.
    lkl::init();

    // --- Phase 5c: Tier 5 close — SHA-256 boot chain verification ---
    // Stream every signed initrd binary through the streaming SHA-256
    // implementation in services/init/src/signify.rs and compare against
    // the manifest produced by scripts/build_signify_manifest.py.
    signify::verify_manifest();

    // --- Phase 6: Userspace process spawning ---
    // Everything between here and just before `vfs_service::start_vfs_service`
    // is boot-time demo/QA scaffolding (test harnesses, deception / tier4-6
    // demos, supervisor walk). With `--features minimal-boot`, skip the whole
    // lot and go straight to the native VFS service + sotsh spawn — useful
    // when the graphical stack is misbehaving and you just want a shell.
    #[cfg(not(feature = "minimal-boot"))]
    {
    spawn_process(b"hello");

    // --- Phase 6a: Tokyo Night layer-shell status bar ---
    // Compositor was spawned by the kernel (see kernel/src/main.rs), so it's
    // already up by the time init reaches this point. The bar gracefully
    // exits with `statusbar: no layer-shell` on compositors that haven't
    // landed G7 (zwlr_layer_shell_v1) yet.
    //
    // TEMPORARILY DISABLED: spawn_process passes self_as_cap=0 to children,
    // so the statusbar can't allocate caps for its SHM pool and ends up in
    // an infinite VMM SEGV loop at 0x903890 that floods the serial bandwidth
    // and starves the rest of the boot. Re-enable once init forwards the
    // child's AS cap (or once kernel-side spawn lands like compositor).
    // spawn_process(b"sot-statusbar");

    // --- Phase 6a2: Keyboard-driven app launcher ---
    // Wayland client (layer-shell Overlay or xdg_toplevel fallback) that
    // presents a 500x400 fuzzy-search modal for launching services and
    // binaries. Same self_as_cap caveat as sot-statusbar applies.
    // spawn_process(b"sot-launcher");

    // --- Phase 6b: STYX exokernel syscall validation (Tier 1.2) ---
    // Validates SOT syscalls 300-310 from userspace. Output goes to serial.
    spawn_process(b"styx-test");

    // --- Phase 6b2: POSIX-equivalence smoke (Tier 5 follow-up) ---
    // Native sotX-side conformance pass for thread/frame/IPC/sleep/io
    // primitives, complementing the LUCAS Linux ABI runners.
    spawn_process(b"posix-test");
    for _ in 0..2000 { sys::yield_now(); }

    // --- Phase 6b3: Per-subsystem kernel test suite (Tier 5 follow-up) ---
    // Mini battery across mm/frame, ipc/endpoint+channel+notify,
    // sched/thread, sot/tx+so+provenance, cap/debug.
    spawn_process(b"kernel-test");
    for _ in 0..3000 { sys::yield_now(); }

    // --- QA kernel test services (early, before slow demos) ---
    spawn_process(b"cap-escalation-test");
    for _ in 0..2000 { sys::yield_now(); }
    spawn_process(b"ipc-storm");
    for _ in 0..4000 { sys::yield_now(); }
    spawn_process(b"smp-stress");
    for _ in 0..4000 { sys::yield_now(); }

    // --- Phase 6c: BSD personality stub (Tier 2.2) ---
    // Spawn rump-vfs server, give it time to register, then exercise the
    // OPEN/READ/CLOSE protocol against /etc/passwd from this process.
    spawn_process(b"rump-vfs");
    for _ in 0..200 { sys::yield_now(); }
    test_rump_vfs();

    // --- Phase 6c2: sotFS graph-structured filesystem service ---
    // Spawn the sotFS service which implements the type graph engine with
    // DPO rewriting rules. Registers as "sotfs" in the service registry.
    // Can be mounted as FsType::SotFs via the VFS mount table.
    spawn_process(b"sotfs");
    for _ in 0..200 { sys::yield_now(); }

    // --- Phase 6d: Deception live demo (Tier 3) ---
    // First spawn the "attacker" binary so it produces real provenance
    // entries on the kernel SOT ring under owner_domain=7. Then run the
    // demo which drains the ring, runs the AnomalyDetector + Migration
    // orchestrator, and exercises the interposition + fake /proc/version
    // path with the Ubuntu 22.04 webserver profile.
    spawn_process(b"attacker");
    for _ in 0..200 { sys::yield_now(); }

    // Start the deception-query IPC service (B1.5d). Registers as
    // "deception" and serves DECEPTION_QUERY_ARMS over a new endpoint.
    // Consumed by the sotsh `arm` builtin; see
    // `docs/sotsh-ipc-protocols.md` Part B.
    deception_service::start();

    deception_demo::run();

    // --- Phase 6d2: FMA predictive engine demo (Unit 12) ---
    // Run the in-process FaultManagement state machine through five
    // canned scenarios (clean, disk-retry cluster, ECC uncorrectable,
    // thermal alone, thermal + behavioral anomalies). Boot test marker:
    // `=== FMA: PASS ===`.
    let _ = crate::fma_demo::run();

    // After the one-shot demo + watchdog launch, spawn the attacker a
    // second time so the watchdog has fresh provenance to drain. Proves
    // continuous draining works, not just the boot one-shot.
    //
    // TCG fix (run-full deadlock U4): bumped from 2K + 8K -> 20K + 200K.
    // Device services (NVMe, xHCI) need order-of-magnitude more wall-clock
    // cycles to settle on TCG because each MMIO read costs ~1000 host
    // cycles. Companion units U1/U2/U3 reduced the worst busy-yield
    // offenders, but this defensive backstop prevents init from racing
    // them. On native + WHPX this is microseconds; on TCG ~1-2 seconds.
    for _ in 0..20_000 { sys::yield_now(); }
    spawn_process(b"attacker");
    // Give the watchdog enough yields to pick up the second wave.
    for _ in 0..200_000 { sys::yield_now(); }

    // --- Phase 6e: Tier 4 advanced features demo ---
    // Storage (ZFS + HAMMER2 snapshot managers driven by SOT tx events),
    // bhyve (bare-metal Intel CPUID/MSR spoofing), and PF firewall
    // (capability interposer with deception override).
    tier4_demo::run();

    // --- Phase 6e+: Crossbow VNIC primitive demo ---
    // Provisions VNICs for three deception domains, drives a small
    // route burst to trip the per-port rate limiter, revokes and
    // re-provisions to confirm slot reuse. Companion to PfInterposer.
    if !crossbow_demo::run() {
        print(b"!! crossbow_demo failed -- continuing anyway\n");
    }

    // --- Phase 6f: Tier 5 production hardening demo ---
    // IPC + provenance ring + cap_interpose benchmarks, real 2PC
    // MultiObject transactions, fuzz / robustness pass.
    tier5_demo::run();

    // --- Unit 9: ABI fuzz harness (Tier 5 follow-up) ---
    // Hammers the kernel syscall surface with deterministic random
    // arguments. Prints `=== abi-fuzz: <ok>/<total> survived ===`
    // when done. Driven from CI by scripts/abi_fuzz.py.
    spawn_process(b"abi-fuzz");
    for _ in 0..4000 { sys::yield_now(); }

    // QA kernel test services moved to right after kernel-test (see below)

    // --- Phase 6g: Tier 6 PANDORA Task 1 — DTrace integration ---
    // Spawn the sot-dtrace service first, give it time to register,
    // then run the client demo that streams provenance-backed probes
    // through the sotx::: provider namespace.
    spawn_process(b"sot-dtrace");
    supervisor::record(b"sot-dtrace");
    for _ in 0..400 { sys::yield_now(); }
    tier6_demo::run();

    // --- Phase 6h: Tier 6 PANDORA Task 2 — pkgsrc bridge ---
    // Spawn the sot-pkg service (the pkgng-compatible package manager
    // shim) and let the tier6b client demo walk through register / list
    // / info / remove against it. This is the in-init equivalent of a
    // pkgsrc `pkg_add` flow once the vendor tools land.
    spawn_process(b"sot-pkg");
    supervisor::record(b"sot-pkg");
    for _ in 0..400 { sys::yield_now(); }
    tier6b_demo::run();

    // --- Phase 6i: Tier 6 PANDORA Task 3 — CARP + pfsync cluster ---
    // Spawn the sot-carp service (the OpenBSD ip_carp + if_pfsync shim
    // -- vendor sources live under vendor/openbsd-carp) and let the
    // tier6c client demo drive a two-node failover scenario, asserting
    // that the elected MASTER changes on death and that the replicated
    // pfsync state table survives the cutover.
    spawn_process(b"sot-carp");
    supervisor::record(b"sot-carp");
    for _ in 0..400 { sys::yield_now(); }
    tier6c_demo::run();

    // --- Phase 6j: Tier 6 PANDORA Task 4 — software CHERI ---
    // Spawn the sot-cheri service (the 128-bit compressed-cap shim,
    // vendored from CTSRD-CHERI under vendor/cheri-compressed-cap) and
    // let the tier6d client demo exercise every CHERI invariant we
    // care about: bounds monotonicity, permission monotonicity,
    // sealing / unsealing, and out-of-bounds enforcement.
    spawn_process(b"sot-cheri");
    supervisor::record(b"sot-cheri");
    for _ in 0..400 { sys::yield_now(); }
    tier6d_demo::run();

    // Unit 1 — SMF active respawn. Wire main.rs's spawn_process into the
    // supervisor as the respawn callback, then run the boot self-test that
    // exercises SYS_THREAD_NOTIFY (143) end-to-end: spawn -> register ->
    // detect natural exit -> respawn -> verify. Prints
    // `=== SMF respawn: PASS ===` for the boot-smoke CI grep.
    supervisor::install_respawn_fn(spawn_process);
    supervisor::run_smf_test();

    // Sprint 2 -- final supervisor sweep before LUCAS shell takes over.
    // Walks the SMF service table and reports current state of every
    // tracked service. Now backed by the new SMF dependency graph.
    supervisor::check_all();

    // Phase 7/8 tests (dynamic linking + WASM) disabled for production boot.
    // Enable via `just build-user-demos` for development.
    #[cfg(feature = "demos")]
    {
        test_dynamic_linking();
        test_wasm();
    }

    // Brief yield to let spawned services settle.
    for _ in 0..50 { sys::yield_now(); }

    // SKIP boot tests for git debugging — go straight to LUCAS shell
    // run_linux_test();
    // run_musl_test();
    // run_dynamic_test();
    // run_busybox_test();
    // if let Some(ref mut b) = blk { run_fat_test(b); }
    // run_phase_validation();

    } // end of `#[cfg(not(feature = "minimal-boot"))]` demo/QA block

    // --- Phase 9: LUCAS shell ---
    // (framebuffer::suspend() already called right after drain_console_ring
    // above; see that site for rationale.)
    let boot_info = unsafe { &*(BOOT_INFO_ADDR as *const BootInfo) };
    print(b"LUCAS-DBG: guest_entry=");
    print_u64(boot_info.guest_entry);
    print(b"\n");

    // Spawn the sotOS-native VFS-IPC service (for sotsh + future clients).
    // Registers as "vfs" in the service registry; clients reach it via
    // `sotos_common::vfs::*`. Ops need SHARED_STORE_PTR to be set — which
    // is what `start_vfs_substrate` below takes care of in the default
    // (non-shell-lucas) path.
    vfs_service::start_vfs_service();

    // Mount ObjectStore on a dedicated "keeper" thread so the native VFS
    // path (sotsh + anything using `sotos_common::vfs::*`) has a real
    // store to resolve against, *even when the Linux-ABI LUCAS handler is
    // gated out*. When `shell-lucas` is on, lucas_handler does its own
    // mount in its startup sequence — our keeper checks SHARED_STORE_PTR
    // and bails if a mount already landed, so the two paths don't fight.
    #[cfg(not(feature = "shell-lucas"))]
    if let Some(blk_dev) = blk.take() {
        start_vfs_substrate(blk_dev);
    }

    // B5: default shell swap. sotsh (native sotOS shell, B1 port) is now the
    // sole boot shell. lucas-shell is opt-in legacy via the `shell-lucas`
    // cargo feature (covers the post-B4 soak period; slated for removal).
    // The deprecated `shell-sotsh` feature pulls in `shell-lucas` so old
    // `just run-sotsh` invocations continue to spawn both shells.
    spawn_sotsh_native();

    #[cfg(feature = "shell-lucas")]
    start_lucas(blk);
    #[cfg(not(feature = "shell-lucas"))]
    let _ = blk;

    sys::thread_exit();
}

// ---------------------------------------------------------------------------
// Block device IPC service (for lkl-server disk I/O)
// ---------------------------------------------------------------------------

/// BLK service endpoint cap — stored globally so handler thread can use it.
static BLK_EP_CAP: AtomicU64 = AtomicU64::new(0);
/// VirtioBlk stored at this address for the blk handler thread.
const BLK_HANDLER_STORE: u64 = 0xE80000; // 1 page, after LUCAS_BLK_STORE

/// BLK IPC protocol:
/// CMD=1 (READ):  regs[0]=sector, regs[1]=count, regs[2]=dest_vaddr, regs[3]=caller_as_cap
/// CMD=2 (WRITE): regs[0]=sector, regs[1]=count, regs[2]=src_vaddr,  regs[3]=caller_as_cap
/// CMD=3 (CAPACITY): no args → reply regs[0]=total_sectors
const BLK_CMD_READ: u64 = 1;
const BLK_CMD_WRITE: u64 = 2;
const BLK_CMD_CAPACITY: u64 = 3;

fn start_blk_service(blk: &mut Option<sotos_virtio::blk::VirtioBlk>) {
    let blk_dev = match blk.take() {
        Some(b) => b,
        None => {
            print(b"BLK-SVC: no block device, skipping\n");
            return;
        }
    };

    // Store VirtioBlk at BLK_HANDLER_STORE for the handler thread
    let frame = match sys::frame_alloc() {
        Ok(f) => f,
        Err(_) => { print(b"BLK-SVC: frame_alloc failed\n"); return; }
    };
    let _ = sys::map(BLK_HANDLER_STORE, frame, 2); // MAP_WRITABLE
    unsafe {
        core::ptr::write(BLK_HANDLER_STORE as *mut sotos_virtio::blk::VirtioBlk, blk_dev);
    }

    // Create endpoint and register as "blk"
    let ep = match sys::endpoint_create() {
        Ok(e) => e,
        Err(_) => { print(b"BLK-SVC: endpoint_create failed\n"); return; }
    };
    BLK_EP_CAP.store(ep, Ordering::Release);

    let name = b"blk";
    let _ = sys::svc_register(name.as_ptr() as u64, name.len() as u64, ep);

    // Spawn handler thread (4 pages stack)
    const BLK_HANDLER_STACK: u64 = 0xE90000;
    const BLK_HANDLER_STACK_PAGES: u64 = 4;
    for i in 0..BLK_HANDLER_STACK_PAGES {
        let f = match sys::frame_alloc() { Ok(f) => f, Err(_) => return };
        let _ = sys::map(BLK_HANDLER_STACK + i * 0x1000, f, 2);
    }

    let _ = sys::thread_create(
        blk_handler as *const () as u64,
        BLK_HANDLER_STACK + BLK_HANDLER_STACK_PAGES * 0x1000,
    );
    print(b"BLK-SVC: registered, handler started\n");
}

extern "C" fn blk_handler() -> ! {
    let ep = BLK_EP_CAP.load(Ordering::Acquire);
    let blk = unsafe { &mut *(BLK_HANDLER_STORE as *mut sotos_virtio::blk::VirtioBlk) };

    // DATA_VADDR is where VirtioBlk reads sectors (defined in blk.rs)
    const DATA_VADDR: u64 = 0xC02000;

    loop {
        let msg = match sys::recv(ep) {
            Ok(m) => m,
            Err(_) => { sys::yield_now(); continue; }
        };

        let cmd = msg.tag;
        let mut reply = sotos_common::IpcMsg { tag: 0, regs: [0; 8] };

        match cmd {
            BLK_CMD_READ => {
                let sector = msg.regs[0];
                let count = msg.regs[1].min(8) as u32; // max 8 sectors = 4KB
                let dest_vaddr = msg.regs[2];
                let caller_as = msg.regs[3];

                match blk.read_sectors_multi(sector, count) {
                    Ok(()) => {
                        let bytes = count as usize * 512;
                        // Write data to caller's address space
                        if caller_as != 0 {
                            let _ = sys::vm_write(caller_as, dest_vaddr, DATA_VADDR, bytes as u64);
                        }
                        reply.regs[0] = bytes as u64;
                    }
                    Err(_) => {
                        reply.regs[0] = (-5i64) as u64; // -EIO
                    }
                }
            }
            BLK_CMD_WRITE => {
                let sector = msg.regs[0];
                let count = msg.regs[1].min(8) as u32;
                let src_vaddr = msg.regs[2];
                let caller_as = msg.regs[3];

                let bytes = count as usize * 512;
                if caller_as != 0 {
                    let _ = sys::vm_read(caller_as, src_vaddr, DATA_VADDR, bytes as u64);
                }
                match blk.write_sector(sector) {
                    Ok(()) => { reply.regs[0] = bytes as u64; }
                    Err(_) => { reply.regs[0] = (-5i64) as u64; }
                }
            }
            BLK_CMD_CAPACITY => {
                reply.regs[0] = blk.capacity;
            }
            _ => {
                reply.regs[0] = (-38i64) as u64; // -ENOSYS
            }
        }

        let _ = sys::send(ep, &reply);
    }
}

/// Spawn a new process from an initrd binary by name.
fn spawn_process(name: &[u8]) -> Option<u64> {
    use sotos_common::elf;

    // Phase I — attacker reroute hook. When the deception pipeline
    // has flagged a binary for VM sandbox reroute, this is where the
    // intercept would happen: instead of loading the ELF on the host,
    // we'd forward the exec request to the L1 Linux guest via vsock.
    //
    // For the demo, we detect the "attacker" binary by name and log
    // the intercept. The binary still runs on the host (it needs to
    // emit provenance events for the Tier 3 demo to detect), but the
    // log shows the hook point where real reroute would fire.
    if name == b"attacker" {
        print(b"[PHASE-I] exec hook: intercepted 'attacker' binary\n");
        print(b"[PHASE-I] VM sandbox reroute point (demo: proceeding on host)\n");
    }

    print(b"SPAWN: loading '");
    print(name);
    print(b"' from initrd...\n");

    static mut SPAWN_FRAMES: [u64; SPAWN_BUF_PAGES as usize] = [0u64; SPAWN_BUF_PAGES as usize];
    let buf_frames = unsafe { &mut SPAWN_FRAMES };
    for i in 0..SPAWN_BUF_PAGES {
        let frame_cap = match sys::frame_alloc() {
            Ok(f) => f,
            Err(_) => {
                print(b"SPAWN: frame_alloc failed for buffer\n");
                return None;
            }
        };
        buf_frames[i as usize] = frame_cap;
        if sys::map(SPAWN_BUF_BASE + i * 0x1000, frame_cap, MAP_WRITABLE).is_err() {
            print(b"SPAWN: map buffer page failed\n");
            return None;
        }
    }

    let file_size = match sys::initrd_read(
        name.as_ptr() as u64,
        name.len() as u64,
        SPAWN_BUF_BASE,
        SPAWN_BUF_PAGES * 0x1000,
    ) {
        Ok(sz) => sz as usize,
        Err(_) => {
            print(b"SPAWN: initrd_read failed (not found?)\n");
            for i in 0..SPAWN_BUF_PAGES {
                let _ = sys::unmap_free(SPAWN_BUF_BASE + i * 0x1000);
            }
            return None;
        }
    };

    print(b"SPAWN: ELF size = ");
    print_u64(file_size as u64);
    print(b" bytes\n");

    let elf_data = unsafe { core::slice::from_raw_parts(SPAWN_BUF_BASE as *const u8, file_size) };
    let elf_info = match elf::parse(elf_data) {
        Ok(info) => info,
        Err(e) => {
            print(b"SPAWN: ELF parse error: ");
            print(e.as_bytes());
            print(b"\n");
            for i in 0..SPAWN_BUF_PAGES {
                let _ = sys::unmap_free(SPAWN_BUF_BASE + i * 0x1000);
            }
            return None;
        }
    };

    print(b"SPAWN: entry = 0x");
    print_hex64(elf_info.entry);
    print(b"\n");

    let as_cap = match sys::addr_space_create() {
        Ok(cap) => cap,
        Err(_) => {
            print(b"SPAWN: addr_space_create failed\n");
            for i in 0..SPAWN_BUF_PAGES {
                let _ = sys::unmap_free(SPAWN_BUF_BASE + i * 0x1000);
            }
            return None;
        }
    };

    let mut segments = [const { elf::LoadSegment { offset: 0, vaddr: 0, filesz: 0, memsz: 0, flags: 0 } }; elf::MAX_LOAD_SEGMENTS];
    let seg_count = elf::load_segments(elf_data, &elf_info, &mut segments);

    for si in 0..seg_count {
        let seg = &segments[si];
        if seg.memsz == 0 {
            continue;
        }
        let seg_start = seg.vaddr & !0xFFF;
        let seg_end = (seg.vaddr + seg.memsz as u64 + 0xFFF) & !0xFFF;
        let is_writable = (seg.flags & 2) != 0;

        let mut page_vaddr = seg_start;
        while page_vaddr < seg_end {
            let frame_cap = match sys::frame_alloc() {
                Ok(f) => f,
                Err(_) => {
                    print(b"SPAWN: frame_alloc failed for segment\n");
                    return None;
                }
            };

            let temp_vaddr = 0x5100000u64;
            if sys::map(temp_vaddr, frame_cap, MAP_WRITABLE).is_err() {
                print(b"SPAWN: temp map failed\n");
                return None;
            }

            unsafe {
                core::ptr::write_bytes(temp_vaddr as *mut u8, 0, 4096);
            }

            let page_start = page_vaddr;
            let page_end = page_vaddr + 4096;
            let file_region_start = seg.vaddr;
            let file_region_end = seg.vaddr + seg.filesz as u64;
            let copy_start = page_start.max(file_region_start);
            let copy_end = page_end.min(file_region_end);

            if copy_start < copy_end {
                let dst_offset = (copy_start - page_start) as usize;
                let src_offset = seg.offset + (copy_start - seg.vaddr) as usize;
                let count = (copy_end - copy_start) as usize;
                unsafe {
                    core::ptr::copy_nonoverlapping(
                        (SPAWN_BUF_BASE as *const u8).add(src_offset),
                        (temp_vaddr as *mut u8).add(dst_offset),
                        count,
                    );
                }
            }

            let _ = sys::unmap(temp_vaddr);

            let flags = if is_writable { MAP_WRITABLE } else { 0 };
            if sys::map_into(as_cap, page_vaddr, frame_cap, flags).is_err() {
                print(b"SPAWN: map_into failed\n");
                return None;
            }

            page_vaddr += 4096;
        }
    }

    let stack_base: u64 = 0x900000;
    let stack_pages: u64 = 4;
    if let Ok(guard_cap) = sys::frame_alloc() {
        let _ = sys::map_into(as_cap, stack_base - 0x1000, guard_cap, 0);
    }
    for i in 0..stack_pages {
        let frame_cap = match sys::frame_alloc() {
            Ok(f) => f,
            Err(_) => {
                print(b"SPAWN: frame_alloc failed for stack\n");
                return None;
            }
        };
        if sys::map_into(as_cap, stack_base + i * 0x1000, frame_cap, MAP_WRITABLE).is_err() {
            print(b"SPAWN: map_into stack failed\n");
            return None;
        }
    }
    let stack_top = stack_base + stack_pages * 0x1000;

    let caps: [u64; 0] = [];
    if sys::bootinfo_write(as_cap, caps.as_ptr() as u64, 0).is_err() {
        print(b"SPAWN: bootinfo_write failed\n");
        return None;
    }

    let result = match sys::thread_create_in(as_cap, elf_info.entry, stack_top, 0) {
        Ok(tid) => {
            print(b"SPAWN: '");
            print(name);
            print(b"' launched (tid cap = ");
            print_u64(tid);
            print(b")\n");
            Some(tid)
        }
        Err(_) => {
            print(b"SPAWN: thread_create_in failed\n");
            None
        }
    };

    for i in 0..SPAWN_BUF_PAGES {
        let _ = sys::unmap_free(SPAWN_BUF_BASE + i * 0x1000);
    }
    result
}

// ---------------------------------------------------------------------------
// Block storage initialization
// ---------------------------------------------------------------------------

fn init_virtio_blk(_boot_info: &BootInfo) -> Option<VirtioBlk> {
    // Find the PCI I/O port capability by type, not by position. The old
    // `CAP_PCI = 0` assumption broke whenever kernel-internal caps landed
    // at lower CapIds (happens routinely with trace-boot / UEFI boot where
    // ACPI + IOAPIC bring-up creates its own IoPort caps before init's
    // PCI cap is minted). `sys::cap_list` gives us every cap with its
    // `CapObject` kind tag, so we can scan for IOPORT whose base covers
    // 0xCF8-0xCFF.
    let mut buf = [sotos_common::CapInfo::zeroed(); 32];
    let n = match sys::cap_list(&mut buf) {
        Ok(n) => n,
        Err(e) => {
            print(b"BLK: cap_list failed errno=");
            print_u64(e as u64);
            print(b"\n");
            return None;
        }
    };
    let mut pci_cap: Option<u64> = None;
    for entry in &buf[..n] {
        if entry.kind == sotos_common::CapInfo::KIND_IOPORT {
            pci_cap = Some(entry.cap_id);
            break;
        }
    }
    let pci_cap = match pci_cap {
        Some(c) => c,
        None => {
            print(b"BLK: no IoPort cap in table\n");
            return None;
        }
    };
    print(b"BLK: PCI IoPort cap=");
    print_u64(pci_cap);
    print(b"\n");
    let pci = PciBus::new(pci_cap);

    let (devices, count) = pci.enumerate::<32>();
    if count > 0 {
        print(b"PCI: ");
        print_u64(count as u64);
        print(b" devices\n");

        for i in 0..count {
            let d = &devices[i];
            print(b"  ");
            print_u64(i as u64);
            print(b": vendor=");
            print_hex(d.vendor_id as u32);
            print(b" device=");
            print_hex(d.device_id as u32);
            print(b" class=");
            print_hex(d.class as u32);
            print(b":");
            print_hex(d.subclass as u32);
            print(b" irq=");
            print_u64(d.irq_line as u64);
            print(b"\n");
        }
    }

    let blk_dev = match pci.find_device(0x1AF4, 0x1001) {
        Some(d) => d,
        None => {
            print(b"BLK: virtio-blk (0x1AF4:0x1001) not found on bus 0\n");
            return None;
        }
    };

    print(b"BLK: found at dev ");
    print_u64(blk_dev.addr.dev as u64);
    print(b" IRQ ");
    print_u64(blk_dev.irq_line as u64);
    print(b"\n");

    match VirtioBlk::init(&blk_dev, &pci) {
        Ok(blk) => {
            print(b"BLK: ");
            print_u64(blk.capacity);
            print(b" sectors\n");
            Some(blk)
        }
        Err(e) => {
            print(b"BLK: init failed: ");
            print(e.as_bytes());
            print(b"\n");
            None
        }
    }
}

fn init_block_storage(boot_info: &BootInfo) -> Option<VirtioBlk> {
    let mut blk = match init_virtio_blk(boot_info) {
        Some(b) => b,
        None => return None,
    };

    match blk.read_sector(0) {
        Ok(()) => {
            print(b"BLK READ: ");
            let data = unsafe { core::slice::from_raw_parts(blk.data_ptr(), 16) };
            for &b in data {
                if b >= 0x20 && b < 0x7F {
                    sys::debug_print(b);
                } else {
                    sys::debug_print(b'.');
                }
            }
            print(b"\n");
        }
        Err(e) => {
            print(b"BLK READ ERR: ");
            print(e.as_bytes());
            print(b"\n");
            return None;
        }
    }

    {
        let data = unsafe { core::slice::from_raw_parts_mut(blk.data_ptr_mut(), 512) };
        for b in data.iter_mut() {
            *b = 0;
        }
        let msg = b"WROTE";
        data[..msg.len()].copy_from_slice(msg);
    }
    match blk.write_sector(1) {
        Ok(()) => print(b"BLK WRITE OK\n"),
        Err(e) => {
            print(b"BLK WRITE ERR: ");
            print(e.as_bytes());
            print(b"\n");
            return None;
        }
    }

    match blk.read_sector(1) {
        Ok(()) => {
            print(b"BLK VERIFY: ");
            let data = unsafe { core::slice::from_raw_parts(blk.data_ptr(), 16) };
            for &b in data {
                if b >= 0x20 && b < 0x7F {
                    sys::debug_print(b);
                } else if b == 0 {
                    break;
                } else {
                    sys::debug_print(b'.');
                }
            }
            print(b"\n");
        }
        Err(e) => {
            print(b"BLK VERIFY ERR: ");
            print(e.as_bytes());
            print(b"\n");
            return None;
        }
    }

    init_objstore(blk)
}

fn init_objstore(blk: VirtioBlk) -> Option<VirtioBlk> {
    match ObjectStore::mount(blk) {
        Ok(store) => {
            // List first 32 root entries (avoid 256KB stack alloc for full DIR_ENTRY_COUNT)
            let mut entries = [DirEntry::zeroed(); 32];
            let count = store.list(&mut entries);
            print(b"OBJSTORE: mounted (");
            print_u64(count as u64);
            print(b" files)\n");
            let show = if count > 32 { 32 } else { count };
            for i in 0..show {
                print(b"  ");
                print(entries[i].name_as_str());
                print(b" size=");
                print_u64(entries[i].size);
                print(b"\n");
            }
            if count > 32 {
                print(b"  ... and ");
                print_u64((count - 32) as u64);
                print(b" more\n");
            }
            Some(store.into_blk())
        }
        Err(_) => {
            let blk = ObjectStore::recover_blk();
            let store = match ObjectStore::format(blk) {
                Ok(s) => s,
                Err(e) => {
                    print(b"OBJSTORE: format failed: ");
                    print(e.as_bytes());
                    print(b"\n");
                    return None;
                }
            };
            print(b"OBJSTORE: formatted new filesystem\n");
            Some(store.into_blk())
        }
    }
}

// ---------------------------------------------------------------------------
// Unit 3 — persistent rootdisk (second virtio-blk device)
// ---------------------------------------------------------------------------
//
// Probes for a SECOND virtio-blk PCI device (added by `just run-rootdisk`).
// If present, mounts a tiny "root store" on it: a SOTROOT magic header in
// sector 0 plus the boot marker `/persist/boot_marker` in sector 2. First
// boot formats the disk; subsequent boots see the signature and re-verify
// the marker, demonstrating persistence.
//
// This intentionally does NOT spin up a second `ObjectStore` — that type
// uses a hardcoded STORE_VADDR (0xD00000) and would collide with the
// primary store. The root store is a self-contained mini-fs on disk.
//
// The root virtio-blk uses 6 pages from 0xEA0000 (vq/hdr/status/data laid
// out by `BlkVaddrs::sequential`); the in-memory `RootStore` lives at
// 0xEB0000. All inside the previously-unused 0xEA0000..0xEC0000 hole,
// disjoint from the primary store (0xD00000..0xE40000) and the BLK
// handler stack (0xE90000..0xE94000).

use sotos_virtio::blk::BlkVaddrs;

const ROOT_BLK_BASE:   u64 = 0xEA0000;
const ROOT_STORE_BASE: u64 = 0xEB0000;

const ROOT_SIGNATURE: &[u8; 8] = b"SOTROOT\0";
const ROOT_SECTOR_SIGNATURE: u64 = 0;
const ROOT_SECTOR_MARKER: u64 = 2;
const ROOT_MARKER_BODY: &[u8] = b"/persist/boot_marker\nsotX persistent rootdisk OK\n";

/// In-memory state for the persistent rootdisk. Lives at ROOT_STORE_BASE.
/// Wraps the second VirtioBlk so child handlers can later borrow it for
/// /persist/* I/O via SHARED_ROOT_STORE_PTR.
#[repr(C)]
pub(crate) struct RootStore {
    pub(crate) blk: VirtioBlk,
}

// Build-time guard: RootStore is mapped into a single 4 KiB page at
// ROOT_STORE_BASE via `frame_alloc + map`, so any future field addition that
// pushes its size past one page must break the build instead of silently
// corrupting adjacent memory.
const _: () = assert!(core::mem::size_of::<RootStore>() <= 4096);

/// Shared pointer to the persistent root store. Null until a second drive
/// is found and successfully mounted.
pub(crate) static SHARED_ROOT_STORE_PTR: AtomicU64 = AtomicU64::new(0);

/// Initialize the SECOND virtio-blk device (persistent rootdisk) using its own
/// vaddr region so it does not collide with the primary device.
fn init_virtio_root_blk(boot_info: &BootInfo) -> Option<VirtioBlk> {
    if boot_info.cap_count <= CAP_PCI as u64 {
        return None;
    }
    let pci = PciBus::new(boot_info.caps[CAP_PCI]);

    // Index 0 is the primary virtio-blk; the rootdisk is index 1.
    let dev = match VirtioBlk::nth_device(&pci, 1) {
        Some(d) => d,
        None => {
            return None;
        }
    };

    print(b"ROOTBLK: found at dev ");
    print_u64(dev.addr.dev as u64);
    print(b" IRQ ");
    print_u64(dev.irq_line as u64);
    print(b"\n");

    match VirtioBlk::init_at(&dev, &pci, BlkVaddrs::sequential(ROOT_BLK_BASE)) {
        Ok(blk) => {
            print(b"ROOTBLK: ");
            print_u64(blk.capacity);
            print(b" sectors\n");
            Some(blk)
        }
        Err(e) => {
            print(b"ROOTBLK: init failed: ");
            print(e.as_bytes());
            print(b"\n");
            None
        }
    }
}

/// Fill the device's data buffer with `bytes` (zero-padded to 512), then
/// write it to `sector`. Returns true on success, prints `prefix` on error.
fn rootblk_write_sector(blk: &mut VirtioBlk, sector: u64, bytes: &[u8], prefix: &[u8]) -> bool {
    unsafe {
        let p = blk.data_ptr_mut();
        core::ptr::write_bytes(p, 0, 512);
        core::ptr::copy_nonoverlapping(bytes.as_ptr(), p, bytes.len());
    }
    match blk.write_sector(sector) {
        Ok(()) => true,
        Err(e) => {
            print(prefix);
            print(e.as_bytes());
            print(b"\n");
            false
        }
    }
}

/// Probe for SOTROOT signature, format if absent, write/read the boot marker,
/// and publish the store via SHARED_ROOT_STORE_PTR. Prints the PASS marker on
/// success. Safe to call when no second drive is present (returns early).
fn mount_or_format_root(boot_info: &BootInfo) {
    let mut blk = match init_virtio_root_blk(boot_info) {
        Some(b) => b,
        None => return,
    };

    if blk.read_sector(ROOT_SECTOR_SIGNATURE).is_err() {
        print(b"ROOTBLK: read sector 0 failed\n");
        return;
    }
    let head = unsafe { core::slice::from_raw_parts(blk.data_ptr(), ROOT_SIGNATURE.len()) };
    let formatted_now = head != &ROOT_SIGNATURE[..];

    if formatted_now {
        print(b"ROOTBLK: no signature, formatting...\n");
        if !rootblk_write_sector(&mut blk, ROOT_SECTOR_SIGNATURE, ROOT_SIGNATURE,
                                 b"ROOTBLK: write signature failed: ") {
            return;
        }
    } else {
        print(b"ROOTBLK: SOTROOT signature found (persistent boot)\n");
    }

    if !rootblk_write_sector(&mut blk, ROOT_SECTOR_MARKER, ROOT_MARKER_BODY,
                             b"ROOTBLK: write marker failed: ") {
        return;
    }

    if let Err(e) = blk.read_sector(ROOT_SECTOR_MARKER) {
        print(b"ROOTBLK: re-read marker failed: ");
        print(e.as_bytes());
        print(b"\n");
        return;
    }
    let verify = unsafe { core::slice::from_raw_parts(blk.data_ptr(), 20) };
    if verify != b"/persist/boot_marker" {
        print(b"ROOTBLK: marker mismatch on read-back\n");
        return;
    }

    let frame = match sys::frame_alloc() {
        Ok(f) => f,
        Err(_) => { print(b"ROOTBLK: frame_alloc failed\n"); return; }
    };
    if sys::map(ROOT_STORE_BASE, frame, MAP_WRITABLE).is_err() {
        print(b"ROOTBLK: map failed\n");
        return;
    }
    unsafe {
        core::ptr::write(ROOT_STORE_BASE as *mut RootStore, RootStore { blk });
    }
    SHARED_ROOT_STORE_PTR.store(ROOT_STORE_BASE, Ordering::Release);

    if formatted_now {
        print(b"ROOTBLK: formatted + marker written\n");
    } else {
        print(b"ROOTBLK: marker re-verified across boot\n");
    }
    print(b"=== persistent rootdisk: PASS ===\n");
}

// ---------------------------------------------------------------------------
// FAT32 boot partition test
// ---------------------------------------------------------------------------

fn run_fat_test(blk: &mut sotos_virtio::blk::VirtioBlk) {
    use sotos_objstore::fat::{VirtioBlkDevice, FixedTimeSource, VolumeManager, VolumeIdx, embedded_sdmmc};

    print(b"FAT32-TEST: mounting boot partition...\n");
    let device = unsafe { VirtioBlkDevice::new(blk as *mut _) };
    let mut mgr = VolumeManager::new(device, FixedTimeSource);

    let vol = match mgr.open_raw_volume(VolumeIdx(0)) {
        Ok(v) => v,
        Err(e) => {
            print(b"FAT32-TEST: failed to open volume: ");
            match e {
                embedded_sdmmc::Error::DeviceError(_) => print(b"DeviceError"),
                embedded_sdmmc::Error::FormatError(s) => { print(b"FormatError("); print(s.as_bytes()); print(b")"); }
                embedded_sdmmc::Error::NoSuchVolume => print(b"NoSuchVolume"),
                embedded_sdmmc::Error::BadBlockSize(sz) => { print(b"BadBlockSize="); print_u64(sz as u64); }
                embedded_sdmmc::Error::Unsupported => print(b"Unsupported"),
                _ => print(b"Other"),
            }
            print(b"\n");
            return;
        }
    };
    print(b"FAT32-TEST: volume opened\n");

    let dir = match mgr.open_root_dir(vol) {
        Ok(d) => d,
        Err(_) => { print(b"FAT32-TEST: failed to open root dir\n"); return; }
    };

    print(b"FAT32-TEST: root directory:\n");
    let mut fat_count = 0u32;
    let dir_result = mgr.iterate_dir(dir, |entry| {
        fat_count += 1;
        print(b"  ");
        for &b in entry.name.base_name() {
            if b != b' ' { sotos_common::sys::debug_print(b); unsafe { framebuffer::fb_putchar(b); } }
        }
        if !entry.attributes.is_directory() {
            let ext = entry.name.extension();
            if ext[0] != b' ' {
                print(b".");
                for &b in ext {
                    if b != b' ' { sotos_common::sys::debug_print(b); unsafe { framebuffer::fb_putchar(b); } }
                }
            }
        } else {
            print(b"/");
        }
        print(b"\n");
    });

    print(b"FAT32-TEST: ");
    print_u64(fat_count as u64);
    print(b" entries found\n");
    if dir_result.is_err() {
        print(b"FAT32-TEST: iterate_dir failed\n");
    }
    let _ = mgr.close_dir(dir);
    let _ = mgr.close_volume(vol);
    print(b"FAT32-TEST: SUCCESS\n");
}

// ---------------------------------------------------------------------------
// LUCAS start
// ---------------------------------------------------------------------------

/// Set up LUCAS: create handler + guest threads, establish IPC redirect.
///
/// Post-B5: opt-in legacy. Only compiled when the `shell-lucas` cargo
/// feature is enabled. sotsh is the default shell (see `spawn_sotsh_native`).
#[cfg(feature = "shell-lucas")]
fn start_lucas(blk: Option<VirtioBlk>) {
    let boot_info = unsafe { &*(BOOT_INFO_ADDR as *const BootInfo) };

    let guest_entry = boot_info.guest_entry;
    if guest_entry == 0 {
        print(b"LUCAS: no guest binary, skipping\n");
        return;
    }

    print(b"LUCAS: starting (guest entry=");
    print_u64(guest_entry);
    print(b")\n");

    if let Some(blk_dev) = blk {
        let blk_frame = sys::frame_alloc().unwrap_or_else(|_| panic_halt());
        sys::map(LUCAS_BLK_STORE, blk_frame, MAP_WRITABLE).unwrap_or_else(|_| panic_halt());
        unsafe {
            core::ptr::write(LUCAS_BLK_STORE as *mut VirtioBlk, blk_dev);
        }
        LUCAS_VFS_READY.store(1, Ordering::Release);
    }

    let ep_cap = sys::endpoint_create().unwrap_or_else(|_| panic_halt());
    LUCAS_EP_CAP.store(ep_cap, Ordering::Release);

    for i in 0..LUCAS_GUEST_STACK_PAGES {
        let f = sys::frame_alloc().unwrap_or_else(|_| panic_halt());
        sys::map(LUCAS_GUEST_STACK + i * 0x1000, f, MAP_WRITABLE).unwrap_or_else(|_| panic_halt());
    }

    for i in 0..LUCAS_HANDLER_STACK_PAGES {
        let f = sys::frame_alloc().unwrap_or_else(|_| panic_halt());
        sys::map(LUCAS_HANDLER_STACK + i * 0x1000, f, MAP_WRITABLE).unwrap_or_else(|_| panic_halt());
    }

    let _handler_thread_cap = sys::thread_create(
        lucas_handler::lucas_handler as *const () as u64,
        LUCAS_HANDLER_STACK + LUCAS_HANDLER_STACK_PAGES * 0x1000,
    ).unwrap_or_else(|_| panic_halt());

    let guest_thread_cap = sys::thread_create_redirected(
        guest_entry,
        LUCAS_GUEST_STACK + LUCAS_GUEST_STACK_PAGES * 0x1000,
        ep_cap,
    ).unwrap_or_else(|_| panic_halt());
    let _ = sys::signal_entry(guest_thread_cap, vdso::SIGNAL_TRAMPOLINE_ADDR);
}

// ---------------------------------------------------------------------------
// B5 -- sotSh native boot integration (default shell, always spawned)
// ---------------------------------------------------------------------------
//
// sotSh is a native sotOS userspace binary (B1 port: no_std, x86_64-unknown-
// none). Unlike lucas-shell it does NOT speak the Linux ABI -- it talks to
// kernel syscalls and the `vfs`/`deception`/etc. services directly. So it
// must be spawned with `sys::thread_create` (no syscall redirect), not
// `sys::thread_create_redirected`.
//
// The kernel does not load sotsh at boot (it only loads `shell`, hardcoded
// in kernel/src/main.rs). Under the `shell-sotsh` feature, init reads the
// `sotsh` entry from initrd, loads its ELF segments into its own AS at the
// binary's linked vaddr (0x1000000 -- same slot as lucas-shell, which is
// fine since we use the kernel-loaded mapping there but sotsh's
// map_elf_segments overwrites that region with sotsh's code before the
// thread runs), allocates a fresh stack, and spawns a native thread.
/// Mount the ObjectStore on a dedicated keeper thread so the native VFS
/// path (sotsh + anything using `sotos_common::vfs::*`) has a real store
/// to resolve against when `shell-lucas` is gated out and `lucas_handler`
/// therefore never runs. The keeper parks itself in an infinite
/// `yield_now` loop after publishing — both to keep the stack-resident
/// `Vfs` alive forever (dropping it would invalidate `SHARED_STORE_PTR`)
/// and to avoid freeing the mapped frames.
#[cfg(not(feature = "shell-lucas"))]
fn start_vfs_substrate(blk_dev: VirtioBlk) {
    // Reuse LUCAS_BLK_STORE as the page that backs the blk handle — it's
    // a well-known 1-page slot that lucas_handler would have used anyway.
    // Safe to reuse because `shell-lucas` is off, so lucas_handler never
    // reads from this address.
    let blk_frame = match sys::frame_alloc() {
        Ok(f) => f,
        Err(_) => { print(b"VFS substrate: frame_alloc(blk) failed\n"); return; }
    };
    if sys::map(LUCAS_BLK_STORE, blk_frame, MAP_WRITABLE).is_err() {
        print(b"VFS substrate: map(blk) failed\n");
        return;
    }
    unsafe { core::ptr::write(LUCAS_BLK_STORE as *mut VirtioBlk, blk_dev); }
    LUCAS_VFS_READY.store(1, Ordering::Release);

    // Map a keeper stack (8 pages, 32 KiB).
    const KEEPER_STACK: u64 = 0xEA0000;
    const KEEPER_STACK_PAGES: u64 = 8;
    for i in 0..KEEPER_STACK_PAGES {
        let f = match sys::frame_alloc() {
            Ok(f) => f,
            Err(_) => { print(b"VFS substrate: frame_alloc(stack) failed\n"); return; }
        };
        if sys::map(KEEPER_STACK + i * 0x1000, f, MAP_WRITABLE).is_err() {
            print(b"VFS substrate: map(stack) failed\n");
            return;
        }
    }
    let tid = match sys::thread_create(
        vfs_keeper_thread as *const () as u64,
        KEEPER_STACK + KEEPER_STACK_PAGES * 0x1000,
    ) {
        Ok(t) => t,
        Err(_) => { print(b"VFS substrate: thread_create failed\n"); return; }
    };
    print(b"vfs-keeper: spawned (tid=");
    print_u64(tid);
    print(b")\n");
}

/// Dedicated thread that mounts the ObjectStore, runs sysroot_init,
/// publishes `SHARED_STORE_PTR`, then idles forever to keep its
/// stack-resident `Vfs` alive. Does nothing if the pointer is already set
/// (e.g. lucas_handler beat us to it in some future hybrid build).
#[cfg(not(feature = "shell-lucas"))]
extern "C" fn vfs_keeper_thread() -> ! {
    use sotos_objstore::Vfs;
    if SHARED_STORE_PTR.load(Ordering::Acquire) == 0 {
        let blk = unsafe { core::ptr::read(LUCAS_BLK_STORE as *const VirtioBlk) };
        match ObjectStore::mount(blk) {
            Ok(mut store) => {
                lucas_handler::sysroot_init(&mut store);
                let vfs = Vfs::new(store);
                let ptr = vfs.store() as *const _ as u64;
                SHARED_STORE_PTR.store(ptr, Ordering::Release);
                print(b"vfs-keeper: ObjectStore mounted, SHARED_STORE_PTR=");
                print_u64(ptr);
                print(b"\n");
                // Park forever holding `vfs` on this thread's stack so the
                // pointer we just published stays valid for the life of
                // the system.
                loop { sys::yield_now(); }
            }
            Err(_) => {
                print(b"vfs-keeper: ObjectStore::mount failed\n");
            }
        }
    }
    loop { sys::yield_now(); }
}

//
// On success the boot log prints `sotsh: spawned (entry=..)` so a `grep
// 'sotsh: spawned'` on serial output confirms the path ran. Post-B5 this
// runs unconditionally on every boot (sotsh is the default shell).
fn spawn_sotsh_native() {
    use exec::{EXEC_BUF_BASE, EXEC_BUF_PAGES, EXEC_LOCK, MAP_WRITABLE,
               map_elf_segments, map_temp_buf, parse_elf_goblin, unmap_temp_buf};

    // Serialize with any concurrent ELF loading (shares EXEC_BUF_BASE buffer).
    while EXEC_LOCK.compare_exchange(0, 1, Ordering::Acquire, Ordering::Relaxed).is_err() {
        sys::yield_now();
    }

    let cleanup = |unmap: bool| {
        if unmap { unmap_temp_buf(EXEC_BUF_BASE, EXEC_BUF_PAGES); }
        EXEC_LOCK.store(0, Ordering::Release);
    };

    if map_temp_buf(EXEC_BUF_BASE, EXEC_BUF_PAGES).is_err() {
        print(b"sotsh: map_temp_buf failed\n");
        cleanup(false);
        return;
    }

    let bin_name = b"sotsh";
    let file_size = match sys::initrd_read(
        bin_name.as_ptr() as u64,
        bin_name.len() as u64,
        EXEC_BUF_BASE,
        EXEC_BUF_PAGES * 0x1000,
    ) {
        Ok(sz) => sz as usize,
        Err(_) => {
            print(b"sotsh: initrd_read failed (binary missing?)\n");
            cleanup(true);
            return;
        }
    };

    let elf_data = unsafe { core::slice::from_raw_parts(EXEC_BUF_BASE as *const u8, file_size) };
    let (info, segments, seg_count, _interp) = match parse_elf_goblin(elf_data) {
        Ok(p) => p,
        Err(_) => {
            print(b"sotsh: ELF parse failed\n");
            cleanup(true);
            return;
        }
    };
    // sotsh is static ET_EXEC (linker.ld fixes .text at 0x1000000), so
    // base = 0 and no PT_INTERP handling needed.
    if map_elf_segments(EXEC_BUF_BASE, &info, &segments, seg_count, 0, 0).is_err() {
        print(b"sotsh: map_elf_segments failed\n");
        cleanup(true);
        return;
    }
    cleanup(true);

    const SOTSH_STACK_PAGES: u64 = 16;
    let stack_base = process::NEXT_CHILD_STACK
        .fetch_add(SOTSH_STACK_PAGES * 0x1000 + 0x1000, Ordering::SeqCst);
    for i in 0..SOTSH_STACK_PAGES {
        let f = match sys::frame_alloc() {
            Ok(f) => f,
            Err(_) => { print(b"sotsh: stack frame_alloc failed\n"); return; }
        };
        if sys::map(stack_base + i * 0x1000, f, MAP_WRITABLE).is_err() {
            print(b"sotsh: stack map failed\n");
            return;
        }
    }
    let stack_top = stack_base + SOTSH_STACK_PAGES * 0x1000;

    let tid = match sys::thread_create(info.entry, stack_top) {
        Ok(t) => t,
        Err(_) => { print(b"sotsh: thread_create failed\n"); return; }
    };

    print(b"sotsh: spawned (entry=");
    print_hex64(info.entry);
    print(b" tid=");
    print_u64(tid);
    print(b")\n");
}

fn panic_halt() -> ! {
    print(b"PANIC\n");
    loop {}
}

// ---------------------------------------------------------------------------
// Tier 2.2 — rump-vfs client smoke test
// ---------------------------------------------------------------------------

/// Exercise the rump-vfs IPC ABI by opening, reading, and printing /etc/passwd.
/// Mirrors the protocol declared in `services/rump-vfs/src/main.rs`.
fn test_rump_vfs() {
    use sotos_common::IpcMsg;

    print(b"RUMP-VFS-TEST: looking up service...\n");
    let svc_name = b"rump-vfs";
    let ep = match sys::svc_lookup(svc_name.as_ptr() as u64, svc_name.len() as u64) {
        Ok(cap) => cap,
        Err(e) => {
            print(b"RUMP-VFS-TEST: svc_lookup failed (");
            print_i64(e);
            print(b")\n");
            return;
        }
    };

    // OPEN /etc/passwd
    let path = b"/etc/passwd";
    let mut open_msg = IpcMsg::empty();
    open_msg.tag = 1; // TAG_OPEN
    {
        let dst = unsafe {
            core::slice::from_raw_parts_mut(open_msg.regs.as_mut_ptr() as *mut u8, 56)
        };
        dst[..path.len()].copy_from_slice(path);
    }
    let open_reply = match sys::call(ep, &open_msg) {
        Ok(r) => r,
        Err(e) => {
            print(b"RUMP-VFS-TEST: OPEN call failed (");
            print_i64(e);
            print(b")\n");
            return;
        }
    };
    let fd = open_reply.regs[0] as i64;
    if fd <= 0 {
        print(b"RUMP-VFS-TEST: OPEN returned errno ");
        print_i64(fd);
        print(b"\n");
        return;
    }
    print(b"RUMP-VFS-TEST: OPEN /etc/passwd -> fd=");
    print_u64(fd as u64);
    print(b"\n");

    // READ in 64-byte chunks until EOF (tag=0)
    print(b"--- /etc/passwd ---\n");
    let mut offset: u64 = 0;
    let mut total: u64 = 0;
    loop {
        let mut read_msg = IpcMsg::empty();
        read_msg.tag = 2; // TAG_READ
        read_msg.regs[0] = fd as u64;
        read_msg.regs[1] = offset;
        let read_reply = match sys::call(ep, &read_msg) {
            Ok(r) => r,
            Err(e) => {
                print(b"\nRUMP-VFS-TEST: READ call failed (");
                print_i64(e);
                print(b")\n");
                break;
            }
        };
        let n = read_reply.tag as usize;
        if n == 0 {
            break;
        }
        let bytes = unsafe {
            core::slice::from_raw_parts(read_reply.regs.as_ptr() as *const u8, n)
        };
        for &b in bytes {
            sys::debug_print(b);
        }
        offset += n as u64;
        total += n as u64;
        if n < 64 {
            // Short read: end of file. Avoid one extra round trip.
            break;
        }
    }
    print(b"--- EOF (");
    print_u64(total);
    print(b" bytes) ---\n");

    // CLOSE
    let mut close_msg = IpcMsg::empty();
    close_msg.tag = 3; // TAG_CLOSE
    close_msg.regs[0] = fd as u64;
    match sys::call(ep, &close_msg) {
        Ok(r) if r.regs[0] == 0 => print(b"RUMP-VFS-TEST: CLOSE ok\n"),
        Ok(r) => {
            print(b"RUMP-VFS-TEST: CLOSE errno ");
            print_i64(r.regs[0] as i64);
            print(b"\n");
        }
        Err(e) => {
            print(b"RUMP-VFS-TEST: CLOSE call failed (");
            print_i64(e);
            print(b")\n");
        }
    }

    if total > 0 {
        print(b"RUMP-VFS-TEST: PASS\n");
    } else {
        print(b"RUMP-VFS-TEST: FAIL (no bytes read)\n");
    }
}

fn print_i64(mut n: i64) {
    if n < 0 {
        sys::debug_print(b'-');
        n = -n;
    }
    print_u64(n as u64);
}

#[panic_handler]
fn panic(info: &core::panic::PanicInfo) -> ! {
    print(b"!!!PANIC-RUST!!!");
    if let Some(loc) = info.location() {
        print(b" at ");
        print(loc.file().as_bytes());
        print(b":");
        print_u64(loc.line() as u64);
    }
    print(b"\n");
    loop {}
}
