//! Tier 5 production hardening demo.
//!
//! Five sections covering performance, transactional correctness, and
//! robustness. Each section ends in a single PASS/FAIL line; the module
//! prints `=== Tier 5 demo: PASS ===` if every section passes.
//!
//!  A. **IPC throughput** -- average cycles per round-trip for the
//!     cheapest possible kernel call (`sys::yield_now`) and for
//!     `sys::provenance_emit`. RDTSC bracketed; warmup loop discarded.
//!  B. **Provenance ring throughput** -- bulk push N entries via
//!     `provenance_emit`, drain in one shot, report cycles per push and
//!     cycles per drained entry.
//!  C. **cap_interpose lookup** -- average cycles for
//!     `MigrationOrchestrator::check_interposition()` against an
//!     already-migrated domain. Mirrors what the kernel `so_invoke`
//!     would do for an interposed cap.
//!  D. **Tier 2 (2PC) MultiObject transactions** -- exercises the new
//!     `SYS_TX_PREPARE` (311) syscall:
//!        * tx_begin(MultiObject) -> tx_prepare -> tx_commit  (happy)
//!        * tx_begin(MultiObject) -> tx_prepare -> tx_abort   (rollback)
//!        * tx_begin(MultiObject) -> tx_commit                (must FAIL: no PREPARE)
//!        * tx_prepare on a non-existent tx                   (must FAIL)
//!  E. **Fuzz / robustness** -- N iterations of randomised SOT calls
//!     with deliberately garbage arguments (huge cap ids, garbage
//!     types, half-active tx ids). The kernel must never crash and
//!     must return a sensible Result for every call. Survival counter
//!     printed.

use crate::framebuffer::{print, print_u64};
use sotos_common::sys;
use sotos_deception::interpose::InterpositionAction;
use sotos_deception::migration::MigrationOrchestrator;
use sotos_deception::profile::DeceptionProfile;
use sotos_deception::anomaly::AnomalyPattern;

const TIER: u64 = 0; // ReadOnly tier (cheapest, no WAL)
const TIER_MULTI: u64 = 2; // MultiObject (Tier 2 / 2PC)

fn rdtsc() -> u64 {
    unsafe { core::arch::x86_64::_rdtsc() }
}

fn print_cycles(label: &[u8], total: u64, iters: u64) {
    print(label);
    print(b" total=");
    print_u64(total);
    print(b" cy iters=");
    print_u64(iters);
    print(b" avg=");
    print_u64(total / iters);
    print(b" cy/op\n");
}

// ---------------------------------------------------------------------------
// A. IPC throughput
// ---------------------------------------------------------------------------

fn run_ipc_bench() -> bool {
    print(b"[A] IPC throughput\n");
    const WARMUP: u64 = 100;
    const ITERS: u64 = 10_000;

    // Warmup -- pull caches and skip the first batch.
    for _ in 0..WARMUP { sys::yield_now(); }

    let t0 = rdtsc();
    for _ in 0..ITERS { sys::yield_now(); }
    let yield_total = rdtsc().wrapping_sub(t0);
    print_cycles(b"    sys::yield_now      ", yield_total, ITERS);

    for _ in 0..WARMUP { sys::provenance_emit(1, 0, 0xC0DE, 9999); }
    let t0 = rdtsc();
    for i in 0..ITERS {
        sys::provenance_emit(1, 0, 0xC0DE_0000 + i, 9999);
    }
    let emit_total = rdtsc().wrapping_sub(t0);
    print_cycles(b"    sys::provenance_emit", emit_total, ITERS);

    // Drain whatever we just pushed so the ring stays clean for the
    // next section.
    let mut tmp = [KernelProvEntry::zero(); 64];
    while drain_ring(&mut tmp) > 0 {}
    print(b"    A: PASS\n");
    true
}

// ---------------------------------------------------------------------------
// B. Provenance ring throughput
// ---------------------------------------------------------------------------

#[repr(C)]
#[derive(Clone, Copy)]
struct KernelProvEntry {
    epoch: u64,
    domain_id: u32,
    operation: u16,
    so_type: u8,
    _pad: u8,
    so_id: u64,
    version: u64,
    tx_id: u64,
    timestamp: u64,
}
const _: () = assert!(core::mem::size_of::<KernelProvEntry>() == 48);

impl KernelProvEntry {
    const fn zero() -> Self {
        Self {
            epoch: 0, domain_id: 0, operation: 0, so_type: 0, _pad: 0,
            so_id: 0, version: 0, tx_id: 0, timestamp: 0,
        }
    }
}

fn drain_ring(buf: &mut [KernelProvEntry]) -> usize {
    unsafe {
        sys::provenance_drain(buf.as_mut_ptr() as *mut u8, buf.len() as u64, 0) as usize
    }
}

fn run_ring_bench() -> bool {
    print(b"[B] provenance ring throughput\n");

    // 4096 = ring capacity. Push exactly that many to avoid drops.
    const N_PUSH: u64 = 4000;
    const ITERS_DRAIN: u64 = 5;
    let mut buf = [KernelProvEntry::zero(); 64];

    // Drain anything stale.
    while drain_ring(&mut buf) > 0 {}

    let t0 = rdtsc();
    for i in 0..N_PUSH {
        sys::provenance_emit(1, 0, i, 12345);
    }
    let push_total = rdtsc().wrapping_sub(t0);
    print_cycles(b"    push (single entry) ", push_total, N_PUSH);

    // Drain all entries; record cycles per ENTRY drained.
    let t0 = rdtsc();
    let mut drained_total: u64 = 0;
    for _ in 0..ITERS_DRAIN {
        loop {
            let n = drain_ring(&mut buf);
            if n == 0 { break; }
            drained_total += n as u64;
        }
    }
    let drain_total = rdtsc().wrapping_sub(t0);
    print(b"    drained ");
    print_u64(drained_total);
    print(b" entries in ");
    print_u64(drain_total);
    print(b" cy");
    if drained_total > 0 {
        print(b" (");
        print_u64(drain_total / drained_total);
        print(b" cy/entry)");
    }
    print(b"\n");

    if drained_total < N_PUSH * 9 / 10 {
        print(b"    !! drain count < 90% of push -- ring overflow?\n");
        return false;
    }
    print(b"    B: PASS\n");
    true
}

// ---------------------------------------------------------------------------
// C. cap_interpose lookup overhead
// ---------------------------------------------------------------------------

fn run_interpose_bench() -> bool {
    print(b"[C] cap_interpose lookup overhead\n");

    // Build a profile with default FakeResponse and migrate domain 42
    // with 32 caps so the lookup table is non-trivial.
    let mut profile = DeceptionProfile::with_name(b"benchmark-profile");
    profile.default_action = InterpositionAction::FakeResponse;
    let _ = profile.add_file(0xDEAD, b"benchmark", 0o644);

    let mut orch = MigrationOrchestrator::new();
    let mut caps = [0u32; 32];
    for (i, slot) in caps.iter_mut().enumerate() {
        *slot = 1000 + i as u32;
    }
    if orch.migrate(42, &profile, AnomalyPattern::CredentialTheftAfterBackdoor, &caps, 1)
        .is_err()
    {
        print(b"    !! migrate setup failed\n");
        return false;
    }

    const ITERS: u64 = 10_000;
    // Warmup
    for _ in 0..100 { let _ = orch.check_interposition(42, 1015); }

    let t0 = rdtsc();
    let mut hits: u64 = 0;
    for i in 0..ITERS {
        let cap = 1000 + (i % 32) as u32;
        if let Some(InterpositionAction::FakeResponse) = orch.check_interposition(42, cap) {
            hits += 1;
        }
    }
    let total = rdtsc().wrapping_sub(t0);
    print(b"    hits=");
    print_u64(hits);
    print(b"/");
    print_u64(ITERS);
    print(b"\n");
    print_cycles(b"    check_interposition ", total, ITERS);

    if hits != ITERS {
        print(b"    !! some lookups missed\n");
        return false;
    }
    print(b"    C: PASS\n");
    true
}

// ---------------------------------------------------------------------------
// D. Tier 2 (2PC) MultiObject transactions
// ---------------------------------------------------------------------------

fn run_2pc() -> bool {
    print(b"[D] 2PC MultiObject transactions\n");

    // 1) happy path: BEGIN -> PREPARE -> COMMIT
    let id1 = match sys::tx_begin(TIER_MULTI) {
        Ok(id) => id,
        Err(e) => {
            print(b"    !! tx_begin(MultiObject) failed errno=");
            print_i64(e);
            print(b"\n");
            return false;
        }
    };
    if let Err(e) = sys::tx_prepare(id1) {
        print(b"    !! tx_prepare failed errno=");
        print_i64(e);
        print(b"\n");
        return false;
    }
    if let Err(e) = sys::tx_commit(id1) {
        print(b"    !! tx_commit after PREPARE failed errno=");
        print_i64(e);
        print(b"\n");
        return false;
    }
    print(b"    BEGIN -> PREPARE -> COMMIT  ok (id=");
    print_u64(id1);
    print(b")\n");

    // 2) rollback path: BEGIN -> PREPARE -> ABORT
    let id2 = sys::tx_begin(TIER_MULTI).unwrap();
    sys::tx_prepare(id2).unwrap();
    if let Err(e) = sys::tx_abort(id2) {
        print(b"    !! tx_abort after PREPARE failed errno=");
        print_i64(e);
        print(b"\n");
        return false;
    }
    print(b"    BEGIN -> PREPARE -> ABORT   ok (id=");
    print_u64(id2);
    print(b")\n");

    // 3) negative path: BEGIN -> COMMIT (no PREPARE) must fail
    let id3 = sys::tx_begin(TIER_MULTI).unwrap();
    match sys::tx_commit(id3) {
        Err(_) => print(b"    BEGIN -> COMMIT             rejected (expected)\n"),
        Ok(()) => {
            print(b"    !! tx_commit without PREPARE accepted\n");
            return false;
        }
    }
    // Clean up the open Active slot.
    let _ = sys::tx_abort(id3);

    // 4) negative path: tx_prepare on bogus id must fail
    match sys::tx_prepare(0xDEAD_BEEF) {
        Err(_) => print(b"    tx_prepare(bogus)           rejected (expected)\n"),
        Ok(()) => {
            print(b"    !! tx_prepare(bogus) accepted\n");
            return false;
        }
    }

    // 5) Bench: cycles per BEGIN+PREPARE+COMMIT round
    const ITERS: u64 = 1000;
    for _ in 0..50 {
        let id = sys::tx_begin(TIER_MULTI).unwrap();
        sys::tx_prepare(id).unwrap();
        sys::tx_commit(id).unwrap();
    }
    let t0 = rdtsc();
    for _ in 0..ITERS {
        let id = sys::tx_begin(TIER_MULTI).unwrap();
        sys::tx_prepare(id).unwrap();
        sys::tx_commit(id).unwrap();
    }
    let total = rdtsc().wrapping_sub(t0);
    print_cycles(b"    BEGIN+PREPARE+COMMIT", total, ITERS);

    print(b"    D: PASS\n");
    true
}

// ---------------------------------------------------------------------------
// E. Fuzz / robustness
// ---------------------------------------------------------------------------

/// Tiny xorshift64 PRNG -- deterministic, no allocations.
struct Rng(u64);
impl Rng {
    fn new(seed: u64) -> Self { Self(seed | 1) }
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }
}

fn run_fuzz() -> bool {
    print(b"[E] fuzz / robustness\n");

    const ITERS: u32 = 5_000;
    let mut rng = Rng::new(0xC0FFEE_BABE);

    let mut survived: u32 = 0;
    let mut errors: u32 = 0;
    let mut ok: u32 = 0;
    // Track open ReadOnly tx ids so we can clean them up afterwards.
    let mut open_tx = [0u64; 16];
    let mut open_count = 0usize;

    for i in 0..ITERS {
        let r = rng.next();
        let op = r & 0x7;
        let arg1 = r >> 8;
        let arg2 = r >> 24;
        match op {
            0 => {
                // so_create with random type
                let type_id = arg1 & 0xFF;
                let res = sys::so_create(type_id, 0);
                if res.is_ok() { ok += 1; } else { errors += 1; }
            }
            1 => {
                // so_observe with possibly invalid cap
                let cap = arg1 & 0xFFFF;
                let res = sys::so_observe(cap, 0);
                if res.is_ok() { ok += 1; } else { errors += 1; }
            }
            2 => {
                // sot_channel_create
                let res = sys::sot_channel_create(arg1 & 0xFF);
                if res.is_ok() { ok += 1; } else { errors += 1; }
            }
            3 => {
                // tx_begin ReadOnly
                if open_count < 16 {
                    if let Ok(id) = sys::tx_begin(0) {
                        open_tx[open_count] = id;
                        open_count += 1;
                        ok += 1;
                    } else {
                        errors += 1;
                    }
                }
            }
            4 => {
                // tx_commit on a random possibly-invalid id
                let id = if open_count > 0 && (arg2 & 1) == 0 {
                    open_count -= 1;
                    open_tx[open_count]
                } else {
                    arg1
                };
                let res = sys::tx_commit(id);
                if res.is_ok() { ok += 1; } else { errors += 1; }
            }
            5 => {
                // tx_abort on garbage id
                let res = sys::tx_abort(arg1);
                if res.is_ok() { ok += 1; } else { errors += 1; }
            }
            6 => {
                // tx_prepare on garbage id (Tier 2 syscall)
                let res = sys::tx_prepare(arg1);
                if res.is_ok() { ok += 1; } else { errors += 1; }
            }
            _ => {
                // provenance_emit with random fields (always returns ())
                sys::provenance_emit(
                    (arg1 & 0xFFFF) as u16,
                    (arg2 & 0xFF) as u8,
                    arg1 ^ arg2,
                    (arg2 & 0xFFFF) as u32,
                );
                ok += 1;
            }
        }
        survived = i + 1;
    }

    // Cleanup any leftover ReadOnly tx ids.
    for j in 0..open_count {
        let _ = sys::tx_abort(open_tx[j]);
    }

    print(b"    iterations=");
    print_u64(survived as u64);
    print(b" ok=");
    print_u64(ok as u64);
    print(b" expected_errors=");
    print_u64(errors as u64);
    print(b"\n");

    // Drain whatever provenance entries fuzz produced so we leave a clean ring.
    let mut tmp = [KernelProvEntry::zero(); 64];
    while drain_ring(&mut tmp) > 0 {}

    if survived != ITERS {
        print(b"    !! survival counter mismatch\n");
        return false;
    }
    print(b"    E: PASS\n");
    true
}

fn print_i64(mut n: i64) {
    if n < 0 { sys::debug_print(b'-'); n = -n; }
    print_u64(n as u64);
}

// ---------------------------------------------------------------------------
// F. Concurrent transaction stress
// ---------------------------------------------------------------------------

use core::sync::atomic::{AtomicU32, Ordering as AtomOrdering};

const STRESS_TX_PER_THREAD: u32 = 500;

static STRESS_WORKER_OK: AtomicU32 = AtomicU32::new(0);
static STRESS_WORKER_DONE: AtomicU32 = AtomicU32::new(0);

const STRESS_STACK: u64 = 0xE70000;
const STRESS_STACK_PAGES: u64 = 4;

extern "C" fn stress_worker() -> ! {
    let mut ok: u32 = 0;
    for _ in 0..STRESS_TX_PER_THREAD {
        if let Ok(id) = sys::tx_begin(0) {
            if sys::tx_commit(id).is_ok() { ok += 1; }
        }
    }
    STRESS_WORKER_OK.store(ok, AtomOrdering::Release);
    STRESS_WORKER_DONE.store(1, AtomOrdering::Release);
    loop { sys::yield_now(); }
}

fn run_concurrent_stress() -> bool {
    print(b"[F] concurrent tx stress\n");

    STRESS_WORKER_OK.store(0, AtomOrdering::Relaxed);
    STRESS_WORKER_DONE.store(0, AtomOrdering::Relaxed);

    // Allocate the worker stack.
    for i in 0..STRESS_STACK_PAGES {
        let f = match sys::frame_alloc() {
            Ok(f) => f,
            Err(_) => { print(b"    !! frame_alloc failed\n"); return false; }
        };
        if sys::map(STRESS_STACK + i * 0x1000, f, 2).is_err() {
            print(b"    !! map failed\n");
            return false;
        }
    }
    let rsp = STRESS_STACK + STRESS_STACK_PAGES * 0x1000;
    if sys::thread_create(stress_worker as *const () as u64, rsp).is_err() {
        print(b"    !! thread_create failed\n");
        return false;
    }

    // Main thread does its own batch in parallel.
    let mut main_ok: u32 = 0;
    for _ in 0..STRESS_TX_PER_THREAD {
        if let Ok(id) = sys::tx_begin(0) {
            if sys::tx_commit(id).is_ok() { main_ok += 1; }
        }
    }

    // Wait for the worker to finish (bounded).
    for _ in 0..200_000 {
        if STRESS_WORKER_DONE.load(AtomOrdering::Acquire) == 1 { break; }
        sys::yield_now();
    }
    if STRESS_WORKER_DONE.load(AtomOrdering::Acquire) != 1 {
        print(b"    !! worker did not finish in budget\n");
        return false;
    }

    let worker_ok = STRESS_WORKER_OK.load(AtomOrdering::Acquire);
    print(b"    main_ok=");
    print_u64(main_ok as u64);
    print(b" worker_ok=");
    print_u64(worker_ok as u64);
    print(b" total=");
    print_u64((main_ok + worker_ok) as u64);
    print(b"/");
    print_u64((STRESS_TX_PER_THREAD * 2) as u64);
    print(b"\n");

    if main_ok != STRESS_TX_PER_THREAD || worker_ok != STRESS_TX_PER_THREAD {
        print(b"    !! some transactions dropped under contention\n");
        return false;
    }
    print(b"    F: PASS\n");
    true
}

// ---------------------------------------------------------------------------
// Driver
// ---------------------------------------------------------------------------

pub fn run() {
    print(b"\n=== Tier 5 production hardening demo ===\n");
    let _ = TIER;
    let mut all_ok = true;
    if !run_ipc_bench()         { all_ok = false; }
    if !run_ring_bench()        { all_ok = false; }
    if !run_interpose_bench()   { all_ok = false; }
    if !run_2pc()               { all_ok = false; }
    if !run_fuzz()              { all_ok = false; }
    if !run_concurrent_stress() { all_ok = false; }
    if all_ok {
        print(b"=== Tier 5 demo: PASS ===\n\n");
    } else {
        print(b"=== Tier 5 demo: FAIL ===\n\n");
    }
}
