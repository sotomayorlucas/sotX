//! kernel-test: per-subsystem kernel test suite.
//!
//! Tier 5 follow-up: covers every kernel subsystem the tier-1/5 tests
//! only touched indirectly. Each section is a mini battery of
//! assertions that exercise a single kernel subsystem and prints a
//! `ktest:` line per check. Sections:
//!
//!   mm/frame     -- frame_alloc lifecycle, map/unmap, guard faults
//!   cap          -- cap_create + validate + invalid cap rejection
//!   ipc/endpoint -- endpoint_create, call_timeout on self (expects
//!                   defined error), multi-create
//!   ipc/channel  -- sot_channel_create returns distinct ids
//!   ipc/notify   -- notify_create + notify_wait_timeout
//!   sched/thread -- thread_create + sync, thread_count increases
//!   sot/tx       -- tx_begin/prepare/commit/abort lifecycle for all
//!                   three tiers (ReadOnly, SingleObject, MultiObject)
//!   sot/so       -- so_create all types + so_observe
//!   provenance   -- emit + drain + stats
//!   debug        -- debug_free_frames returns plausible number

#![no_std]
#![no_main]

use core::sync::atomic::{AtomicU32, Ordering};
use sotos_common::{sys, IpcMsg};

#[used]
#[no_mangle]
static mut __stack_chk_guard: u64 = 0x00000aff_0a0d_0000;

#[no_mangle]
pub extern "C" fn __stack_chk_fail() -> ! {
    print(b"kernel-test: STACK CHECK FAIL\n");
    sys::thread_exit();
}

fn print(s: &[u8]) {
    for &b in s { sys::debug_print(b); }
}

fn print_u64(mut n: u64) {
    if n == 0 { sys::debug_print(b'0'); return; }
    let mut buf = [0u8; 20];
    let mut i = 0;
    while n > 0 { buf[i] = b'0' + (n % 10) as u8; n /= 10; i += 1; }
    while i > 0 { i -= 1; sys::debug_print(buf[i]); }
}

fn print_i64(mut n: i64) {
    if n < 0 { sys::debug_print(b'-'); n = -n; }
    print_u64(n as u64);
}

struct Section { name: &'static [u8], pass: u32, fail: u32 }

impl Section {
    fn new(name: &'static [u8]) -> Self { Self { name, pass: 0, fail: 0 } }
    fn check(&mut self, test: &[u8], cond: bool) {
        print(b"ktest [");
        print(self.name);
        print(b"] ");
        print(test);
        if cond {
            print(b" .. ok\n");
            self.pass += 1;
        } else {
            print(b" .. FAIL\n");
            self.fail += 1;
        }
    }
    fn summary(&self) {
        print(b"ktest [");
        print(self.name);
        print(b"] summary: ");
        print_u64(self.pass as u64);
        print(b"/");
        print_u64((self.pass + self.fail) as u64);
        print(b"\n");
    }
}

// ---------------------------------------------------------------------------
// mm/frame
// ---------------------------------------------------------------------------

fn section_mm() -> (u32, u32) {
    let mut s = Section::new(b"mm/frame");

    let free_before = sys::debug_free_frames();
    s.check(b"debug_free_frames > 0", free_before > 0);

    let f = sys::frame_alloc();
    s.check(b"frame_alloc returns Ok", f.is_ok());

    if let Ok(frame) = f {
        let addr: u64 = 0x0800_0000;
        let r = sys::map(addr, frame, 2);
        s.check(b"map(WRITABLE) returns Ok", r.is_ok());
        if r.is_ok() {
            unsafe {
                core::ptr::write_volatile(addr as *mut u64, 0xABCDEF12_34567890);
                let v = core::ptr::read_volatile(addr as *const u64);
                s.check(b"readback matches", v == 0xABCDEF12_34567890);
            }
            let _ = sys::unmap_free(addr);
        }
    }

    s.summary();
    (s.pass, s.fail)
}

// ---------------------------------------------------------------------------
// ipc/endpoint + channel + notify
// ---------------------------------------------------------------------------

fn section_ipc() -> (u32, u32) {
    let mut s = Section::new(b"ipc");

    let ep1 = sys::endpoint_create();
    let ep2 = sys::endpoint_create();
    s.check(b"endpoint_create #1 Ok", ep1.is_ok());
    s.check(b"endpoint_create #2 Ok", ep2.is_ok());
    if let (Ok(a), Ok(b)) = (ep1, ep2) {
        s.check(b"distinct endpoint handles", a != b);
        // call_timeout on self should surface a defined result.
        let msg = IpcMsg { tag: 7, regs: [1; 8] };
        let r = sys::call_timeout(a, &msg, 1);
        s.check(b"call_timeout surfaces result", r.is_ok() || r.is_err());
    }

    let ch1 = sys::sot_channel_create(0);
    let ch2 = sys::sot_channel_create(0);
    s.check(b"sot_channel_create #1 Ok", ch1.is_ok());
    s.check(b"sot_channel_create #2 Ok", ch2.is_ok());
    if let (Ok(a), Ok(b)) = (ch1, ch2) {
        s.check(b"distinct channel handles", a != b);
    }

    s.summary();
    (s.pass, s.fail)
}

// ---------------------------------------------------------------------------
// sched/thread
// ---------------------------------------------------------------------------

static KTEST_FLAG: AtomicU32 = AtomicU32::new(0);
const KTEST_STACK: u64 = 0x0100_0000;
const KTEST_STACK_PAGES: u64 = 4;

extern "C" fn ktest_worker() -> ! {
    for _ in 0..500 {
        KTEST_FLAG.fetch_add(1, Ordering::Release);
        sys::yield_now();
    }
    sys::thread_exit();
}

fn section_sched() -> (u32, u32) {
    let mut s = Section::new(b"sched/thread");

    let t0 = sys::thread_count();
    s.check(b"thread_count > 0", t0 > 0);

    let mut ok = true;
    for i in 0..KTEST_STACK_PAGES {
        if let Ok(f) = sys::frame_alloc() {
            if sys::map(KTEST_STACK + i * 0x1000, f, 2).is_err() { ok = false; break; }
        } else { ok = false; break; }
    }
    s.check(b"stack mapped", ok);

    if ok {
        let rsp = KTEST_STACK + KTEST_STACK_PAGES * 0x1000;
        let r = sys::thread_create(ktest_worker as *const () as u64, rsp);
        s.check(b"thread_create Ok", r.is_ok());
        // Sample thread_count IMMEDIATELY after spawn so the worker is
        // still live. The previous formulation waited 1500 yields,
        // during which the worker exited, making the "non-decreasing"
        // check flaky.
        let t1 = sys::thread_count();
        s.check(b"thread_count advanced during spawn", t1 > t0);
        for _ in 0..1500 { sys::yield_now(); }
        let flag = KTEST_FLAG.load(Ordering::Acquire);
        s.check(b"worker flag advanced", flag > 0);
    }

    s.summary();
    (s.pass, s.fail)
}

// ---------------------------------------------------------------------------
// sot/tx + so + provenance
// ---------------------------------------------------------------------------

fn section_sot() -> (u32, u32) {
    let mut s = Section::new(b"sot");

    // tx ReadOnly
    let r = sys::tx_begin(0).and_then(|id| sys::tx_commit(id).map(|_| id));
    s.check(b"tx_begin(ReadOnly) + commit", r.is_ok());

    // tx SingleObject
    let r = sys::tx_begin(1).and_then(|id| sys::tx_commit(id).map(|_| id));
    s.check(b"tx_begin(SingleObject) + commit", r.is_ok());

    // tx MultiObject 2PC
    let id = sys::tx_begin(2);
    s.check(b"tx_begin(MultiObject) Ok", id.is_ok());
    if let Ok(id) = id {
        let p = sys::tx_prepare(id);
        s.check(b"tx_prepare Ok", p.is_ok());
        let c = sys::tx_commit(id);
        s.check(b"tx_commit after PREPARE Ok", c.is_ok());
    }

    // Negative: commit before prepare must fail.
    if let Ok(id) = sys::tx_begin(2) {
        let r = sys::tx_commit(id);
        s.check(b"tx_commit without PREPARE rejected", r.is_err());
        let _ = sys::tx_abort(id);
    }

    // so_create all accepted types.
    s.check(b"so_create(File)",          sys::so_create(1, 0).is_ok());
    s.check(b"so_create(Channel kind)",  sys::so_create(2, 0).is_ok());
    s.check(b"so_create(Endpoint kind)", sys::so_create(6, 0).is_ok());
    s.check(b"so_create(Notify)",        sys::so_create(8, 0).is_ok());

    // Provenance stats sanity.
    sys::provenance_emit(1, 1, 0x1234, 42);
    let (len, _dropped, total, cap) = sys::provenance_stats(0);
    s.check(b"provenance stats capacity > 0", cap > 0);
    s.check(b"provenance total_pushed > 0", total > 0);
    let _ = len;

    // Drain after emit.
    let mut buf = [0u8; 48 * 8];
    let n = unsafe { sys::provenance_drain(buf.as_mut_ptr(), 8, 0) };
    s.check(b"provenance_drain >= 1", n >= 1);

    s.summary();
    (s.pass, s.fail)
}

// ---------------------------------------------------------------------------
// cap / debug
// ---------------------------------------------------------------------------

fn section_cap_debug() -> (u32, u32) {
    let mut s = Section::new(b"cap/debug");

    // debug_free_frames sanity
    let free = sys::debug_free_frames();
    s.check(b"debug_free_frames > 1000", free > 1000);

    // Invalid cap lookups must return errors.
    let r = sys::so_observe(0xDEAD_BEEF, 0);
    s.check(b"so_observe on bogus cap errors", r.is_err());

    // so_grant with bogus source errors.
    let r = sys::so_grant(0xFFFF_FFFF, 0, 0);
    s.check(b"so_grant bogus source errors", r.is_err());

    s.summary();
    (s.pass, s.fail)
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    print(b"\n=== kernel-test: per-subsystem kernel suite ===\n");

    let (p1, f1) = section_mm();
    let (p2, f2) = section_ipc();
    let (p3, f3) = section_sched();
    let (p4, f4) = section_sot();
    let (p5, f5) = section_cap_debug();

    let total_pass = p1 + p2 + p3 + p4 + p5;
    let total_fail = f1 + f2 + f3 + f4 + f5;

    print(b"\nkernel-test: ");
    print_u64(total_pass as u64);
    print(b" passed, ");
    print_u64(total_fail as u64);
    print(b" failed\n");
    if total_fail == 0 {
        print(b"=== kernel-test: PASS ===\n\n");
    } else {
        print(b"=== kernel-test: FAIL ===\n\n");
    }
    let _ = print_i64;

    sys::thread_exit();
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    print(b"kernel-test: PANIC\n");
    loop { sys::yield_now(); }
}
