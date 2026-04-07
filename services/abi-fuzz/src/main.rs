//! ABI fuzz harness — Unit 9.
//!
//! Tier 5 follow-up: hammers the kernel syscall surface with
//! pseudo-random arguments to find ABI bugs and validate that bad
//! input never crashes the kernel. Each iteration picks a random
//! syscall number from a curated whitelist of `sotos_common::Syscall`
//! variants and fills the argument registers with deterministic
//! pseudo-random u64 values from a xorshift64 PRNG seeded with
//! a constant -- failures are reproducible bit-for-bit.
//!
//! The fuzzer skips a small set of inherently destructive numbers:
//!
//!   * `Syscall::ThreadExit` (42)        -- terminates our own thread
//!   * `Syscall::Recv` (2)               -- blocks indefinitely on a
//!                                          valid endpoint cap
//!   * `Syscall::ChannelRecv` (6)        -- same blocking risk
//!   * `Syscall::FaultRecv` (81)         -- same blocking risk
//!   * `Syscall::NotifyWait` (71)        -- same blocking risk
//!
//! Everything else is fair game: random caps fail validation cleanly,
//! random vaddrs trip USER_ADDR_LIMIT checks, random sizes/flags get
//! ENOSYS or EINVAL. The harness expects every call to return without
//! the kernel page-faulting or panicking.
//!
//! On completion the binary prints
//! `=== abi-fuzz: <ok>/<total> survived ===` and exits cleanly. The
//! host driver `scripts/abi_fuzz.py` greps the serial log for that
//! marker and the CI workflow `.github/workflows/fuzz.yml` runs the
//! whole pipeline nightly.

#![no_std]
#![no_main]

use sotos_common::sys;

// Stack canary support (-Zstack-protector=strong, kept off by default
// for this binary, but the symbol is required if rebuilt with it on).
#[used]
#[no_mangle]
static mut __stack_chk_guard: u64 = 0x00000aff_0a0d_0000;

#[no_mangle]
pub extern "C" fn __stack_chk_fail() -> ! {
    print(b"abi-fuzz: STACK CHECK FAIL\n");
    sys::thread_exit();
}

// ---------------------------------------------------------------------------
// Output helpers
// ---------------------------------------------------------------------------

fn print(s: &[u8]) {
    for &b in s {
        sys::debug_print(b);
    }
}

fn print_u64(mut n: u64) {
    if n == 0 {
        sys::debug_print(b'0');
        return;
    }
    let mut buf = [0u8; 20];
    let mut i = 0;
    while n > 0 {
        buf[i] = b'0' + (n % 10) as u8;
        n /= 10;
        i += 1;
    }
    while i > 0 {
        i -= 1;
        sys::debug_print(buf[i]);
    }
}

// ---------------------------------------------------------------------------
// Deterministic xorshift64 PRNG
// ---------------------------------------------------------------------------

/// Default seed: a fixed prime so reproducibility is guaranteed across
/// boots. To pick a new seed, set the SOTOS_ABI_FUZZ_SEED env var when
/// rebuilding -- but the binary itself is hard-coded so failures stay
/// bit-for-bit identical.
const DEFAULT_SEED: u64 = 0x9E37_79B9_7F4A_7C15;

/// Default iteration count -- the unit instructions ask for 10 000.
const DEFAULT_ITERATIONS: u32 = 10_000;

#[inline(always)]
fn xorshift64(state: &mut u64) -> u64 {
    // Caller seeds with a nonzero constant, so the absorbing zero
    // state is unreachable -- no defensive reseed needed.
    let mut x = *state;
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    *state = x;
    x
}

// ---------------------------------------------------------------------------
// syscall6 helper -- sotos_common::sys only exposes up to syscall5, but
// the unit spec asks for "6 registers". We provide a local wrapper that
// loads rdi/rsi/rdx/r8/r10/r9 like the Linux x86_64 calling convention.
// ---------------------------------------------------------------------------

#[inline(always)]
fn syscall6(nr: u64, a1: u64, a2: u64, a3: u64, a4: u64, a5: u64, a6: u64) -> u64 {
    let ret: u64;
    unsafe {
        core::arch::asm!(
            "syscall",
            inlateout("rax") nr => ret,
            in("rdi") a1,
            in("rsi") a2,
            in("rdx") a3,
            in("r8") a4,
            in("r10") a5,
            in("r9") a6,
            lateout("rcx") _,
            lateout("r11") _,
            options(nostack),
        );
    }
    ret
}

// ---------------------------------------------------------------------------
// Curated syscall whitelist
//
// Every numeric value here is the raw integer matching a variant of
// `sotos_common::Syscall`. We hard-code the table instead of iterating
// the enum so this binary stays no_std-friendly and the list survives
// any future enum reordering.
//
// Numbers intentionally absent (and the reason):
//
//   2  Recv         -- blocks until peer sends
//   6  ChannelRecv  -- blocks until producer enqueues
//   42 ThreadExit   -- terminates the fuzzer thread itself
//   71 NotifyWait   -- blocks until signal
//   81 FaultRecv    -- blocks until fault arrives
//
// Everything else returns within microseconds even when fed random
// pointers and caps -- the kernel handlers all validate caps and
// USER_ADDR_LIMIT before dereferencing.
// ---------------------------------------------------------------------------

const SYSCALL_TABLE: &[u64] = &[
    // IPC -- non-blocking variants
    1,   // Send (random cap fails validation)
    3,   // Call
    4,   // ChannelCreate
    5,   // ChannelSend
    7,   // ChannelClose
    10,  // EndpointCreate
    // Memory
    20, 21, 22, 23, 24,
    // Capabilities
    30, 31,
    // Threads (excluding ThreadExit=42)
    40, 43,
    // IRQ
    50, 51,
    // I/O ports
    60, 61,
    // Notify (excluding NotifyWait=71)
    70, 72,
    // Fault (excluding FaultRecv=81)
    80,
    // Domains
    90, 91, 92, 93, 94,
    // Device infrastructure
    100, 101, 102, 103, 104,
    // LUCAS redirect
    110,
    // Multi-AS
    120, 121, 122, 123, 125, 126, 127, 128, 129,
    // Service registry + spawn
    130, 131, 132, 133,
    // Protect
    134,
    // Call/recv timeout (have built-in escape hatch)
    135, 136,
    // Thread info / resource limits
    140, 141, 142,
    // Permissions
    150, 151,
    // FS_BASE
    160, 161,
    // Protect-in / WX-relax
    175, 177,
    // Shared memory
    180, 181, 182, 183,
    // Debug
    253, 255,
    // SOT exokernel layer
    300, 301, 302, 303, 304, 305, 306, 307, 308, 309, 310,
];

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    print(b"\n=== abi-fuzz: deterministic ABI fuzz harness ===\n");
    print(b"abi-fuzz: seed=");
    print_u64(DEFAULT_SEED);
    print(b" iterations=");
    print_u64(DEFAULT_ITERATIONS as u64);
    print(b" table_len=");
    print_u64(SYSCALL_TABLE.len() as u64);
    print(b"\n");

    let mut rng = DEFAULT_SEED;
    let mut survived: u32 = 0;

    for _ in 0..DEFAULT_ITERATIONS {
        let idx = (xorshift64(&mut rng) as usize) % SYSCALL_TABLE.len();
        let nr = SYSCALL_TABLE[idx];

        let a1 = xorshift64(&mut rng);
        let a2 = xorshift64(&mut rng);
        let a3 = xorshift64(&mut rng);
        let a4 = xorshift64(&mut rng);
        let a5 = xorshift64(&mut rng);
        let a6 = xorshift64(&mut rng);

        // SYS_CALL_TIMEOUT and SYS_RECV_TIMEOUT pack a timeout into
        // the upper 32 bits of rdi -- force it to a tiny non-zero
        // value so we don't accidentally block for u64::MAX ticks
        // when the random low half hits a valid endpoint cap.
        let a1 = if nr == 135 || nr == 136 {
            (a1 & 0xFFFF_FFFF) | (1u64 << 32)
        } else {
            a1
        };

        // Fire the call. Return value is ignored on purpose: a fuzz
        // harness only cares that the *kernel* survives, not what
        // each individual call returned.
        let _ = syscall6(nr, a1, a2, a3, a4, a5, a6);
        survived += 1;
    }

    print(b"=== abi-fuzz: ");
    print_u64(survived as u64);
    print(b"/");
    print_u64(DEFAULT_ITERATIONS as u64);
    print(b" survived ===\n");

    sys::thread_exit();
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    print(b"abi-fuzz: PANIC!\n");
    loop {
        sys::yield_now();
    }
}
