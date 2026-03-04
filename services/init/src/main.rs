#![no_std]
#![no_main]

use sotos_common::sys;
use sotos_common::spsc;
use sotos_common::{BootInfo, BOOT_INFO_ADDR};
use sotos_pci::PciBus;
use sotos_virtio::blk::VirtioBlk;
use sotos_objstore::{ObjectStore, Vfs, DirEntry, DIR_ENTRY_COUNT};

use core::sync::atomic::{AtomicU64, Ordering};

/// Shared memory page for the SPSC ring buffer.
const RING_ADDR: u64 = 0xA00000;
/// Producer thread stack base (1 page).
const PRODUCER_STACK_BASE: u64 = 0xA10000;
/// Producer thread stack top.
const PRODUCER_STACK_TOP: u64 = PRODUCER_STACK_BASE + 0x1000;
/// Number of messages to send through the ring.
const MSG_COUNT: u64 = 1000;
/// WRITABLE flag for map syscall (bit 1).
const MAP_WRITABLE: u64 = 2;

// ---------------------------------------------------------------------------
// LUCAS (Phase 10.1) — syscall redirect demo
// ---------------------------------------------------------------------------

/// LUCAS guest stack (4 pages).
const LUCAS_GUEST_STACK: u64 = 0xE00000;
const LUCAS_GUEST_STACK_PAGES: u64 = 4;
/// LUCAS handler stack (4 pages).
const LUCAS_HANDLER_STACK: u64 = 0xE04000;
const LUCAS_HANDLER_STACK_PAGES: u64 = 4;

/// LUCAS endpoint cap — shared between handler and _start via atomic.
static LUCAS_EP_CAP: AtomicU64 = AtomicU64::new(0);

// ---------------------------------------------------------------------------
// Root capability indices (must match kernel create_init_caps() order)
// Keyboard caps removed — kbd runs as a separate process.
// ---------------------------------------------------------------------------
const CAP_VMM_NOTIFY: usize = 0;  // Notification (VMM page faults)
const CAP_PCI: usize = 1;         // I/O port 0xCF8-0xCFF (PCI config)

fn print(s: &[u8]) {
    for &b in s {
        sys::debug_print(b);
        unsafe { fb_putchar(b); }
    }
}

fn print_u64(mut n: u64) {
    if n == 0 {
        sys::debug_print(b'0');
        unsafe { fb_putchar(b'0'); }
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
        unsafe { fb_putchar(buf[i]); }
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    // --- Phase 1: Read BootInfo ---
    let boot_info = unsafe { &*(BOOT_INFO_ADDR as *const BootInfo) };
    let cap_count = if boot_info.is_valid() {
        boot_info.cap_count
    } else {
        0
    };

    print(b"INIT: boot complete, ");
    print_u64(cap_count);
    print(b" caps received\n");

    // --- Spawn VMM service thread (must be early, before any demand paging) ---
    // Keyboard driver is now a separate process (services/kbd).
    spawn_service_thread(vmm_server as *const () as u64, VMM_STACK_BASE);

    // --- Phase 2: SPSC channel test ---
    // 1. Allocate and map shared page for ring buffer
    let ring_frame = sys::frame_alloc().unwrap_or_else(|_| panic_halt());
    sys::map(RING_ADDR, ring_frame, MAP_WRITABLE).unwrap_or_else(|_| panic_halt());

    // 2. Create notification objects (empty = consumer waits, full = producer waits)
    let empty_cap = sys::notify_create().unwrap_or_else(|_| panic_halt());
    let full_cap = sys::notify_create().unwrap_or_else(|_| panic_halt());

    // 3. Initialize SPSC ring at shared address
    let ring = unsafe {
        spsc::SpscRing::init(RING_ADDR as *mut u8, 128, empty_cap as u32, full_cap as u32)
    };

    // 4. Allocate and map producer stack
    let stack_frame = sys::frame_alloc().unwrap_or_else(|_| panic_halt());
    sys::map(PRODUCER_STACK_BASE, stack_frame, MAP_WRITABLE).unwrap_or_else(|_| panic_halt());

    // 5. Spawn producer thread
    let _thread_cap = sys::thread_create(producer as *const () as u64, PRODUCER_STACK_TOP)
        .unwrap_or_else(|_| panic_halt());

    // 6. Consumer loop: receive MSG_COUNT values and sum them
    let mut sum: u64 = 0;
    for _ in 0..MSG_COUNT {
        sum += spsc::recv(ring);
    }

    // 7. Print result: expected sum = 0+1+2+...+999 = 499500
    print(b"SPSC: sum=");
    print_u64(sum);
    print(b"\n");

    // --- Phase 3: Benchmarks ---
    run_benchmarks(ring);

    // --- Phase 4: Virtio-BLK demo + Object Store ---
    let blk = run_virtio_blk_demo(boot_info);

    // --- Phase 5: LUCAS syscall redirect demo ---
    run_lucas_demo(blk);

    // Give LUCAS threads time to complete before exiting init.
    for _ in 0..100 {
        sys::yield_now();
    }

    sys::thread_exit();
}

/// Producer entry point — runs in a separate thread, same address space.
#[unsafe(no_mangle)]
pub extern "C" fn producer() -> ! {
    let ring = unsafe { spsc::SpscRing::from_ptr(RING_ADDR as *mut u8) };
    for i in 0..MSG_COUNT {
        spsc::send(ring, i);
    }
    sys::thread_exit();
}

// ---------------------------------------------------------------------------
// VMM server + Keyboard driver (migrated from assembly blobs)
// ---------------------------------------------------------------------------

/// VMM server stack (1 page, allocated by init).
const VMM_STACK_BASE: u64 = 0x520000;

/// Allocate a stack page and spawn a service thread.
fn spawn_service_thread(entry: u64, stack_base: u64) {
    let f = sys::frame_alloc().unwrap_or_else(|_| panic_halt());
    sys::map(stack_base, f, MAP_WRITABLE).unwrap_or_else(|_| panic_halt());
    sys::thread_create(entry, stack_base + 0x1000).unwrap_or_else(|_| panic_halt());
}

/// VMM server — handles page faults by allocating frames and mapping them.
/// Replaces the 60-line assembly blob `user_vmm`.
#[unsafe(no_mangle)]
pub extern "C" fn vmm_server() -> ! {
    let boot_info = unsafe { &*(BOOT_INFO_ADDR as *const BootInfo) };
    let notify_cap = boot_info.caps[CAP_VMM_NOTIFY];

    sys::fault_register(notify_cap).unwrap_or_else(|_| panic_halt());

    loop {
        sys::notify_wait(notify_cap);
        loop {
            match sys::fault_recv() {
                Ok(fault) => {
                    let frame = sys::frame_alloc().unwrap_or_else(|_| panic_halt());
                    let vaddr = fault.addr & !0xFFF;
                    sys::map(vaddr, frame, MAP_WRITABLE).unwrap_or_else(|_| panic_halt());
                    sys::thread_resume(fault.tid as u64).unwrap_or_else(|_| panic_halt());
                }
                Err(_) => break,
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Benchmarks
// ---------------------------------------------------------------------------

/// Read the CPU timestamp counter.
#[inline(always)]
fn rdtsc() -> u64 {
    let lo: u32;
    let hi: u32;
    unsafe {
        core::arch::asm!("rdtsc", out("eax") lo, out("edx") hi, options(nomem, nostack));
    }
    ((hi as u64) << 32) | lo as u64
}

/// Run SPSC benchmarks after the main test completes.
fn run_benchmarks(ring: &spsc::SpscRing) {
    // Latency: measure try_send + try_recv round-trip (single-threaded, no contention)
    const LAT_ITERS: u64 = 10000;

    // Warm up
    for i in 0..128 {
        spsc::try_send(ring, i);
    }
    for _ in 0..128 {
        spsc::try_recv(ring);
    }

    let start = rdtsc();
    for i in 0..LAT_ITERS {
        spsc::try_send(ring, i);
        spsc::try_recv(ring);
    }
    let end = rdtsc();
    let cycles_per_msg = (end - start) / LAT_ITERS;

    print(b"BENCH: spsc_rt=");
    print_u64(cycles_per_msg);
    print(b"cy/msg\n");

    // Throughput: stream 10K messages (single-threaded, no blocking)
    const TPUT_MSGS: u64 = 10000;
    let start = rdtsc();
    for i in 0..TPUT_MSGS {
        while !spsc::try_send(ring, i) {}
        while spsc::try_recv(ring).is_none() {}
    }
    let end = rdtsc();
    let tput_cy = (end - start) / TPUT_MSGS;

    print(b"BENCH: spsc_tput=");
    print_u64(tput_cy);
    print(b"cy/msg (10000 msgs)\n");
}

fn print_hex(val: u32) {
    let hex = b"0123456789ABCDEF";
    for i in (0..8).rev() {
        sys::debug_print(hex[((val >> (i * 4)) & 0xF) as usize]);
    }
}

// ---------------------------------------------------------------------------
// Framebuffer console (Phase 13)
// ---------------------------------------------------------------------------

/// VGA 8x16 font (CP437, 256 chars × 16 bytes each = 4096 bytes).
static VGA_FONT: [u8; 4096] = [
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x7e,0x81,0xa5,0x81,0x81,0xbd,0x99,0x81,0x81,0x7e,0x00,0x00,0x00,0x00,
    0x00,0x00,0x7e,0xff,0xdb,0xff,0xff,0xc3,0xe7,0xff,0xff,0x7e,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x6c,0xfe,0xfe,0xfe,0xfe,0x7c,0x38,0x10,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x10,0x38,0x7c,0xfe,0x7c,0x38,0x10,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x18,0x3c,0x3c,0xe7,0xe7,0xe7,0x18,0x18,0x3c,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x18,0x3c,0x7e,0xff,0xff,0x7e,0x18,0x18,0x3c,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x18,0x3c,0x3c,0x18,0x00,0x00,0x00,0x00,0x00,0x00,
    0xff,0xff,0xff,0xff,0xff,0xff,0xe7,0xc3,0xc3,0xe7,0xff,0xff,0xff,0xff,0xff,0xff,
    0x00,0x00,0x00,0x00,0x00,0x3c,0x66,0x42,0x42,0x66,0x3c,0x00,0x00,0x00,0x00,0x00,
    0xff,0xff,0xff,0xff,0xff,0xc3,0x99,0xbd,0xbd,0x99,0xc3,0xff,0xff,0xff,0xff,0xff,
    0x00,0x00,0x1e,0x0e,0x1a,0x32,0x78,0xcc,0xcc,0xcc,0xcc,0x78,0x00,0x00,0x00,0x00,
    0x00,0x00,0x3c,0x66,0x66,0x66,0x66,0x3c,0x18,0x7e,0x18,0x18,0x00,0x00,0x00,0x00,
    0x00,0x00,0x3f,0x33,0x3f,0x30,0x30,0x30,0x30,0x70,0xf0,0xe0,0x00,0x00,0x00,0x00,
    0x00,0x00,0x7f,0x63,0x7f,0x63,0x63,0x63,0x63,0x67,0xe7,0xe6,0xc0,0x00,0x00,0x00,
    0x00,0x00,0x00,0x18,0x18,0xdb,0x3c,0xe7,0x3c,0xdb,0x18,0x18,0x00,0x00,0x00,0x00,
    0x00,0x80,0xc0,0xe0,0xf0,0xf8,0xfe,0xf8,0xf0,0xe0,0xc0,0x80,0x00,0x00,0x00,0x00,
    0x00,0x02,0x06,0x0e,0x1e,0x3e,0xfe,0x3e,0x1e,0x0e,0x06,0x02,0x00,0x00,0x00,0x00,
    0x00,0x00,0x18,0x3c,0x7e,0x18,0x18,0x18,0x7e,0x3c,0x18,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x00,0x66,0x66,0x00,0x00,0x00,0x00,
    0x00,0x00,0x7f,0xdb,0xdb,0xdb,0x7b,0x1b,0x1b,0x1b,0x1b,0x1b,0x00,0x00,0x00,0x00,
    0x00,0x7c,0xc6,0x60,0x38,0x6c,0xc6,0xc6,0x6c,0x38,0x0c,0xc6,0x7c,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xfe,0xfe,0xfe,0xfe,0x00,0x00,0x00,0x00,
    0x00,0x00,0x18,0x3c,0x7e,0x18,0x18,0x18,0x7e,0x3c,0x18,0x7e,0x00,0x00,0x00,0x00,
    0x00,0x00,0x18,0x3c,0x7e,0x18,0x18,0x18,0x18,0x18,0x18,0x18,0x00,0x00,0x00,0x00,
    0x00,0x00,0x18,0x18,0x18,0x18,0x18,0x18,0x18,0x7e,0x3c,0x18,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x18,0x0c,0xfe,0x0c,0x18,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x30,0x60,0xfe,0x60,0x30,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0xc0,0xc0,0xc0,0xfe,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x28,0x6c,0xfe,0x6c,0x28,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x10,0x38,0x38,0x7c,0x7c,0xfe,0xfe,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0xfe,0xfe,0x7c,0x7c,0x38,0x38,0x10,0x00,0x00,0x00,0x00,0x00,
    // 0x20 (space) through 0x7E (~)
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x18,0x3c,0x3c,0x3c,0x18,0x18,0x18,0x00,0x18,0x18,0x00,0x00,0x00,0x00,
    0x00,0x66,0x66,0x66,0x24,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x6c,0x6c,0xfe,0x6c,0x6c,0x6c,0xfe,0x6c,0x6c,0x00,0x00,0x00,0x00,
    0x18,0x18,0x7c,0xc6,0xc2,0xc0,0x7c,0x06,0x06,0x86,0xc6,0x7c,0x18,0x18,0x00,0x00,
    0x00,0x00,0x00,0x00,0xc2,0xc6,0x0c,0x18,0x30,0x60,0xc6,0x86,0x00,0x00,0x00,0x00,
    0x00,0x00,0x38,0x6c,0x6c,0x38,0x76,0xdc,0xcc,0xcc,0xcc,0x76,0x00,0x00,0x00,0x00,
    0x00,0x30,0x30,0x30,0x60,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x0c,0x18,0x30,0x30,0x30,0x30,0x30,0x30,0x18,0x0c,0x00,0x00,0x00,0x00,
    0x00,0x00,0x30,0x18,0x0c,0x0c,0x0c,0x0c,0x0c,0x0c,0x18,0x30,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x66,0x3c,0xff,0x3c,0x66,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x18,0x18,0x7e,0x18,0x18,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x18,0x18,0x18,0x30,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xfe,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x18,0x18,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x02,0x06,0x0c,0x18,0x30,0x60,0xc0,0x80,0x00,0x00,0x00,0x00,
    0x00,0x00,0x38,0x6c,0xc6,0xc6,0xd6,0xd6,0xc6,0xc6,0x6c,0x38,0x00,0x00,0x00,0x00,
    0x00,0x00,0x18,0x38,0x78,0x18,0x18,0x18,0x18,0x18,0x18,0x7e,0x00,0x00,0x00,0x00,
    0x00,0x00,0x7c,0xc6,0x06,0x0c,0x18,0x30,0x60,0xc0,0xc6,0xfe,0x00,0x00,0x00,0x00,
    0x00,0x00,0x7c,0xc6,0x06,0x06,0x3c,0x06,0x06,0x06,0xc6,0x7c,0x00,0x00,0x00,0x00,
    0x00,0x00,0x0c,0x1c,0x3c,0x6c,0xcc,0xfe,0x0c,0x0c,0x0c,0x1e,0x00,0x00,0x00,0x00,
    0x00,0x00,0xfe,0xc0,0xc0,0xc0,0xfc,0x06,0x06,0x06,0xc6,0x7c,0x00,0x00,0x00,0x00,
    0x00,0x00,0x38,0x60,0xc0,0xc0,0xfc,0xc6,0xc6,0xc6,0xc6,0x7c,0x00,0x00,0x00,0x00,
    0x00,0x00,0xfe,0xc6,0x06,0x06,0x0c,0x18,0x30,0x30,0x30,0x30,0x00,0x00,0x00,0x00,
    0x00,0x00,0x7c,0xc6,0xc6,0xc6,0x7c,0xc6,0xc6,0xc6,0xc6,0x7c,0x00,0x00,0x00,0x00,
    0x00,0x00,0x7c,0xc6,0xc6,0xc6,0x7e,0x06,0x06,0x06,0x0c,0x78,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x18,0x18,0x00,0x00,0x00,0x18,0x18,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x18,0x18,0x00,0x00,0x00,0x18,0x18,0x30,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x06,0x0c,0x18,0x30,0x60,0x30,0x18,0x0c,0x06,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x7e,0x00,0x00,0x7e,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x60,0x30,0x18,0x0c,0x06,0x0c,0x18,0x30,0x60,0x00,0x00,0x00,0x00,
    0x00,0x00,0x7c,0xc6,0xc6,0x0c,0x18,0x18,0x18,0x00,0x18,0x18,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x7c,0xc6,0xc6,0xde,0xde,0xde,0xdc,0xc0,0x7c,0x00,0x00,0x00,0x00,
    0x00,0x00,0x10,0x38,0x6c,0xc6,0xc6,0xfe,0xc6,0xc6,0xc6,0xc6,0x00,0x00,0x00,0x00,
    0x00,0x00,0xfc,0x66,0x66,0x66,0x7c,0x66,0x66,0x66,0x66,0xfc,0x00,0x00,0x00,0x00,
    0x00,0x00,0x3c,0x66,0xc2,0xc0,0xc0,0xc0,0xc0,0xc2,0x66,0x3c,0x00,0x00,0x00,0x00,
    0x00,0x00,0xf8,0x6c,0x66,0x66,0x66,0x66,0x66,0x66,0x6c,0xf8,0x00,0x00,0x00,0x00,
    0x00,0x00,0xfe,0x66,0x62,0x68,0x78,0x68,0x60,0x62,0x66,0xfe,0x00,0x00,0x00,0x00,
    0x00,0x00,0xfe,0x66,0x62,0x68,0x78,0x68,0x60,0x60,0x60,0xf0,0x00,0x00,0x00,0x00,
    0x00,0x00,0x3c,0x66,0xc2,0xc0,0xc0,0xde,0xc6,0xc6,0x66,0x3a,0x00,0x00,0x00,0x00,
    0x00,0x00,0xc6,0xc6,0xc6,0xc6,0xfe,0xc6,0xc6,0xc6,0xc6,0xc6,0x00,0x00,0x00,0x00,
    0x00,0x00,0x3c,0x18,0x18,0x18,0x18,0x18,0x18,0x18,0x18,0x3c,0x00,0x00,0x00,0x00,
    0x00,0x00,0x1e,0x0c,0x0c,0x0c,0x0c,0x0c,0xcc,0xcc,0xcc,0x78,0x00,0x00,0x00,0x00,
    0x00,0x00,0xe6,0x66,0x66,0x6c,0x78,0x78,0x6c,0x66,0x66,0xe6,0x00,0x00,0x00,0x00,
    0x00,0x00,0xf0,0x60,0x60,0x60,0x60,0x60,0x60,0x62,0x66,0xfe,0x00,0x00,0x00,0x00,
    0x00,0x00,0xc6,0xee,0xfe,0xfe,0xd6,0xc6,0xc6,0xc6,0xc6,0xc6,0x00,0x00,0x00,0x00,
    0x00,0x00,0xc6,0xe6,0xf6,0xfe,0xde,0xce,0xc6,0xc6,0xc6,0xc6,0x00,0x00,0x00,0x00,
    0x00,0x00,0x7c,0xc6,0xc6,0xc6,0xc6,0xc6,0xc6,0xc6,0xc6,0x7c,0x00,0x00,0x00,0x00,
    0x00,0x00,0xfc,0x66,0x66,0x66,0x7c,0x60,0x60,0x60,0x60,0xf0,0x00,0x00,0x00,0x00,
    0x00,0x00,0x7c,0xc6,0xc6,0xc6,0xc6,0xc6,0xc6,0xd6,0xde,0x7c,0x0c,0x0e,0x00,0x00,
    0x00,0x00,0xfc,0x66,0x66,0x66,0x7c,0x6c,0x66,0x66,0x66,0xe6,0x00,0x00,0x00,0x00,
    0x00,0x00,0x7c,0xc6,0xc6,0x60,0x38,0x0c,0x06,0xc6,0xc6,0x7c,0x00,0x00,0x00,0x00,
    0x00,0x00,0x7e,0x7e,0x5a,0x18,0x18,0x18,0x18,0x18,0x18,0x3c,0x00,0x00,0x00,0x00,
    0x00,0x00,0xc6,0xc6,0xc6,0xc6,0xc6,0xc6,0xc6,0xc6,0xc6,0x7c,0x00,0x00,0x00,0x00,
    0x00,0x00,0xc6,0xc6,0xc6,0xc6,0xc6,0xc6,0xc6,0x6c,0x38,0x10,0x00,0x00,0x00,0x00,
    0x00,0x00,0xc6,0xc6,0xc6,0xc6,0xd6,0xd6,0xd6,0xfe,0xee,0x6c,0x00,0x00,0x00,0x00,
    0x00,0x00,0xc6,0xc6,0x6c,0x7c,0x38,0x38,0x7c,0x6c,0xc6,0xc6,0x00,0x00,0x00,0x00,
    0x00,0x00,0x66,0x66,0x66,0x66,0x3c,0x18,0x18,0x18,0x18,0x3c,0x00,0x00,0x00,0x00,
    0x00,0x00,0xfe,0xc6,0x86,0x0c,0x18,0x30,0x60,0xc2,0xc6,0xfe,0x00,0x00,0x00,0x00,
    0x00,0x00,0x3c,0x30,0x30,0x30,0x30,0x30,0x30,0x30,0x30,0x3c,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x80,0xc0,0xe0,0x70,0x38,0x1c,0x0e,0x06,0x02,0x00,0x00,0x00,0x00,
    0x00,0x00,0x3c,0x0c,0x0c,0x0c,0x0c,0x0c,0x0c,0x0c,0x0c,0x3c,0x00,0x00,0x00,0x00,
    0x10,0x38,0x6c,0xc6,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xff,0x00,0x00,
    0x00,0x30,0x18,0x0c,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x78,0x0c,0x7c,0xcc,0xcc,0xcc,0x76,0x00,0x00,0x00,0x00,
    0x00,0x00,0xe0,0x60,0x60,0x78,0x6c,0x66,0x66,0x66,0x66,0x7c,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x7c,0xc6,0xc0,0xc0,0xc0,0xc6,0x7c,0x00,0x00,0x00,0x00,
    0x00,0x00,0x1c,0x0c,0x0c,0x3c,0x6c,0xcc,0xcc,0xcc,0xcc,0x76,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x7c,0xc6,0xfe,0xc0,0xc0,0xc6,0x7c,0x00,0x00,0x00,0x00,
    0x00,0x00,0x1c,0x36,0x32,0x30,0x78,0x30,0x30,0x30,0x30,0x78,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x76,0xcc,0xcc,0xcc,0xcc,0xcc,0x7c,0x0c,0xcc,0x78,0x00,
    0x00,0x00,0xe0,0x60,0x60,0x6c,0x76,0x66,0x66,0x66,0x66,0xe6,0x00,0x00,0x00,0x00,
    0x00,0x00,0x18,0x18,0x00,0x38,0x18,0x18,0x18,0x18,0x18,0x3c,0x00,0x00,0x00,0x00,
    0x00,0x00,0x06,0x06,0x00,0x0e,0x06,0x06,0x06,0x06,0x06,0x06,0x66,0x66,0x3c,0x00,
    0x00,0x00,0xe0,0x60,0x60,0x66,0x6c,0x78,0x78,0x6c,0x66,0xe6,0x00,0x00,0x00,0x00,
    0x00,0x00,0x38,0x18,0x18,0x18,0x18,0x18,0x18,0x18,0x18,0x3c,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0xec,0xfe,0xd6,0xd6,0xd6,0xd6,0xc6,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0xdc,0x66,0x66,0x66,0x66,0x66,0x66,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x7c,0xc6,0xc6,0xc6,0xc6,0xc6,0x7c,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0xdc,0x66,0x66,0x66,0x66,0x66,0x7c,0x60,0x60,0xf0,0x00,
    0x00,0x00,0x00,0x00,0x00,0x76,0xcc,0xcc,0xcc,0xcc,0xcc,0x7c,0x0c,0x0c,0x1e,0x00,
    0x00,0x00,0x00,0x00,0x00,0xdc,0x76,0x66,0x60,0x60,0x60,0xf0,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x7c,0xc6,0x60,0x38,0x0c,0xc6,0x7c,0x00,0x00,0x00,0x00,
    0x00,0x00,0x10,0x30,0x30,0xfc,0x30,0x30,0x30,0x30,0x36,0x1c,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0x76,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0xc6,0xc6,0xc6,0xc6,0xc6,0x6c,0x38,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0xc6,0xc6,0xd6,0xd6,0xd6,0xfe,0x6c,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0xc6,0x6c,0x38,0x38,0x38,0x6c,0xc6,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0xc6,0xc6,0xc6,0xc6,0xc6,0xc6,0x7e,0x06,0x0c,0xf8,0x00,
    0x00,0x00,0x00,0x00,0x00,0xfe,0xcc,0x18,0x30,0x60,0xc6,0xfe,0x00,0x00,0x00,0x00,
    0x00,0x00,0x0e,0x18,0x18,0x18,0x70,0x18,0x18,0x18,0x18,0x0e,0x00,0x00,0x00,0x00,
    0x00,0x00,0x18,0x18,0x18,0x18,0x18,0x18,0x18,0x18,0x18,0x18,0x00,0x00,0x00,0x00,
    0x00,0x00,0x70,0x18,0x18,0x18,0x0e,0x18,0x18,0x18,0x18,0x70,0x00,0x00,0x00,0x00,
    0x00,0x76,0xdc,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    // 0x7F
    0x00,0x00,0x00,0x00,0x10,0x38,0x6c,0xc6,0xc6,0xc6,0xfe,0x00,0x00,0x00,0x00,0x00,
    // 0x80-0xFF: extended characters (zeroed for simplicity)
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
];

/// Console state (global statics).
static mut FB_PTR: u64 = 0;
static mut FB_PITCH: u32 = 0;
static mut FB_WIDTH: u32 = 0;
static mut FB_HEIGHT: u32 = 0;
static mut CON_COLS: u32 = 0;
static mut CON_ROWS: u32 = 0;
static mut CON_CUR_COL: u32 = 0;
static mut CON_CUR_ROW: u32 = 0;

/// Keyboard state.
static mut KB_SHIFT: bool = false;
static mut KB_CTRL: bool = false;

/// Keyboard ring buffer address (shared between keyboard_driver thread + LUCAS handler).
const KB_RING_ADDR: u64 = 0x510000;

/// Initialize framebuffer console from BootInfo.
unsafe fn fb_init(boot_info: &BootInfo) {
    FB_PTR = boot_info.fb_addr;
    FB_PITCH = boot_info.fb_pitch;
    FB_WIDTH = boot_info.fb_width;
    FB_HEIGHT = boot_info.fb_height;
    CON_COLS = boot_info.fb_width / 8;
    CON_ROWS = boot_info.fb_height / 16;
    CON_CUR_COL = 0;
    CON_CUR_ROW = 0;
    fb_clear();
}

/// Fill the entire framebuffer with black.
unsafe fn fb_clear() {
    let total = FB_PITCH as u64 * FB_HEIGHT as u64;
    let ptr = FB_PTR as *mut u8;
    core::ptr::write_bytes(ptr, 0, total as usize);
}

/// Draw an 8x16 character glyph at (col, row) position.
unsafe fn fb_draw_char(col: u32, row: u32, ch: u8) {
    let glyph = &VGA_FONT[(ch as usize) * 16..(ch as usize) * 16 + 16];
    let x = col * 8;
    let y = row * 16;
    for gy in 0..16u32 {
        let row_byte = glyph[gy as usize];
        let line_base = FB_PTR + ((y + gy) as u64) * (FB_PITCH as u64) + (x as u64) * 4;
        for gx in 0..8u32 {
            let pixel = if row_byte & (0x80 >> gx) != 0 { 0x00FFFFFFu32 } else { 0x00000000u32 };
            let addr = line_base + (gx as u64) * 4;
            *(addr as *mut u32) = pixel;
        }
    }
}

/// Scroll the console up by one text row (16 pixels).
unsafe fn fb_scroll() {
    let row_bytes = FB_PITCH as usize * 16;
    let total_rows = (CON_ROWS - 1) as usize;
    let src = (FB_PTR as usize + row_bytes) as *const u8;
    let dst = FB_PTR as *mut u8;
    core::ptr::copy(src, dst, total_rows * row_bytes);
    // Clear the bottom row.
    let bottom = (FB_PTR as usize + total_rows * row_bytes) as *mut u8;
    core::ptr::write_bytes(bottom, 0, row_bytes);
}

/// Write a single character to the framebuffer console.
unsafe fn fb_putchar(ch: u8) {
    if FB_PTR == 0 { return; }
    match ch {
        b'\n' => {
            CON_CUR_COL = 0;
            CON_CUR_ROW += 1;
            if CON_CUR_ROW >= CON_ROWS {
                CON_CUR_ROW = CON_ROWS - 1;
                fb_scroll();
            }
        }
        b'\r' => {
            CON_CUR_COL = 0;
        }
        0x08 => {
            // Backspace
            if CON_CUR_COL > 0 {
                CON_CUR_COL -= 1;
                fb_draw_char(CON_CUR_COL, CON_CUR_ROW, b' ');
            }
        }
        _ => {
            if ch >= 0x20 {
                fb_draw_char(CON_CUR_COL, CON_CUR_ROW, ch);
                CON_CUR_COL += 1;
                if CON_CUR_COL >= CON_COLS {
                    CON_CUR_COL = 0;
                    CON_CUR_ROW += 1;
                    if CON_CUR_ROW >= CON_ROWS {
                        CON_CUR_ROW = CON_ROWS - 1;
                        fb_scroll();
                    }
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// PS/2 Scancode translation (Set 1)
// ---------------------------------------------------------------------------

/// Unshifted scancode → ASCII (Set 1, make codes only, 0 = no mapping).
static SCANCODE_TO_ASCII: [u8; 128] = [
    0,  27, b'1',b'2',b'3',b'4',b'5',b'6',b'7',b'8',b'9',b'0',b'-',b'=',0x08,b'\t',
    b'q',b'w',b'e',b'r',b't',b'y',b'u',b'i',b'o',b'p',b'[',b']',b'\n', 0, b'a',b's',
    b'd',b'f',b'g',b'h',b'j',b'k',b'l',b';',b'\'',b'`', 0, b'\\',b'z',b'x',b'c',b'v',
    b'b',b'n',b'm',b',',b'.',b'/', 0, b'*', 0, b' ', 0, 0,0,0,0,0,
    0,0,0,0,0, 0, 0, 0,0,0,b'-', 0,0,0,b'+', 0,
    0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0,
    0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0,
    0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0,
];

/// Shifted scancode → ASCII.
static SCANCODE_TO_ASCII_SHIFT: [u8; 128] = [
    0,  27, b'!',b'@',b'#',b'$',b'%',b'^',b'&',b'*',b'(',b')',b'_',b'+',0x08,b'\t',
    b'Q',b'W',b'E',b'R',b'T',b'Y',b'U',b'I',b'O',b'P',b'{',b'}',b'\n', 0, b'A',b'S',
    b'D',b'F',b'G',b'H',b'J',b'K',b'L',b':',b'"',b'~', 0, b'|',b'Z',b'X',b'C',b'V',
    b'B',b'N',b'M',b'<',b'>',b'?', 0, b'*', 0, b' ', 0, 0,0,0,0,0,
    0,0,0,0,0, 0, 0, 0,0,0,b'-', 0,0,0,b'+', 0,
    0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0,
    0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0,
    0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0,
];

/// Read one ASCII character from the keyboard ring buffer (non-blocking).
/// Handles Shift/Ctrl modifier tracking, returns None if no key available.
unsafe fn kb_read_char() -> Option<u8> {
    let ring = KB_RING_ADDR as *mut u32;
    loop {
        let write_idx = core::ptr::read_volatile(ring);
        let read_idx = core::ptr::read_volatile(ring.add(1));
        if read_idx == write_idx {
            return None; // Ring empty
        }
        let scancode = *((KB_RING_ADDR + 8 + (read_idx & 0xFF) as u64) as *const u8);
        let new_read = (read_idx + 1) & 0xFF;
        core::ptr::write_volatile(ring.add(1), new_read);

        // Track modifier keys
        match scancode {
            0x2A | 0x36 => { KB_SHIFT = true; continue; }   // Shift press
            0xAA | 0xB6 => { KB_SHIFT = false; continue; }  // Shift release
            0x1D => { KB_CTRL = true; continue; }            // Ctrl press
            0x9D => { KB_CTRL = false; continue; }           // Ctrl release
            _ => {}
        }

        // Ignore break codes (key release, bit 7 set)
        if scancode & 0x80 != 0 {
            continue;
        }

        let ascii = if KB_SHIFT {
            SCANCODE_TO_ASCII_SHIFT[scancode as usize]
        } else {
            SCANCODE_TO_ASCII[scancode as usize]
        };

        if ascii == 0 { continue; }

        // Ctrl+key: map to control character
        if KB_CTRL {
            if ascii >= b'a' && ascii <= b'z' {
                return Some(ascii - b'a' + 1);
            }
            if ascii >= b'A' && ascii <= b'Z' {
                return Some(ascii - b'A' + 1);
            }
        }

        return Some(ascii);
    }
}

fn init_virtio_blk(boot_info: &BootInfo) -> Option<VirtioBlk> {
    if boot_info.cap_count <= CAP_PCI as u64 {
        print(b"BLK: no PCI cap, skipping\n");
        return None;
    }
    let pci_cap = boot_info.caps[CAP_PCI];
    let pci = PciBus::new(pci_cap);

    let (devices, count) = pci.enumerate::<32>();
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

    let blk_dev = match pci.find_device(0x1AF4, 0x1001) {
        Some(d) => d,
        None => {
            print(b"BLK: virtio-blk not found\n");
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

fn run_virtio_blk_demo(boot_info: &BootInfo) -> Option<VirtioBlk> {
    let mut blk = match init_virtio_blk(boot_info) {
        Some(b) => b,
        None => return None,
    };

    // Read sector 0 and print first 16 bytes.
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

    // Write "WROTE\0" to sector 1.
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

    // Read back sector 1 to verify.
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

    // --- Object Store + VFS demo ---
    run_objstore_demo(blk)
}

fn run_objstore_demo(blk: VirtioBlk) -> Option<VirtioBlk> {
    // 1. Format a new filesystem.
    let store = match ObjectStore::format(blk) {
        Ok(s) => s,
        Err(e) => {
            print(b"OBJSTORE: format failed: ");
            print(e.as_bytes());
            print(b"\n");
            return None;
        }
    };

    // 2. Create VFS.
    let mut vfs = Vfs::new(store);

    // 3. Create and write hello.txt.
    let fd = match vfs.create(b"hello.txt") {
        Ok(f) => f,
        Err(e) => {
            print(b"VFS CREATE ERR: ");
            print(e.as_bytes());
            print(b"\n");
            return None;
        }
    };
    if let Err(e) = vfs.write(fd, b"Hello from sotOS!") {
        print(b"VFS WRITE ERR: ");
        print(e.as_bytes());
        print(b"\n");
        return None;
    }
    let _ = vfs.close(fd);

    // 4. Read back hello.txt.
    let fd = match vfs.open(b"hello.txt", 1) {
        Ok(f) => f,
        Err(e) => {
            print(b"VFS OPEN ERR: ");
            print(e.as_bytes());
            print(b"\n");
            return None;
        }
    };
    let mut buf = [0u8; 64];
    match vfs.read(fd, &mut buf) {
        Ok(n) => {
            print(b"VFS READ: ");
            print(&buf[..n]);
            print(b"\n");
        }
        Err(e) => {
            print(b"VFS READ ERR: ");
            print(e.as_bytes());
            print(b"\n");
        }
    }
    let _ = vfs.close(fd);

    // 5. Create data.bin with binary data.
    let fd = match vfs.create(b"data.bin") {
        Ok(f) => f,
        Err(e) => {
            print(b"VFS CREATE ERR: ");
            print(e.as_bytes());
            print(b"\n");
            return None;
        }
    };
    let _ = vfs.write(fd, &[0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE]);
    let _ = vfs.close(fd);

    // 6. List files.
    let mut entries = [DirEntry::zeroed(); DIR_ENTRY_COUNT];
    let count = vfs.store().list(&mut entries);
    print(b"VFS LIST: ");
    print_u64(count as u64);
    print(b" files\n");
    for i in 0..count {
        print(b"  ");
        print(entries[i].name_as_str());
        print(b" oid=");
        print_u64(entries[i].oid);
        print(b" size=");
        print_u64(entries[i].size);
        print(b"\n");
    }

    // 7. Delete data.bin.
    if let Err(e) = vfs.delete(b"data.bin") {
        print(b"VFS DELETE ERR: ");
        print(e.as_bytes());
        print(b"\n");
    }
    let remain = vfs.store().list(&mut entries);
    print(b"VFS: ");
    print_u64(remain as u64);
    print(b" files remain\n");

    // 8. Re-mount from disk and verify persistence.
    let blk = vfs.store_mut().into_blk();
    let store = match ObjectStore::mount(blk) {
        Ok(s) => s,
        Err(e) => {
            print(b"OBJSTORE: mount failed: ");
            print(e.as_bytes());
            print(b"\n");
            return None;
        }
    };
    let mut vfs = Vfs::new(store);
    let fd = match vfs.open(b"hello.txt", 1) {
        Ok(f) => f,
        Err(e) => {
            print(b"VFS REMOUNT OPEN ERR: ");
            print(e.as_bytes());
            print(b"\n");
            return None;
        }
    };
    let mut buf2 = [0u8; 64];
    match vfs.read(fd, &mut buf2) {
        Ok(n) => {
            print(b"VFS REMOUNT READ: ");
            print(&buf2[..n]);
            print(b"\n");
        }
        Err(e) => {
            print(b"VFS REMOUNT READ ERR: ");
            print(e.as_bytes());
            print(b"\n");
        }
    }
    let _ = vfs.close(fd);

    // Return VirtioBlk for LUCAS handler use.
    Some(vfs.store_mut().into_blk())
}

// ---------------------------------------------------------------------------
// LUCAS demo
// ---------------------------------------------------------------------------

/// Address where VirtioBlk is stored for the LUCAS handler (1 page).
const LUCAS_BLK_STORE: u64 = 0xE08000;

/// Flag: VirtioBlk stored and ready at LUCAS_BLK_STORE.
static LUCAS_VFS_READY: AtomicU64 = AtomicU64::new(0);

// ---------------------------------------------------------------------------
// LUCAS process table (Phase 10.5) — shared between handler threads
// ---------------------------------------------------------------------------

const MAX_PROCS: usize = 8;

/// Process state: 0=Free, 1=Running, 2=Zombie.
static PROC_STATE: [AtomicU64; MAX_PROCS] = [
    AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0),
    AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0),
];
/// Exit status (valid when Zombie).
static PROC_EXIT: [AtomicU64; MAX_PROCS] = [
    AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0),
    AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0),
];
/// Parent PID (0=none).
static PROC_PARENT: [AtomicU64; MAX_PROCS] = [
    AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0),
    AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0),
];
/// Pending signal per process: 0=none, 2=SIGINT, 9=SIGKILL, 15=SIGTERM.
static PROC_SIGNAL: [AtomicU64; MAX_PROCS] = [
    AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0),
    AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0),
];
/// Boot TSC value for uptime calculation.
static BOOT_TSC: AtomicU64 = AtomicU64::new(0);

/// Next PID to allocate (monotonically increasing, starts at 1).
static NEXT_PID: AtomicU64 = AtomicU64::new(1);
/// Next vaddr for child stacks (guest + handler interleaved, 0x2000 apart).
static NEXT_CHILD_STACK: AtomicU64 = AtomicU64::new(0xE10000);

// Handshake statics for passing setup info to child handler thread.
static CHILD_SETUP_EP: AtomicU64 = AtomicU64::new(0);
static CHILD_SETUP_PID: AtomicU64 = AtomicU64::new(0);
static CHILD_SETUP_READY: AtomicU64 = AtomicU64::new(0);

/// Send an IPC reply with a single return value.
fn reply_val(ep_cap: u64, val: i64) {
    let reply = sotos_common::IpcMsg {
        tag: 0,
        regs: [val as u64, 0, 0, 0, 0, 0, 0, 0],
    };
    let _ = sys::send(ep_cap, &reply);
}

/// Format a u64 as decimal into buf. Returns number of bytes written.
fn format_u64_into(buf: &mut [u8], mut n: u64) -> usize {
    if n == 0 {
        if !buf.is_empty() {
            buf[0] = b'0';
        }
        return 1;
    }
    let mut tmp = [0u8; 20];
    let mut i = 0;
    while n > 0 {
        tmp[i] = b'0' + (n % 10) as u8;
        n /= 10;
        i += 1;
    }
    let len = i.min(buf.len());
    for j in 0..len {
        buf[j] = tmp[i - 1 - j];
    }
    len
}

/// Copy a NUL-terminated path from guest memory into a local buffer.
/// Returns the length (excluding NUL).
fn copy_guest_path(guest_ptr: u64, out: &mut [u8]) -> usize {
    let max = out.len() - 1; // leave room for NUL
    let mut i = 0;
    while i < max {
        let b = unsafe { *((guest_ptr + i as u64) as *const u8) };
        if b == 0 {
            break;
        }
        out[i] = b;
        i += 1;
    }
    out[i] = 0;
    i
}

/// Check if a byte slice starts with a prefix.
fn starts_with(hay: &[u8], needle: &[u8]) -> bool {
    hay.len() >= needle.len() && &hay[..needle.len()] == needle
}

/// Parse a decimal u64 from byte slice. Returns (value, digits_consumed).
fn parse_u64_from(s: &[u8]) -> (u64, usize) {
    let mut val: u64 = 0;
    let mut i = 0;
    while i < s.len() && s[i] >= b'0' && s[i] <= b'9' {
        val = val * 10 + (s[i] - b'0') as u64;
        i += 1;
    }
    (val, i)
}

/// Format /proc/N/status content into buf. Returns bytes written.
fn format_proc_status(buf: &mut [u8], pid: usize) -> usize {
    let mut pos: usize = 0;
    // Name:\tprocess_N
    let prefix = b"Name:\tprocess_";
    buf[pos..pos + prefix.len()].copy_from_slice(prefix);
    pos += prefix.len();
    pos += format_u64_into(&mut buf[pos..], pid as u64);
    buf[pos] = b'\n';
    pos += 1;
    // State:\tR or Z
    let sp = b"State:\t";
    buf[pos..pos + sp.len()].copy_from_slice(sp);
    pos += sp.len();
    let state = PROC_STATE[pid - 1].load(Ordering::Acquire);
    buf[pos] = match state {
        1 => b'R',
        2 => b'Z',
        _ => b'?',
    };
    pos += 1;
    buf[pos] = b'\n';
    pos += 1;
    // Pid:\tN
    let pp = b"Pid:\t";
    buf[pos..pos + pp.len()].copy_from_slice(pp);
    pos += pp.len();
    pos += format_u64_into(&mut buf[pos..], pid as u64);
    buf[pos] = b'\n';
    pos += 1;
    // PPid:\tP
    let ppp = b"PPid:\t";
    buf[pos..pos + ppp.len()].copy_from_slice(ppp);
    pos += ppp.len();
    let ppid = PROC_PARENT[pid - 1].load(Ordering::Acquire);
    pos += format_u64_into(&mut buf[pos..], ppid);
    buf[pos] = b'\n';
    pos += 1;
    pos
}

// ---------------------------------------------------------------------------
// LUCAS FD table types (Phase 10.4)
// ---------------------------------------------------------------------------

#[repr(u8)]
#[derive(Clone, Copy, PartialEq)]
enum FdKind {
    Free = 0,
    Stdin = 1,
    Stdout = 2,
    VfsFile = 3,
    DirList = 4,
}

#[derive(Clone, Copy)]
struct FdEntry {
    kind: FdKind,
    vfs_fd: u32,
}

impl FdEntry {
    const fn free() -> Self {
        Self { kind: FdKind::Free, vfs_fd: 0 }
    }
}

#[derive(Clone, Copy)]
struct MmapEntry {
    addr: u64,
    len: u64,
    pages: u32,
}

impl MmapEntry {
    const fn empty() -> Self {
        Self { addr: 0, len: 0, pages: 0 }
    }
}

const MAX_FDS: usize = 32;
const MAX_MMAPS: usize = 16;
const BRK_BASE: u64 = 0x2000000;
const MMAP_BASE: u64 = 0x3000000;

/// Find the next free FD slot starting from `from`.
fn alloc_fd(fds: &[FdEntry; MAX_FDS], from: usize) -> Option<usize> {
    for i in from..MAX_FDS {
        if fds[i].kind == FdKind::Free {
            return Some(i);
        }
    }
    None
}

/// Write a minimal Linux stat64 struct (144 bytes) into guest memory.
/// Layout matches x86_64 struct stat (see man 2 stat).
fn write_linux_stat(stat_ptr: u64, oid: u64, size: u64, is_dir: bool) {
    let buf = unsafe { core::slice::from_raw_parts_mut(stat_ptr as *mut u8, 144) };
    // Zero the entire struct first.
    for b in buf.iter_mut() {
        *b = 0;
    }
    // st_ino at offset 8 (u64)
    let ino_bytes = oid.to_le_bytes();
    buf[8..16].copy_from_slice(&ino_bytes);
    // st_mode at offset 24 (u32): S_IFREG=0o100644 or S_IFDIR=0o40755
    let mode: u32 = if is_dir { 0o40755 } else { 0o100644 };
    buf[24..28].copy_from_slice(&mode.to_le_bytes());
    // st_nlink at offset 28 (u64) — but only lower 32 bits matter
    buf[28] = 1;
    // st_size at offset 48 (i64)
    let size_bytes = size.to_le_bytes();
    buf[48..56].copy_from_slice(&size_bytes);
    // st_blksize at offset 56 (i64)
    let blksize: u64 = 512;
    buf[56..64].copy_from_slice(&blksize.to_le_bytes());
    // st_blocks at offset 64 (i64)
    let blocks: u64 = (size + 511) / 512;
    buf[64..72].copy_from_slice(&blocks.to_le_bytes());
}

/// Child process handler — stripped-down handler for child processes.
/// Supports stdin/stdout I/O, getpid, getppid, exec, exit.
/// No VFS access (VirtioBlk is single-threaded).
#[unsafe(no_mangle)]
pub extern "C" fn child_handler() -> ! {
    // Wait for parent to provide setup info
    while CHILD_SETUP_READY.load(Ordering::Acquire) != 1 {
        sys::yield_now();
    }
    let mut ep_cap = CHILD_SETUP_EP.load(Ordering::Acquire);
    let pid = CHILD_SETUP_PID.load(Ordering::Acquire) as usize;
    let parent_pid = PROC_PARENT[pid - 1].load(Ordering::Acquire);
    // Signal that we consumed the setup
    CHILD_SETUP_READY.store(0, Ordering::Release);

    loop {
        let msg = match sys::recv(ep_cap) {
            Ok(m) => m,
            Err(_) => break,
        };

        // Check for pending signal
        let pending = PROC_SIGNAL[pid - 1].swap(0, Ordering::AcqRel);
        if pending == 9 {
            // SIGKILL — terminate immediately
            PROC_EXIT[pid - 1].store(137, Ordering::Release);
            PROC_STATE[pid - 1].store(2, Ordering::Release);
            break;
        }

        let syscall_nr = msg.tag;
        match syscall_nr {
            // SYS_read(fd, buf, len) — stdin only
            0 => {
                let fd = msg.regs[0] as usize;
                let buf_ptr = msg.regs[1];
                let len = msg.regs[2] as usize;
                if fd != 0 {
                    reply_val(ep_cap, -9); // -EBADF
                    continue;
                }
                if len == 0 {
                    reply_val(ep_cap, 0);
                    continue;
                }
                loop {
                    // Check for pending signal while polling stdin
                    let sig = PROC_SIGNAL[pid - 1].swap(0, Ordering::AcqRel);
                    if sig == 9 {
                        PROC_EXIT[pid - 1].store(137, Ordering::Release);
                        PROC_STATE[pid - 1].store(2, Ordering::Release);
                        reply_val(ep_cap, -4);
                        break;
                    }
                    match unsafe { kb_read_char() } {
                        Some(0x03) => {
                            reply_val(ep_cap, -4);
                            break;
                        }
                        Some(ch) => {
                            unsafe { *(buf_ptr as *mut u8) = ch; }
                            reply_val(ep_cap, 1);
                            break;
                        }
                        None => { sys::yield_now(); }
                    }
                }
            }

            // SYS_write(fd, buf, len) — stdout/stderr only
            1 => {
                let fd = msg.regs[0] as usize;
                let buf_ptr = msg.regs[1];
                let len = msg.regs[2] as usize;
                if fd == 1 || fd == 2 {
                    let data = unsafe { core::slice::from_raw_parts(buf_ptr as *const u8, len) };
                    for &b in data {
                        sys::debug_print(b);
                        unsafe { fb_putchar(b); }
                    }
                    reply_val(ep_cap, len as i64);
                } else {
                    reply_val(ep_cap, -9); // -EBADF
                }
            }

            // SYS_close(fd)
            3 => {
                reply_val(ep_cap, 0);
            }

            // SYS_getpid
            39 => {
                reply_val(ep_cap, pid as i64);
            }

            // SYS_execve(path)
            59 => {
                let path_ptr = msg.regs[0];
                let mut path = [0u8; 48];
                let path_len = copy_guest_path(path_ptr, &mut path);
                let name = &path[..path_len];

                // Only known program: "shell"
                let is_shell = (path_len == 5 && name == b"shell")
                    || (path_len == 10 && name == b"/bin/shell")
                    || (path_len == 7 && name == b"/bin/sh");
                if !is_shell {
                    reply_val(ep_cap, -2); // -ENOENT
                    continue;
                }

                let boot_info = unsafe { &*(BOOT_INFO_ADDR as *const BootInfo) };
                let entry = boot_info.guest_entry;
                if entry == 0 {
                    reply_val(ep_cap, -2);
                    continue;
                }

                // Allocate new guest stack
                let stack_addr = NEXT_CHILD_STACK.fetch_add(0x2000, Ordering::SeqCst);
                let guest_frame = match sys::frame_alloc() {
                    Ok(f) => f,
                    Err(_) => { reply_val(ep_cap, -12); continue; }
                };
                if sys::map(stack_addr, guest_frame, MAP_WRITABLE).is_err() {
                    reply_val(ep_cap, -12);
                    continue;
                }

                // Create new endpoint
                let new_ep = match sys::endpoint_create() {
                    Ok(e) => e,
                    Err(_) => { reply_val(ep_cap, -12); continue; }
                };

                // Create new guest thread
                let new_thread = match sys::thread_create(entry, stack_addr + 0x1000) {
                    Ok(t) => t,
                    Err(_) => { reply_val(ep_cap, -12); continue; }
                };

                // Set redirect on new thread
                if sys::redirect_set(new_thread, new_ep).is_err() {
                    reply_val(ep_cap, -12);
                    continue;
                }

                // Switch handler to service the new thread.
                // Do NOT reply to old guest (stays blocked on old EP).
                ep_cap = new_ep;
                continue;
            }

            // SYS_exit(status)
            60 => {
                let status = msg.regs[0];
                if pid > 0 && pid <= MAX_PROCS {
                    PROC_EXIT[pid - 1].store(status, Ordering::Release);
                    PROC_STATE[pid - 1].store(2, Ordering::Release); // Zombie
                }
                break;
            }

            // SYS_kill(pid, sig)
            62 => {
                let target = msg.regs[0] as usize;
                let sig = msg.regs[1];
                if target == 0 || target > MAX_PROCS || PROC_STATE[target - 1].load(Ordering::Acquire) == 0 {
                    reply_val(ep_cap, -3); // -ESRCH
                    continue;
                }
                PROC_SIGNAL[target - 1].store(sig, Ordering::Release);
                if sig == 9 {
                    // SIGKILL: also force zombie
                    PROC_EXIT[target - 1].store(137, Ordering::Release);
                    PROC_STATE[target - 1].store(2, Ordering::Release);
                }
                reply_val(ep_cap, 0);
            }

            // SYS_getppid
            110 => {
                reply_val(ep_cap, parent_pid as i64);
            }

            // Unknown → -ENOSYS
            _ => {
                reply_val(ep_cap, -38);
            }
        }
    }

    sys::thread_exit();
}

/// LUCAS handler — receives forwarded Linux syscalls and translates them.
/// Supports VFS-backed file I/O, FD table, brk, mmap, stat, lseek, dup.
#[unsafe(no_mangle)]
pub extern "C" fn lucas_handler() -> ! {
    let ep_cap = LUCAS_EP_CAP.load(Ordering::Acquire);
    // Capture boot TSC for /proc/uptime
    BOOT_TSC.store(rdtsc(), Ordering::Release);

    // Register as PID 1 in process table
    let pid: u64 = NEXT_PID.fetch_add(1, Ordering::SeqCst);
    PROC_STATE[pid as usize - 1].store(1, Ordering::Release); // Running

    // --- VFS init: read VirtioBlk from storage page, mount ObjectStore ---
    let has_vfs = LUCAS_VFS_READY.load(Ordering::Acquire) != 0;
    let mut vfs_opt: Option<Vfs> = if has_vfs {
        let blk = unsafe { core::ptr::read(LUCAS_BLK_STORE as *const VirtioBlk) };
        match ObjectStore::mount(blk) {
            Ok(store) => {
                print(b"LUCAS: VFS bridge active\n");
                Some(Vfs::new(store))
            }
            Err(e) => {
                print(b"LUCAS: VFS mount failed: ");
                print(e.as_bytes());
                print(b"\n");
                None
            }
        }
    } else {
        None
    };

    // FD table: 0=stdin, 1=stdout, 2=stderr(→stdout)
    let mut fds = [FdEntry::free(); MAX_FDS];
    fds[0] = FdEntry { kind: FdKind::Stdin, vfs_fd: 0 };
    fds[1] = FdEntry { kind: FdKind::Stdout, vfs_fd: 0 };
    fds[2] = FdEntry { kind: FdKind::Stdout, vfs_fd: 0 };

    // Directory listing buffer and state
    let mut dir_buf = [0u8; 1024];
    let mut dir_len: usize = 0;
    let mut dir_pos: usize = 0;

    // brk heap tracking
    let mut current_brk: u64 = BRK_BASE;

    // mmap tracking
    let mut mmaps = [MmapEntry::empty(); MAX_MMAPS];
    let mut mmap_next: u64 = MMAP_BASE;

    loop {
        let msg = match sys::recv(ep_cap) {
            Ok(m) => m,
            Err(_) => break,
        };

        // Check for pending signal
        let pending = PROC_SIGNAL[pid as usize - 1].swap(0, Ordering::AcqRel);
        if pending == 9 {
            PROC_EXIT[pid as usize - 1].store(137, Ordering::Release);
            PROC_STATE[pid as usize - 1].store(2, Ordering::Release);
            break;
        }

        let syscall_nr = msg.tag;
        match syscall_nr {
            // SYS_read(fd, buf, len)
            0 => {
                let fd = msg.regs[0] as usize;
                let buf_ptr = msg.regs[1];
                let len = msg.regs[2] as usize;

                if fd >= MAX_FDS || fds[fd].kind == FdKind::Free {
                    reply_val(ep_cap, -9); // -EBADF
                    continue;
                }

                match fds[fd].kind {
                    FdKind::Stdin => {
                        if len == 0 {
                            reply_val(ep_cap, 0);
                            continue;
                        }
                        loop {
                            // Check for pending signal while polling stdin
                            let sig = PROC_SIGNAL[pid as usize - 1].swap(0, Ordering::AcqRel);
                            if sig == 9 {
                                PROC_EXIT[pid as usize - 1].store(137, Ordering::Release);
                                PROC_STATE[pid as usize - 1].store(2, Ordering::Release);
                                reply_val(ep_cap, -4);
                                break;
                            }
                            match unsafe { kb_read_char() } {
                                Some(0x03) => {
                                    // Ctrl+C
                                    reply_val(ep_cap, -4);
                                    break;
                                }
                                Some(ch) => {
                                    unsafe { *(buf_ptr as *mut u8) = ch; }
                                    reply_val(ep_cap, 1);
                                    break;
                                }
                                None => { sys::yield_now(); }
                            }
                        }
                    }
                    FdKind::DirList => {
                        if dir_pos >= dir_len {
                            reply_val(ep_cap, 0);
                            continue;
                        }
                        let avail = dir_len - dir_pos;
                        let to_copy = len.min(avail);
                        let dst = unsafe { core::slice::from_raw_parts_mut(buf_ptr as *mut u8, to_copy) };
                        dst.copy_from_slice(&dir_buf[dir_pos..dir_pos + to_copy]);
                        dir_pos += to_copy;
                        reply_val(ep_cap, to_copy as i64);
                    }
                    FdKind::VfsFile => {
                        let vfs_fd = fds[fd].vfs_fd;
                        match vfs_opt.as_mut() {
                            Some(vfs) => {
                                let dst = unsafe { core::slice::from_raw_parts_mut(buf_ptr as *mut u8, len) };
                                match vfs.read(vfs_fd, dst) {
                                    Ok(n) => reply_val(ep_cap, n as i64),
                                    Err(_) => reply_val(ep_cap, -9),
                                }
                            }
                            None => reply_val(ep_cap, -9),
                        }
                    }
                    FdKind::Stdout => {
                        reply_val(ep_cap, -9); // can't read stdout
                    }
                    FdKind::Free => unreachable!(),
                }
            }

            // SYS_write(fd, buf, len)
            1 => {
                let fd = msg.regs[0] as usize;
                let buf_ptr = msg.regs[1];
                let len = msg.regs[2] as usize;

                if fd >= MAX_FDS || fds[fd].kind == FdKind::Free {
                    reply_val(ep_cap, -9);
                    continue;
                }

                match fds[fd].kind {
                    FdKind::Stdout => {
                        let data = unsafe { core::slice::from_raw_parts(buf_ptr as *const u8, len) };
                        for &b in data {
                            sys::debug_print(b);
                            unsafe { fb_putchar(b); }
                        }
                        reply_val(ep_cap, len as i64);
                    }
                    FdKind::VfsFile => {
                        let vfs_fd = fds[fd].vfs_fd;
                        match vfs_opt.as_mut() {
                            Some(vfs) => {
                                let data = unsafe { core::slice::from_raw_parts(buf_ptr as *const u8, len) };
                                match vfs.write(vfs_fd, data) {
                                    Ok(n) => reply_val(ep_cap, n as i64),
                                    Err(_) => reply_val(ep_cap, -9),
                                }
                            }
                            None => reply_val(ep_cap, -9),
                        }
                    }
                    _ => {
                        reply_val(ep_cap, -9); // can't write to stdin/dirlist
                    }
                }
            }

            // SYS_open(path, flags, mode)
            2 => {
                let path_ptr = msg.regs[0];
                let flags = msg.regs[1] as u32;

                let mut path = [0u8; 48];
                let path_len = copy_guest_path(path_ptr, &mut path);
                let name = &path[..path_len];

                let new_fd = match alloc_fd(&fds, 3) {
                    Some(f) => f,
                    None => {
                        reply_val(ep_cap, -24); // -EMFILE
                        continue;
                    }
                };

                // "." → directory listing
                if path_len == 1 && path[0] == b'.' {
                    dir_len = 0;
                    dir_pos = 0;
                    if let Some(vfs) = vfs_opt.as_ref() {
                        let mut entries = [DirEntry::zeroed(); DIR_ENTRY_COUNT];
                        let count = vfs.store().list(&mut entries);
                        for i in 0..count {
                            let ename = entries[i].name_as_str();
                            let elen = ename.len();
                            if dir_len + elen + 20 > dir_buf.len() {
                                break;
                            }
                            dir_buf[dir_len..dir_len + elen].copy_from_slice(ename);
                            dir_len += elen;
                            dir_buf[dir_len] = b' ';
                            dir_buf[dir_len + 1] = b' ';
                            dir_len += 2;
                            let n = format_u64_into(&mut dir_buf[dir_len..], entries[i].size);
                            dir_len += n;
                            dir_buf[dir_len] = b'\n';
                            dir_len += 1;
                        }
                    }
                    fds[new_fd] = FdEntry { kind: FdKind::DirList, vfs_fd: 0 };
                    reply_val(ep_cap, new_fd as i64);
                    continue;
                }

                // /proc virtual filesystem
                if starts_with(name, b"/proc") {
                    dir_len = 0;
                    dir_pos = 0;

                    if path_len == 5 || (path_len == 6 && path[5] == b'/') {
                        // "/proc" or "/proc/" → PID listing
                        let hdr = b"PID  STATE  PPID\n";
                        dir_buf[..hdr.len()].copy_from_slice(hdr);
                        dir_len = hdr.len();
                        for i in 0..MAX_PROCS {
                            let st = PROC_STATE[i].load(Ordering::Acquire);
                            if st == 0 { continue; }
                            let n = format_u64_into(&mut dir_buf[dir_len..], (i + 1) as u64);
                            dir_len += n;
                            dir_buf[dir_len..dir_len + 2].copy_from_slice(b"  ");
                            dir_len += 2;
                            dir_buf[dir_len] = if st == 1 { b'R' } else { b'Z' };
                            dir_len += 1;
                            dir_buf[dir_len..dir_len + 6].copy_from_slice(b"      ");
                            dir_len += 6;
                            let ppid = PROC_PARENT[i].load(Ordering::Acquire);
                            let n = format_u64_into(&mut dir_buf[dir_len..], ppid);
                            dir_len += n;
                            dir_buf[dir_len] = b'\n';
                            dir_len += 1;
                        }
                    } else if path_len == 12 && &path[..12] == b"/proc/uptime" {
                        // "/proc/uptime" → ticks since boot
                        let boot = BOOT_TSC.load(Ordering::Acquire);
                        let now = rdtsc();
                        let delta = now.saturating_sub(boot);
                        let n = format_u64_into(&mut dir_buf[dir_len..], delta);
                        dir_len += n;
                        let tail = b" 0\n";
                        dir_buf[dir_len..dir_len + tail.len()].copy_from_slice(tail);
                        dir_len += tail.len();
                    } else if path_len == 17 && &path[..17] == b"/proc/self/status" {
                        // "/proc/self/status"
                        dir_len = format_proc_status(&mut dir_buf, pid as usize);
                    } else if starts_with(name, b"/proc/") && path_len > 6 {
                        // "/proc/N/status" or "/proc/N"
                        let rest = &path[6..path_len];
                        let (n, consumed) = parse_u64_from(rest);
                        if consumed > 0 && n >= 1 && n <= MAX_PROCS as u64 &&
                           PROC_STATE[n as usize - 1].load(Ordering::Acquire) != 0 {
                            // Check for "/status" suffix
                            let after = &rest[consumed..];
                            if after == b"/status" || after.is_empty() {
                                dir_len = format_proc_status(&mut dir_buf, n as usize);
                            } else {
                                reply_val(ep_cap, -2); // -ENOENT
                                continue;
                            }
                        } else {
                            reply_val(ep_cap, -2);
                            continue;
                        }
                    } else {
                        reply_val(ep_cap, -2);
                        continue;
                    }

                    fds[new_fd] = FdEntry { kind: FdKind::DirList, vfs_fd: 0 };
                    reply_val(ep_cap, new_fd as i64);
                    continue;
                }

                match vfs_opt.as_mut() {
                    Some(vfs) => {
                        let linux_access = flags & 0x3;
                        let has_creat = flags & 0x40 != 0;
                        let vfs_flags = match linux_access {
                            0 => 1u32,
                            1 => 2u32,
                            2 => 3u32,
                            _ => 1u32,
                        };

                        let result = if has_creat {
                            match vfs.open(name, vfs_flags) {
                                Ok(fd) => Ok(fd),
                                Err(_) => vfs.create(name),
                            }
                        } else {
                            vfs.open(name, vfs_flags)
                        };

                        match result {
                            Ok(vfs_fd) => {
                                fds[new_fd] = FdEntry { kind: FdKind::VfsFile, vfs_fd };
                                reply_val(ep_cap, new_fd as i64);
                            }
                            Err(_) => reply_val(ep_cap, -2),
                        }
                    }
                    None => reply_val(ep_cap, -2),
                }
            }

            // SYS_close(fd)
            3 => {
                let fd = msg.regs[0] as usize;
                if fd >= MAX_FDS || fds[fd].kind == FdKind::Free {
                    reply_val(ep_cap, -9);
                    continue;
                }

                match fds[fd].kind {
                    FdKind::VfsFile => {
                        if let Some(vfs) = vfs_opt.as_mut() {
                            let _ = vfs.close(fds[fd].vfs_fd);
                        }
                    }
                    FdKind::DirList => {
                        dir_len = 0;
                        dir_pos = 0;
                    }
                    _ => {}
                }
                fds[fd] = FdEntry::free();
                reply_val(ep_cap, 0);
            }

            // SYS_stat(path, statbuf)
            4 => {
                let path_ptr = msg.regs[0];
                let stat_ptr = msg.regs[1];

                let mut path = [0u8; 48];
                let path_len = copy_guest_path(path_ptr, &mut path);
                let name = &path[..path_len];

                // "." → directory
                if path_len == 1 && path[0] == b'.' {
                    write_linux_stat(stat_ptr, 1, 0, true);
                    reply_val(ep_cap, 0);
                    continue;
                }

                match vfs_opt.as_ref() {
                    Some(vfs) => {
                        match vfs.store().find(name) {
                            Some(oid) => {
                                let size = match vfs.store().stat(oid) {
                                    Some(entry) => entry.size,
                                    None => 0,
                                };
                                write_linux_stat(stat_ptr, oid, size, false);
                                reply_val(ep_cap, 0);
                            }
                            None => reply_val(ep_cap, -2),
                        }
                    }
                    None => reply_val(ep_cap, -2),
                }
            }

            // SYS_fstat(fd, statbuf)
            5 => {
                let fd = msg.regs[0] as usize;
                let stat_ptr = msg.regs[1];

                if fd >= MAX_FDS || fds[fd].kind == FdKind::Free {
                    reply_val(ep_cap, -9);
                    continue;
                }

                match fds[fd].kind {
                    FdKind::Stdin | FdKind::Stdout => {
                        // Char device (terminal)
                        let buf = unsafe { core::slice::from_raw_parts_mut(stat_ptr as *mut u8, 144) };
                        for b in buf.iter_mut() { *b = 0; }
                        let mode: u32 = 0o20600; // S_IFCHR | rw
                        buf[24..28].copy_from_slice(&mode.to_le_bytes());
                        reply_val(ep_cap, 0);
                    }
                    FdKind::DirList => {
                        write_linux_stat(stat_ptr, 1, 0, true);
                        reply_val(ep_cap, 0);
                    }
                    FdKind::VfsFile => {
                        let vfs_fd = fds[fd].vfs_fd;
                        match vfs_opt.as_ref() {
                            Some(vfs) => {
                                let oid = vfs.file_oid(vfs_fd).unwrap_or(0);
                                let size = vfs.file_size(vfs_fd).unwrap_or(0);
                                write_linux_stat(stat_ptr, oid, size, false);
                                reply_val(ep_cap, 0);
                            }
                            None => reply_val(ep_cap, -9),
                        }
                    }
                    FdKind::Free => reply_val(ep_cap, -9),
                }
            }

            // SYS_lseek(fd, offset, whence)
            8 => {
                let fd = msg.regs[0] as usize;
                let offset = msg.regs[1] as i64;
                let whence = msg.regs[2] as u32;

                if fd >= MAX_FDS || fds[fd].kind != FdKind::VfsFile {
                    reply_val(ep_cap, -9);
                    continue;
                }

                let vfs_fd = fds[fd].vfs_fd;
                match vfs_opt.as_mut() {
                    Some(vfs) => {
                        let new_pos = match whence {
                            0 => {
                                // SEEK_SET
                                offset as u64
                            }
                            1 => {
                                // SEEK_CUR
                                let cur = vfs.tell(vfs_fd).unwrap_or(0);
                                (cur as i64 + offset) as u64
                            }
                            2 => {
                                // SEEK_END
                                let size = vfs.file_size(vfs_fd).unwrap_or(0);
                                (size as i64 + offset) as u64
                            }
                            _ => {
                                reply_val(ep_cap, -22); // -EINVAL
                                continue;
                            }
                        };
                        let _ = vfs.seek(vfs_fd, new_pos);
                        reply_val(ep_cap, new_pos as i64);
                    }
                    None => reply_val(ep_cap, -9),
                }
            }

            // SYS_mmap(addr, len, prot, flags, fd, offset)
            9 => {
                let _addr = msg.regs[0];
                let len = msg.regs[1];
                let _prot = msg.regs[2];
                let flags = msg.regs[3]; // r10 in kernel
                // MAP_ANONYMOUS = 0x20
                if flags & 0x20 == 0 {
                    reply_val(ep_cap, -22); // only anonymous supported
                    continue;
                }

                let pages = ((len + 0xFFF) / 0x1000) as u32;
                // Find a free mmap slot
                let slot = {
                    let mut found = None;
                    for i in 0..MAX_MMAPS {
                        if mmaps[i].addr == 0 {
                            found = Some(i);
                            break;
                        }
                    }
                    match found {
                        Some(s) => s,
                        None => {
                            reply_val(ep_cap, -12); // -ENOMEM
                            continue;
                        }
                    }
                };

                let base = mmap_next;
                let mut ok = true;
                for p in 0..pages {
                    match sys::frame_alloc() {
                        Ok(frame) => {
                            if sys::map(base + (p as u64) * 0x1000, frame, MAP_WRITABLE).is_err() {
                                ok = false;
                                break;
                            }
                        }
                        Err(_) => { ok = false; break; }
                    }
                }
                if !ok {
                    reply_val(ep_cap, -12);
                    continue;
                }

                // Zero the mapped region
                let region = unsafe { core::slice::from_raw_parts_mut(base as *mut u8, (pages as usize) * 0x1000) };
                for b in region.iter_mut() { *b = 0; }

                mmaps[slot] = MmapEntry { addr: base, len, pages };
                mmap_next += (pages as u64) * 0x1000;
                reply_val(ep_cap, base as i64);
            }

            // SYS_munmap(addr, len)
            11 => {
                let addr = msg.regs[0];
                let mut found = false;
                for i in 0..MAX_MMAPS {
                    if mmaps[i].addr == addr {
                        for p in 0..mmaps[i].pages {
                            let _ = sys::unmap(addr + (p as u64) * 0x1000);
                        }
                        mmaps[i] = MmapEntry::empty();
                        found = true;
                        break;
                    }
                }
                reply_val(ep_cap, if found { 0 } else { -22 });
            }

            // SYS_brk(addr)
            12 => {
                let addr = msg.regs[0];
                if addr == 0 {
                    // Query current brk
                    reply_val(ep_cap, current_brk as i64);
                } else if addr > current_brk && addr <= BRK_BASE + 0x40000 {
                    // Grow: allocate and map pages from current_brk to addr
                    let start_page = (current_brk + 0xFFF) & !0xFFF;
                    let end_page = (addr + 0xFFF) & !0xFFF;
                    let mut page = start_page;
                    let mut ok = true;
                    while page < end_page {
                        // Only map if this page hasn't been mapped yet
                        if page >= (current_brk & !0xFFF) + 0x1000 || current_brk == BRK_BASE {
                            match sys::frame_alloc() {
                                Ok(frame) => {
                                    if sys::map(page, frame, MAP_WRITABLE).is_err() {
                                        ok = false;
                                        break;
                                    }
                                }
                                Err(_) => { ok = false; break; }
                            }
                        }
                        page += 0x1000;
                    }
                    if ok {
                        current_brk = addr;
                    }
                    reply_val(ep_cap, current_brk as i64);
                } else if addr <= current_brk {
                    // Shrink or no-op
                    current_brk = addr.max(BRK_BASE);
                    reply_val(ep_cap, current_brk as i64);
                } else {
                    // Beyond limit
                    reply_val(ep_cap, current_brk as i64);
                }
            }

            // SYS_dup(oldfd)
            32 => {
                let oldfd = msg.regs[0] as usize;
                if oldfd >= MAX_FDS || fds[oldfd].kind == FdKind::Free {
                    reply_val(ep_cap, -9);
                    continue;
                }
                match alloc_fd(&fds, 0) {
                    Some(newfd) => {
                        fds[newfd] = fds[oldfd];
                        reply_val(ep_cap, newfd as i64);
                    }
                    None => reply_val(ep_cap, -24),
                }
            }

            // SYS_dup2(oldfd, newfd)
            33 => {
                let oldfd = msg.regs[0] as usize;
                let newfd = msg.regs[1] as usize;
                if oldfd >= MAX_FDS || fds[oldfd].kind == FdKind::Free || newfd >= MAX_FDS {
                    reply_val(ep_cap, -9);
                    continue;
                }
                // Close newfd if open
                if fds[newfd].kind == FdKind::VfsFile {
                    if let Some(vfs) = vfs_opt.as_mut() {
                        let _ = vfs.close(fds[newfd].vfs_fd);
                    }
                }
                fds[newfd] = fds[oldfd];
                reply_val(ep_cap, newfd as i64);
            }

            // SYS_getpid
            39 => {
                reply_val(ep_cap, pid as i64);
            }

            // SYS_clone(child_fn) — fork a child process
            56 => {
                let child_fn = msg.regs[0];

                // Allocate child stacks (guest + handler, interleaved)
                let stack_base = NEXT_CHILD_STACK.fetch_add(0x2000, Ordering::SeqCst);
                let guest_stack = stack_base;
                let handler_stack = stack_base + 0x1000;

                // Map guest stack
                let gf = match sys::frame_alloc() {
                    Ok(f) => f,
                    Err(_) => { reply_val(ep_cap, -12); continue; }
                };
                if sys::map(guest_stack, gf, MAP_WRITABLE).is_err() {
                    reply_val(ep_cap, -12);
                    continue;
                }

                // Map handler stack
                let hf = match sys::frame_alloc() {
                    Ok(f) => f,
                    Err(_) => { reply_val(ep_cap, -12); continue; }
                };
                if sys::map(handler_stack, hf, MAP_WRITABLE).is_err() {
                    reply_val(ep_cap, -12);
                    continue;
                }

                // Create child endpoint
                let child_ep = match sys::endpoint_create() {
                    Ok(e) => e,
                    Err(_) => { reply_val(ep_cap, -12); continue; }
                };

                // Assign PID
                let child_pid = NEXT_PID.fetch_add(1, Ordering::SeqCst);

                // Set parent in process table (before handshake so child can read it)
                PROC_PARENT[child_pid as usize - 1].store(pid, Ordering::Release);

                // Pass setup info to child handler
                CHILD_SETUP_EP.store(child_ep, Ordering::Release);
                CHILD_SETUP_PID.store(child_pid, Ordering::Release);
                CHILD_SETUP_READY.store(1, Ordering::Release);

                // Spawn child handler thread
                if sys::thread_create(
                    child_handler as *const () as u64,
                    handler_stack + 0x1000,
                ).is_err() {
                    CHILD_SETUP_READY.store(0, Ordering::Release);
                    reply_val(ep_cap, -12);
                    continue;
                }

                // Wait for child handler to consume setup
                while CHILD_SETUP_READY.load(Ordering::Acquire) != 0 {
                    sys::yield_now();
                }

                // Spawn child guest thread
                let child_thread = match sys::thread_create(child_fn, guest_stack + 0x1000) {
                    Ok(t) => t,
                    Err(_) => { reply_val(ep_cap, -12); continue; }
                };

                // Set redirect on child guest → child endpoint
                if sys::redirect_set(child_thread, child_ep).is_err() {
                    reply_val(ep_cap, -12);
                    continue;
                }

                // Mark child as running
                PROC_STATE[child_pid as usize - 1].store(1, Ordering::Release);

                // Reply to parent with child PID
                reply_val(ep_cap, child_pid as i64);
            }

            // SYS_exit(status)
            60 => {
                let status = msg.regs[0];
                print(b"LUCAS: guest exit(");
                print_u64(status);
                print(b")\n");
                break;
            }

            // SYS_wait4(pid, ...) — waitpid
            61 => {
                let target_pid = msg.regs[0] as i64;
                if target_pid <= 0 || target_pid as usize > MAX_PROCS {
                    reply_val(ep_cap, -10); // -ECHILD
                    continue;
                }
                let idx = target_pid as usize - 1;
                // Spin until child becomes Zombie
                while PROC_STATE[idx].load(Ordering::Acquire) != 2 {
                    sys::yield_now();
                }
                let status = PROC_EXIT[idx].load(Ordering::Acquire);
                PROC_STATE[idx].store(0, Ordering::Release); // Free
                reply_val(ep_cap, status as i64);
            }

            // SYS_kill(pid, sig)
            62 => {
                let target = msg.regs[0] as usize;
                let sig = msg.regs[1];
                if target == 0 || target > MAX_PROCS || PROC_STATE[target - 1].load(Ordering::Acquire) == 0 {
                    reply_val(ep_cap, -3); // -ESRCH
                    continue;
                }
                PROC_SIGNAL[target - 1].store(sig, Ordering::Release);
                if sig == 9 {
                    // SIGKILL: also force zombie
                    PROC_EXIT[target - 1].store(137, Ordering::Release);
                    PROC_STATE[target - 1].store(2, Ordering::Release);
                }
                reply_val(ep_cap, 0);
            }

            // SYS_unlink(path)
            87 => {
                let path_ptr = msg.regs[0];
                let mut path = [0u8; 48];
                let path_len = copy_guest_path(path_ptr, &mut path);
                let name = &path[..path_len];

                match vfs_opt.as_mut() {
                    Some(vfs) => {
                        match vfs.delete(name) {
                            Ok(()) => reply_val(ep_cap, 0),
                            Err(_) => reply_val(ep_cap, -2),
                        }
                    }
                    None => reply_val(ep_cap, -2),
                }
            }

            // SYS_getppid
            110 => {
                reply_val(ep_cap, 0); // PID 1 has no parent
            }

            // Unknown Linux syscall → -ENOSYS
            _ => {
                reply_val(ep_cap, -38);
            }
        }
    }

    print(b"LUCAS: done\n");
    sys::thread_exit();
}

/// Set up and run the LUCAS syscall redirect demo.
/// Reads guest_entry from BootInfo; if 0, skips LUCAS entirely.
/// If `blk` is provided, stores it for the handler to mount as VFS.
fn run_lucas_demo(blk: Option<VirtioBlk>) {
    let boot_info = unsafe { &*(BOOT_INFO_ADDR as *const BootInfo) };

    // Initialize framebuffer console if available.
    if boot_info.fb_addr != 0 {
        unsafe { fb_init(boot_info); }
        print(b"[FB OK]\n");
    }

    let guest_entry = boot_info.guest_entry;
    if guest_entry == 0 {
        print(b"LUCAS: no guest binary, skipping\n");
        return;
    }

    print(b"LUCAS: starting (guest entry=");
    print_u64(guest_entry);
    print(b")\n");

    // Store VirtioBlk at fixed address for handler to pick up.
    if let Some(blk_dev) = blk {
        let blk_frame = sys::frame_alloc().unwrap_or_else(|_| panic_halt());
        sys::map(LUCAS_BLK_STORE, blk_frame, MAP_WRITABLE).unwrap_or_else(|_| panic_halt());
        unsafe {
            core::ptr::write(LUCAS_BLK_STORE as *mut VirtioBlk, blk_dev);
        }
        LUCAS_VFS_READY.store(1, Ordering::Release);
    }

    // 1. Create endpoint for LUCAS IPC.
    let ep_cap = sys::endpoint_create().unwrap_or_else(|_| panic_halt());
    LUCAS_EP_CAP.store(ep_cap, Ordering::Release);

    // 2. Allocate and map guest stack (4 pages).
    for i in 0..LUCAS_GUEST_STACK_PAGES {
        let f = sys::frame_alloc().unwrap_or_else(|_| panic_halt());
        sys::map(LUCAS_GUEST_STACK + i * 0x1000, f, MAP_WRITABLE).unwrap_or_else(|_| panic_halt());
    }

    // 3. Allocate and map handler stack (4 pages).
    for i in 0..LUCAS_HANDLER_STACK_PAGES {
        let f = sys::frame_alloc().unwrap_or_else(|_| panic_halt());
        sys::map(LUCAS_HANDLER_STACK + i * 0x1000, f, MAP_WRITABLE).unwrap_or_else(|_| panic_halt());
    }

    // 4. Spawn handler thread first so it's ready when guest starts.
    let _handler_thread_cap = sys::thread_create(
        lucas_handler as *const () as u64,
        LUCAS_HANDLER_STACK + LUCAS_HANDLER_STACK_PAGES * 0x1000,
    ).unwrap_or_else(|_| panic_halt());

    // 5. Create guest thread at the shell binary's entry point.
    let guest_thread_cap = sys::thread_create(
        guest_entry,
        LUCAS_GUEST_STACK + LUCAS_GUEST_STACK_PAGES * 0x1000,
    ).unwrap_or_else(|_| panic_halt());

    // 6. Set redirect on guest thread so its syscalls go to the LUCAS endpoint.
    sys::redirect_set(guest_thread_cap, ep_cap).unwrap_or_else(|_| panic_halt());
}

fn panic_halt() -> ! {
    print(b"PANIC\n");
    loop {}
}

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    print(b"!!!PANIC-RUST!!!\n");
    loop {}
}
