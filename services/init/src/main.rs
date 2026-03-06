#![no_std]
#![no_main]

use sotos_common::sys;
use sotos_common::spsc;
use sotos_common::{BootInfo, BOOT_INFO_ADDR, KB_RING_ADDR, MOUSE_RING_ADDR};
use sotos_pci::PciBus;
use sotos_virtio::blk::VirtioBlk;
use sotos_objstore::{ObjectStore, Vfs, DirEntry, DIR_ENTRY_COUNT};

use core::sync::atomic::{AtomicU64, Ordering};

mod vdso;

// ---------------------------------------------------------------------------
// Init address space layout:
//   0x200000        ELF .text (init binary)
//   0x510000        KB ring (shared, from sotos_common)
//   0x520000        Mouse ring (shared, from sotos_common)
//   0x900000        Stack (4 pages, ASLR offset)
//   0xA00000        SPSC ring + producer stack
//   0xB00000        BootInfo (RO)
//   0xC00000+       Virtio MMIO pages
//   0xD00000+       ObjectStore + VFS
//   0xE00000        LUCAS guest stack (4 pages)
//   0xE10000        LUCAS handler stack (16 pages)
//   0xE20000        VirtioBlk storage (1 page)
//   0xE30000+       Child process stacks (0x2000 each)
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
/// WRITABLE flag for map syscall (bit 1).
const MAP_WRITABLE: u64 = 2;

// ---------------------------------------------------------------------------
// LUCAS — Linux-ABI User Compatibility Shim
// ---------------------------------------------------------------------------

/// LUCAS guest stack (4 pages).
const LUCAS_GUEST_STACK: u64 = 0xE00000;
const LUCAS_GUEST_STACK_PAGES: u64 = 4;
/// LUCAS handler stack (16 pages = 64KB, large due to VFS/ObjectStore locals).
const LUCAS_HANDLER_STACK: u64 = 0xE10000;
const LUCAS_HANDLER_STACK_PAGES: u64 = 16;

/// LUCAS endpoint cap — shared between handler and _start via atomic.
static LUCAS_EP_CAP: AtomicU64 = AtomicU64::new(0);

/// Net service IPC endpoint cap — looked up via svc_lookup("net").
static NET_EP_CAP: AtomicU64 = AtomicU64::new(0);

// ---------------------------------------------------------------------------
// Root capability indices (must match kernel create_init_caps() order)
// VMM and keyboard caps removed — they run as separate processes.
// ---------------------------------------------------------------------------
const CAP_PCI: usize = 0;         // I/O port 0xCF8-0xCFF (PCI config)

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

    // --- Initialize framebuffer console with desktop GUI ---
    if boot_info.fb_addr != 0 {
        unsafe {
            fb_init(boot_info);
            // Draw initial mouse cursor.
            fb_save_under_cursor();
            fb_draw_cursor();
            MOUSE_PREV_X = MOUSE_X;
            MOUSE_PREV_Y = MOUSE_Y;
        }
        print(b"[DESKTOP OK]\n");
    }

    print(b"INIT: boot complete, ");
    print_u64(cap_count);
    print(b" caps received\n");

    // VMM and keyboard driver are now separate processes (services/vmm, services/kbd).

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

    // --- Phase 4: Virtio-BLK + Object Store ---
    let blk = init_block_storage(boot_info);

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
            print(b"INIT: net service not found (networking disabled)\n");
        }
    }

    // --- Phase 6: Userspace process spawning ---
    spawn_process(b"hello");

    // --- Phase 7: Dynamic linking test ---
    test_dynamic_linking();

    // --- Wait for spawned processes to finish ---
    for _ in 0..200 { sys::yield_now(); }

    // --- Phase 7.5: Linux ABI test (hello-linux via LUCAS redirect) ---
    run_linux_test();

    // --- Phase 7.6: musl-static binary test (Busybox milestone) ---
    run_musl_test();

    // --- Phase 7.7: dynamically-linked binary test ---
    run_dynamic_test();

    // --- Phase 8: LUCAS shell (LAST — interactive, takes over serial+framebuffer) ---
    start_lucas(blk);

    // LUCAS threads run forever; main thread exits.
    sys::thread_exit();
}

// ---------------------------------------------------------------------------
// Userspace process spawning (Feature 3)
// ---------------------------------------------------------------------------

/// Temporary buffer region for reading ELF data from initrd.
const SPAWN_BUF_BASE: u64 = 0x5000000;
/// Max ELF size we support for spawning (512 KiB = 128 pages).
const SPAWN_BUF_PAGES: u64 = 128;

/// Spawn a new process from an initrd binary by name.
///
/// Uses InitrdRead to get ELF data, parses headers with the userspace ELF
/// parser, creates a new address space, maps segments + stack, writes
/// BootInfo, and launches the thread.
fn spawn_process(name: &[u8]) {
    use sotos_common::elf;

    print(b"SPAWN: loading '");
    print(name);
    print(b"' from initrd...\n");

    // Step 1: Map temporary buffer pages into our address space.
    let mut buf_frames = [0u64; SPAWN_BUF_PAGES as usize];
    for i in 0..SPAWN_BUF_PAGES {
        let frame_cap = match sys::frame_alloc() {
            Ok(f) => f,
            Err(_) => {
                print(b"SPAWN: frame_alloc failed for buffer\n");
                return;
            }
        };
        buf_frames[i as usize] = frame_cap;
        if sys::map(SPAWN_BUF_BASE + i * 0x1000, frame_cap, MAP_WRITABLE).is_err() {
            print(b"SPAWN: map buffer page failed\n");
            return;
        }
    }

    // Step 2: Read ELF from initrd into our buffer.
    let file_size = match sys::initrd_read(
        name.as_ptr() as u64,
        name.len() as u64,
        SPAWN_BUF_BASE,
        SPAWN_BUF_PAGES * 0x1000,
    ) {
        Ok(sz) => sz as usize,
        Err(_) => {
            print(b"SPAWN: initrd_read failed (not found?)\n");
            // Cleanup buffer pages.
            for i in 0..SPAWN_BUF_PAGES {
                let _ = sys::unmap(SPAWN_BUF_BASE + i * 0x1000);
            }
            return;
        }
    };

    print(b"SPAWN: ELF size = ");
    print_u64(file_size as u64);
    print(b" bytes\n");

    // Step 3: Parse ELF header.
    let elf_data = unsafe { core::slice::from_raw_parts(SPAWN_BUF_BASE as *const u8, file_size) };
    let elf_info = match elf::parse(elf_data) {
        Ok(info) => info,
        Err(e) => {
            print(b"SPAWN: ELF parse error: ");
            print(e.as_bytes());
            print(b"\n");
            for i in 0..SPAWN_BUF_PAGES {
                let _ = sys::unmap(SPAWN_BUF_BASE + i * 0x1000);
            }
            return;
        }
    };

    print(b"SPAWN: entry = 0x");
    print_hex64(elf_info.entry);
    print(b"\n");

    // Step 4: Create new address space.
    let as_cap = match sys::addr_space_create() {
        Ok(cap) => cap,
        Err(_) => {
            print(b"SPAWN: addr_space_create failed\n");
            for i in 0..SPAWN_BUF_PAGES {
                let _ = sys::unmap(SPAWN_BUF_BASE + i * 0x1000);
            }
            return;
        }
    };

    // Step 5: Parse and map each PT_LOAD segment into the new AS.
    let mut segments = [const { elf::LoadSegment { offset: 0, vaddr: 0, filesz: 0, memsz: 0, flags: 0 } }; elf::MAX_LOAD_SEGMENTS];
    let seg_count = elf::load_segments(elf_data, &elf_info, &mut segments);

    for si in 0..seg_count {
        let seg = &segments[si];
        if seg.memsz == 0 {
            continue;
        }
        let seg_start = seg.vaddr & !0xFFF;
        let seg_end = (seg.vaddr + seg.memsz as u64 + 0xFFF) & !0xFFF;
        let is_writable = (seg.flags & 2) != 0; // PF_W

        let mut page_vaddr = seg_start;
        while page_vaddr < seg_end {
            // Allocate a frame.
            let frame_cap = match sys::frame_alloc() {
                Ok(f) => f,
                Err(_) => {
                    print(b"SPAWN: frame_alloc failed for segment\n");
                    return;
                }
            };

            // Map temporarily into our AS to copy data.
            let temp_vaddr = 0x5100000u64; // Just past our buffer
            if sys::map(temp_vaddr, frame_cap, MAP_WRITABLE).is_err() {
                print(b"SPAWN: temp map failed\n");
                return;
            }

            // Zero the page first.
            unsafe {
                core::ptr::write_bytes(temp_vaddr as *mut u8, 0, 4096);
            }

            // Copy overlapping file data.
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

            // Unmap from our AS.
            let _ = sys::unmap(temp_vaddr);

            // Map into the target AS.
            let flags = if is_writable { MAP_WRITABLE } else { 0 };
            if sys::map_into(as_cap, page_vaddr, frame_cap, flags).is_err() {
                print(b"SPAWN: map_into failed\n");
                return;
            }

            page_vaddr += 4096;
        }
    }

    // Step 6: Allocate stack (4 pages at 0x900000) with guard page below.
    let stack_base: u64 = 0x900000;
    let stack_pages: u64 = 4;
    // Guard page: present but not user-accessible — triggers fault on overflow.
    if let Ok(guard_cap) = sys::frame_alloc() {
        // Map with flags=0 (no WRITABLE) — PAGE_PRESENT|PAGE_USER set by kernel,
        // but no WRITABLE means any write triggers a fault.
        let _ = sys::map_into(as_cap, stack_base - 0x1000, guard_cap, 0);
    }
    for i in 0..stack_pages {
        let frame_cap = match sys::frame_alloc() {
            Ok(f) => f,
            Err(_) => {
                print(b"SPAWN: frame_alloc failed for stack\n");
                return;
            }
        };
        if sys::map_into(as_cap, stack_base + i * 0x1000, frame_cap, MAP_WRITABLE).is_err() {
            print(b"SPAWN: map_into stack failed\n");
            return;
        }
    }
    let stack_top = stack_base + stack_pages * 0x1000;

    // Step 7: Write BootInfo into target AS (no caps for hello).
    let caps: [u64; 0] = [];
    if sys::bootinfo_write(as_cap, caps.as_ptr() as u64, 0).is_err() {
        print(b"SPAWN: bootinfo_write failed\n");
        return;
    }

    // Step 8: Create thread in target AS.
    match sys::thread_create_in(as_cap, elf_info.entry, stack_top) {
        Ok(tid) => {
            print(b"SPAWN: '");
            print(name);
            print(b"' launched (tid cap = ");
            print_u64(tid);
            print(b")\n");
        }
        Err(_) => {
            print(b"SPAWN: thread_create_in failed\n");
        }
    }

    // Cleanup: unmap our temporary buffer pages.
    for i in 0..SPAWN_BUF_PAGES {
        let _ = sys::unmap(SPAWN_BUF_BASE + i * 0x1000);
    }
}

fn print_hex64(mut n: u64) {
    if n == 0 {
        sys::debug_print(b'0');
        unsafe { fb_putchar(b'0'); }
        return;
    }
    let mut buf = [0u8; 16];
    let mut i = 0;
    while n > 0 {
        let digit = (n & 0xF) as u8;
        buf[i] = if digit < 10 { b'0' + digit } else { b'a' + digit - 10 };
        n >>= 4;
        i += 1;
    }
    while i > 0 {
        i -= 1;
        sys::debug_print(buf[i]);
        unsafe { fb_putchar(buf[i]); }
    }
}

// ---------------------------------------------------------------------------
// Dynamic linking test (Feature 4)
// ---------------------------------------------------------------------------

/// Base address for loading shared libraries.
const DL_LOAD_BASE: u64 = 0x6000000;
/// Buffer region for reading .so data from initrd.
const DL_BUF_BASE: u64 = 0x5200000;
/// Max .so size (128 KiB = 32 pages).
const DL_BUF_PAGES: u64 = 32;

fn test_dynamic_linking() {
    print(b"DLOPEN: loading libtest.so...\n");

    // Step 1: Map buffer pages for reading the .so.
    for i in 0..DL_BUF_PAGES {
        let frame_cap = match sys::frame_alloc() {
            Ok(f) => f,
            Err(_) => {
                print(b"DLOPEN: frame_alloc failed for buffer\n");
                return;
            }
        };
        if sys::map(DL_BUF_BASE + i * 0x1000, frame_cap, MAP_WRITABLE).is_err() {
            print(b"DLOPEN: map buffer page failed\n");
            return;
        }
    }

    // Step 2: Read .so from initrd.
    let name = b"libtest.so";
    let file_size = match sys::initrd_read(
        name.as_ptr() as u64,
        name.len() as u64,
        DL_BUF_BASE,
        DL_BUF_PAGES * 0x1000,
    ) {
        Ok(sz) => sz as usize,
        Err(_) => {
            print(b"DLOPEN: initrd_read failed for libtest.so\n");
            for i in 0..DL_BUF_PAGES {
                let _ = sys::unmap(DL_BUF_BASE + i * 0x1000);
            }
            return;
        }
    };

    print(b"DLOPEN: libtest.so size = ");
    print_u64(file_size as u64);
    print(b" bytes\n");

    // Step 3: Load and relocate the shared library.
    let elf_data = unsafe { core::slice::from_raw_parts(DL_BUF_BASE as *const u8, file_size) };
    let handle = match sotos_ld::dl_open(elf_data, DL_LOAD_BASE) {
        Ok(h) => h,
        Err(e) => {
            print(b"DLOPEN: dl_open failed: ");
            print(e.as_bytes());
            print(b"\n");
            for i in 0..DL_BUF_PAGES {
                let _ = sys::unmap(DL_BUF_BASE + i * 0x1000);
            }
            return;
        }
    };

    print(b"DLOPEN: loaded at base 0x");
    print_hex64(handle.base);
    print(b"\n");

    // Step 4: Look up the "add" symbol.
    match sotos_ld::dl_sym(&handle, b"add") {
        Some(add_addr) => {
            print(b"DLSYM: add = 0x");
            print_hex64(add_addr);
            print(b"\n");

            // Call add(3, 4) — should return 7.
            let add_fn: extern "C" fn(u64, u64) -> u64 = unsafe {
                core::mem::transmute(add_addr)
            };
            let result = add_fn(3, 4);
            print(b"DLCALL: add(3, 4) = ");
            print_u64(result);
            print(b"\n");

            if result == 7 {
                print(b"DLTEST: PASS - dynamic linking works!\n");
            } else {
                print(b"DLTEST: FAIL - expected 7\n");
            }
        }
        None => {
            print(b"DLSYM: 'add' not found\n");
        }
    }

    // Step 5: Also test "mul" symbol.
    match sotos_ld::dl_sym(&handle, b"mul") {
        Some(mul_addr) => {
            let mul_fn: extern "C" fn(u64, u64) -> u64 = unsafe {
                core::mem::transmute(mul_addr)
            };
            let result = mul_fn(6, 7);
            print(b"DLCALL: mul(6, 7) = ");
            print_u64(result);
            print(b"\n");

            if result == 42 {
                print(b"DLTEST: mul PASS\n");
            } else {
                print(b"DLTEST: mul FAIL - expected 42\n");
            }
        }
        None => {
            print(b"DLSYM: 'mul' not found\n");
        }
    }

    // Step 6: Cleanup.
    sotos_ld::dl_close(&handle);
    for i in 0..DL_BUF_PAGES {
        let _ = sys::unmap(DL_BUF_BASE + i * 0x1000);
    }
}

/// Run a Linux-ABI test binary (hello-linux) via LUCAS redirect.
/// Loads the ELF, redirects its syscalls, and handles them inline.
fn run_linux_test() {
    print(b"LINUX-TEST: loading hello-linux...\n");

    // Acquire exec lock
    while EXEC_LOCK.compare_exchange(0, 1, Ordering::AcqRel, Ordering::Relaxed).is_err() {
        sys::yield_now();
    }

    let ep_cap = match exec_from_initrd(b"hello-linux") {
        Ok((ep, _tc)) => {
            EXEC_LOCK.store(0, Ordering::Release);
            ep
        }
        Err(e) => {
            EXEC_LOCK.store(0, Ordering::Release);
            print(b"LINUX-TEST: failed to load (errno=");
            print_u64((-e) as u64);
            print(b")\n");
            return;
        }
    };

    print(b"LINUX-TEST: running...\n");

    // Use a temp PID slot for signal state (slot 15 = MAX_PROCS-1)
    let test_pid: usize = MAX_PROCS; // Use last slot (index MAX_PROCS-1)

    // brk/mmap state for this child
    let mut current_brk: u64 = BRK_BASE;
    let mut mmap_next: u64 = MMAP_BASE;

    // Handle the child's syscalls until it exits
    loop {
        let msg = match sys::recv(ep_cap) {
            Ok(m) => m,
            Err(_) => break,
        };

        let nr = msg.tag;
        match nr {
            // write(fd, buf, len)
            1 => {
                let buf_ptr = msg.regs[1];
                let len = msg.regs[2] as usize;
                let data = unsafe { core::slice::from_raw_parts(buf_ptr as *const u8, len) };
                for &b in data {
                    sys::debug_print(b);
                    unsafe { fb_putchar(b); }
                }
                reply_val(ep_cap, len as i64);
            }
            // getpid
            39 => reply_val(ep_cap, 999),
            // arch_prctl — handled by kernel redirect intercept, shouldn't reach here
            158 => reply_val(ep_cap, 0),
            // brk(addr)
            12 => {
                let addr = msg.regs[0];
                if addr == 0 || addr <= current_brk {
                    reply_val(ep_cap, current_brk as i64);
                } else {
                    let new_brk = (addr + 0xFFF) & !0xFFF;
                    let mut ok = true;
                    let mut pg = (current_brk + 0xFFF) & !0xFFF;
                    while pg < new_brk {
                        if let Ok(f) = sys::frame_alloc() {
                            if sys::map(pg, f, MAP_WRITABLE).is_err() {
                                ok = false;
                                break;
                            }
                        } else {
                            ok = false;
                            break;
                        }
                        pg += 0x1000;
                    }
                    if ok {
                        current_brk = new_brk;
                    }
                    reply_val(ep_cap, current_brk as i64);
                }
            }
            // mmap(addr, len, prot, flags, fd, offset)
            9 => {
                let len = msg.regs[1];
                let fd = msg.regs[4] as i64;
                if fd >= 0 {
                    reply_val(ep_cap, -22); // -EINVAL: no file-backed mmap
                } else {
                    let pages = ((len + 0xFFF) & !0xFFF) / 0x1000;
                    let base = mmap_next;
                    let mut ok = true;
                    for p in 0..pages {
                        if let Ok(f) = sys::frame_alloc() {
                            if sys::map(base + p * 0x1000, f, MAP_WRITABLE).is_err() {
                                ok = false;
                                break;
                            }
                        } else {
                            ok = false;
                            break;
                        }
                    }
                    if ok {
                        mmap_next += pages * 0x1000;
                        reply_val(ep_cap, base as i64);
                    } else {
                        reply_val(ep_cap, -12); // -ENOMEM
                    }
                }
            }
            // munmap
            11 => reply_val(ep_cap, 0),
            // uname(buf)
            63 => {
                let buf = msg.regs[0] as *mut u8;
                unsafe {
                    // Each field is 65 bytes in struct utsname
                    core::ptr::write_bytes(buf, 0, 390);
                    let sysname = b"sotOS";
                    core::ptr::copy_nonoverlapping(sysname.as_ptr(), buf, sysname.len());
                    let nodename = b"lucas";
                    core::ptr::copy_nonoverlapping(nodename.as_ptr(), buf.add(65), nodename.len());
                    let release = b"0.1.0";
                    core::ptr::copy_nonoverlapping(release.as_ptr(), buf.add(130), release.len());
                    let version = b"sotOS 0.1.0 LUCAS";
                    core::ptr::copy_nonoverlapping(version.as_ptr(), buf.add(195), version.len());
                    let machine = b"x86_64";
                    core::ptr::copy_nonoverlapping(machine.as_ptr(), buf.add(260), machine.len());
                }
                reply_val(ep_cap, 0);
            }
            // close
            3 => reply_val(ep_cap, 0),
            // nanosleep
            35 => reply_val(ep_cap, 0),
            // exit / exit_group
            60 | 231 => {
                let status = msg.regs[0] as i64;
                print(b"LINUX-TEST: exited with status ");
                print_u64(status as u64);
                print(b"\n");
                break;
            }
            // rt_sigaction(sig, act, oldact, sigsetsize)
            13 => {
                let signo = msg.regs[0] as usize;
                let act_ptr = msg.regs[1];
                let oldact = msg.regs[2];
                let sigsetsize = msg.regs[3].max(8) as usize;
                let ksa_size = (24 + sigsetsize).min(64);
                let idx = test_pid - 1;
                if signo == 9 || signo == 19 {
                    reply_val(ep_cap, -22); continue;
                }
                if oldact != 0 && oldact < 0x0000_8000_0000_0000 {
                    let buf = unsafe { core::slice::from_raw_parts_mut(oldact as *mut u8, ksa_size) };
                    for b in buf.iter_mut() { *b = 0; }
                    if signo > 0 && signo < 32 {
                        let old_h = SIG_HANDLER[idx][signo].load(Ordering::Acquire);
                        let old_f = SIG_FLAGS[idx][signo].load(Ordering::Acquire);
                        let old_r = SIG_RESTORER[idx][signo].load(Ordering::Acquire);
                        buf[0..8].copy_from_slice(&old_h.to_le_bytes());
                        buf[8..16].copy_from_slice(&old_f.to_le_bytes());
                        buf[16..24].copy_from_slice(&old_r.to_le_bytes());
                    }
                }
                if act_ptr != 0 && act_ptr < 0x0000_8000_0000_0000 && signo > 0 && signo < 32 {
                    let handler = unsafe { *(act_ptr as *const u64) };
                    let flags = unsafe { *((act_ptr + 8) as *const u64) };
                    let restorer = unsafe { *((act_ptr + 16) as *const u64) };
                    SIG_HANDLER[idx][signo].store(handler, Ordering::Release);
                    SIG_FLAGS[idx][signo].store(flags, Ordering::Release);
                    SIG_RESTORER[idx][signo].store(restorer, Ordering::Release);
                }
                reply_val(ep_cap, 0);
            }
            // rt_sigprocmask(how, set, oldset, sigsetsize)
            14 => {
                let how = msg.regs[0];
                let set_ptr = msg.regs[1];
                let oldset = msg.regs[2];
                let idx = test_pid - 1;
                let cur_mask = SIG_BLOCKED[idx].load(Ordering::Acquire);
                if oldset != 0 && oldset < 0x0000_8000_0000_0000 {
                    unsafe { *(oldset as *mut u64) = cur_mask; }
                }
                if set_ptr != 0 && set_ptr < 0x0000_8000_0000_0000 {
                    let new_set = unsafe { *(set_ptr as *const u64) };
                    let safe_set = new_set & !((1 << SIGKILL) | (1 << 19));
                    match how {
                        0 => SIG_BLOCKED[idx].store(cur_mask | safe_set, Ordering::Release),
                        1 => SIG_BLOCKED[idx].store(cur_mask & !safe_set, Ordering::Release),
                        2 => SIG_BLOCKED[idx].store(safe_set, Ordering::Release),
                        _ => {}
                    }
                }
                reply_val(ep_cap, 0);
            }
            // sigaltstack — stub
            131 => reply_val(ep_cap, 0),
            // writev(fd, iov, iovcnt)
            20 => {
                let iov_ptr = msg.regs[1];
                let iovcnt = msg.regs[2] as usize;
                let mut total: usize = 0;
                let cnt = iovcnt.min(16);
                for i in 0..cnt {
                    let entry = iov_ptr + (i as u64) * 16;
                    let base = unsafe { *(entry as *const u64) };
                    let len = unsafe { *((entry + 8) as *const u64) } as usize;
                    if base == 0 || len == 0 { continue; }
                    let data = unsafe { core::slice::from_raw_parts(base as *const u8, len) };
                    for &b in data { sys::debug_print(b); unsafe { fb_putchar(b); } }
                    total += len;
                }
                reply_val(ep_cap, total as i64);
            }
            // set_tid_address
            218 => reply_val(ep_cap, 999),
            // clock_gettime
            228 => {
                let tp = msg.regs[1] as *mut u64;
                unsafe {
                    *tp = 0;
                    *tp.add(1) = 0;
                }
                reply_val(ep_cap, 0);
            }
            _ => {
                print(b"LINUX-TEST: unhandled syscall ");
                print_u64(nr);
                print(b"\n");
                reply_val(ep_cap, -38); // -ENOSYS
            }
        }
    }

    print(b"LINUX-TEST: complete\n");
}

/// Run a real musl-static binary (hello-musl) via LUCAS redirect.
/// This is the Busybox milestone test — proves LUCAS can run real Linux binaries.
fn run_musl_test() {
    print(b"MUSL-TEST: loading hello-musl...\n");

    // Acquire exec lock
    while EXEC_LOCK.compare_exchange(0, 1, Ordering::AcqRel, Ordering::Relaxed).is_err() {
        sys::yield_now();
    }

    let ep_cap = match exec_from_initrd(b"hello-musl") {
        Ok((ep, _tc)) => {
            EXEC_LOCK.store(0, Ordering::Release);
            ep
        }
        Err(e) => {
            EXEC_LOCK.store(0, Ordering::Release);
            print(b"MUSL-TEST: failed to load (errno=");
            print_u64((-e) as u64);
            print(b")\n");
            return;
        }
    };

    print(b"MUSL-TEST: running musl-static binary...\n");

    // Use temp PID slot for signal state
    let test_pid: usize = MAX_PROCS;

    // brk/mmap state
    let mut current_brk: u64 = BRK_BASE;
    let mut mmap_next: u64 = MMAP_BASE;

    // Handle the musl binary's syscalls
    loop {
        let msg = match sys::recv(ep_cap) {
            Ok(m) => m,
            Err(_) => break,
        };

        let nr = msg.tag;
        // Debug: log syscall number
        print(b"MUSL-SYS: ");
        print_u64(nr);
        print(b"\n");
        match nr {
            // write(fd, buf, len)
            1 => {
                let buf_ptr = msg.regs[1];
                let len = msg.regs[2] as usize;
                if len > 0 && buf_ptr != 0 && buf_ptr < 0x0000_8000_0000_0000 {
                    let data = unsafe { core::slice::from_raw_parts(buf_ptr as *const u8, len) };
                    for &b in data { sys::debug_print(b); unsafe { fb_putchar(b); } }
                }
                reply_val(ep_cap, len as i64);
            }
            // read(fd, buf, len)
            0 => reply_val(ep_cap, 0), // EOF
            // close
            3 => reply_val(ep_cap, 0),
            // poll(fds, nfds, timeout) — Rust std sanitize_standard_fds
            7 => {
                // Return 0 = no events ready (fds are valid)
                let nfds = msg.regs[1] as usize;
                // Zero out revents in each pollfd struct (8 bytes each)
                let fds_ptr = msg.regs[0];
                if fds_ptr != 0 && fds_ptr < 0x0000_8000_0000_0000 {
                    for i in 0..nfds.min(16) {
                        let revents_ptr = (fds_ptr + (i as u64) * 8 + 6) as *mut u16;
                        unsafe { *revents_ptr = 0; }
                    }
                }
                reply_val(ep_cap, 0);
            }
            // fstat(fd, statbuf) — musl uses this
            5 => {
                let stat_ptr = msg.regs[1];
                if stat_ptr != 0 && stat_ptr < 0x0000_8000_0000_0000 {
                    write_linux_stat(stat_ptr, 0, 0, false);
                }
                reply_val(ep_cap, 0);
            }
            // mmap(addr, len, prot, flags, fd, offset)
            9 => {
                let len = msg.regs[1];
                let flags = msg.regs[3];
                if flags & 0x20 == 0 {
                    reply_val(ep_cap, -22); // No file-backed mmap in test handler
                    continue;
                }
                let pages = ((len + 0xFFF) / 0x1000) as u32;
                let base = mmap_next;
                let mut ok = true;
                for p in 0..pages {
                    match sys::frame_alloc() {
                        Ok(frame) => {
                            if sys::map(base + (p as u64) * 0x1000, frame, MAP_WRITABLE).is_err() {
                                ok = false; break;
                            }
                        }
                        Err(_) => { ok = false; break; }
                    }
                }
                if !ok { reply_val(ep_cap, -12); continue; }
                let region = unsafe { core::slice::from_raw_parts_mut(base as *mut u8, (pages as usize) * 0x1000) };
                for b in region.iter_mut() { *b = 0; }
                mmap_next += (pages as u64) * 0x1000;
                reply_val(ep_cap, base as i64);
            }
            // mprotect(addr, len, prot)
            10 => reply_val(ep_cap, 0),
            // munmap
            11 => reply_val(ep_cap, 0),
            // brk
            12 => {
                let new_brk = msg.regs[0];
                if new_brk == 0 {
                    reply_val(ep_cap, current_brk as i64);
                } else if new_brk < current_brk {
                    reply_val(ep_cap, current_brk as i64);
                } else {
                    let mut ok = true;
                    let mut pg = (current_brk + 0xFFF) & !0xFFF;
                    while pg < new_brk {
                        if let Ok(f) = sys::frame_alloc() {
                            if sys::map(pg, f, MAP_WRITABLE).is_err() { ok = false; break; }
                        } else { ok = false; break; }
                        pg += 0x1000;
                    }
                    if ok { current_brk = new_brk; }
                    reply_val(ep_cap, current_brk as i64);
                }
            }
            // rt_sigaction(signo, act, oldact, sigsetsize)
            // Kernel struct: handler(8) + flags(8) + restorer(8) + mask(sigsetsize)
            13 => {
                let signo = msg.regs[0] as usize;
                let act_ptr = msg.regs[1];
                let oldact = msg.regs[2];
                let sigsetsize = msg.regs[3].max(8) as usize; // r10 = sigsetsize
                let ksa_size = 24 + sigsetsize; // handler + flags + restorer + mask
                let idx = test_pid - 1;
                if signo == 9 || signo == 19 { reply_val(ep_cap, -22); continue; }
                if oldact != 0 && oldact < 0x0000_8000_0000_0000 {
                    let buf = unsafe { core::slice::from_raw_parts_mut(oldact as *mut u8, ksa_size.min(64)) };
                    for b in buf.iter_mut() { *b = 0; }
                    if signo > 0 && signo < 32 {
                        let h = SIG_HANDLER[idx][signo].load(Ordering::Acquire);
                        let f = SIG_FLAGS[idx][signo].load(Ordering::Acquire);
                        buf[0..8].copy_from_slice(&h.to_le_bytes());
                        buf[8..16].copy_from_slice(&f.to_le_bytes());
                    }
                }
                if act_ptr != 0 && act_ptr < 0x0000_8000_0000_0000 && signo > 0 && signo < 32 {
                    let handler = unsafe { *(act_ptr as *const u64) };
                    let flags = unsafe { *((act_ptr + 8) as *const u64) };
                    SIG_HANDLER[idx][signo].store(handler, Ordering::Release);
                    SIG_FLAGS[idx][signo].store(flags, Ordering::Release);
                }
                reply_val(ep_cap, 0);
            }
            // rt_sigprocmask
            14 => {
                let how = msg.regs[0];
                let set_ptr = msg.regs[1];
                let oldset = msg.regs[2];
                let idx = test_pid - 1;
                let cur = SIG_BLOCKED[idx].load(Ordering::Acquire);
                if oldset != 0 && oldset < 0x0000_8000_0000_0000 {
                    unsafe { *(oldset as *mut u64) = cur; }
                }
                if set_ptr != 0 && set_ptr < 0x0000_8000_0000_0000 {
                    let new_set = unsafe { *(set_ptr as *const u64) };
                    let safe = new_set & !((1 << SIGKILL) | (1 << 19));
                    match how {
                        0 => SIG_BLOCKED[idx].store(cur | safe, Ordering::Release),
                        1 => SIG_BLOCKED[idx].store(cur & !safe, Ordering::Release),
                        2 => SIG_BLOCKED[idx].store(safe, Ordering::Release),
                        _ => {}
                    }
                }
                reply_val(ep_cap, 0);
            }
            // ioctl — return ENOTTY for terminal queries
            16 => reply_val(ep_cap, -25),
            // writev(fd, iov, iovcnt)
            20 => {
                let iov_ptr = msg.regs[1];
                let iovcnt = msg.regs[2] as usize;
                let mut total: usize = 0;
                let cnt = iovcnt.min(16);
                for i in 0..cnt {
                    let entry = iov_ptr + (i as u64) * 16;
                    let base = unsafe { *(entry as *const u64) };
                    let len = unsafe { *((entry + 8) as *const u64) } as usize;
                    if base == 0 || len == 0 { continue; }
                    let data = unsafe { core::slice::from_raw_parts(base as *const u8, len) };
                    for &b in data { sys::debug_print(b); unsafe { fb_putchar(b); } }
                    total += len;
                }
                reply_val(ep_cap, total as i64);
            }
            // getpid
            39 => reply_val(ep_cap, test_pid as i64),
            // nanosleep
            35 => reply_val(ep_cap, 0),
            // exit / exit_group
            60 | 231 => {
                let status = msg.regs[0] as i64;
                print(b"MUSL-TEST: exited with status ");
                print_u64(status as u64);
                print(b"\n");
                if status == 0 {
                    print(b"MUSL-TEST: SUCCESS -- real musl-static binary ran under LUCAS!\n");
                } else {
                    print(b"MUSL-TEST: FAILED\n");
                }
                break;
            }
            // uname
            63 => {
                let buf_ptr = msg.regs[0];
                if buf_ptr != 0 && buf_ptr < 0x0000_8000_0000_0000 {
                    let buf = unsafe { core::slice::from_raw_parts_mut(buf_ptr as *mut u8, 390) };
                    for b in buf.iter_mut() { *b = 0; }
                    let fields: [&[u8]; 5] = [b"sotOS", b"sotos", b"0.1.0", b"sotOS 0.1.0 LUCAS", b"x86_64"];
                    for (i, field) in fields.iter().enumerate() {
                        let off = i * 65;
                        let len = field.len().min(64);
                        buf[off..off + len].copy_from_slice(&field[..len]);
                    }
                }
                reply_val(ep_cap, 0);
            }
            // getuid/getgid/geteuid/getegid
            102 | 104 | 107 | 108 => reply_val(ep_cap, 0),
            // sigaltstack
            131 => {
                let old_ss = msg.regs[1];
                if old_ss != 0 && old_ss < 0x0000_8000_0000_0000 {
                    let buf = unsafe { core::slice::from_raw_parts_mut(old_ss as *mut u8, 24) };
                    for b in buf.iter_mut() { *b = 0; }
                    buf[8..12].copy_from_slice(&2u32.to_le_bytes());
                }
                reply_val(ep_cap, 0);
            }
            // set_tid_address
            218 => reply_val(ep_cap, test_pid as i64),
            // clock_gettime
            228 => {
                let tp_ptr = msg.regs[1];
                if tp_ptr != 0 && tp_ptr < 0x0000_8000_0000_0000 {
                    let elapsed = rdtsc().saturating_sub(BOOT_TSC.load(Ordering::Acquire));
                    let elapsed_ns = elapsed.saturating_mul(10);
                    let tp = unsafe { core::slice::from_raw_parts_mut(tp_ptr as *mut u8, 16) };
                    tp[0..8].copy_from_slice(&((elapsed_ns / 1_000_000_000) as i64).to_le_bytes());
                    tp[8..16].copy_from_slice(&((elapsed_ns % 1_000_000_000) as i64).to_le_bytes());
                }
                reply_val(ep_cap, 0);
            }
            // getrandom
            318 => {
                let buf = msg.regs[0];
                let len = msg.regs[1] as usize;
                if buf != 0 && buf < 0x0000_8000_0000_0000 && len > 0 {
                    let dst = unsafe { core::slice::from_raw_parts_mut(buf as *mut u8, len) };
                    let mut seed = rdtsc();
                    for b in dst.iter_mut() {
                        seed ^= seed << 13; seed ^= seed >> 7; seed ^= seed << 17;
                        *b = seed as u8;
                    }
                }
                reply_val(ep_cap, msg.regs[1] as i64);
            }
            // tkill(tid, sig) — used by raise()/abort()
            200 => {
                // We don't implement signals, just return success
                // so the caller thinks the signal was delivered.
                reply_val(ep_cap, 0);
            }
            // prlimit64
            302 => reply_val(ep_cap, 0),
            // sched_getaffinity — musl sometimes calls this
            204 => reply_val(ep_cap, -38), // -ENOSYS
            // futex — real implementation
            202 => {
                let uaddr = msg.regs[0];
                let op = (msg.regs[1] & 0x7F) as u32;
                let val = msg.regs[2] as u32;
                match op {
                    0 => reply_val(ep_cap, futex_wait(uaddr, val)),
                    1 => reply_val(ep_cap, futex_wake(uaddr, val)),
                    _ => reply_val(ep_cap, 0),
                }
            }
            // readlinkat — /proc/self/exe
            267 => reply_val(ep_cap, -22),
            // Unknown syscall — log and return -ENOSYS
            _ => {
                print(b"MUSL-TEST: unhandled syscall ");
                print_u64(nr);
                print(b"\n");
                reply_val(ep_cap, -38); // -ENOSYS
            }
        }
    }

    print(b"MUSL-TEST: complete\n");
}

/// Run a dynamically-linked musl binary (hello_dynamic) via LUCAS.
/// Tests the dynamic linker loading infrastructure: PT_INTERP, file-backed mmap, etc.
fn run_dynamic_test() {
    print(b"DYNAMIC-TEST: loading hello_dynamic...\n");

    while EXEC_LOCK.compare_exchange(0, 1, Ordering::AcqRel, Ordering::Relaxed).is_err() {
        sys::yield_now();
    }

    let ep_cap = match exec_from_initrd(b"hello_dynamic") {
        Ok((ep, _tc)) => {
            EXEC_LOCK.store(0, Ordering::Release);
            ep
        }
        Err(e) => {
            EXEC_LOCK.store(0, Ordering::Release);
            print(b"DYNAMIC-TEST: failed to load (errno=");
            print_u64((-e) as u64);
            print(b")\n");
            return;
        }
    };

    print(b"DYNAMIC-TEST: running dynamic binary...\n");

    // Re-use child brk/mmap for this test — use a dedicated region
    let mut current_brk: u64 = 0x9000000;
    let mut mmap_next: u64 = 0x9100000;

    // Initrd file tracking
    const DYN_MAX_FDS: usize = 32;
    let mut child_fds = [0u8; DYN_MAX_FDS];
    child_fds[0] = 1; // stdin
    child_fds[1] = 2; // stdout
    child_fds[2] = 2; // stderr

    const DYN_MAX_INITRD_FILES: usize = 8;
    let mut initrd_files: [[u64; 4]; DYN_MAX_INITRD_FILES] = [[0; 4]; DYN_MAX_INITRD_FILES];
    let initrd_file_buf_base: u64 = 0x9200000;

    loop {
        let msg = match sys::recv(ep_cap) {
            Ok(m) => m,
            Err(_) => break,
        };

        let nr = msg.tag;
        match nr {
            // write(fd, buf, len)
            1 => {
                let buf_ptr = msg.regs[1];
                let len = msg.regs[2] as usize;
                if len > 0 && buf_ptr != 0 && buf_ptr < 0x0000_8000_0000_0000 {
                    let data = unsafe { core::slice::from_raw_parts(buf_ptr as *const u8, len) };
                    for &b in data { sys::debug_print(b); unsafe { fb_putchar(b); } }
                }
                reply_val(ep_cap, len as i64);
            }
            // read(fd, buf, len)
            0 => {
                let fd = msg.regs[0] as usize;
                if fd < DYN_MAX_FDS && child_fds[fd] == 12 {
                    // Initrd file read
                    let buf_ptr = msg.regs[1];
                    let len = msg.regs[2] as usize;
                    let mut found = false;
                    for s in 0..DYN_MAX_INITRD_FILES {
                        if initrd_files[s][3] == fd as u64 && initrd_files[s][0] != 0 {
                            let data_base = initrd_files[s][0];
                            let file_size = initrd_files[s][1];
                            let pos = initrd_files[s][2];
                            let avail = if pos < file_size { file_size - pos } else { 0 };
                            let to_read = (len as u64).min(avail) as usize;
                            if to_read > 0 {
                                unsafe {
                                    core::ptr::copy_nonoverlapping(
                                        (data_base + pos) as *const u8,
                                        buf_ptr as *mut u8,
                                        to_read,
                                    );
                                }
                                initrd_files[s][2] = pos + to_read as u64;
                            }
                            reply_val(ep_cap, to_read as i64);
                            found = true;
                            break;
                        }
                    }
                    if !found { reply_val(ep_cap, 0); }
                } else {
                    reply_val(ep_cap, 0); // EOF
                }
            }
            // open(path, flags, mode) — musl dynamic linker uses SYS_open
            2 => {
                let path_ptr = msg.regs[0];
                let mut path = [0u8; 128];
                let path_len = copy_guest_path(path_ptr, &mut path);
                let name = &path[..path_len];

                // Try initrd by basename
                let mut basename_start = 0usize;
                for idx in 0..path_len {
                    if name[idx] == b'/' { basename_start = idx + 1; }
                }
                let basename = &name[basename_start..];

                let mut slot = None;
                for s in 0..DYN_MAX_INITRD_FILES {
                    if initrd_files[s][0] == 0 { slot = Some(s); break; }
                }

                if basename.is_empty() || slot.is_none() {
                    reply_val(ep_cap, -2);
                    continue;
                }
                let slot = slot.unwrap();

                let file_buf = initrd_file_buf_base + (slot as u64) * 0x100000;
                const FILE_BUF_PAGES_DYN: u64 = 256;
                let mut buf_ok = true;
                for p in 0..FILE_BUF_PAGES_DYN {
                    if let Ok(f) = sys::frame_alloc() {
                        if sys::map(file_buf + p * 0x1000, f, MAP_WRITABLE).is_err() {
                            buf_ok = false; break;
                        }
                    } else { buf_ok = false; break; }
                }
                if !buf_ok { reply_val(ep_cap, -12); continue; }

                match sys::initrd_read(
                    basename.as_ptr() as u64,
                    basename.len() as u64,
                    file_buf,
                    FILE_BUF_PAGES_DYN * 0x1000,
                ) {
                    Ok(sz) => {
                        let mut fd = None;
                        for i in 3..DYN_MAX_FDS { if child_fds[i] == 0 { fd = Some(i); break; } }
                        if let Some(f) = fd {
                            child_fds[f] = 12;
                            initrd_files[slot] = [file_buf, sz, 0, f as u64];
                            print(b"DYNAMIC: open(");
                            for &b in basename { sys::debug_print(b); unsafe { fb_putchar(b); } }
                            print(b") = fd ");
                            print_u64(f as u64);
                            print(b" size=");
                            print_u64(sz);
                            print(b"\n");
                            reply_val(ep_cap, f as i64);
                        } else {
                            for p in 0..FILE_BUF_PAGES_DYN { let _ = sys::unmap(file_buf + p * 0x1000); }
                            reply_val(ep_cap, -24);
                        }
                    }
                    Err(_) => {
                        for p in 0..FILE_BUF_PAGES_DYN { let _ = sys::unmap(file_buf + p * 0x1000); }
                        reply_val(ep_cap, -2);
                    }
                }
            }
            // close
            3 => {
                let fd = msg.regs[0] as usize;
                if fd < DYN_MAX_FDS && child_fds[fd] == 12 {
                    for s in 0..DYN_MAX_INITRD_FILES {
                        if initrd_files[s][3] == fd as u64 {
                            initrd_files[s][3] = u64::MAX;
                            break;
                        }
                    }
                }
                if fd < DYN_MAX_FDS { child_fds[fd] = 0; }
                reply_val(ep_cap, 0);
            }
            // fstat
            5 => {
                let fd = msg.regs[0] as usize;
                let stat_ptr = msg.regs[1];
                if fd < DYN_MAX_FDS && child_fds[fd] == 12 {
                    let mut size = 0u64;
                    for s in 0..DYN_MAX_INITRD_FILES {
                        if initrd_files[s][3] == fd as u64 && initrd_files[s][0] != 0 {
                            size = initrd_files[s][1];
                            break;
                        }
                    }
                    write_linux_stat(stat_ptr, fd as u64, size, false);
                } else {
                    write_linux_stat(stat_ptr, fd as u64, 0, false);
                }
                reply_val(ep_cap, 0);
            }
            // poll
            7 => reply_val(ep_cap, 0),
            // mmap(addr, len, prot, flags, fd, offset)
            9 => {
                let req_addr = msg.regs[0];
                let len = msg.regs[1];
                let flags = msg.regs[3] as u32;
                let fd = msg.regs[4] as i64;
                let offset = msg.regs[5];

                let map_fixed = (flags & 0x10) != 0;
                let pages = ((len + 0xFFF) & !0xFFF) / 0x1000;

                let base = if map_fixed && req_addr != 0 {
                    for p in 0..pages { let _ = sys::unmap(req_addr + p * 0x1000); }
                    req_addr
                } else {
                    let b = mmap_next;
                    mmap_next += pages * 0x1000;
                    b
                };

                // Allocate pages
                let mut ok = true;
                for p in 0..pages {
                    if let Ok(f) = sys::frame_alloc() {
                        if sys::map(base + p * 0x1000, f, MAP_WRITABLE).is_err() { ok = false; break; }
                    } else { ok = false; break; }
                }
                if !ok { reply_val(ep_cap, -12); continue; }

                // Zero the region
                unsafe { core::ptr::write_bytes(base as *mut u8, 0, (pages * 0x1000) as usize); }

                // If file-backed, copy data from initrd file
                if fd >= 0 {
                    let fdu = fd as usize;
                    let mut file_data: u64 = 0;
                    let mut file_size: u64 = 0;
                    for s in 0..DYN_MAX_INITRD_FILES {
                        if initrd_files[s][0] != 0 && (initrd_files[s][3] == fdu as u64 || initrd_files[s][3] == u64::MAX) {
                            if initrd_files[s][3] == fdu as u64 {
                                file_data = initrd_files[s][0];
                                file_size = initrd_files[s][1];
                                break;
                            }
                        }
                    }
                    if file_data != 0 {
                        let file_off = offset as usize;
                        let avail = if file_off < file_size as usize { file_size as usize - file_off } else { 0 };
                        let to_copy = ((pages * 0x1000) as usize).min(avail);
                        if to_copy > 0 {
                            unsafe {
                                core::ptr::copy_nonoverlapping(
                                    (file_data + file_off as u64) as *const u8,
                                    base as *mut u8,
                                    to_copy,
                                );
                            }
                        }
                    }
                }

                reply_val(ep_cap, base as i64);
            }
            // mprotect
            10 => reply_val(ep_cap, 0),
            // munmap
            11 => {
                let addr = msg.regs[0];
                let len = msg.regs[1];
                let pages = ((len + 0xFFF) & !0xFFF) / 0x1000;
                for p in 0..pages { let _ = sys::unmap(addr + p * 0x1000); }
                reply_val(ep_cap, 0);
            }
            // brk
            12 => {
                let addr = msg.regs[0];
                if addr == 0 || addr <= current_brk {
                    reply_val(ep_cap, current_brk as i64);
                } else {
                    let new_brk = (addr + 0xFFF) & !0xFFF;
                    let mut pg = (current_brk + 0xFFF) & !0xFFF;
                    let mut ok = true;
                    while pg < new_brk {
                        if let Ok(f) = sys::frame_alloc() {
                            if sys::map(pg, f, MAP_WRITABLE).is_err() { ok = false; break; }
                        } else { ok = false; break; }
                        pg += 0x1000;
                    }
                    if ok { current_brk = new_brk; }
                    reply_val(ep_cap, current_brk as i64);
                }
            }
            // rt_sigaction
            13 => reply_val(ep_cap, 0),
            // rt_sigprocmask
            14 => reply_val(ep_cap, 0),
            // fcntl
            72 => reply_val(ep_cap, 0),
            // getpid
            39 => reply_val(ep_cap, 999),
            // arch_prctl — kernel intercepts, shouldn't reach
            158 => reply_val(ep_cap, 0),
            // set_tid_address
            218 => reply_val(ep_cap, 999),
            // exit / exit_group
            60 | 231 => {
                let status = msg.regs[0] as i64;
                print(b"DYNAMIC-TEST: exited with status ");
                print_u64(status as u64);
                print(b"\n");
                if status == 0 {
                    print(b"DYNAMIC-TEST: SUCCESS -- dynamically-linked musl binary ran under LUCAS!\n");
                } else {
                    print(b"DYNAMIC-TEST: FAILED\n");
                }
                break;
            }
            // Unknown
            _ => {
                print(b"DYNAMIC: unhandled syscall ");
                print_u64(nr);
                print(b"\n");
                reply_val(ep_cap, -38);
            }
        }
    }

    print(b"DYNAMIC-TEST: complete\n");
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

/// Desktop layout constants.
const TASKBAR_HEIGHT: u32 = 32;
const TITLEBAR_HEIGHT: u32 = 24;
const WIN_BORDER: u32 = 2;
const WIN_MARGIN: u32 = 8; // margin from screen edges

/// Desktop layout: computed window positions (set in fb_init).
static mut WIN_X: u32 = 0;
static mut WIN_Y: u32 = 0;
static mut WIN_W: u32 = 0;
static mut WIN_H: u32 = 0;
/// Text area origin (inside the terminal window client area).
static mut TEXT_X: u32 = 0;
static mut TEXT_Y: u32 = 0;

/// Mouse cursor state.
static mut MOUSE_X: i32 = 512;
static mut MOUSE_Y: i32 = 384;
static mut MOUSE_PREV_X: i32 = -1;
static mut MOUSE_PREV_Y: i32 = -1;

// Ring buffer addresses imported from sotos_common::{KB_RING_ADDR, MOUSE_RING_ADDR}.

/// Keyboard state.
static mut KB_SHIFT: bool = false;
static mut KB_CTRL: bool = false;

// ---------------------------------------------------------------------------
// Desktop color palette
// ---------------------------------------------------------------------------
const COL_DESKTOP: u32    = 0xFF285078; // teal blue desktop background
const COL_TASKBAR: u32    = 0xFF1E1E2E; // dark taskbar
const COL_TASKBAR_TXT: u32= 0xFFCDD6F4; // light text on taskbar
const COL_TITLEBAR: u32   = 0xFF3366AA; // blue title bar (active)
const COL_TITLE_TXT: u32  = 0xFFFFFFFF; // white title text
const COL_CLOSE_BG: u32   = 0xFFCC4444; // close button red
const COL_MIN_BG: u32     = 0xFFCCAA44; // minimize button yellow
const COL_BORDER: u32     = 0xFF404060; // window border
const COL_WIN_BG: u32     = 0xFF1A1B26; // dark terminal background
const COL_TEXT: u32        = 0xFFA9B1D6; // terminal text (soft white-blue)
const COL_CURSOR_FG: u32  = 0xFFFFFFFF; // mouse cursor white
const COL_CURSOR_BG: u32  = 0xFF000000; // mouse cursor outline

// ---------------------------------------------------------------------------
// Mouse cursor sprite (16x16)
// ---------------------------------------------------------------------------
const CURSOR_BITMAP: [u16; 16] = [
    0b1000_0000_0000_0000, 0b1100_0000_0000_0000,
    0b1110_0000_0000_0000, 0b1111_0000_0000_0000,
    0b1111_1000_0000_0000, 0b1111_1100_0000_0000,
    0b1111_1110_0000_0000, 0b1111_1111_0000_0000,
    0b1111_1111_1000_0000, 0b1111_1100_0000_0000,
    0b1111_1100_0000_0000, 0b1100_1100_0000_0000,
    0b1000_0110_0000_0000, 0b0000_0110_0000_0000,
    0b0000_0011_0000_0000, 0b0000_0011_0000_0000,
];
const CURSOR_MASK: [u16; 16] = [
    0b1100_0000_0000_0000, 0b1110_0000_0000_0000,
    0b1111_0000_0000_0000, 0b1111_1000_0000_0000,
    0b1111_1100_0000_0000, 0b1111_1110_0000_0000,
    0b1111_1111_0000_0000, 0b1111_1111_1000_0000,
    0b1111_1111_1100_0000, 0b1111_1111_1100_0000,
    0b1111_1110_0000_0000, 0b1110_1111_0000_0000,
    0b1100_0111_0000_0000, 0b0000_0111_1000_0000,
    0b0000_0011_1000_0000, 0b0000_0011_1000_0000,
];

/// Initialize framebuffer console with desktop GUI.
unsafe fn fb_init(boot_info: &BootInfo) {
    FB_PTR = boot_info.fb_addr;
    FB_PITCH = boot_info.fb_pitch;
    FB_WIDTH = boot_info.fb_width;
    FB_HEIGHT = boot_info.fb_height;

    // Compute terminal window geometry.
    WIN_X = WIN_MARGIN;
    WIN_Y = WIN_MARGIN;
    WIN_W = FB_WIDTH - WIN_MARGIN * 2;
    WIN_H = FB_HEIGHT - WIN_MARGIN * 2 - TASKBAR_HEIGHT;

    // Text area starts inside the window (below title bar, inside border).
    TEXT_X = WIN_X + WIN_BORDER + 4;
    TEXT_Y = WIN_Y + TITLEBAR_HEIGHT + WIN_BORDER;

    // Console dimensions based on text area.
    let text_w = WIN_W - (WIN_BORDER + 4) * 2;
    let text_h = WIN_H - TITLEBAR_HEIGHT - WIN_BORDER * 2 - 4;
    CON_COLS = text_w / 8;
    CON_ROWS = text_h / 16;
    CON_CUR_COL = 0;
    CON_CUR_ROW = 0;

    // Initialize mouse ring buffer.
    let _mring = MOUSE_RING_ADDR as *mut u32;
    // Don't init here — only if the page is mapped.

    // Draw the complete desktop.
    fb_draw_desktop();
}

/// Draw the full desktop: background, taskbar, terminal window.
unsafe fn fb_draw_desktop() {
    let fb = FB_PTR as *mut u32;
    let stride = FB_PITCH / 4;

    // 1. Desktop background (gradient teal).
    for y in 0..FB_HEIGHT {
        let r = 20 + (y * 20 / FB_HEIGHT) as u8;
        let g = 50 + (y * 40 / FB_HEIGHT) as u8;
        let b = 80 + (y * 40 / FB_HEIGHT) as u8;
        let col = 0xFF000000 | (r as u32) << 16 | (g as u32) << 8 | b as u32;
        for x in 0..FB_WIDTH {
            *fb.add((y * stride + x) as usize) = col;
        }
    }

    // 2. Taskbar at bottom.
    let tb_y = FB_HEIGHT - TASKBAR_HEIGHT;
    for y in tb_y..FB_HEIGHT {
        for x in 0..FB_WIDTH {
            *fb.add((y * stride + x) as usize) = COL_TASKBAR;
        }
    }
    // Taskbar separator line.
    for x in 0..FB_WIDTH {
        *fb.add((tb_y * stride + x) as usize) = COL_BORDER;
    }
    // "sotOS" branding on taskbar.
    fb_draw_text_at(8, tb_y + 8, b"sotOS", COL_TASKBAR_TXT);
    // Separator.
    fb_draw_text_at(56, tb_y + 8, b"|", COL_BORDER);
    // System info.
    fb_draw_text_at(72, tb_y + 8, b"Terminal", COL_TASKBAR_TXT);

    // 3. Terminal window.
    // Window border.
    fb_fill_rect(WIN_X, WIN_Y, WIN_W, WIN_H, COL_BORDER);
    // Title bar.
    fb_fill_rect(WIN_X + 1, WIN_Y + 1, WIN_W - 2, TITLEBAR_HEIGHT - 1, COL_TITLEBAR);
    // Title text.
    fb_draw_text_at(WIN_X + 8, WIN_Y + 4, b"Terminal - sotOS", COL_TITLE_TXT);
    // Close button [X].
    let close_x = WIN_X + WIN_W - 26;
    fb_fill_rect(close_x, WIN_Y + 1, 25, TITLEBAR_HEIGHT - 1, COL_CLOSE_BG);
    fb_draw_text_at(close_x + 8, WIN_Y + 4, b"X", COL_TITLE_TXT);
    // Minimize button [-].
    let min_x = close_x - 26;
    fb_fill_rect(min_x, WIN_Y + 1, 25, TITLEBAR_HEIGHT - 1, COL_MIN_BG);
    fb_draw_text_at(min_x + 8, WIN_Y + 4, b"-", 0xFF000000);
    // Client area (dark terminal).
    let client_y = WIN_Y + TITLEBAR_HEIGHT;
    let client_h = WIN_H - TITLEBAR_HEIGHT - 1;
    fb_fill_rect(WIN_X + 1, client_y, WIN_W - 2, client_h, COL_WIN_BG);
}

/// Fill a rectangle with a solid color.
unsafe fn fb_fill_rect(x: u32, y: u32, w: u32, h: u32, color: u32) {
    let fb = FB_PTR as *mut u32;
    let stride = FB_PITCH / 4;
    for row in 0..h {
        let py = y + row;
        if py >= FB_HEIGHT { break; }
        for col in 0..w {
            let px = x + col;
            if px >= FB_WIDTH { break; }
            *fb.add((py * stride + px) as usize) = color;
        }
    }
}

/// Draw text at pixel position using VGA 8x16 font.
unsafe fn fb_draw_text_at(x: u32, y: u32, text: &[u8], color: u32) {
    for (i, &ch) in text.iter().enumerate() {
        fb_draw_glyph_at(x + i as u32 * 8, y, ch, color, 0);
    }
}

/// Draw an 8x16 glyph at pixel position (x, y) with foreground color, background 0 = transparent.
unsafe fn fb_draw_glyph_at(px: u32, py: u32, ch: u8, fg: u32, bg: u32) {
    let glyph = &VGA_FONT[(ch as usize) * 16..(ch as usize) * 16 + 16];
    let fb = FB_PTR as *mut u32;
    let stride = FB_PITCH / 4;
    for gy in 0..16u32 {
        let row_byte = glyph[gy as usize];
        let y = py + gy;
        if y >= FB_HEIGHT { break; }
        for gx in 0..8u32 {
            let x = px + gx;
            if x >= FB_WIDTH { break; }
            let is_fg = row_byte & (0x80 >> gx) != 0;
            if is_fg {
                *fb.add((y * stride + x) as usize) = fg;
            } else if bg != 0 {
                *fb.add((y * stride + x) as usize) = bg;
            }
        }
    }
}

/// Draw an 8x16 character glyph at (col, row) position in the terminal text area.
unsafe fn fb_draw_char(col: u32, row: u32, ch: u8) {
    let x = TEXT_X + col * 8;
    let y = TEXT_Y + row * 16;
    fb_draw_glyph_at(x, y, ch, COL_TEXT, COL_WIN_BG);
}

/// Scroll the terminal text area up by one text row (16 pixels).
unsafe fn fb_scroll() {
    let fb = FB_PTR as *mut u8;
    let pitch = FB_PITCH as usize;
    let text_width_bytes = (CON_COLS * 8 * 4) as usize;
    let text_x_bytes = (TEXT_X * 4) as usize;

    for row in 0..(CON_ROWS - 1) {
        for py in 0..16u32 {
            let src_y = (TEXT_Y + (row + 1) * 16 + py) as usize;
            let dst_y = (TEXT_Y + row * 16 + py) as usize;
            let src = fb.add(src_y * pitch + text_x_bytes);
            let dst = fb.add(dst_y * pitch + text_x_bytes);
            core::ptr::copy(src, dst, text_width_bytes);
        }
    }
    // Clear the bottom row.
    let last_row = CON_ROWS - 1;
    for py in 0..16u32 {
        let y = (TEXT_Y + last_row * 16 + py) as usize;
        for col in 0..CON_COLS * 8 {
            let x = TEXT_X as usize + col as usize;
            let fb32 = FB_PTR as *mut u32;
            let stride = FB_PITCH / 4;
            *fb32.add(y * stride as usize + x) = COL_WIN_BG;
        }
    }
}

/// Write a single character to the framebuffer console (inside terminal window).
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

/// Draw the mouse cursor at the current position.
unsafe fn fb_draw_cursor() {
    let fb = FB_PTR as *mut u32;
    let stride = FB_PITCH / 4;
    for row in 0..16usize {
        for col in 0..16usize {
            let px = MOUSE_X + col as i32;
            let py = MOUSE_Y + row as i32;
            if px >= 0 && py >= 0 && (px as u32) < FB_WIDTH && (py as u32) < FB_HEIGHT {
                let bit = 1u16 << (15 - col);
                let offset = (py as u32 * stride + px as u32) as usize;
                if CURSOR_BITMAP[row] & bit != 0 {
                    *fb.add(offset) = COL_CURSOR_FG;
                } else if CURSOR_MASK[row] & bit != 0 {
                    *fb.add(offset) = COL_CURSOR_BG;
                }
            }
        }
    }
}

/// Save pixels under cursor (for restoration when cursor moves).
static mut CURSOR_SAVE: [u32; 256] = [0; 256]; // 16x16

/// Save the pixels under the cursor before drawing it.
unsafe fn fb_save_under_cursor() {
    let fb = FB_PTR as *mut u32;
    let stride = FB_PITCH / 4;
    for row in 0..16usize {
        for col in 0..16usize {
            let px = MOUSE_X + col as i32;
            let py = MOUSE_Y + row as i32;
            if px >= 0 && py >= 0 && (px as u32) < FB_WIDTH && (py as u32) < FB_HEIGHT {
                CURSOR_SAVE[row * 16 + col] = *fb.add((py as u32 * stride + px as u32) as usize);
            }
        }
    }
}

/// Restore pixels from under the old cursor position.
unsafe fn fb_restore_under_cursor(old_x: i32, old_y: i32) {
    let fb = FB_PTR as *mut u32;
    let stride = FB_PITCH / 4;
    for row in 0..16usize {
        for col in 0..16usize {
            let px = old_x + col as i32;
            let py = old_y + row as i32;
            if px >= 0 && py >= 0 && (px as u32) < FB_WIDTH && (py as u32) < FB_HEIGHT {
                let bit = 1u16 << (15 - col);
                if CURSOR_MASK[row] & bit != 0 {
                    *fb.add((py as u32 * stride + px as u32) as usize) = CURSOR_SAVE[row * 16 + col];
                }
            }
        }
    }
}

/// Mouse ring read index (init-side).
static mut MOUSE_READ_IDX: u32 = 0;

/// Poll the mouse ring buffer and update the cursor on screen.
/// Call this frequently (e.g. between yield_now calls) for responsive tracking.
unsafe fn poll_mouse() {
    if FB_PTR == 0 { return; }

    let mring = MOUSE_RING_ADDR as *mut u32;
    let mut moved = false;

    loop {
        let write_idx = core::ptr::read_volatile(mring);
        if MOUSE_READ_IDX == write_idx { break; }

        let idx = (MOUSE_READ_IDX & 63) as usize;
        let base = MOUSE_RING_ADDR + 8 + (idx * 4) as u64;
        let dx = *(base as *const i8);
        let dy = *((base + 1) as *const i8);
        let _buttons = *((base + 2) as *const u8); // mouse buttons (b0=left, b1=right, b2=middle)

        MOUSE_X += dx as i32;
        MOUSE_Y -= dy as i32; // PS/2 Y is inverted

        // Clamp to screen bounds.
        if MOUSE_X < 0 { MOUSE_X = 0; }
        if MOUSE_Y < 0 { MOUSE_Y = 0; }
        if MOUSE_X >= FB_WIDTH as i32 { MOUSE_X = FB_WIDTH as i32 - 1; }
        if MOUSE_Y >= FB_HEIGHT as i32 { MOUSE_Y = FB_HEIGHT as i32 - 1; }

        MOUSE_READ_IDX = (MOUSE_READ_IDX.wrapping_add(1)) & 63;
        moved = true;
    }

    if moved {
        let old_x = MOUSE_PREV_X;
        let old_y = MOUSE_PREV_Y;
        if old_x >= 0 && old_y >= 0 {
            fb_restore_under_cursor(old_x, old_y);
        }
        fb_save_under_cursor();
        fb_draw_cursor();
        MOUSE_PREV_X = MOUSE_X;
        MOUSE_PREV_Y = MOUSE_Y;
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

/// Read one ASCII character from the keyboard ring buffer OR serial (non-blocking).
/// Checks PS/2 keyboard ring first, then falls back to serial input.
/// Handles Shift/Ctrl modifier tracking, returns None if no key available.
/// Buffered byte from serial peek (0 = empty, otherwise byte value).
static KB_PEEK_BUF: AtomicU64 = AtomicU64::new(0);

/// Check if a character is available without consuming it.
unsafe fn kb_has_char() -> bool {
    if KB_PEEK_BUF.load(Ordering::Relaxed) != 0 { return true; }
    if let Some(b) = sys::debug_read() {
        let ch = if b == b'\r' { b'\n' } else { b };
        KB_PEEK_BUF.store(ch as u64, Ordering::Relaxed);
        return true;
    }
    let ring = KB_RING_ADDR as *mut u32;
    let write_idx = core::ptr::read_volatile(ring);
    let read_idx = core::ptr::read_volatile(ring.add(1));
    read_idx != write_idx
}

unsafe fn kb_read_char() -> Option<u8> {
    // Return buffered peek byte first.
    let peeked = KB_PEEK_BUF.swap(0, Ordering::Relaxed);
    if peeked != 0 {
        return Some(peeked as u8);
    }
    // Check serial input first (works in headless mode).
    if let Some(b) = sys::debug_read() {
        // Convert \r to \n for terminal compatibility.
        return Some(if b == b'\r' { b'\n' } else { b });
    }

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

fn init_block_storage(boot_info: &BootInfo) -> Option<VirtioBlk> {
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

    // --- Object Store + VFS init ---
    init_objstore(blk)
}

fn init_objstore(blk: VirtioBlk) -> Option<VirtioBlk> {
    // Try to mount existing filesystem first (preserves data across reboots).
    match ObjectStore::mount(blk) {
        Ok(store) => {
            let mut entries = [DirEntry::zeroed(); DIR_ENTRY_COUNT];
            let count = store.list(&mut entries);
            print(b"OBJSTORE: mounted (");
            print_u64(count as u64);
            print(b" files)\n");
            for i in 0..count {
                print(b"  ");
                print(entries[i].name_as_str());
                print(b" size=");
                print_u64(entries[i].size);
                print(b"\n");
            }
            Some(store.into_blk())
        }
        Err(_) => {
            // No valid filesystem — recover blk and format a new one.
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
// LUCAS handler setup
// ---------------------------------------------------------------------------

/// Address where VirtioBlk is stored for the LUCAS handler (1 page).
const LUCAS_BLK_STORE: u64 = 0xE20000;

/// Flag: VirtioBlk stored and ready at LUCAS_BLK_STORE.
static LUCAS_VFS_READY: AtomicU64 = AtomicU64::new(0);

/// Shared ObjectStore pointer — set by lucas_handler after mount, read by child_handlers.
/// Points to the &'static mut ObjectStore inside the Vfs. 0 = not available.
static SHARED_STORE_PTR: AtomicU64 = AtomicU64::new(0);
/// Spinlock protecting shared ObjectStore access (0=free, 1=held).
static VFS_LOCK: AtomicU64 = AtomicU64::new(0);

fn vfs_lock() {
    while VFS_LOCK.compare_exchange(0, 1, Ordering::AcqRel, Ordering::Relaxed).is_err() {
        sys::yield_now();
    }
}
fn vfs_unlock() {
    VFS_LOCK.store(0, Ordering::Release);
}

/// Get a mutable reference to the shared ObjectStore (caller MUST hold VFS_LOCK).
unsafe fn shared_store() -> Option<&'static mut sotos_objstore::ObjectStore> {
    let ptr = SHARED_STORE_PTR.load(Ordering::Acquire);
    if ptr == 0 { None } else { Some(&mut *(ptr as *mut sotos_objstore::ObjectStore)) }
}

// ---------------------------------------------------------------------------
// LUCAS process table (Phase 10.5) — shared between handler threads
// ---------------------------------------------------------------------------

const MAX_PROCS: usize = 16;

/// Process state: 0=Free, 1=Running, 2=Zombie.
static PROC_STATE: [AtomicU64; MAX_PROCS] = {
    const INIT: AtomicU64 = AtomicU64::new(0);
    [INIT; MAX_PROCS]
};
/// Exit status (valid when Zombie).
static PROC_EXIT: [AtomicU64; MAX_PROCS] = {
    const INIT: AtomicU64 = AtomicU64::new(0);
    [INIT; MAX_PROCS]
};
/// Parent PID (0=none).
static PROC_PARENT: [AtomicU64; MAX_PROCS] = {
    const INIT: AtomicU64 = AtomicU64::new(0);
    [INIT; MAX_PROCS]
};
/// Kernel thread ID (raw) for each LUCAS pid (for async signal injection).
static PROC_KERNEL_TID: [AtomicU64; MAX_PROCS] = {
    const INIT: AtomicU64 = AtomicU64::new(0);
    [INIT; MAX_PROCS]
};
/// Pending signals bitmask per process (bit N = signal N pending).
static SIG_PENDING: [AtomicU64; MAX_PROCS] = {
    const INIT: AtomicU64 = AtomicU64::new(0);
    [INIT; MAX_PROCS]
};
/// Blocked signals bitmask per process (bit N = signal N blocked).
static SIG_BLOCKED: [AtomicU64; MAX_PROCS] = {
    const INIT: AtomicU64 = AtomicU64::new(0);
    [INIT; MAX_PROCS]
};
/// Signal handler addresses per process, 32 signals each.
/// 0 = SIG_DFL, 1 = SIG_IGN, else = user handler address.
static SIG_HANDLER: [[AtomicU64; 32]; MAX_PROCS] = {
    const H: AtomicU64 = AtomicU64::new(0);
    const ROW: [AtomicU64; 32] = [H; 32];
    [ROW; MAX_PROCS]
};
/// Signal flags (SA_RESTART etc.) per process per signal.
static SIG_FLAGS: [[AtomicU64; 32]; MAX_PROCS] = {
    const H: AtomicU64 = AtomicU64::new(0);
    const ROW: [AtomicU64; 32] = [H; 32];
    [ROW; MAX_PROCS]
};
/// Signal handler masks per process per signal (blocked during handler).
static SIG_RESTORER: [[AtomicU64; 32]; MAX_PROCS] = {
    const H: AtomicU64 = AtomicU64::new(0);
    const ROW: [AtomicU64; 32] = [H; 32];
    [ROW; MAX_PROCS]
};

// Signal constants
const SIG_DFL: u64 = 0;
const SIG_IGN: u64 = 1;
const _SIGINT: u64 = 2;
const SIGKILL: u64 = 9;
const SIGCHLD: u64 = 17;
const _SIGTERM: u64 = 15;
const SA_RESTART: u64 = 0x10000000;
const _SA_RESTORER: u64 = 0x04000000;
const _SA_NOCLDSTOP: u64 = 1;
const _SA_NOCLDWAIT: u64 = 2;

/// Default action for a signal: 0=terminate, 1=ignore, 2=stop, 3=continue.
fn sig_default_action(sig: u64) -> u8 {
    match sig {
        1 => 0,  // SIGHUP → terminate
        2 => 0,  // SIGINT → terminate
        3 => 0,  // SIGQUIT → terminate (core)
        4 => 0,  // SIGILL → terminate (core)
        5 => 0,  // SIGTRAP → terminate (core)
        6 => 0,  // SIGABRT → terminate (core)
        7 => 0,  // SIGBUS → terminate (core)
        8 => 0,  // SIGFPE → terminate (core)
        9 => 0,  // SIGKILL → terminate (uncatchable)
        10 => 0, // SIGUSR1 → terminate
        11 => 0, // SIGSEGV → terminate (core)
        12 => 0, // SIGUSR2 → terminate
        13 => 0, // SIGPIPE → terminate
        14 => 0, // SIGALRM → terminate
        15 => 0, // SIGTERM → terminate
        17 => 1, // SIGCHLD → ignore
        18 => 3, // SIGCONT → continue
        19 => 2, // SIGSTOP → stop (uncatchable)
        20 => 2, // SIGTSTP → stop
        21 => 2, // SIGTTIN → stop
        22 => 2, // SIGTTOU → stop
        23 => 0, // SIGURG → ignore (treat as terminate for simplicity)
        _ => 0,  // default: terminate
    }
}

/// Deliver a signal to a process. Sets the pending bit.
fn sig_send(pid: usize, sig: u64) {
    if sig == 0 || sig >= 32 || pid == 0 || pid > MAX_PROCS { return; }
    SIG_PENDING[pid - 1].fetch_or(1 << sig, Ordering::Release);
    // SIGKILL always terminates immediately
    if sig == SIGKILL {
        PROC_EXIT[pid - 1].store(128 + sig, Ordering::Release);
        PROC_STATE[pid - 1].store(2, Ordering::Release);
    }
    // Inject into kernel for async delivery (timer interrupt will redirect to trampoline)
    let tc = PROC_KERNEL_TID[pid - 1].load(Ordering::Acquire);
    if tc != 0 {
        let _ = sys::signal_inject(tc, sig);
    }
}

/// Check pending unblocked signals. Returns the lowest signal number that
/// should be acted on, or 0 if none. Clears the signal from pending.
fn sig_dequeue(pid: usize) -> u64 {
    if pid == 0 || pid > MAX_PROCS { return 0; }
    let idx = pid - 1;
    let pending = SIG_PENDING[idx].load(Ordering::Acquire);
    let blocked = SIG_BLOCKED[idx].load(Ordering::Acquire);
    let actionable = pending & !blocked;
    if actionable == 0 { return 0; }
    // Find lowest set bit
    let sig = actionable.trailing_zeros() as u64;
    // Clear it
    SIG_PENDING[idx].fetch_and(!(1 << sig), Ordering::AcqRel);
    sig
}

/// Process a dequeued signal for a process. Returns:
/// - 0: signal ignored (continue normally)
/// - 1: process should be terminated
/// - 2: return -EINTR to current syscall
/// - 3: signal has a user handler → caller should call signal_deliver()
fn sig_dispatch(pid: usize, sig: u64) -> u8 {
    if sig == 0 || sig >= 32 || pid == 0 || pid > MAX_PROCS { return 0; }
    let idx = pid - 1;

    // SIGKILL/SIGSTOP cannot be caught or ignored
    if sig == SIGKILL {
        PROC_EXIT[idx].store(128 + sig, Ordering::Release);
        PROC_STATE[idx].store(2, Ordering::Release);
        return 1;
    }

    let handler = SIG_HANDLER[idx][sig as usize].load(Ordering::Acquire);

    match handler {
        SIG_DFL => {
            // Apply default action
            match sig_default_action(sig) {
                0 => {
                    // Terminate
                    PROC_EXIT[idx].store(128 + sig, Ordering::Release);
                    PROC_STATE[idx].store(2, Ordering::Release);
                    1
                }
                1 => 0, // Ignore
                2 => 0, // Stop (not implemented, treat as ignore)
                3 => 0, // Continue (not implemented, treat as ignore)
                _ => 0,
            }
        }
        SIG_IGN => 0, // Explicitly ignored
        _handler_addr => {
            // User handler registered — deliver via signal frame injection
            3
        }
    }
}

/// Deliver a signal to a child process by building a SignalFrame on the
/// child's user stack and replying with SIG_REDIRECT_TAG.
///
/// `ep_cap`: the IPC endpoint to reply on
/// `pid`: process slot (1-based)
/// `sig`: signal number to deliver
/// `child_tid`: kernel thread ID of the child
/// `syscall_ret`: the original syscall return value (saved in signal frame)
///
/// Returns true if delivery succeeded (caller should NOT send another reply).
fn signal_deliver(ep_cap: u64, pid: usize, sig: u64, child_tid: u64, syscall_ret: i64, is_async: bool) -> bool {
    if sig == 0 || sig >= 32 || pid == 0 || pid > MAX_PROCS { return false; }
    let idx = pid - 1;

    let handler = SIG_HANDLER[idx][sig as usize].load(Ordering::Acquire);
    let restorer = SIG_RESTORER[idx][sig as usize].load(Ordering::Acquire);

    if handler <= 1 { return false; } // SIG_DFL or SIG_IGN — can't deliver

    // Need a restorer (sa_restorer) — musl always sets one via SA_RESTORER.
    // If not set, we can't return from the handler. Use a fallback that just
    // calls rt_sigreturn directly.
    let restorer_addr = if restorer != 0 {
        restorer
    } else {
        // No restorer — the handler can't return cleanly. Skip delivery.
        return false;
    };

    // Read the child's saved register state from the kernel
    let mut saved_regs = [0u64; 18];
    if sys::get_thread_regs(child_tid, &mut saved_regs).is_err() {
        return false;
    }

    // saved_regs layout: [rax,rbx,rcx,rdx,rsi,rdi,rbp,r8..r15,rsp,fs_base,rflags_or_0]
    let saved_rax = saved_regs[0];
    let saved_rbx = saved_regs[1];
    let saved_rcx = saved_regs[2]; // user RIP (from SYSCALL: rcx = rip)
    let saved_rdx = saved_regs[3];
    let saved_rsi = saved_regs[4];
    let saved_rdi = saved_regs[5];
    let saved_rbp = saved_regs[6];
    let saved_r8  = saved_regs[7];
    let saved_r9  = saved_regs[8];
    let saved_r10 = saved_regs[9];
    let saved_r11 = saved_regs[10]; // user RFLAGS (from SYSCALL: r11 = rflags)
    let saved_r12 = saved_regs[11];
    let saved_r13 = saved_regs[12];
    let saved_r14 = saved_regs[13];
    let saved_r15 = saved_regs[14];
    let saved_rsp = saved_regs[15];
    let saved_fsbase = saved_regs[16];
    // saved_regs[17] may hold rflags for async signals

    // For the signal frame, rip and rflags:
    let saved_rip = saved_rcx;    // rcx holds user RIP for SYSCALL
    let saved_rflags = saved_r11; // r11 holds user RFLAGS for SYSCALL

    // For sync signals: use the syscall return value (what rax would have been).
    // For async signals: use the actual user rax at interrupt time.
    let frame_rax = if is_async { saved_rax } else { syscall_ret as u64 };

    // Compute new RSP for signal frame (below current user RSP, 16-byte aligned - 8)
    let frame_size = sotos_common::SIGNAL_FRAME_SIZE as u64;
    let new_rsp = ((saved_rsp - frame_size) & !0xF) - 8;

    // Write the SignalFrame onto the child's user stack
    // (LUCAS has access to child's pages at the same virtual addresses)
    let frame_ptr = new_rsp as *mut u64;
    unsafe {
        core::ptr::write_volatile(frame_ptr.add(0),  restorer_addr);  // restorer
        core::ptr::write_volatile(frame_ptr.add(1),  sig);            // signo
        core::ptr::write_volatile(frame_ptr.add(2),  frame_rax);      // rax (syscall return)
        core::ptr::write_volatile(frame_ptr.add(3),  saved_rbx);      // rbx
        core::ptr::write_volatile(frame_ptr.add(4),  saved_rcx);      // rcx
        core::ptr::write_volatile(frame_ptr.add(5),  saved_rdx);      // rdx
        core::ptr::write_volatile(frame_ptr.add(6),  saved_rsi);      // rsi
        core::ptr::write_volatile(frame_ptr.add(7),  saved_rdi);      // rdi
        core::ptr::write_volatile(frame_ptr.add(8),  saved_rbp);      // rbp
        core::ptr::write_volatile(frame_ptr.add(9),  saved_r8);       // r8
        core::ptr::write_volatile(frame_ptr.add(10), saved_r9);       // r9
        core::ptr::write_volatile(frame_ptr.add(11), saved_r10);      // r10
        core::ptr::write_volatile(frame_ptr.add(12), saved_r11);      // r11
        core::ptr::write_volatile(frame_ptr.add(13), saved_r12);      // r12
        core::ptr::write_volatile(frame_ptr.add(14), saved_r13);      // r13
        core::ptr::write_volatile(frame_ptr.add(15), saved_r14);      // r14
        core::ptr::write_volatile(frame_ptr.add(16), saved_r15);      // r15
        core::ptr::write_volatile(frame_ptr.add(17), saved_rip);      // rip
        core::ptr::write_volatile(frame_ptr.add(18), saved_rsp);      // rsp
        core::ptr::write_volatile(frame_ptr.add(19), saved_rflags);   // rflags
        core::ptr::write_volatile(frame_ptr.add(20), saved_fsbase);   // fs_base
        // old_sigmask: save current mask, then apply sa_mask
        let old_mask = SIG_BLOCKED[idx].load(Ordering::Acquire);
        core::ptr::write_volatile(frame_ptr.add(21), old_mask);       // old_sigmask
    }

    // Block the signal during handler execution (add to blocked mask)
    let cur_mask = SIG_BLOCKED[idx].load(Ordering::Acquire);
    SIG_BLOCKED[idx].store(cur_mask | (1 << sig), Ordering::Release);

    // Reply with SIG_REDIRECT_TAG to redirect the child to the handler
    let reply = sotos_common::IpcMsg {
        tag: sotos_common::SIG_REDIRECT_TAG,
        regs: [
            handler,      // regs[0] = new RIP (handler address)
            sig,          // regs[1] = signal number (RDI = arg0)
            0,            // regs[2] = &siginfo (RSI = arg1, 0 for now)
            0,            // regs[3] = &ucontext (RDX = arg2, 0 for now)
            new_rsp,      // regs[4] = new RSP (below signal frame)
            0, 0, 0,
        ],
    };
    let _ = sys::send(ep_cap, &reply);
    true
}
/// Boot TSC value for uptime calculation.
static BOOT_TSC: AtomicU64 = AtomicU64::new(0);

/// Next PID to allocate (monotonically increasing, starts at 1).
static NEXT_PID: AtomicU64 = AtomicU64::new(1);
/// Next vaddr for child stacks (guest + handler interleaved, 0x2000 apart).
/// Range: 0xE30000..0x2000000 (safe: BRK_BASE is at 0x2000000).
static NEXT_CHILD_STACK: AtomicU64 = AtomicU64::new(0xE30000);

// Handshake statics for passing setup info to child handler thread.
static CHILD_SETUP_EP: AtomicU64 = AtomicU64::new(0);
static CHILD_SETUP_PID: AtomicU64 = AtomicU64::new(0);
static CHILD_SETUP_READY: AtomicU64 = AtomicU64::new(0);
static CHILD_SETUP_FLAGS: AtomicU64 = AtomicU64::new(0);

// ---------------------------------------------------------------------------
// Phase 4: Thread groups, shared FD tables, and futex
// ---------------------------------------------------------------------------

// Clone flag constants (Linux ABI)
const CLONE_VM: u64 = 0x00000100;
const _CLONE_FS: u64 = 0x00000200;
const CLONE_FILES: u64 = 0x00000400;
const CLONE_SIGHAND: u64 = 0x00000800;
const CLONE_THREAD: u64 = 0x00010000;
const CLONE_SETTLS: u64 = 0x00080000;
const CLONE_PARENT_SETTID: u64 = 0x00100000;
const CLONE_CHILD_CLEARTID: u64 = 0x00200000;
const _CLONE_DETACHED: u64 = 0x00400000;
const _CLONE_SYSVSEM: u64 = 0x00040000;

/// Thread group ID per process slot. tgid = pid for leaders, tgid = leader's pid for threads.
static PROC_TGID: [AtomicU64; MAX_PROCS] = {
    const INIT: AtomicU64 = AtomicU64::new(0);
    [INIT; MAX_PROCS]
};
/// FD group index for each process (threads with CLONE_FILES share the same group).
static PROC_FD_GROUP: [AtomicU64; MAX_PROCS] = {
    const INIT: AtomicU64 = AtomicU64::new(0);
    [INIT; MAX_PROCS]
};
/// Memory group index (threads with CLONE_VM share brk/mmap state).
static PROC_MEM_GROUP: [AtomicU64; MAX_PROCS] = {
    const INIT: AtomicU64 = AtomicU64::new(0);
    [INIT; MAX_PROCS]
};
/// Signal handler group (threads with CLONE_SIGHAND share signal handlers).
static PROC_SIG_GROUP: [AtomicU64; MAX_PROCS] = {
    const INIT: AtomicU64 = AtomicU64::new(0);
    [INIT; MAX_PROCS]
};
/// clear_child_tid pointer (CLONE_CHILD_CLEARTID): on exit, *ptr = 0 + futex_wake.
static PROC_CLEAR_TID: [AtomicU64; MAX_PROCS] = {
    const INIT: AtomicU64 = AtomicU64::new(0);
    [INIT; MAX_PROCS]
};

// Per-group shared FD tables (protected by GRP_FD_LOCK spinlock).
// Each "group" corresponds to a thread group (process). Threads sharing
// CLONE_FILES point to the same group index.
// Uses `static mut` raw arrays for direct mutable reference compatibility
// with existing child_handler code. All mutations must hold the group lock.
const GRP_MAX_FDS: usize = 32;
const GRP_MAX_INITRD: usize = 8;
const GRP_MAX_VFS: usize = 8;

/// FD kind per slot: 0=free, 1=stdin, 2=stdout, 8=devnull, 9=devzero, 12=initrd, 13=vfs, 14=vfsdir.
static mut GRP_FDS: [[u8; GRP_MAX_FDS]; MAX_PROCS] = [[0; GRP_MAX_FDS]; MAX_PROCS];
/// Initrd file tracking per group: [data_vaddr, file_size, read_position, fd_index].
static mut GRP_INITRD: [[[u64; 4]; GRP_MAX_INITRD]; MAX_PROCS] = [[[0; 4]; GRP_MAX_INITRD]; MAX_PROCS];
/// VFS file tracking per group: [oid, size, position, fd_index].
static mut GRP_VFS: [[[u64; 4]; GRP_MAX_VFS]; MAX_PROCS] = [[[0; 4]; GRP_MAX_VFS]; MAX_PROCS];
/// Directory listing buffer per group.
static mut GRP_DIR_BUF: [[u8; 1024]; MAX_PROCS] = [[0; 1024]; MAX_PROCS];
/// Directory listing length per group.
static mut GRP_DIR_LEN: [usize; MAX_PROCS] = [0; MAX_PROCS];
/// Directory listing position per group.
static mut GRP_DIR_POS: [usize; MAX_PROCS] = [0; MAX_PROCS];

/// Spinlock per FD group (protects all GRP_ arrays for that group).
static GRP_FD_LOCK: [AtomicU64; MAX_PROCS] = {
    const INIT: AtomicU64 = AtomicU64::new(0);
    [INIT; MAX_PROCS]
};

/// Shared brk state per memory group.
static mut GRP_BRK: [u64; MAX_PROCS] = [0; MAX_PROCS];
/// Shared mmap_next state per memory group.
static mut GRP_MMAP_NEXT: [u64; MAX_PROCS] = [0; MAX_PROCS];
/// Initrd file buf base per memory group.
static mut GRP_INITRD_BUF_BASE: [u64; MAX_PROCS] = [0; MAX_PROCS];

// ---------------------------------------------------------------------------
// Futex wait queue (Phase 4)
// ---------------------------------------------------------------------------
const MAX_FUTEX_WAITERS: usize = 64;
/// Address being waited on (0 = free slot).
static FUTEX_ADDR: [AtomicU64; MAX_FUTEX_WAITERS] = {
    const INIT: AtomicU64 = AtomicU64::new(0);
    [INIT; MAX_FUTEX_WAITERS]
};
/// Wake flag: 1 = woken. Waiter spins until this is set.
static FUTEX_WOKEN: [AtomicU64; MAX_FUTEX_WAITERS] = {
    const INIT: AtomicU64 = AtomicU64::new(0);
    [INIT; MAX_FUTEX_WAITERS]
};

/// Lock a FD group spinlock.
fn fd_grp_lock(g: usize) {
    while GRP_FD_LOCK[g].compare_exchange(0, 1, Ordering::AcqRel, Ordering::Relaxed).is_err() {
        sys::yield_now();
    }
}
/// Unlock a FD group spinlock.
fn fd_grp_unlock(g: usize) {
    GRP_FD_LOCK[g].store(0, Ordering::Release);
}

/// Initialize a FD group with default stdin/stdout/stderr.
fn fd_grp_init(g: usize) {
    unsafe {
        GRP_FDS[g] = [0; GRP_MAX_FDS];
        GRP_FDS[g][0] = 1; // stdin
        GRP_FDS[g][1] = 2; // stdout
        GRP_FDS[g][2] = 2; // stderr
        GRP_INITRD[g] = [[0; 4]; GRP_MAX_INITRD];
        GRP_VFS[g] = [[0; 4]; GRP_MAX_VFS];
        GRP_DIR_BUF[g] = [0; 1024];
        GRP_DIR_LEN[g] = 0;
        GRP_DIR_POS[g] = 0;
    }
}

/// Initialize process group state for a new process (leader).
fn proc_group_init(pid: usize) {
    let idx = pid - 1;
    PROC_TGID[idx].store(pid as u64, Ordering::Release);
    PROC_FD_GROUP[idx].store(idx as u64, Ordering::Release);
    PROC_MEM_GROUP[idx].store(idx as u64, Ordering::Release);
    PROC_SIG_GROUP[idx].store(idx as u64, Ordering::Release);
    PROC_CLEAR_TID[idx].store(0, Ordering::Release);
    fd_grp_init(idx);
}

/// Initialize process group state for a thread (CLONE_THREAD).
/// Shares parent's groups based on clone flags.
fn proc_thread_init(child_pid: usize, parent_pid: usize, flags: u64) {
    let cidx = child_pid - 1;
    let pidx = parent_pid - 1;

    // Thread group: if CLONE_THREAD, share parent's tgid
    if flags & CLONE_THREAD != 0 {
        let parent_tgid = PROC_TGID[pidx].load(Ordering::Acquire);
        PROC_TGID[cidx].store(parent_tgid, Ordering::Release);
    } else {
        PROC_TGID[cidx].store(child_pid as u64, Ordering::Release);
    }

    // FD group: if CLONE_FILES, share parent's FD table
    if flags & CLONE_FILES != 0 {
        let parent_fdg = PROC_FD_GROUP[pidx].load(Ordering::Acquire);
        PROC_FD_GROUP[cidx].store(parent_fdg, Ordering::Release);
    } else {
        PROC_FD_GROUP[cidx].store(cidx as u64, Ordering::Release);
        fd_grp_init(cidx);
    }

    // Memory group: if CLONE_VM, share parent's brk/mmap state
    if flags & CLONE_VM != 0 {
        let parent_memg = PROC_MEM_GROUP[pidx].load(Ordering::Acquire);
        PROC_MEM_GROUP[cidx].store(parent_memg, Ordering::Release);
    } else {
        PROC_MEM_GROUP[cidx].store(cidx as u64, Ordering::Release);
    }

    // Signal handler group: if CLONE_SIGHAND, share parent's signal handlers
    if flags & CLONE_SIGHAND != 0 {
        let parent_sigg = PROC_SIG_GROUP[pidx].load(Ordering::Acquire);
        PROC_SIG_GROUP[cidx].store(parent_sigg, Ordering::Release);
    } else {
        PROC_SIG_GROUP[cidx].store(cidx as u64, Ordering::Release);
    }

    PROC_CLEAR_TID[cidx].store(0, Ordering::Release);
}

// Futex operations

/// FUTEX_WAIT: if *addr == expected, block until woken. Returns 0 on wake, -EAGAIN if mismatch.
fn futex_wait(addr: u64, expected: u32) -> i64 {
    // Find a free slot and register
    let mut slot = usize::MAX;
    for i in 0..MAX_FUTEX_WAITERS {
        if FUTEX_ADDR[i].compare_exchange(0, addr, Ordering::AcqRel, Ordering::Relaxed).is_ok() {
            FUTEX_WOKEN[i].store(0, Ordering::Release);
            slot = i;
            break;
        }
    }
    if slot == usize::MAX {
        return -12; // -ENOMEM (no free slots)
    }

    // Check the value AFTER registering (to avoid missing a wake between check and register)
    let current = unsafe { core::ptr::read_volatile(addr as *const u32) };
    if current != expected {
        FUTEX_ADDR[slot].store(0, Ordering::Release);
        return -11; // -EAGAIN
    }

    // Spin-wait until woken (with yield to avoid burning CPU)
    let mut spins = 0u64;
    while FUTEX_WOKEN[slot].load(Ordering::Acquire) == 0 {
        sys::yield_now();
        spins += 1;
        // Safety timeout: ~10 seconds at 100Hz scheduler
        if spins > 10_000 {
            FUTEX_ADDR[slot].store(0, Ordering::Release);
            return -110; // -ETIMEDOUT
        }
    }

    // Clean up slot
    FUTEX_ADDR[slot].store(0, Ordering::Release);
    0
}

/// FUTEX_WAKE: wake up to `count` waiters on addr. Returns number actually woken.
fn futex_wake(addr: u64, count: u32) -> i64 {
    let mut woken = 0u32;
    for i in 0..MAX_FUTEX_WAITERS {
        if woken >= count { break; }
        if FUTEX_ADDR[i].load(Ordering::Acquire) == addr {
            FUTEX_WOKEN[i].store(1, Ordering::Release);
            woken += 1;
        }
    }
    woken as i64
}

/// Spinlock for serializing execve ELF loading (shared temp buffer).
static EXEC_LOCK: AtomicU64 = AtomicU64::new(0);
/// Temp buffer for execve ELF loading (separate from SPAWN/DL buffers).
const EXEC_BUF_BASE: u64 = 0x5400000;
const EXEC_BUF_PAGES: u64 = 128; // 512 KiB
const EXEC_TEMP_MAP: u64 = 0x5480000; // past EXEC_BUF_BASE + 128*4K
/// Temp buffer for loading the interpreter ELF (for dynamic binaries).
const INTERP_BUF_BASE: u64 = 0xA000000; // Far from other regions
const INTERP_BUF_PAGES: u64 = 220; // ~900 KiB, enough for ld-musl (~845 KiB)
/// Load base for the dynamic interpreter (ET_DYN, position-independent).
const INTERP_LOAD_BASE: u64 = 0x6000000;

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

/// Map ELF PT_LOAD segments from a buffer into the current address space.
/// For ET_DYN (position-independent), vaddrs are offset by `base`.
/// For ET_EXEC, `base` should be 0.
/// `buf_base` is the virtual address where the ELF file data is mapped.
fn map_elf_segments(
    buf_base: u64,
    elf_info: &sotos_common::elf::ElfInfo,
    segments: &[sotos_common::elf::LoadSegment; sotos_common::elf::MAX_LOAD_SEGMENTS],
    seg_count: usize,
    base: u64,
) -> Result<(), i64> {
    for si in 0..seg_count {
        let seg = &segments[si];
        if seg.memsz == 0 { continue; }
        let load_vaddr = base + seg.vaddr;
        let seg_start = load_vaddr & !0xFFF;
        let seg_end = (load_vaddr + seg.memsz as u64 + 0xFFF) & !0xFFF;
        let is_writable = (seg.flags & 2) != 0;

        let mut page_vaddr = seg_start;
        while page_vaddr < seg_end {
            let frame_cap = sys::frame_alloc().map_err(|_| -12i64)?;

            // Map temporarily to copy data
            if sys::map(EXEC_TEMP_MAP, frame_cap, MAP_WRITABLE).is_err() {
                return Err(-12);
            }

            unsafe { core::ptr::write_bytes(EXEC_TEMP_MAP as *mut u8, 0, 4096); }

            // Copy file data for this page
            let page_start = page_vaddr;
            let page_end = page_vaddr + 4096;
            let file_region_start = load_vaddr;
            let file_region_end = load_vaddr + seg.filesz as u64;
            let copy_start = page_start.max(file_region_start);
            let copy_end = page_end.min(file_region_end);

            if copy_start < copy_end {
                let dst_offset = (copy_start - page_start) as usize;
                let src_offset = seg.offset + (copy_start - load_vaddr) as usize;
                let count = (copy_end - copy_start) as usize;
                unsafe {
                    core::ptr::copy_nonoverlapping(
                        (buf_base as *const u8).add(src_offset),
                        (EXEC_TEMP_MAP as *mut u8).add(dst_offset),
                        count,
                    );
                }
            }

            let _ = sys::unmap(EXEC_TEMP_MAP);

            let flags = if is_writable { MAP_WRITABLE } else { 0 };
            if sys::map(page_vaddr, frame_cap, flags).is_err() {
                return Err(-12);
            }

            page_vaddr += 4096;
        }
    }
    Ok(())
}

/// Map a temporary buffer for reading ELF files from initrd.
fn map_temp_buf(base: u64, pages: u64) -> Result<(), i64> {
    for i in 0..pages {
        let f = sys::frame_alloc().map_err(|_| -12i64)?;
        if sys::map(base + i * 0x1000, f, MAP_WRITABLE).is_err() {
            for j in 0..i { let _ = sys::unmap(base + j * 0x1000); }
            return Err(-12);
        }
    }
    Ok(())
}

/// Unmap a temporary buffer.
fn unmap_temp_buf(base: u64, pages: u64) {
    for i in 0..pages { let _ = sys::unmap(base + i * 0x1000); }
}

/// Load an ELF from initrd into the current address space, create a thread
/// with syscall redirect, and return the new endpoint cap.
/// Supports both static (ET_EXEC) and dynamic (ET_DYN with PT_INTERP) binaries.
/// Caller must hold EXEC_LOCK.
fn exec_from_initrd(bin_name: &[u8]) -> Result<(u64, u64), i64> {
    use sotos_common::elf;

    // Step 1: Map temp buffer and read main ELF
    map_temp_buf(EXEC_BUF_BASE, EXEC_BUF_PAGES)?;

    let file_size = match sys::initrd_read(
        bin_name.as_ptr() as u64,
        bin_name.len() as u64,
        EXEC_BUF_BASE,
        EXEC_BUF_PAGES * 0x1000,
    ) {
        Ok(sz) => sz as usize,
        Err(_) => {
            unmap_temp_buf(EXEC_BUF_BASE, EXEC_BUF_PAGES);
            return Err(-2);
        }
    };

    // Step 2: Parse main ELF
    let elf_data = unsafe { core::slice::from_raw_parts(EXEC_BUF_BASE as *const u8, file_size) };
    let elf_info = match elf::parse(elf_data) {
        Ok(info) => info,
        Err(_) => {
            unmap_temp_buf(EXEC_BUF_BASE, EXEC_BUF_PAGES);
            return Err(-8);
        }
    };

    let mut segments = [const { elf::LoadSegment { offset: 0, vaddr: 0, filesz: 0, memsz: 0, flags: 0 } }; elf::MAX_LOAD_SEGMENTS];
    let seg_count = elf::load_segments(elf_data, &elf_info, &mut segments);

    // Step 3: Check for PT_INTERP (dynamic binary)
    let interp_info = elf::parse_interp(elf_data, &elf_info);
    let is_dynamic = interp_info.is_some();

    // For ET_DYN main binary, we load it at a fixed base to avoid address 0
    let main_base: u64 = if elf_info.elf_type == 3 { 0x400000 } else { 0 };

    // Step 4: Map main binary segments
    if let Err(e) = map_elf_segments(EXEC_BUF_BASE, &elf_info, &segments, seg_count, main_base) {
        unmap_temp_buf(EXEC_BUF_BASE, EXEC_BUF_PAGES);
        return Err(e);
    }

    // Step 5: If dynamic, load the interpreter too
    let mut exec_entry = main_base + elf_info.entry;
    let mut interp_base: u64 = 0;

    if let Some(ref interp) = interp_info {
        // Extract interpreter filename (basename from path like /lib/ld-musl-x86_64.so.1)
        // Copy to stack buffer before we potentially use the exec buf for anything else
        let mut interp_name_buf = [0u8; 64];
        let interp_path = &elf_data[interp.offset..interp.offset + interp.len];
        let mut basename_start = 0;
        for idx in 0..interp.len {
            if interp_path[idx] == b'/' { basename_start = idx + 1; }
        }
        let interp_name_len = interp.len - basename_start;
        let safe_len = interp_name_len.min(63);
        interp_name_buf[..safe_len].copy_from_slice(&interp_path[basename_start..basename_start + safe_len]);
        let interp_name = &interp_name_buf[..safe_len];

        // Map interpreter buffer and read from initrd
        if let Err(e) = map_temp_buf(INTERP_BUF_BASE, INTERP_BUF_PAGES) {
            unmap_temp_buf(EXEC_BUF_BASE, EXEC_BUF_PAGES);
            return Err(e);
        }

        let interp_size = match sys::initrd_read(
            interp_name.as_ptr() as u64,
            interp_name.len() as u64,
            INTERP_BUF_BASE,
            INTERP_BUF_PAGES * 0x1000,
        ) {
            Ok(sz) => sz as usize,
            Err(_) => {
                print(b"EXEC: interpreter not found in initrd\n");
                unmap_temp_buf(INTERP_BUF_BASE, INTERP_BUF_PAGES);
                unmap_temp_buf(EXEC_BUF_BASE, EXEC_BUF_PAGES);
                return Err(-2);
            }
        };

        let interp_data = unsafe { core::slice::from_raw_parts(INTERP_BUF_BASE as *const u8, interp_size) };
        let interp_elf = match elf::parse(interp_data) {
            Ok(info) => info,
            Err(_) => {
                unmap_temp_buf(INTERP_BUF_BASE, INTERP_BUF_PAGES);
                unmap_temp_buf(EXEC_BUF_BASE, EXEC_BUF_PAGES);
                return Err(-8);
            }
        };

        let mut interp_segs = [const { elf::LoadSegment { offset: 0, vaddr: 0, filesz: 0, memsz: 0, flags: 0 } }; elf::MAX_LOAD_SEGMENTS];
        let interp_seg_count = elf::load_segments(interp_data, &interp_elf, &mut interp_segs);

        // Load interpreter at INTERP_LOAD_BASE (it's ET_DYN, position-independent)
        interp_base = INTERP_LOAD_BASE;
        if let Err(e) = map_elf_segments(INTERP_BUF_BASE, &interp_elf, &interp_segs, interp_seg_count, interp_base) {
            unmap_temp_buf(INTERP_BUF_BASE, INTERP_BUF_PAGES);
            unmap_temp_buf(EXEC_BUF_BASE, EXEC_BUF_PAGES);
            return Err(e);
        }

        // Execution starts at interpreter's entry point
        exec_entry = interp_base + interp_elf.entry;

        unmap_temp_buf(INTERP_BUF_BASE, INTERP_BUF_PAGES);
    }

    // Step 6: Allocate stack (4 pages)
    let stack_addr = NEXT_CHILD_STACK.fetch_add(0x4000, Ordering::SeqCst);
    for pg in 0..4u64 {
        let f = sys::frame_alloc().map_err(|_| -12i64)?;
        if sys::map(stack_addr + pg * 0x1000, f, MAP_WRITABLE).is_err() {
            unmap_temp_buf(EXEC_BUF_BASE, EXEC_BUF_PAGES);
            return Err(-12);
        }
    }

    // Step 7: Set up Linux-style initial stack
    let stack_top = stack_addr + 0x4000;

    // Write program name string and AT_RANDOM data at top of stack
    let name_len = bin_name.len();
    let name_start = stack_top - 256;
    unsafe {
        let dst = name_start as *mut u8;
        core::ptr::copy_nonoverlapping(bin_name.as_ptr(), dst, name_len);
        *dst.add(name_len) = 0;
    }

    // Write 16 bytes of pseudo-random data for AT_RANDOM
    let random_addr = name_start + 128;
    unsafe {
        let rp = random_addr as *mut u64;
        let mut seed = rdtsc();
        seed ^= seed << 13; seed ^= seed >> 7; seed ^= seed << 17;
        *rp = seed;
        seed ^= seed << 13; seed ^= seed >> 7; seed ^= seed << 17;
        *rp.add(1) = seed;
    }

    // Find phdr vaddr for main binary
    let elf_base = main_base + if seg_count > 0 { segments[0].vaddr & !0xFFF } else { 0 };
    let phdr_vaddr = elf_base + elf_info.phoff as u64;

    // Write environment strings just below the program name
    let env_term = b"TERM=xterm\0";
    let env_home = b"HOME=/\0";
    let env_terminfo = b"TERMINFO=/usr/share/terminfo\0";
    let env_term_addr = random_addr + 16;
    let env_home_addr = env_term_addr + env_term.len() as u64;
    let env_terminfo_addr = env_home_addr + env_home.len() as u64;
    unsafe {
        core::ptr::copy_nonoverlapping(env_term.as_ptr(), env_term_addr as *mut u8, env_term.len());
        core::ptr::copy_nonoverlapping(env_home.as_ptr(), env_home_addr as *mut u8, env_home.len());
        core::ptr::copy_nonoverlapping(env_terminfo.as_ptr(), env_terminfo_addr as *mut u8, env_terminfo.len());
    }

    // Build auxv — AT_SYSINFO_EHDR for vDSO, AT_BASE for dynamic binaries
    // auxv pairs: PHDR, PHENT, PHNUM, PAGESZ, RANDOM, ENTRY, SYSINFO_EHDR, [BASE], NULL
    let auxv_pairs: u64 = if is_dynamic { 9 } else { 8 };
    let env_count: u64 = 3; // TERM, HOME, TERMINFO
    let entries: u64 = 4 + env_count + auxv_pairs * 2; // argc + argv[0] + NULL + env[0..n] + NULL + auxv
    let rsp = (name_start - entries * 8) & !0xF;

    unsafe {
        let sp = rsp as *mut u64;
        let mut i: usize = 0;
        // argc
        *sp.add(i) = 1; i += 1;
        // argv[0]
        *sp.add(i) = name_start; i += 1;
        // argv terminator
        *sp.add(i) = 0; i += 1;
        // envp[0] = TERM=xterm
        *sp.add(i) = env_term_addr; i += 1;
        // envp[1] = HOME=/
        *sp.add(i) = env_home_addr; i += 1;
        // envp[2] = TERMINFO=/usr/share/terminfo
        *sp.add(i) = env_terminfo_addr; i += 1;
        // envp terminator
        *sp.add(i) = 0; i += 1;
        // AT_PHDR(3)
        *sp.add(i) = 3; i += 1;
        *sp.add(i) = phdr_vaddr; i += 1;
        // AT_PHENT(4) = 56
        *sp.add(i) = 4; i += 1;
        *sp.add(i) = 56; i += 1;
        // AT_PHNUM(5)
        *sp.add(i) = 5; i += 1;
        *sp.add(i) = elf_info.phnum as u64; i += 1;
        // AT_PAGESZ(6)
        *sp.add(i) = 6; i += 1;
        *sp.add(i) = 4096; i += 1;
        // AT_RANDOM(25)
        *sp.add(i) = 25; i += 1;
        *sp.add(i) = random_addr; i += 1;
        // AT_ENTRY(9) = main binary's entry (not interpreter's)
        *sp.add(i) = 9; i += 1;
        *sp.add(i) = main_base + elf_info.entry; i += 1;
        // AT_SYSINFO_EHDR(33) = vDSO page address
        *sp.add(i) = 33; i += 1;
        *sp.add(i) = vdso::VDSO_BASE; i += 1;
        // AT_BASE(7) = interpreter load address (only for dynamic binaries)
        if is_dynamic {
            *sp.add(i) = 7; i += 1;
            *sp.add(i) = interp_base; i += 1;
        }
        // AT_NULL(0)
        *sp.add(i) = 0; i += 1;
        *sp.add(i) = 0;
    }

    print(b"EXEC: entry=0x");
    print_hex64(exec_entry);
    print(b" rsp=0x");
    print_hex64(rsp);
    if is_dynamic {
        print(b" [dynamic] AT_BASE=0x");
        print_hex64(interp_base);
        print(b" AT_ENTRY=0x");
        print_hex64(main_base + elf_info.entry);
    }
    print(b"\n");

    // Step 8: Create endpoint + redirected thread
    let new_ep = match sys::endpoint_create() {
        Ok(e) => e,
        Err(_) => {
            unmap_temp_buf(EXEC_BUF_BASE, EXEC_BUF_PAGES);
            return Err(-12);
        }
    };
    let new_thread = match sys::thread_create_redirected(exec_entry, rsp, new_ep) {
        Ok(t) => t,
        Err(_) => {
            unmap_temp_buf(EXEC_BUF_BASE, EXEC_BUF_PAGES);
            return Err(-12);
        }
    };
    let _ = sys::signal_entry(new_thread, vdso::SIGNAL_TRAMPOLINE_ADDR);

    unmap_temp_buf(EXEC_BUF_BASE, EXEC_BUF_PAGES);
    Ok((new_ep, new_thread))
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
    Socket = 5,      // TCP socket
    PipeRead = 6,
    PipeWrite = 7,
    SocketUdp = 8,   // UDP socket
    EpollFd = 9,     // epoll instance
}

#[derive(Clone, Copy)]
struct FdEntry {
    kind: FdKind,
    vfs_fd: u32,
    /// For Socket/SocketUdp FDs: connection/socket ID in the net service.
    net_conn_id: u32,
    /// For SocketUdp: local port, remote IP, remote port (set by connect/sendto).
    udp_local_port: u16,
    udp_remote_ip: u32,
    udp_remote_port: u16,
    /// For EpollFd: index into epoll table.
    epoll_idx: u16,
    /// Socket flags (SOCK_NONBLOCK, SOCK_CLOEXEC).
    sock_flags: u16,
}

impl FdEntry {
    const fn free() -> Self {
        Self {
            kind: FdKind::Free, vfs_fd: 0, net_conn_id: 0,
            udp_local_port: 0, udp_remote_ip: 0, udp_remote_port: 0,
            epoll_idx: 0, sock_flags: 0,
        }
    }
    const fn new(kind: FdKind, vfs_fd: u32, net_conn_id: u32) -> Self {
        Self {
            kind, vfs_fd, net_conn_id,
            udp_local_port: 0, udp_remote_ip: 0, udp_remote_port: 0,
            epoll_idx: 0, sock_flags: 0,
        }
    }
}

// IPC command constants for net service (must match services/net).
const NET_CMD_PING: u64 = 1;
const NET_CMD_DNS_QUERY: u64 = 2;
const NET_CMD_TCP_CONNECT: u64 = 3;
const NET_CMD_TCP_SEND: u64 = 4;
const NET_CMD_TCP_RECV: u64 = 5;
const NET_CMD_TCP_CLOSE: u64 = 6;
const NET_CMD_UDP_BIND: u64 = 8;
const NET_CMD_UDP_SENDTO: u64 = 9;
const NET_CMD_UDP_RECV: u64 = 10;
const NET_CMD_TCP_STATUS: u64 = 11; // Query TCP connection status (for poll)

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

const MAX_FDS: usize = 64;
const MAX_MMAPS: usize = 32;
const BRK_BASE: u64 = 0x2000000;
const BRK_LIMIT: u64 = 0x100000; // 1 MiB max heap (BRK_BASE..BRK_BASE+BRK_LIMIT)
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

/// Write a Linux stat struct (144 bytes) into guest memory.
fn write_linux_stat(stat_ptr: u64, oid: u64, size: u64, is_dir: bool) {
    use sotos_common::linux_abi::{Stat, S_IFREG, S_IFDIR};
    let mut st = Stat::zeroed();
    st.st_ino = oid;
    st.st_nlink = 1;
    st.st_mode = if is_dir { S_IFDIR | 0o755 } else { S_IFREG | 0o644 };
    st.st_size = size as i64;
    st.st_blksize = 512;
    st.st_blocks = ((size + 511) / 512) as i64;
    unsafe { st.write_to(stat_ptr); }
}

/// Trampoline for clone(CLONE_THREAD) child threads.
/// Stack layout set up by the handler: [fn_ptr, arg, tls_ptr] (growing upward from RSP).
/// Calls arch_prctl(SET_FS, tls) if tls != 0, then calls fn(arg), then exit.
#[unsafe(no_mangle)]
#[unsafe(naked)]
pub unsafe extern "C" fn clone_child_trampoline() -> ! {
    core::arch::naked_asm!(
        "pop rsi",              // fn_ptr
        "pop rdi",              // arg
        "pop rdx",              // tls_ptr (0 if no CLONE_SETTLS)
        "test rdx, rdx",
        "jz 2f",
        // arch_prctl(ARCH_SET_FS, tls) — intercepted by kernel before redirect
        "push rsi",
        "push rdi",
        "mov rdi, 0x1002",      // ARCH_SET_FS
        "mov rsi, rdx",
        "mov rax, 158",         // SYS_arch_prctl
        "syscall",
        "pop rdi",
        "pop rsi",
        "2:",
        "xor ebp, ebp",
        "call rsi",             // fn(arg)
        "mov edi, eax",         // exit status = fn return value
        "mov eax, 60",          // SYS_exit
        "syscall",
        "ud2",
    );
}

/// Child process handler — full-featured handler for child processes.
/// Supports brk, mmap, munmap, FD table (shared via GRP_ tables),
/// file I/O, all musl-libc init syscalls, execve, clone(CLONE_THREAD), and futex.
#[unsafe(no_mangle)]
pub extern "C" fn child_handler() -> ! {
    // Wait for parent to provide setup info
    while CHILD_SETUP_READY.load(Ordering::Acquire) != 1 {
        sys::yield_now();
    }
    let mut ep_cap = CHILD_SETUP_EP.load(Ordering::Acquire);
    let pid = CHILD_SETUP_PID.load(Ordering::Acquire) as usize;
    let parent_pid = PROC_PARENT[pid - 1].load(Ordering::Acquire);
    let clone_flags = CHILD_SETUP_FLAGS.load(Ordering::Acquire);
    // Signal that we consumed the setup
    CHILD_SETUP_READY.store(0, Ordering::Release);

    // Resolve group indices for this thread
    let fdg = PROC_FD_GROUP[pid - 1].load(Ordering::Acquire) as usize;
    let memg = PROC_MEM_GROUP[pid - 1].load(Ordering::Acquire) as usize;
    let _sigg = PROC_SIG_GROUP[pid - 1].load(Ordering::Acquire) as usize;

    // Per-child brk/mmap state. Each memory group gets its own region.
    const CHILD_REGION_SIZE: u64 = 0x200000; // 2 MiB per child
    const CHILD_BRK_BASE: u64 = 0x7000000;
    const CHILD_MMAP_OFFSET: u64 = 0x100000; // mmap starts 1 MiB into the region

    // Initialize memory group state if this is a new group (not CLONE_VM reuse)
    unsafe {
        if clone_flags & CLONE_VM == 0 || GRP_BRK[memg] == 0 {
            let my_brk_base = CHILD_BRK_BASE + ((memg as u64) % 16) * CHILD_REGION_SIZE;
            GRP_BRK[memg] = my_brk_base;
            GRP_MMAP_NEXT[memg] = my_brk_base + CHILD_MMAP_OFFSET;
            GRP_INITRD_BUF_BASE[memg] = my_brk_base + CHILD_REGION_SIZE;
        }
    }

    // Compute the brk base for this memory group (needed for limit checks).
    let my_brk_base = CHILD_BRK_BASE + ((memg as u64) % 16) * CHILD_REGION_SIZE;

    // Create local mutable references to the shared FD and memory state.
    // These are references into `static mut` arrays, protected by GRP_FD_LOCK[fdg].
    // This gives backward compatibility: existing code using child_fds[fd],
    // initrd_files[s][i], vfs_files[s][i], etc. works unchanged.
    const CHILD_MAX_FDS: usize = GRP_MAX_FDS;
    const MAX_INITRD_FILES: usize = GRP_MAX_INITRD;
    let child_fds: &mut [u8; GRP_MAX_FDS] = unsafe { &mut GRP_FDS[fdg] };
    let initrd_files: &mut [[u64; 4]; GRP_MAX_INITRD] = unsafe { &mut GRP_INITRD[fdg] };
    let initrd_file_buf_base: u64 = unsafe { GRP_INITRD_BUF_BASE[memg] };
    const MAX_VFS_FILES: usize = GRP_MAX_VFS;
    let vfs_files: &mut [[u64; 4]; GRP_MAX_VFS] = unsafe { &mut GRP_VFS[fdg] };
    let dir_buf: &mut [u8; 1024] = unsafe { &mut GRP_DIR_BUF[fdg] };
    let dir_len: &mut usize = unsafe { &mut GRP_DIR_LEN[fdg] };
    let dir_pos: &mut usize = unsafe { &mut GRP_DIR_POS[fdg] };
    // current_brk and mmap_next: mutable references into GRP_BRK/GRP_MMAP_NEXT
    let current_brk: &mut u64 = unsafe { &mut GRP_BRK[memg] };
    let mmap_next: &mut u64 = unsafe { &mut GRP_MMAP_NEXT[memg] };

    // Socket state (parallel arrays indexed by FD number)
    // FD kind 16=TCP socket, 17=UDP socket
    let mut sock_conn_id: [u32; GRP_MAX_FDS] = [0xFFFF; GRP_MAX_FDS];
    let mut sock_udp_local_port: [u16; GRP_MAX_FDS] = [0; GRP_MAX_FDS];
    let mut sock_udp_remote_ip: [u32; GRP_MAX_FDS] = [0; GRP_MAX_FDS];
    let mut sock_udp_remote_port: [u16; GRP_MAX_FDS] = [0; GRP_MAX_FDS];
    static NEXT_UDP_PORT: AtomicU64 = AtomicU64::new(49152);

    loop {
        let msg = match sys::recv(ep_cap) {
            Ok(m) => m,
            Err(_) => break,
        };

        // Cache the kernel thread ID for async signal injection
        let kernel_tid = msg.regs[6];
        if kernel_tid != 0 {
            PROC_KERNEL_TID[pid - 1].store(kernel_tid, Ordering::Release);
        }

        // Check for pending unblocked signals
        let sig = sig_dequeue(pid);
        if sig != 0 {
            let child_tid = kernel_tid;
            match sig_dispatch(pid, sig) {
                1 => break, // terminated
                2 => { reply_val(ep_cap, -4); continue; } // -EINTR
                3 => {
                    // User handler registered — deliver signal via frame injection
                    if signal_deliver(ep_cap, pid, sig, child_tid, 0, false) {
                        continue; // signal_deliver already replied
                    }
                    // Delivery failed (no restorer, etc.) — fall through
                }
                _ => {} // ignored, continue
            }
        }

        let syscall_nr = msg.tag;
        match syscall_nr {
            // SYS_read(fd, buf, len)
            0 => {
                let fd = msg.regs[0] as usize;
                let buf_ptr = msg.regs[1];
                let len = msg.regs[2] as usize;
                if fd >= CHILD_MAX_FDS || child_fds[fd] == 0 {
                    reply_val(ep_cap, -9); // -EBADF
                    continue;
                }
                match child_fds[fd] {
                    1 => {
                        // stdin
                        if len == 0 { reply_val(ep_cap, 0); continue; }
                        loop {
                            let s = sig_dequeue(pid);
                            if s != 0 && sig_dispatch(pid, s) >= 1 {
                                reply_val(ep_cap, -4); break; // -EINTR
                            }
                            match unsafe { kb_read_char() } {
                                Some(0x03) => { reply_val(ep_cap, -4); break; }
                                Some(ch) => {
                                    unsafe { *(buf_ptr as *mut u8) = ch; }
                                    reply_val(ep_cap, 1); break;
                                }
                                None => { unsafe { poll_mouse(); } sys::yield_now(); }
                            }
                        }
                    }
                    9 => reply_val(ep_cap, 0), // /dev/zero → read zeros (simplified: EOF)
                    8 => reply_val(ep_cap, 0), // /dev/null → EOF
                    12 => {
                        // Initrd file: find the slot for this FD
                        let mut found = false;
                        for s in 0..MAX_INITRD_FILES {
                            if initrd_files[s][3] == fd as u64 && initrd_files[s][0] != 0 {
                                let data_base = initrd_files[s][0];
                                let file_size = initrd_files[s][1];
                                let pos = initrd_files[s][2];
                                let avail = if pos < file_size { file_size - pos } else { 0 };
                                let to_read = (len as u64).min(avail) as usize;
                                if to_read > 0 {
                                    unsafe {
                                        core::ptr::copy_nonoverlapping(
                                            (data_base + pos) as *const u8,
                                            buf_ptr as *mut u8,
                                            to_read,
                                        );
                                    }
                                    initrd_files[s][2] = pos + to_read as u64;
                                }
                                reply_val(ep_cap, to_read as i64);
                                found = true;
                                break;
                            }
                        }
                        if !found { reply_val(ep_cap, -9); }
                    }
                    13 => {
                        // VFS file: read via shared ObjectStore
                        let mut found = false;
                        for s in 0..MAX_VFS_FILES {
                            if vfs_files[s][3] == fd as u64 && vfs_files[s][0] != 0 {
                                let oid = vfs_files[s][0];
                                let pos = vfs_files[s][2] as usize;
                                let dst = unsafe { core::slice::from_raw_parts_mut(buf_ptr as *mut u8, len) };
                                vfs_lock();
                                let result = unsafe { shared_store() }
                                    .and_then(|store| store.read_obj_range(oid, pos, dst).ok());
                                vfs_unlock();
                                match result {
                                    Some(n) => {
                                        vfs_files[s][2] += n as u64;
                                        reply_val(ep_cap, n as i64);
                                    }
                                    None => reply_val(ep_cap, -5), // -EIO
                                }
                                found = true;
                                break;
                            }
                        }
                        if !found { reply_val(ep_cap, -9); }
                    }
                    15 => {
                        // Procfs virtual file: read from dir_buf
                        let avail = if *dir_pos < *dir_len { *dir_len - *dir_pos } else { 0 };
                        let to_read = len.min(avail);
                        if to_read > 0 {
                            unsafe {
                                core::ptr::copy_nonoverlapping(
                                    dir_buf[*dir_pos..].as_ptr(),
                                    buf_ptr as *mut u8,
                                    to_read,
                                );
                            }
                            *dir_pos += to_read;
                        }
                        reply_val(ep_cap, to_read as i64);
                    }
                    16 => {
                        // TCP socket read → NET_CMD_TCP_RECV (retry up to 500 times)
                        let net_cap = NET_EP_CAP.load(Ordering::Acquire);
                        let conn_id = sock_conn_id[fd] as u64;
                        let recv_len = len.min(56);
                        let mut got = 0usize;
                        let mut tcp_retries = 0u32;
                        while tcp_retries < 500 {
                            let req = sotos_common::IpcMsg {
                                tag: NET_CMD_TCP_RECV,
                                regs: [conn_id, recv_len as u64, 0, 0, 0, 0, 0, 0],
                            };
                            match sys::call_timeout(net_cap, &req, 50) {
                                Ok(resp) => {
                                    let n = resp.regs[0] as usize;
                                    if n > 0 && n <= recv_len {
                                        unsafe {
                                            let src = &resp.regs[1] as *const u64 as *const u8;
                                            core::ptr::copy_nonoverlapping(src, buf_ptr as *mut u8, n);
                                        }
                                        got = n;
                                        break;
                                    }
                                    // n==0: no data yet, retry
                                }
                                Err(_) => {} // timeout, retry
                            }
                            sys::yield_now();
                            tcp_retries += 1;
                        }
                        if got > 0 {
                            reply_val(ep_cap, got as i64);
                        } else {
                            reply_val(ep_cap, -11); // -EAGAIN after exhausting retries
                        }
                    }
                    17 => {
                        // UDP socket read → NET_CMD_UDP_RECV
                        let net_cap = NET_EP_CAP.load(Ordering::Acquire);
                        let port = sock_udp_local_port[fd];
                        let recv_len = len.min(56);
                        if net_cap == 0 || port == 0 {
                            reply_val(ep_cap, -9);
                        } else {
                            let req = sotos_common::IpcMsg {
                                tag: NET_CMD_UDP_RECV,
                                regs: [port as u64, recv_len as u64, 0, 0, 0, 0, 0, 0],
                            };
                            match sys::call_timeout(net_cap, &req, 500) {
                                Ok(resp) => {
                                    let n = resp.regs[0] as usize;
                                    if n > 0 && n <= recv_len {
                                        unsafe {
                                            let src = &resp.regs[1] as *const u64 as *const u8;
                                            core::ptr::copy_nonoverlapping(src, buf_ptr as *mut u8, n);
                                        }
                                    }
                                    reply_val(ep_cap, n as i64);
                                }
                                Err(_) => reply_val(ep_cap, 0),
                            }
                        }
                    }
                    _ => reply_val(ep_cap, -9),
                }
            }

            // SYS_write(fd, buf, len)
            1 => {
                let fd = msg.regs[0] as usize;
                let buf_ptr = msg.regs[1];
                let len = msg.regs[2] as usize;
                if fd >= CHILD_MAX_FDS || child_fds[fd] == 0 {
                    reply_val(ep_cap, -9);
                    continue;
                }
                match child_fds[fd] {
                    2 => {
                        // stdout/stderr
                        let data = unsafe { core::slice::from_raw_parts(buf_ptr as *const u8, len) };
                        for &b in data { sys::debug_print(b); unsafe { fb_putchar(b); } }
                        reply_val(ep_cap, len as i64);
                    }
                    8 => reply_val(ep_cap, len as i64), // /dev/null → discard
                    16 => {
                        // TCP socket write → NET_CMD_TCP_SEND
                        let net_cap = NET_EP_CAP.load(Ordering::Acquire);
                        let conn_id = sock_conn_id[fd] as u64;
                        let send_len = len.min(40);
                        let mut req = sotos_common::IpcMsg {
                            tag: NET_CMD_TCP_SEND,
                            regs: [conn_id, 0, send_len as u64, 0, 0, 0, 0, 0],
                        };
                        let data = unsafe { core::slice::from_raw_parts(buf_ptr as *const u8, send_len) };
                        unsafe {
                            let dst = &mut req.regs[3] as *mut u64 as *mut u8;
                            core::ptr::copy_nonoverlapping(data.as_ptr(), dst, send_len);
                        }
                        match sys::call_timeout(net_cap, &req, 500) {
                            Ok(resp) => reply_val(ep_cap, resp.regs[0] as i64),
                            Err(_) => reply_val(ep_cap, -5),
                        }
                    }
                    17 => {
                        // UDP socket write → NET_CMD_UDP_SENDTO with stored remote addr
                        let net_cap = NET_EP_CAP.load(Ordering::Acquire);
                        let remote_ip = sock_udp_remote_ip[fd];
                        let remote_port = sock_udp_remote_port[fd];
                        let src_port = sock_udp_local_port[fd];
                        if net_cap == 0 || remote_ip == 0 {
                            reply_val(ep_cap, -89); // -EDESTADDRREQ
                        } else {
                            let send_len = len.min(32);
                            let mut req = sotos_common::IpcMsg {
                                tag: NET_CMD_UDP_SENDTO,
                                regs: [remote_ip as u64, remote_port as u64, src_port as u64, send_len as u64, 0, 0, 0, 0],
                            };
                            let data = unsafe { core::slice::from_raw_parts(buf_ptr as *const u8, send_len) };
                            unsafe {
                                let dst = &mut req.regs[4] as *mut u64 as *mut u8;
                                core::ptr::copy_nonoverlapping(data.as_ptr(), dst, send_len);
                            }
                            match sys::call_timeout(net_cap, &req, 500) {
                                Ok(resp) => reply_val(ep_cap, resp.regs[0] as i64),
                                Err(_) => reply_val(ep_cap, -5),
                            }
                        }
                    }
                    13 => {
                        // VFS file: write via shared ObjectStore
                        let mut found = false;
                        for s in 0..MAX_VFS_FILES {
                            if vfs_files[s][3] == fd as u64 && vfs_files[s][0] != 0 {
                                let oid = vfs_files[s][0];
                                let pos = vfs_files[s][2] as usize;
                                let data = unsafe { core::slice::from_raw_parts(buf_ptr as *const u8, len) };
                                vfs_lock();
                                let result = unsafe { shared_store() }
                                    .and_then(|store| store.write_obj_range(oid, pos, data).ok());
                                vfs_unlock();
                                match result {
                                    Some(_) => {
                                        vfs_files[s][2] += len as u64;
                                        // Update cached size if we extended the file
                                        let new_end = vfs_files[s][2];
                                        if new_end > vfs_files[s][1] { vfs_files[s][1] = new_end; }
                                        reply_val(ep_cap, len as i64);
                                    }
                                    None => reply_val(ep_cap, -5), // -EIO
                                }
                                found = true;
                                break;
                            }
                        }
                        if !found { reply_val(ep_cap, -9); }
                    }
                    _ => reply_val(ep_cap, -9),
                }
            }

            // SYS_close(fd)
            3 => {
                let fd = msg.regs[0] as usize;
                if fd < CHILD_MAX_FDS && child_fds[fd] != 0 {
                    if child_fds[fd] == 12 {
                        for s in 0..MAX_INITRD_FILES {
                            if initrd_files[s][3] == fd as u64 {
                                initrd_files[s][3] = u64::MAX; // mark FD closed but data alive
                                break;
                            }
                        }
                    } else if child_fds[fd] == 13 || child_fds[fd] == 14 {
                        for s in 0..MAX_VFS_FILES {
                            if vfs_files[s][3] == fd as u64 { vfs_files[s] = [0; 4]; break; }
                        }
                    } else if child_fds[fd] == 16 {
                        // TCP socket close → NET_CMD_TCP_CLOSE
                        let net_cap = NET_EP_CAP.load(Ordering::Acquire);
                        let cid = sock_conn_id[fd];
                        if net_cap != 0 && cid != 0xFFFF {
                            let req = sotos_common::IpcMsg {
                                tag: NET_CMD_TCP_CLOSE,
                                regs: [cid as u64, 0, 0, 0, 0, 0, 0, 0],
                            };
                            let _ = sys::call_timeout(net_cap, &req, 500);
                        }
                        sock_conn_id[fd] = 0xFFFF;
                    }
                    child_fds[fd] = 0;
                }
                reply_val(ep_cap, 0);
            }

            // SYS_open(path, flags, mode) — used by musl dynamic linker
            2 => {
                let path_ptr = msg.regs[0];
                let mut path = [0u8; 128];
                let path_len = copy_guest_path(path_ptr, &mut path);
                let name = &path[..path_len];

                let kind = if name == b"/dev/null" { 8u8 }
                    else if name == b"/dev/zero" { 9u8 }
                    else if name == b"/dev/urandom" || name == b"/dev/random" { 9u8 }
                    else { 0u8 };

                if kind != 0 {
                    let mut fd = None;
                    for i in 3..CHILD_MAX_FDS { if child_fds[i] == 0 { fd = Some(i); break; } }
                    if let Some(f) = fd {
                        child_fds[f] = kind;
                        reply_val(ep_cap, f as i64);
                    } else {
                        reply_val(ep_cap, -24);
                    }
                } else {
                    // Try initrd — extract basename
                    let mut basename_start = 0usize;
                    for idx in 0..path_len {
                        if name[idx] == b'/' { basename_start = idx + 1; }
                    }
                    let basename = &name[basename_start..];

                    let mut slot = None;
                    for s in 0..MAX_INITRD_FILES {
                        if initrd_files[s][0] == 0 { slot = Some(s); break; }
                    }

                    if basename.is_empty() || slot.is_none() {
                        reply_val(ep_cap, -2);
                        continue;
                    }
                    let slot = slot.unwrap();

                    let file_buf = initrd_file_buf_base + (slot as u64) * 0x100000;
                    const FILE_BUF_PAGES_OPEN: u64 = 256;
                    let mut buf_ok = true;
                    for p in 0..FILE_BUF_PAGES_OPEN {
                        if let Ok(f) = sys::frame_alloc() {
                            if sys::map(file_buf + p * 0x1000, f, MAP_WRITABLE).is_err() {
                                buf_ok = false; break;
                            }
                        } else { buf_ok = false; break; }
                    }
                    if !buf_ok {
                        reply_val(ep_cap, -12);
                        continue;
                    }

                    match sys::initrd_read(
                        basename.as_ptr() as u64,
                        basename.len() as u64,
                        file_buf,
                        FILE_BUF_PAGES_OPEN * 0x1000,
                    ) {
                        Ok(sz) => {
                            let mut fd = None;
                            for i in 3..CHILD_MAX_FDS { if child_fds[i] == 0 { fd = Some(i); break; } }
                            if let Some(f) = fd {
                                child_fds[f] = 12;
                                initrd_files[slot] = [file_buf, sz, 0, f as u64];
                                reply_val(ep_cap, f as i64);
                            } else {
                                for p in 0..FILE_BUF_PAGES_OPEN { let _ = sys::unmap(file_buf + p * 0x1000); }
                                reply_val(ep_cap, -24);
                            }
                        }
                        Err(_) => {
                            for p in 0..FILE_BUF_PAGES_OPEN { let _ = sys::unmap(file_buf + p * 0x1000); }
                            reply_val(ep_cap, -2);
                        }
                    }
                }
            }

            // SYS_fstat(fd, stat_buf)
            5 => {
                let fd = msg.regs[0] as usize;
                let stat_ptr = msg.regs[1];
                if fd >= CHILD_MAX_FDS || child_fds[fd] == 0 {
                    reply_val(ep_cap, -9);
                } else if child_fds[fd] == 12 {
                    let mut size = 0u64;
                    for s in 0..MAX_INITRD_FILES {
                        if initrd_files[s][3] == fd as u64 && initrd_files[s][0] != 0 {
                            size = initrd_files[s][1];
                            break;
                        }
                    }
                    write_linux_stat(stat_ptr, fd as u64, size, false);
                    reply_val(ep_cap, 0);
                } else if child_fds[fd] == 13 {
                    // VFS file: get real size from store
                    let mut size = 0u64;
                    let mut oid = 0u64;
                    for s in 0..MAX_VFS_FILES {
                        if vfs_files[s][3] == fd as u64 && vfs_files[s][0] != 0 {
                            oid = vfs_files[s][0];
                            vfs_lock();
                            if let Some(store) = unsafe { shared_store() } {
                                if let Some(entry) = store.stat(oid) {
                                    size = entry.size;
                                }
                            }
                            vfs_unlock();
                            break;
                        }
                    }
                    write_linux_stat(stat_ptr, oid, size, false);
                    reply_val(ep_cap, 0);
                } else if child_fds[fd] == 15 {
                    // Procfs virtual file: report content length
                    write_linux_stat(stat_ptr, fd as u64, *dir_len as u64, false);
                    reply_val(ep_cap, 0);
                } else {
                    write_linux_stat(stat_ptr, fd as u64, 0, false);
                    reply_val(ep_cap, 0);
                }
            }

            // SYS_stat(path, statbuf) — check if path exists (for terminfo etc.)
            4 => {
                let path_ptr = msg.regs[0];
                let stat_ptr = msg.regs[1];
                let mut path = [0u8; 128];
                let path_len = copy_guest_path(path_ptr, &mut path);
                let name = &path[..path_len];

                // First try initrd by basename (files take priority over directory stubs)
                let mut basename_start = 0usize;
                for idx in 0..path_len { if name[idx] == b'/' { basename_start = idx + 1; } }
                let basename = &name[basename_start..];
                if !basename.is_empty() {
                    if let Ok(sz) = sys::initrd_read(basename.as_ptr() as u64, basename.len() as u64, 0, 0) {
                        write_linux_stat(stat_ptr, 0, sz, false);
                        reply_val(ep_cap, 0);
                        continue;
                    }
                }

                // Fall back to directory stubs ("." = CWD)
                let is_dir = name == b"." || path_len == 0
                    || starts_with(name, b"/usr") || starts_with(name, b"/etc")
                    || starts_with(name, b"/lib") || name == b"/";
                if is_dir {
                    write_linux_stat(stat_ptr, 0, 4096, true);
                    reply_val(ep_cap, 0);
                } else {
                    reply_val(ep_cap, -2);
                }
            }

            // SYS_lstat(path, statbuf) — same as stat (no symlinks)
            6 => {
                let path_ptr = msg.regs[0];
                let stat_ptr = msg.regs[1];
                let mut path = [0u8; 128];
                let path_len = copy_guest_path(path_ptr, &mut path);
                let name = &path[..path_len];
                let mut basename_start = 0usize;
                for idx in 0..path_len { if name[idx] == b'/' { basename_start = idx + 1; } }
                let basename = &name[basename_start..];
                if !basename.is_empty() {
                    if let Ok(sz) = sys::initrd_read(basename.as_ptr() as u64, basename.len() as u64, 0, 0) {
                        write_linux_stat(stat_ptr, 0, sz, false);
                        reply_val(ep_cap, 0);
                        continue;
                    }
                }
                // Fall back to directory stubs ("." = CWD)
                let is_dir = name == b"." || path_len == 0
                    || starts_with(name, b"/usr") || starts_with(name, b"/etc")
                    || starts_with(name, b"/lib") || name == b"/";
                if is_dir {
                    write_linux_stat(stat_ptr, 0, 4096, true);
                    reply_val(ep_cap, 0);
                } else {
                    reply_val(ep_cap, -2);
                }
            }

            // SYS_poll(fds, nfds, timeout)
            7 => {
                let fds_ptr = msg.regs[0] as *mut u8;
                let nfds = msg.regs[1] as usize;
                let timeout = msg.regs[2] as i32;
                let mut ready = 0u32;
                // struct pollfd { int fd; short events; short revents; } = 8 bytes each
                for i in 0..nfds.min(16) {
                    let pfd = unsafe { fds_ptr.add(i * 8) };
                    let fd = unsafe { *(pfd as *const i32) };
                    let events = unsafe { *((pfd.add(4)) as *const i16) };
                    let mut revents: i16 = 0;
                    if fd >= 0 && (fd as usize) < CHILD_MAX_FDS && child_fds[fd as usize] != 0 {
                        // POLLIN = 1
                        if events & 1 != 0 {
                            if fd == 0 && child_fds[0] == 1 {
                                // stdin — check if char available
                                if unsafe { kb_has_char() } { revents |= 1; }
                            } else {
                                // Other readable FDs: always ready
                                revents |= 1;
                            }
                        }
                        // POLLOUT = 4
                        if events & 4 != 0 { revents |= 4; } // stdout always writable
                    } else if fd >= 0 {
                        revents = 0x20; // POLLNVAL
                    }
                    unsafe { *((pfd.add(6)) as *mut i16) = revents; }
                    if revents != 0 { ready += 1; }
                }
                if ready > 0 || timeout == 0 {
                    reply_val(ep_cap, ready as i64);
                } else {
                    // Blocking poll — spin-wait (with yield) until input
                    let mut waited = 0u32;
                    let max_iters = if timeout > 0 { (timeout as u32) * 100 } else { u32::MAX };
                    let mut interrupted = false;
                    loop {
                        if unsafe { kb_has_char() } {
                            // Re-check all fds
                            ready = 0;
                            for i in 0..nfds.min(16) {
                                let pfd = unsafe { fds_ptr.add(i * 8) };
                                let fd = unsafe { *(pfd as *const i32) };
                                let events = unsafe { *((pfd.add(4)) as *const i16) };
                                let mut revents: i16 = 0;
                                if fd == 0 && (events & 1 != 0) { revents |= 1; }
                                if events & 4 != 0 { revents |= 4; }
                                unsafe { *((pfd.add(6)) as *mut i16) = revents; }
                                if revents != 0 { ready += 1; }
                            }
                            break;
                        }
                        let s = sig_dequeue(pid);
                        if s != 0 && sig_dispatch(pid, s) >= 1 {
                            interrupted = true;
                            break;
                        }
                        sys::yield_now();
                        waited += 1;
                        if waited >= max_iters { break; }
                    }
                    if interrupted {
                        reply_val(ep_cap, -4); // -EINTR
                    } else {
                        reply_val(ep_cap, ready as i64);
                    }
                }
            }

            // SYS_lseek(fd, offset, whence)
            8 => {
                let fd = msg.regs[0] as usize;
                let offset_val = msg.regs[1] as i64;
                let whence = msg.regs[2] as u32;
                if fd >= CHILD_MAX_FDS || child_fds[fd] == 0 {
                    reply_val(ep_cap, -9); // -EBADF
                } else if child_fds[fd] == 12 {
                    let mut found = false;
                    for s in 0..MAX_INITRD_FILES {
                        if initrd_files[s][3] == fd as u64 && initrd_files[s][0] != 0 {
                            let file_size = initrd_files[s][1] as i64;
                            let cur_pos = initrd_files[s][2] as i64;
                            let new_pos = match whence {
                                0 => offset_val,                    // SEEK_SET
                                1 => cur_pos + offset_val,          // SEEK_CUR
                                2 => file_size + offset_val,        // SEEK_END
                                _ => { reply_val(ep_cap, -22); found = true; break; }
                            };
                            if new_pos < 0 {
                                reply_val(ep_cap, -22); // -EINVAL
                            } else {
                                initrd_files[s][2] = new_pos as u64;
                                reply_val(ep_cap, new_pos);
                            }
                            found = true;
                            break;
                        }
                    }
                    if !found { reply_val(ep_cap, -9); }
                } else if child_fds[fd] == 13 || child_fds[fd] == 14 {
                    // VFS file or directory: seek
                    let mut found = false;
                    for s in 0..MAX_VFS_FILES {
                        if vfs_files[s][3] == fd as u64 && vfs_files[s][0] != 0 {
                            let file_size = vfs_files[s][1] as i64;
                            let cur_pos = vfs_files[s][2] as i64;
                            let new_pos = match whence {
                                0 => offset_val,
                                1 => cur_pos + offset_val,
                                2 => file_size + offset_val,
                                _ => { reply_val(ep_cap, -22); found = true; break; }
                            };
                            if new_pos < 0 {
                                reply_val(ep_cap, -22);
                            } else {
                                vfs_files[s][2] = new_pos as u64;
                                reply_val(ep_cap, new_pos);
                            }
                            found = true;
                            break;
                        }
                    }
                    if !found { reply_val(ep_cap, -9); }
                } else {
                    reply_val(ep_cap, -29); // -ESPIPE (not seekable)
                }
            }

            // SYS_mmap(addr, len, prot, flags, fd, offset)
            9 => {
                let req_addr = msg.regs[0];
                let len = msg.regs[1];
                let prot = msg.regs[2]; // PROT_READ=1, PROT_WRITE=2, PROT_EXEC=4
                let flags = msg.regs[3] as u32;
                let fd = msg.regs[4] as i64;
                let offset = msg.regs[5];

                let map_fixed = (flags & 0x10) != 0; // MAP_FIXED
                let map_anon = (flags & 0x20) != 0; // MAP_ANONYMOUS
                let pages = ((len + 0xFFF) & !0xFFF) / 0x1000;

                // Determine base address
                let base = if map_fixed && req_addr != 0 {
                    // MAP_FIXED: use the exact requested address
                    // First unmap any existing pages at that range
                    for p in 0..pages {
                        let _ = sys::unmap(req_addr + p * 0x1000);
                    }
                    req_addr
                } else {
                    let b = *mmap_next;
                    *mmap_next += pages * 0x1000;
                    b
                };

                // Helper: apply final page permissions based on prot flags.
                // Pages were mapped writable for data copy; now fix permissions.
                // Must be a closure to capture base, pages, prot.
                let mmap_fixup_prot = |base: u64, pages: u64, prot: u64| {
                    if prot & 2 == 0 {
                        // Not writable — need to change from writable to read-only
                        let pflags = if prot & 4 != 0 { 0u64 } else { 1u64 << 63 }; // exec → 0; read-only → NX
                        for p in 0..pages {
                            let _ = sys::protect(base + p * 0x1000, pflags);
                        }
                    }
                    // If writable, kernel already set NX (W^X), nothing to do
                };

                if fd >= 0 && !map_anon {
                    // File-backed mmap: find initrd file data for this FD
                    let fdu = fd as usize;
                    let mut file_data: u64 = 0;
                    let mut file_size: u64 = 0;

                    if fdu < CHILD_MAX_FDS {
                        for s in 0..MAX_INITRD_FILES {
                            if initrd_files[s][0] != 0 && (initrd_files[s][3] == fdu as u64 || initrd_files[s][3] == u64::MAX) {
                                file_data = initrd_files[s][0];
                                file_size = initrd_files[s][1];
                                break;
                            }
                        }
                    }

                    if file_data == 0 {
                        reply_val(ep_cap, -9); // -EBADF
                        continue;
                    }

                    // Map pages and copy file data
                    let mut ok = true;
                    for p in 0..pages {
                        if let Ok(f) = sys::frame_alloc() {
                            if sys::map(base + p * 0x1000, f, MAP_WRITABLE).is_err() {
                                ok = false; break;
                            }
                        } else { ok = false; break; }
                    }
                    if ok {
                        let map_size = (pages * 0x1000) as usize;
                        unsafe { core::ptr::write_bytes(base as *mut u8, 0, map_size); }
                        let file_off = offset as usize;
                        let avail = if file_off < file_size as usize { file_size as usize - file_off } else { 0 };
                        let to_copy = map_size.min(avail);
                        if to_copy > 0 {
                            unsafe {
                                core::ptr::copy_nonoverlapping(
                                    (file_data + file_off as u64) as *const u8,
                                    base as *mut u8,
                                    to_copy,
                                );
                            }
                        }
                        mmap_fixup_prot(base, pages, prot);
                        reply_val(ep_cap, base as i64);
                    } else {
                        reply_val(ep_cap, -12);
                    }
                    continue;
                }

                // Anonymous mmap
                let mut ok = true;
                for p in 0..pages {
                    if let Ok(f) = sys::frame_alloc() {
                        if sys::map(base + p * 0x1000, f, MAP_WRITABLE).is_err() {
                            ok = false; break;
                        }
                    } else { ok = false; break; }
                }
                if ok {
                    // Zero anonymous pages
                    unsafe { core::ptr::write_bytes(base as *mut u8, 0, (pages * 0x1000) as usize); }
                    mmap_fixup_prot(base, pages, prot);
                    reply_val(ep_cap, base as i64);
                } else {
                    reply_val(ep_cap, -12);
                }
            }

            // SYS_mprotect(addr, len, prot) — change page permissions
            10 => {
                let addr = msg.regs[0] & !0xFFF;
                let len = msg.regs[1];
                let prot = msg.regs[2]; // PROT_READ=1, PROT_WRITE=2, PROT_EXEC=4
                let pages = ((len + 0xFFF) & !0xFFF) / 0x1000;
                // Convert Linux prot to kernel flags:
                // PROT_WRITE → MAP_WRITABLE (kernel sets NX for W^X)
                // PROT_EXEC without PROT_WRITE → flags=0 (read-only, executable)
                // PROT_READ only → PAGE_NO_EXECUTE (read-only, not executable)
                let flags = if prot & 2 != 0 {
                    MAP_WRITABLE // writable → kernel auto-sets NX (W^X)
                } else if prot & 4 != 0 {
                    0u64 // executable, not writable → no NX
                } else {
                    1u64 << 63 // PAGE_NO_EXECUTE: read-only, not executable
                };
                let mut ok = true;
                for p in 0..pages {
                    if sys::protect(addr + p * 0x1000, flags).is_err() {
                        ok = false;
                    }
                }
                reply_val(ep_cap, if ok { 0 } else { -22 });
            }

            // SYS_pread64(fd, buf, count, offset)
            17 => {
                let fd = msg.regs[0] as usize;
                let buf_ptr = msg.regs[1];
                let count = msg.regs[2] as usize;
                let off = msg.regs[3];
                if fd >= CHILD_MAX_FDS || child_fds[fd] == 0 {
                    reply_val(ep_cap, -9);
                } else if child_fds[fd] == 12 {
                    let mut found = false;
                    for s in 0..MAX_INITRD_FILES {
                        if initrd_files[s][3] == fd as u64 && initrd_files[s][0] != 0 {
                            let data_base = initrd_files[s][0];
                            let file_size = initrd_files[s][1];
                            let avail = if off < file_size { (file_size - off) as usize } else { 0 };
                            let to_read = count.min(avail);
                            if to_read > 0 {
                                unsafe {
                                    core::ptr::copy_nonoverlapping(
                                        (data_base + off) as *const u8,
                                        buf_ptr as *mut u8,
                                        to_read,
                                    );
                                }
                            }
                            reply_val(ep_cap, to_read as i64);
                            found = true;
                            break;
                        }
                    }
                    if !found { reply_val(ep_cap, -9); }
                } else {
                    reply_val(ep_cap, -9);
                }
            }

            // SYS_munmap
            11 => {
                let addr = msg.regs[0];
                let len = msg.regs[1];
                let pages = ((len + 0xFFF) & !0xFFF) / 0x1000;
                for p in 0..pages {
                    let _ = sys::unmap(addr + p * 0x1000);
                }
                reply_val(ep_cap, 0);
            }

            // SYS_brk(addr)
            12 => {
                let addr = msg.regs[0];
                if addr == 0 || addr <= *current_brk {
                    reply_val(ep_cap, *current_brk as i64);
                } else {
                    let new_brk = (addr + 0xFFF) & !0xFFF;
                    let limit = my_brk_base + CHILD_MMAP_OFFSET; // don't overlap mmap region
                    if new_brk > limit {
                        reply_val(ep_cap, *current_brk as i64);
                        continue;
                    }
                    let mut ok = true;
                    let mut pg = (*current_brk + 0xFFF) & !0xFFF;
                    while pg < new_brk {
                        if let Ok(f) = sys::frame_alloc() {
                            if sys::map(pg, f, MAP_WRITABLE).is_err() { ok = false; break; }
                        } else { ok = false; break; }
                        pg += 0x1000;
                    }
                    if ok { *current_brk = new_brk; }
                    reply_val(ep_cap, *current_brk as i64);
                }
            }

            // SYS_rt_sigaction(sig, act, oldact, sigsetsize)
            13 => {
                let signo = msg.regs[0] as usize;
                let act_ptr = msg.regs[1];
                let oldact = msg.regs[2];
                let sigsetsize = msg.regs[3].max(8) as usize;
                let ksa_size = (24 + sigsetsize).min(64);
                if signo == 0 || signo >= 32 || signo == 9 || signo == 19 {
                    // SIGKILL(9) and SIGSTOP(19) cannot be caught
                    if signo == 9 || signo == 19 { reply_val(ep_cap, -22); continue; }
                }
                let idx = pid - 1;
                // Write old handler to oldact
                if oldact != 0 && oldact < 0x0000_8000_0000_0000 {
                    let buf = unsafe { core::slice::from_raw_parts_mut(oldact as *mut u8, ksa_size) };
                    for b in buf.iter_mut() { *b = 0; }
                    if signo > 0 && signo < 32 {
                        let old_h = SIG_HANDLER[idx][signo].load(Ordering::Acquire);
                        let old_f = SIG_FLAGS[idx][signo].load(Ordering::Acquire);
                        let old_r = SIG_RESTORER[idx][signo].load(Ordering::Acquire);
                        buf[0..8].copy_from_slice(&old_h.to_le_bytes());
                        buf[8..16].copy_from_slice(&old_f.to_le_bytes());
                        buf[16..24].copy_from_slice(&old_r.to_le_bytes());
                    }
                }
                // Install new handler from act
                if act_ptr != 0 && act_ptr < 0x0000_8000_0000_0000 && signo > 0 && signo < 32 {
                    let handler = unsafe { *(act_ptr as *const u64) };
                    let flags = unsafe { *((act_ptr + 8) as *const u64) };
                    let restorer = unsafe { *((act_ptr + 16) as *const u64) };
                    SIG_HANDLER[idx][signo].store(handler, Ordering::Release);
                    SIG_FLAGS[idx][signo].store(flags, Ordering::Release);
                    SIG_RESTORER[idx][signo].store(restorer, Ordering::Release);
                }
                reply_val(ep_cap, 0);
            }

            // SYS_rt_sigprocmask(how, set, oldset, sigsetsize)
            14 => {
                let how = msg.regs[0];
                let set_ptr = msg.regs[1];
                let oldset = msg.regs[2];
                let idx = pid - 1;
                let cur_mask = SIG_BLOCKED[idx].load(Ordering::Acquire);
                // Write old mask
                if oldset != 0 && oldset < 0x0000_8000_0000_0000 {
                    unsafe { *(oldset as *mut u64) = cur_mask; }
                }
                // Apply new mask
                if set_ptr != 0 && set_ptr < 0x0000_8000_0000_0000 {
                    let new_set = unsafe { *(set_ptr as *const u64) };
                    // Can't block SIGKILL or SIGSTOP
                    let safe_set = new_set & !((1 << SIGKILL) | (1 << 19));
                    match how {
                        0 => SIG_BLOCKED[idx].store(cur_mask | safe_set, Ordering::Release),  // SIG_BLOCK
                        1 => SIG_BLOCKED[idx].store(cur_mask & !safe_set, Ordering::Release), // SIG_UNBLOCK
                        2 => SIG_BLOCKED[idx].store(safe_set, Ordering::Release),             // SIG_SETMASK
                        _ => {}
                    }
                }
                reply_val(ep_cap, 0);
            }

            // SYS_ioctl — terminal emulation
            16 => {
                use sotos_common::linux_abi::*;
                let fd = msg.regs[0] as usize;
                let req = msg.regs[1] as u32;
                if fd <= 2 {
                    match req {
                        TCGETS => {
                            let buf = msg.regs[2] as *mut u8;
                            if !buf.is_null() {
                                // Write 60 bytes: 44-byte Termios struct + 16 bytes padding (musl expects 60)
                                unsafe { core::ptr::write_bytes(buf, 0, 60); }
                                let p = buf as *mut u32;
                                unsafe {
                                    *p = 0x0100 | 0x0400;           // c_iflag: ICRNL | IXON
                                    *p.add(1) = 0x0001 | 0x0004;   // c_oflag: OPOST | ONLCR
                                    *p.add(2) = 0x0030 | 0x0080 | 0x000F; // c_cflag: CS8|CREAD|B38400
                                    *p.add(3) = 0x0008 | 0x0010 | 0x0020 | 0x0002 | 0x0001 | 0x8000 | 0x0200 | 0x0800; // c_lflag
                                }
                                let cc = unsafe { buf.add(17) };
                                unsafe {
                                    *cc = 0x03;           // VINTR = Ctrl-C
                                    *cc.add(1) = 0x1C;   // VQUIT = Ctrl-backslash
                                    *cc.add(2) = 0x7F;   // VERASE = DEL
                                    *cc.add(3) = 0x15;   // VKILL = Ctrl-U
                                    *cc.add(4) = 0x04;   // VEOF = Ctrl-D
                                    *cc.add(6) = 0x01;   // VMIN = 1
                                    *cc.add(13) = 0x1A;  // VSUSP = Ctrl-Z
                                }
                            }
                            reply_val(ep_cap, 0);
                        }
                        TCSETS | TCSETSW | TCSETSF => reply_val(ep_cap, 0),
                        TIOCGWINSZ => {
                            let ws = Winsize::default_serial();
                            let buf = msg.regs[2] as *mut Winsize;
                            if !buf.is_null() { unsafe { *buf = ws; } }
                            reply_val(ep_cap, 0);
                        }
                        TIOCSWINSZ => reply_val(ep_cap, 0),
                        TIOCGPGRP | TIOCSPGRP => {
                            if req == TIOCGPGRP {
                                let buf = msg.regs[2] as *mut i32;
                                if !buf.is_null() { unsafe { *buf = pid as i32; } }
                            }
                            reply_val(ep_cap, 0);
                        }
                        FIONREAD => {
                            let buf = msg.regs[2] as *mut i32;
                            if !buf.is_null() {
                                let avail = if unsafe { kb_has_char() } { 1i32 } else { 0i32 };
                                unsafe { *buf = avail; }
                            }
                            reply_val(ep_cap, 0);
                        }
                        _ => reply_val(ep_cap, -25), // -ENOTTY
                    }
                } else { reply_val(ep_cap, -9); }
            }

            // SYS_readv(fd, iov, iovcnt) — scatter read
            19 => {
                let fd = msg.regs[0] as usize;
                let iov_ptr = msg.regs[1];
                let iovcnt = msg.regs[2] as usize;
                if fd >= CHILD_MAX_FDS || child_fds[fd] == 0 {
                    reply_val(ep_cap, -9); // -EBADF
                } else if child_fds[fd] == 1 {
                    // stdin readv: read one char into first iovec
                    if iovcnt > 0 && iov_ptr < 0x0000_8000_0000_0000 {
                        let base = unsafe { *(iov_ptr as *const u64) };
                        loop {
                            let s = sig_dequeue(pid);
                            if s != 0 && sig_dispatch(pid, s) >= 1 {
                                reply_val(ep_cap, -4); break;
                            }
                            match unsafe { kb_read_char() } {
                                Some(ch) => {
                                    if base != 0 { unsafe { *(base as *mut u8) = ch; } }
                                    reply_val(ep_cap, 1); break;
                                }
                                None => { unsafe { poll_mouse(); } sys::yield_now(); }
                            }
                        }
                    } else {
                        reply_val(ep_cap, 0);
                    }
                } else if child_fds[fd] == 12 {
                    // Initrd file readv
                    let mut total: usize = 0;
                    let mut found = false;
                    for s_idx in 0..MAX_INITRD_FILES {
                        if initrd_files[s_idx][3] == fd as u64 && initrd_files[s_idx][0] != 0 {
                            let data_base = initrd_files[s_idx][0];
                            let file_size = initrd_files[s_idx][1];
                            let mut pos = initrd_files[s_idx][2];
                            let cnt = iovcnt.min(16);
                            for i in 0..cnt {
                                let entry = iov_ptr + (i as u64) * 16;
                                if entry + 16 > 0x0000_8000_0000_0000 { break; }
                                let base = unsafe { *(entry as *const u64) };
                                let len = unsafe { *((entry + 8) as *const u64) } as usize;
                                if base == 0 || len == 0 { continue; }
                                let avail = if pos < file_size { (file_size - pos) as usize } else { 0 };
                                let to_read = len.min(avail);
                                if to_read > 0 {
                                    unsafe {
                                        core::ptr::copy_nonoverlapping(
                                            (data_base + pos) as *const u8,
                                            base as *mut u8,
                                            to_read,
                                        );
                                    }
                                    pos += to_read as u64;
                                    total += to_read;
                                }
                                if to_read < len { break; } // EOF mid-iovec
                            }
                            initrd_files[s_idx][2] = pos;
                            found = true;
                            break;
                        }
                    }
                    if found {
                        reply_val(ep_cap, total as i64);
                    } else {
                        reply_val(ep_cap, -9);
                    }
                } else if child_fds[fd] == 2 {
                    // stdout/stderr readv → -EBADF (write-only)
                    reply_val(ep_cap, -9);
                } else {
                    reply_val(ep_cap, 0); // other FD types: EOF
                }
            }

            // SYS_writev
            20 => {
                let fd = msg.regs[0] as usize;
                let iov_ptr = msg.regs[1];
                let iovcnt = msg.regs[2] as usize;
                if fd < CHILD_MAX_FDS && child_fds[fd] == 2 {
                    let mut total: usize = 0;
                    let cnt = iovcnt.min(16);
                    for i in 0..cnt {
                        let entry = iov_ptr + (i as u64) * 16;
                        if entry + 16 > 0x0000_8000_0000_0000 { break; }
                        let base = unsafe { *(entry as *const u64) };
                        let len = unsafe { *((entry + 8) as *const u64) } as usize;
                        if base == 0 || len == 0 { continue; }
                        let data = unsafe { core::slice::from_raw_parts(base as *const u8, len) };
                        for &b in data { sys::debug_print(b); unsafe { fb_putchar(b); } }
                        total += len;
                    }
                    reply_val(ep_cap, total as i64);
                } else if fd < CHILD_MAX_FDS && child_fds[fd] == 8 {
                    // /dev/null: count bytes and discard
                    let mut total: usize = 0;
                    let cnt = iovcnt.min(16);
                    for i in 0..cnt {
                        let entry = iov_ptr + (i as u64) * 16;
                        if entry + 16 > 0x0000_8000_0000_0000 { break; }
                        let len = unsafe { *((entry + 8) as *const u64) } as usize;
                        total += len;
                    }
                    reply_val(ep_cap, total as i64);
                } else {
                    reply_val(ep_cap, -9);
                }
            }

            // SYS_access / SYS_faccessat — check file accessibility
            21 | 269 => {
                let path_ptr = if syscall_nr == 269 { msg.regs[1] } else { msg.regs[0] };
                let mut path = [0u8; 128];
                let path_len = copy_guest_path(path_ptr, &mut path);
                let name = &path[..path_len];
                // Directories
                let is_dir = starts_with(name, b"/usr") || starts_with(name, b"/etc")
                    || starts_with(name, b"/lib") || name == b"/";
                if is_dir {
                    reply_val(ep_cap, 0);
                } else {
                    // Check initrd by basename
                    let mut basename_start = 0usize;
                    for idx in 0..path_len { if name[idx] == b'/' { basename_start = idx + 1; } }
                    let basename = &name[basename_start..];
                    if !basename.is_empty() {
                        match sys::initrd_read(basename.as_ptr() as u64, basename.len() as u64, 0, 0) {
                            Ok(_) => reply_val(ep_cap, 0),
                            Err(_) => reply_val(ep_cap, -2),
                        }
                    } else {
                        reply_val(ep_cap, -2);
                    }
                }
            }

            // SYS_pipe
            22 => {
                let pipefd = msg.regs[0] as *mut i32;
                // Allocate two FDs for pipe (read=PipeRead, write=PipeWrite)
                let mut r_fd = None;
                let mut w_fd = None;
                for i in 3..CHILD_MAX_FDS {
                    if child_fds[i] == 0 {
                        if r_fd.is_none() { r_fd = Some(i); }
                        else if w_fd.is_none() { w_fd = Some(i); break; }
                    }
                }
                if let (Some(r), Some(w)) = (r_fd, w_fd) {
                    child_fds[r] = 10; // pipe read end
                    child_fds[w] = 11; // pipe write end
                    unsafe { *pipefd = r as i32; *pipefd.add(1) = w as i32; }
                    reply_val(ep_cap, 0);
                } else {
                    reply_val(ep_cap, -24); // -EMFILE
                }
            }

            // SYS_nanosleep
            35 => reply_val(ep_cap, 0),

            // SYS_getpid — returns tgid (thread group ID), not tid
            39 => {
                let tgid = PROC_TGID[pid - 1].load(Ordering::Acquire);
                reply_val(ep_cap, if tgid != 0 { tgid as i64 } else { pid as i64 });
            }

            // SYS_gettid — returns actual thread ID
            186 => reply_val(ep_cap, pid as i64),

            // SYS_dup(oldfd)
            32 => {
                let oldfd = msg.regs[0] as usize;
                if oldfd >= CHILD_MAX_FDS || child_fds[oldfd] == 0 {
                    reply_val(ep_cap, -9);
                } else {
                    let mut newfd = None;
                    for i in 0..CHILD_MAX_FDS {
                        if child_fds[i] == 0 { newfd = Some(i); break; }
                    }
                    if let Some(nfd) = newfd {
                        child_fds[nfd] = child_fds[oldfd];
                        reply_val(ep_cap, nfd as i64);
                    } else {
                        reply_val(ep_cap, -24);
                    }
                }
            }

            // SYS_dup2(oldfd, newfd)
            33 => {
                let oldfd = msg.regs[0] as usize;
                let newfd = msg.regs[1] as usize;
                if oldfd >= CHILD_MAX_FDS || child_fds[oldfd] == 0 || newfd >= CHILD_MAX_FDS {
                    reply_val(ep_cap, -9);
                } else {
                    child_fds[newfd] = child_fds[oldfd];
                    reply_val(ep_cap, newfd as i64);
                }
            }

            // SYS_execve(path) — generic: loads any ELF from initrd
            59 => {
                let path_ptr = msg.regs[0];
                let mut path = [0u8; 48];
                let path_len = copy_guest_path(path_ptr, &mut path);
                let name = &path[..path_len];
                let bin_name = if path_len > 5 && starts_with(name, b"/bin/") { &name[5..] } else { name };

                let is_shell = bin_name == b"shell" || bin_name == b"sh";
                if is_shell {
                    let boot_info = unsafe { &*(BOOT_INFO_ADDR as *const BootInfo) };
                    let entry = boot_info.guest_entry;
                    if entry == 0 { reply_val(ep_cap, -2); continue; }
                    let stack_addr = NEXT_CHILD_STACK.fetch_add(0x2000, Ordering::SeqCst);
                    let guest_frame = match sys::frame_alloc() { Ok(f) => f, Err(_) => { reply_val(ep_cap, -12); continue; } };
                    if sys::map(stack_addr, guest_frame, MAP_WRITABLE).is_err() { reply_val(ep_cap, -12); continue; }
                    let new_ep = match sys::endpoint_create() { Ok(e) => e, Err(_) => { reply_val(ep_cap, -12); continue; } };
                    let new_thread = match sys::thread_create_redirected(entry, stack_addr + 0x1000, new_ep) { Ok(t) => t, Err(_) => { reply_val(ep_cap, -12); continue; } };
                    let _ = sys::signal_entry(new_thread, vdso::SIGNAL_TRAMPOLINE_ADDR);
                    ep_cap = new_ep;
                    continue;
                }

                while EXEC_LOCK.compare_exchange(0, 1, Ordering::AcqRel, Ordering::Relaxed).is_err() { sys::yield_now(); }
                match exec_from_initrd(bin_name) {
                    Ok((new_ep, _tc)) => { EXEC_LOCK.store(0, Ordering::Release); ep_cap = new_ep; continue; }
                    Err(errno) => { EXEC_LOCK.store(0, Ordering::Release); reply_val(ep_cap, errno); continue; }
                }
            }

            // SYS_exit(status)
            60 => {
                let status = msg.regs[0];
                if pid > 0 && pid <= MAX_PROCS {
                    // CLONE_CHILD_CLEARTID: write 0 to *clear_child_tid + futex_wake
                    let ctid_ptr = PROC_CLEAR_TID[pid - 1].load(Ordering::Acquire);
                    if ctid_ptr != 0 {
                        unsafe { core::ptr::write_volatile(ctid_ptr as *mut u32, 0); }
                        futex_wake(ctid_ptr, 1);
                    }
                    PROC_EXIT[pid - 1].store(status, Ordering::Release);
                    PROC_STATE[pid - 1].store(2, Ordering::Release);
                    // Deliver SIGCHLD to parent
                    let ppid = PROC_PARENT[pid - 1].load(Ordering::Acquire) as usize;
                    if ppid > 0 && ppid <= MAX_PROCS {
                        sig_send(ppid, SIGCHLD);
                    }
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
                sig_send(target, sig);
                reply_val(ep_cap, 0);
            }

            // SYS_clone(flags, child_stack, ptid, ctid, newtls) — create a thread
            56 => {
                let flags = msg.regs[0];
                let child_stack = msg.regs[1];
                let ptid_ptr = msg.regs[2];
                let ctid_ptr = msg.regs[3];
                let newtls = msg.regs[4];
                let fn_ptr = msg.regs[5]; // r9 = fn (from musl's __clone)

                // Allocate child PID
                let child_pid = NEXT_PID.fetch_add(1, Ordering::SeqCst) as usize;
                if child_pid > MAX_PROCS {
                    reply_val(ep_cap, -12); // -ENOMEM
                    continue;
                }

                // Initialize thread group state based on clone flags
                PROC_PARENT[child_pid - 1].store(pid as u64, Ordering::Release);
                proc_thread_init(child_pid, pid, flags);

                // CLONE_PARENT_SETTID: write child TID to *ptid
                if flags & CLONE_PARENT_SETTID != 0 && ptid_ptr != 0 {
                    unsafe { core::ptr::write_volatile(ptid_ptr as *mut u32, child_pid as u32); }
                }

                // CLONE_CHILD_CLEARTID: store ctid pointer for exit cleanup
                if flags & CLONE_CHILD_CLEARTID != 0 && ctid_ptr != 0 {
                    PROC_CLEAR_TID[child_pid - 1].store(ctid_ptr, Ordering::Release);
                }

                // Set up the child's stack for clone_child_trampoline:
                // Layout: [fn_ptr, arg, tls_ptr] (popped in order by trampoline)
                // musl __clone pushed arg at [child_stack], so read it first
                let arg = if child_stack != 0 {
                    unsafe { core::ptr::read_volatile(child_stack as *const u64) }
                } else {
                    0
                };
                let tls = if flags & CLONE_SETTLS != 0 { newtls } else { 0 };

                // Write trampoline setup below child_stack (stack grows down)
                let child_sp = child_stack - 24;
                unsafe {
                    core::ptr::write_volatile((child_sp) as *mut u64, fn_ptr);        // [rsp+0] → fn
                    core::ptr::write_volatile((child_sp + 8) as *mut u64, arg);       // [rsp+8] → arg
                    core::ptr::write_volatile((child_sp + 16) as *mut u64, tls);      // [rsp+16] → tls
                }

                // Allocate handler stack (4 pages)
                let handler_stack_base = NEXT_CHILD_STACK.fetch_add(0x4000, Ordering::SeqCst);
                let mut hok = true;
                for hp in 0..4u64 {
                    let hf = match sys::frame_alloc() {
                        Ok(f) => f,
                        Err(_) => { hok = false; break; }
                    };
                    if sys::map(handler_stack_base + hp * 0x1000, hf, MAP_WRITABLE).is_err() {
                        hok = false; break;
                    }
                }
                if !hok {
                    reply_val(ep_cap, -12);
                    continue;
                }

                // Create child endpoint
                let child_ep = match sys::endpoint_create() {
                    Ok(e) => e,
                    Err(_) => { reply_val(ep_cap, -12); continue; }
                };

                // Pass setup info to child handler
                while CHILD_SETUP_READY.load(Ordering::Acquire) != 0 { sys::yield_now(); }
                CHILD_SETUP_EP.store(child_ep, Ordering::Release);
                CHILD_SETUP_PID.store(child_pid as u64, Ordering::Release);
                CHILD_SETUP_FLAGS.store(flags, Ordering::Release);
                CHILD_SETUP_READY.store(1, Ordering::Release);

                // Spawn child handler thread
                if sys::thread_create(
                    child_handler as *const () as u64,
                    handler_stack_base + 0x4000,
                ).is_err() {
                    CHILD_SETUP_READY.store(0, Ordering::Release);
                    reply_val(ep_cap, -12);
                    continue;
                }

                // Wait for child handler to consume setup
                while CHILD_SETUP_READY.load(Ordering::Acquire) != 0 {
                    sys::yield_now();
                }

                // Spawn child guest thread at clone_child_trampoline, redirected to child handler
                let child_thread = match sys::thread_create_redirected(
                    clone_child_trampoline as *const () as u64,
                    child_sp,
                    child_ep,
                ) {
                    Ok(t) => t,
                    Err(_) => { reply_val(ep_cap, -12); continue; }
                };
                let _ = sys::signal_entry(child_thread, vdso::SIGNAL_TRAMPOLINE_ADDR);

                // Mark child as running
                PROC_STATE[child_pid - 1].store(1, Ordering::Release);

                // Reply to parent with child TID
                reply_val(ep_cap, child_pid as i64);
            }

            // SYS_uname
            63 => {
                let buf_ptr = msg.regs[0];
                if buf_ptr != 0 && buf_ptr < 0x0000_8000_0000_0000 {
                    let buf = unsafe { core::slice::from_raw_parts_mut(buf_ptr as *mut u8, 390) };
                    for b in buf.iter_mut() { *b = 0; }
                    let fields: [&[u8]; 5] = [b"sotOS", b"sotos", b"0.1.0", b"sotOS 0.1.0 LUCAS", b"x86_64"];
                    for (i, field) in fields.iter().enumerate() {
                        let off = i * 65;
                        let len = field.len().min(64);
                        buf[off..off + len].copy_from_slice(&field[..len]);
                    }
                }
                reply_val(ep_cap, 0);
            }

            // SYS_fcntl
            72 => {
                let fd = msg.regs[0] as usize;
                let cmd = msg.regs[1] as u32;
                match cmd {
                    0 => { // F_DUPFD
                        let min = msg.regs[2] as usize;
                        if fd >= CHILD_MAX_FDS || child_fds[fd] == 0 { reply_val(ep_cap, -9); }
                        else {
                            let mut nfd = None;
                            for i in min..CHILD_MAX_FDS { if child_fds[i] == 0 { nfd = Some(i); break; } }
                            if let Some(n) = nfd { child_fds[n] = child_fds[fd]; reply_val(ep_cap, n as i64); }
                            else { reply_val(ep_cap, -24); }
                        }
                    }
                    1 | 3 => reply_val(ep_cap, 0), // F_GETFD, F_GETFL
                    2 | 4 => reply_val(ep_cap, 0), // F_SETFD, F_SETFL
                    _ => reply_val(ep_cap, -22),
                }
            }

            // SYS_getcwd
            79 => {
                let buf = msg.regs[0] as *mut u8;
                let size = msg.regs[1] as usize;
                if size >= 2 {
                    unsafe { *buf = b'/'; *buf.add(1) = 0; }
                    reply_val(ep_cap, buf as i64);
                } else {
                    reply_val(ep_cap, -34); // -ERANGE
                }
            }

            // SYS_rename — stub
            82 => reply_val(ep_cap, -38),

            // SYS_gettimeofday
            96 => {
                let tv = msg.regs[0] as *mut u64;
                if !tv.is_null() {
                    let tsc = rdtsc();
                    let boot_tsc = BOOT_TSC.load(Ordering::Acquire);
                    let elapsed_us = if tsc > boot_tsc { (tsc - boot_tsc) / 2000 } else { 0 };
                    unsafe { *tv = elapsed_us / 1_000_000; *tv.add(1) = elapsed_us % 1_000_000; }
                }
                reply_val(ep_cap, 0);
            }

            // SYS_sysinfo — stub
            99 => {
                let buf = msg.regs[0] as *mut u8;
                if !buf.is_null() {
                    unsafe { core::ptr::write_bytes(buf, 0, 128); }
                    let tsc = rdtsc();
                    let boot_tsc = BOOT_TSC.load(Ordering::Acquire);
                    let secs = if tsc > boot_tsc { (tsc - boot_tsc) / 2_000_000_000 } else { 0 };
                    unsafe { *(buf as *mut u64) = secs; } // uptime
                }
                reply_val(ep_cap, 0);
            }

            // SYS_getuid/geteuid/getgid/getegid
            102 | 104 | 107 | 108 => reply_val(ep_cap, 0),

            // SYS_setpgid
            109 => reply_val(ep_cap, 0),

            // SYS_getppid
            110 => reply_val(ep_cap, parent_pid as i64),

            // SYS_getpgrp
            111 => reply_val(ep_cap, pid as i64),

            // SYS_setsid
            112 => reply_val(ep_cap, pid as i64),

            // SYS_setfsuid / SYS_setfsgid — return previous (0)
            122 | 123 => reply_val(ep_cap, 0),

            // SYS_sigaltstack — stub
            131 => {
                let old_ss = msg.regs[1];
                if old_ss != 0 && old_ss < 0x0000_8000_0000_0000 {
                    let buf = unsafe { core::slice::from_raw_parts_mut(old_ss as *mut u8, 24) };
                    for b in buf.iter_mut() { *b = 0; }
                    buf[8..12].copy_from_slice(&2u32.to_le_bytes());
                }
                reply_val(ep_cap, 0);
            }

            // SYS_openat — /dev files + initrd files + VFS files
            257 => {
                let path_ptr = msg.regs[1];
                let flags = msg.regs[2] as u32;
                let mut path = [0u8; 128];
                let path_len = copy_guest_path(path_ptr, &mut path);
                let name = &path[..path_len];

                let kind = if name == b"/dev/null" { 8u8 }
                    else if name == b"/dev/zero" { 9u8 }
                    else if name == b"/dev/urandom" || name == b"/dev/random" { 9u8 }
                    else { 0u8 };

                if kind != 0 {
                    let mut fd = None;
                    for i in 3..CHILD_MAX_FDS { if child_fds[i] == 0 { fd = Some(i); break; } }
                    if let Some(f) = fd {
                        child_fds[f] = kind;
                        reply_val(ep_cap, f as i64);
                    } else {
                        reply_val(ep_cap, -24);
                    }
                } else if starts_with(name, b"/etc/") {
                    // /etc virtual files for DNS resolution
                    let mut gen_len: usize = 0;
                    if name == b"/etc/resolv.conf" {
                        let c = b"nameserver 10.0.2.3\n";
                        dir_buf[..c.len()].copy_from_slice(c);
                        gen_len = c.len();
                    } else if name == b"/etc/hosts" {
                        let c = b"127.0.0.1 localhost\n::1 localhost\n";
                        dir_buf[..c.len()].copy_from_slice(c);
                        gen_len = c.len();
                    } else if name == b"/etc/nsswitch.conf" {
                        let c = b"hosts: files dns\n";
                        dir_buf[..c.len()].copy_from_slice(c);
                        gen_len = c.len();
                    } else if name == b"/etc/gai.conf" || name == b"/etc/host.conf"
                           || name == b"/etc/services" || name == b"/etc/protocols" {
                        gen_len = 0; // empty
                    } else {
                        reply_val(ep_cap, -2);
                        continue;
                    }
                    *dir_len = gen_len;
                    *dir_pos = 0;
                    let mut fd = None;
                    for i in 3..CHILD_MAX_FDS { if child_fds[i] == 0 { fd = Some(i); break; } }
                    if let Some(f) = fd {
                        child_fds[f] = 15; // kind=15 = virtual procfs file (reuse)
                        reply_val(ep_cap, f as i64);
                    } else {
                        reply_val(ep_cap, -24);
                    }
                } else if starts_with(name, b"/proc/") || starts_with(name, b"/sys/") {
                    // Virtual procfs/sysfs files — generate content into dir_buf
                    let mut gen_len: usize = 0;
                    let mut handled = true;
                    if name == b"/proc/self/maps" || name == b"/proc/self/smaps" {
                        // Minimal memory map (approximate but enough for parsers)
                        let map_text = b"\
00400000-00500000 r-xp 00000000 00:00 0          [text]\n\
00e30000-00e34000 rw-p 00000000 00:00 0          [stack]\n\
07000000-07200000 rw-p 00000000 00:00 0          [heap]\n\
00b80000-00b81000 r-xp 00000000 00:00 0          [vdso]\n";
                        let n = map_text.len().min(dir_buf.len());
                        dir_buf[..n].copy_from_slice(&map_text[..n]);
                        gen_len = n;
                    } else if name == b"/proc/self/status" {
                        gen_len = format_proc_status(dir_buf, pid);
                    } else if name == b"/proc/self/stat" {
                        // Minimal: "pid (name) R ppid pgid sid ..."
                        let mut pos = 0usize;
                        pos += format_u64_into(&mut dir_buf[pos..], pid as u64);
                        let tail = b" (program) R 0 1 1 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0\n";
                        let n = tail.len().min(dir_buf.len() - pos);
                        dir_buf[pos..pos + n].copy_from_slice(&tail[..n]);
                        gen_len = pos + n;
                    } else if name == b"/proc/cpuinfo" {
                        let info = b"processor\t: 0\nvendor_id\t: GenuineIntel\ncpu family\t: 6\nmodel name\t: QEMU Virtual CPU\ncache size\t: 4096 KB\nflags\t\t: fpu sse sse2 ssse3 sse4_1 sse4_2 rdtsc\n\n";
                        let n = info.len().min(dir_buf.len());
                        dir_buf[..n].copy_from_slice(&info[..n]);
                        gen_len = n;
                    } else if name == b"/proc/meminfo" {
                        let info = b"MemTotal:       262144 kB\nMemFree:        131072 kB\nMemAvailable:   196608 kB\nBuffers:         8192 kB\nCached:         32768 kB\n";
                        let n = info.len().min(dir_buf.len());
                        dir_buf[..n].copy_from_slice(&info[..n]);
                        gen_len = n;
                    } else if name == b"/proc/self/auxv" || name == b"/proc/self/environ" {
                        // Empty content — valid FD that reads EOF
                    } else if starts_with(name, b"/proc/") {
                        // Other /proc paths — check for /proc/N/status
                        let rest = &path[6..path_len];
                        let (n, consumed) = parse_u64_from(rest);
                        if consumed > 0 && n >= 1 && n <= MAX_PROCS as u64
                            && PROC_STATE[n as usize - 1].load(Ordering::Acquire) != 0
                        {
                            let after = &rest[consumed..];
                            if after == b"/status" || after.is_empty() {
                                gen_len = format_proc_status(dir_buf, n as usize);
                            } else {
                                handled = false;
                            }
                        } else {
                            handled = false;
                        }
                    } else if starts_with(name, b"/sys/") {
                        // Sysfs: return empty content for known paths, ENOENT otherwise
                        if name == b"/sys/devices/system/cpu/online" {
                            let info = b"0-0\n";
                            dir_buf[..info.len()].copy_from_slice(info);
                            gen_len = info.len();
                        } else {
                            handled = false;
                        }
                    }

                    if !handled {
                        reply_val(ep_cap, -2); // -ENOENT
                    } else {
                        *dir_len = gen_len;
                        *dir_pos = 0;
                        let mut fd = None;
                        for i in 3..CHILD_MAX_FDS { if child_fds[i] == 0 { fd = Some(i); break; } }
                        if let Some(f) = fd {
                            child_fds[f] = 15; // procfs virtual file
                            reply_val(ep_cap, f as i64);
                        } else {
                            reply_val(ep_cap, -24); // -EMFILE
                        }
                    }
                } else {
                    // Try to open from initrd — extract basename from path
                    let mut basename_start = 0usize;
                    for idx in 0..path_len {
                        if name[idx] == b'/' { basename_start = idx + 1; }
                    }
                    let basename = &name[basename_start..];
                    let mut opened_initrd = false;

                    if !basename.is_empty() {
                        // Find a free initrd file slot
                        let mut slot = None;
                        for s in 0..MAX_INITRD_FILES {
                            if initrd_files[s][0] == 0 { slot = Some(s); break; }
                        }
                        if let Some(slot) = slot {
                            let file_buf = initrd_file_buf_base + (slot as u64) * 0x100000;
                            const FILE_BUF_PAGES_OPEN: u64 = 256;
                            let mut buf_ok = true;
                            for p in 0..FILE_BUF_PAGES_OPEN {
                                if let Ok(f) = sys::frame_alloc() {
                                    if sys::map(file_buf + p * 0x1000, f, MAP_WRITABLE).is_err() {
                                        buf_ok = false; break;
                                    }
                                } else { buf_ok = false; break; }
                            }
                            if buf_ok {
                                if let Ok(sz) = sys::initrd_read(
                                    basename.as_ptr() as u64,
                                    basename.len() as u64,
                                    file_buf,
                                    FILE_BUF_PAGES_OPEN * 0x1000,
                                ) {
                                    let mut fd = None;
                                    for i in 3..CHILD_MAX_FDS { if child_fds[i] == 0 { fd = Some(i); break; } }
                                    if let Some(f) = fd {
                                        child_fds[f] = 12;
                                        initrd_files[slot] = [file_buf, sz, 0, f as u64];
                                        reply_val(ep_cap, f as i64);
                                        opened_initrd = true;
                                    } else {
                                        for p in 0..FILE_BUF_PAGES_OPEN { let _ = sys::unmap(file_buf + p * 0x1000); }
                                        reply_val(ep_cap, -24);
                                        opened_initrd = true; // error already replied
                                    }
                                } else {
                                    for p in 0..FILE_BUF_PAGES_OPEN { let _ = sys::unmap(file_buf + p * 0x1000); }
                                }
                            }
                        }
                    }

                    // Fall through to VFS if initrd didn't handle it
                    if !opened_initrd {
                        let has_creat = (flags & 0o100) != 0; // O_CREAT
                        let has_trunc = (flags & 0o1000) != 0; // O_TRUNC

                        let has_dir = (flags & 0o200000) != 0; // O_DIRECTORY

                        vfs_lock();
                        // Returns (oid, size, is_dir)
                        let vfs_result = unsafe { shared_store() }.and_then(|store| {
                            use sotos_objstore::ROOT_OID;
                            match store.resolve_path(name, ROOT_OID) {
                                Ok(oid) => {
                                    let entry = store.stat(oid)?;
                                    if has_dir && !entry.is_dir() {
                                        return None; // O_DIRECTORY on non-dir → ENOTDIR
                                    }
                                    if has_trunc && !entry.is_dir() {
                                        let parent = entry.parent_oid;
                                        let fname = entry.name_as_str();
                                        let mut fname_buf = [0u8; 48];
                                        let flen = fname.len().min(48);
                                        fname_buf[..flen].copy_from_slice(&fname[..flen]);
                                        let _ = store.delete(oid);
                                        match store.create_in(&fname_buf[..flen], &[], parent) {
                                            Ok(new_oid) => Some((new_oid, 0u64, false)),
                                            Err(_) => None,
                                        }
                                    } else {
                                        Some((oid, entry.size, entry.is_dir()))
                                    }
                                }
                                Err(_) if has_creat => {
                                    let mut last_slash = None;
                                    for (i, &b) in name.iter().enumerate() {
                                        if b == b'/' { last_slash = Some(i); }
                                    }
                                    let (parent_oid, filename) = match last_slash {
                                        Some(pos) => {
                                            let parent_path = &name[..pos];
                                            let fname = &name[pos + 1..];
                                            let p = if parent_path.is_empty() {
                                                ROOT_OID
                                            } else {
                                                store.resolve_path(parent_path, ROOT_OID).ok()?
                                            };
                                            (p, fname)
                                        }
                                        None => (ROOT_OID, name),
                                    };
                                    match store.create_in(filename, &[], parent_oid) {
                                        Ok(oid) => Some((oid, 0u64, false)),
                                        Err(_) => None,
                                    }
                                }
                                Err(_) => None,
                            }
                        });
                        vfs_unlock();

                        match vfs_result {
                            Some((oid, size, is_dir)) => {
                                let mut vslot = None;
                                for s in 0..MAX_VFS_FILES {
                                    if vfs_files[s][0] == 0 { vslot = Some(s); break; }
                                }
                                let mut fd = None;
                                for i in 3..CHILD_MAX_FDS { if child_fds[i] == 0 { fd = Some(i); break; } }
                                if let (Some(vs), Some(f)) = (vslot, fd) {
                                    child_fds[f] = if is_dir { 14 } else { 13 }; // 14=VFS dir, 13=VFS file
                                    vfs_files[vs] = [oid, size, 0, f as u64];
                                    reply_val(ep_cap, f as i64);
                                } else {
                                    reply_val(ep_cap, -24); // -EMFILE
                                }
                            }
                            None => reply_val(ep_cap, -2), // -ENOENT
                        }
                    }
                }
            }

            // SYS_set_tid_address — store clear_child_tid pointer, return TID
            218 => {
                let tidptr = msg.regs[0];
                PROC_CLEAR_TID[pid - 1].store(tidptr, Ordering::Release);
                reply_val(ep_cap, pid as i64);
            }

            // SYS_clock_gettime
            228 => {
                let tp_ptr = msg.regs[1];
                if tp_ptr != 0 && tp_ptr < 0x0000_8000_0000_0000 {
                    let tsc = rdtsc();
                    let boot_tsc = BOOT_TSC.load(Ordering::Acquire);
                    let elapsed_ns = if tsc > boot_tsc { (tsc - boot_tsc) / 2 } else { 0 };
                    let tp = unsafe { core::slice::from_raw_parts_mut(tp_ptr as *mut u8, 16) };
                    tp[0..8].copy_from_slice(&((elapsed_ns / 1_000_000_000) as i64).to_le_bytes());
                    tp[8..16].copy_from_slice(&((elapsed_ns % 1_000_000_000) as i64).to_le_bytes());
                }
                reply_val(ep_cap, 0);
            }

            // SYS_exit_group
            231 => {
                let status = msg.regs[0] as i32;
                // CLONE_CHILD_CLEARTID: write 0 to *clear_child_tid + futex_wake
                let ctid_ptr = PROC_CLEAR_TID[pid - 1].load(Ordering::Acquire);
                if ctid_ptr != 0 {
                    unsafe { core::ptr::write_volatile(ctid_ptr as *mut u32, 0); }
                    futex_wake(ctid_ptr, 1);
                }
                PROC_EXIT[pid - 1].store(status as u64, Ordering::Release);
                PROC_STATE[pid - 1].store(2, Ordering::Release);
                // Deliver SIGCHLD to parent
                let ppid = PROC_PARENT[pid - 1].load(Ordering::Acquire) as usize;
                if ppid > 0 && ppid <= MAX_PROCS {
                    sig_send(ppid, SIGCHLD);
                }
                break;
            }

            // SYS_fstatat(dirfd, path, statbuf, flags)
            262 => {
                let dirfd = msg.regs[0] as i64;
                let path_ptr = msg.regs[1];
                let stat_ptr = msg.regs[2];
                let flags = msg.regs[3] as u32;
                let mut path = [0u8; 128];
                let path_len = copy_guest_path(path_ptr, &mut path);
                let name = &path[..path_len];

                // AT_EMPTY_PATH (0x1000): use dirfd as the file descriptor
                if (flags & 0x1000) != 0 && path_len == 0 {
                    let fd = dirfd as usize;
                    if fd < CHILD_MAX_FDS && child_fds[fd] != 0 {
                        if child_fds[fd] == 12 {
                            let mut size = 0u64;
                            for s in 0..MAX_INITRD_FILES {
                                if initrd_files[s][3] == fd as u64 && initrd_files[s][0] != 0 {
                                    size = initrd_files[s][1];
                                    break;
                                }
                            }
                            write_linux_stat(stat_ptr, fd as u64, size, false);
                        } else {
                            write_linux_stat(stat_ptr, fd as u64, 0, false);
                        }
                        reply_val(ep_cap, 0);
                    } else {
                        reply_val(ep_cap, -9); // -EBADF
                    }
                    continue;
                }

                // First try initrd by basename (files take priority)
                let mut basename_start = 0usize;
                for idx in 0..path_len { if name[idx] == b'/' { basename_start = idx + 1; } }
                let basename = &name[basename_start..];
                if !basename.is_empty() {
                    if let Ok(sz) = sys::initrd_read(basename.as_ptr() as u64, basename.len() as u64, 0, 0) {
                        write_linux_stat(stat_ptr, 0, sz, false);
                        reply_val(ep_cap, 0);
                        continue;
                    }
                }
                // Fall back to directory stubs ("." = CWD)
                let is_dir = name == b"." || path_len == 0
                    || starts_with(name, b"/usr") || starts_with(name, b"/etc")
                    || starts_with(name, b"/lib") || name == b"/";
                if is_dir {
                    write_linux_stat(stat_ptr, 0, 4096, true);
                    reply_val(ep_cap, 0);
                } else {
                    // Try VFS
                    vfs_lock();
                    let vfs_stat = unsafe { shared_store() }.and_then(|store| {
                        let oid = store.resolve_path(name, sotos_objstore::ROOT_OID).ok()?;
                        store.stat(oid)
                    });
                    vfs_unlock();
                    match vfs_stat {
                        Some(entry) => {
                            write_linux_stat(stat_ptr, entry.oid, entry.size, entry.is_dir());
                            reply_val(ep_cap, 0);
                        }
                        None => reply_val(ep_cap, -2),
                    }
                }
            }

            // SYS_readlinkat(dirfd, path, buf, bufsiz)
            267 => {
                let path_ptr = msg.regs[1];
                let out_buf = msg.regs[2];
                let bufsiz = msg.regs[3] as usize;
                let mut rpath = [0u8; 64];
                let rpath_len = copy_guest_path(path_ptr, &mut rpath);
                if rpath_len >= 14 && &rpath[..14] == b"/proc/self/exe" {
                    // Return a generic executable path
                    let exe = b"/bin/program";
                    let n = exe.len().min(bufsiz);
                    if out_buf != 0 && out_buf < 0x0000_8000_0000_0000 {
                        unsafe {
                            core::ptr::copy_nonoverlapping(
                                exe.as_ptr(), out_buf as *mut u8, n,
                            );
                        }
                    }
                    reply_val(ep_cap, n as i64);
                } else {
                    reply_val(ep_cap, -22); // -EINVAL
                }
            }

            // SYS_prlimit64
            302 => {
                let new_limit = msg.regs[2];
                let old_limit = msg.regs[3];
                if old_limit != 0 && old_limit < 0x0000_8000_0000_0000 {
                    // Return generous limits
                    let buf = unsafe { core::slice::from_raw_parts_mut(old_limit as *mut u8, 16) };
                    let big: u64 = 0x7FFF_FFFF_FFFF_FFFF;
                    buf[0..8].copy_from_slice(&big.to_le_bytes()); // rlim_cur
                    buf[8..16].copy_from_slice(&big.to_le_bytes()); // rlim_max
                }
                let _ = new_limit;
                reply_val(ep_cap, 0);
            }

            // SYS_getrandom
            318 => {
                let buf_ptr = msg.regs[0] as *mut u8;
                let buflen = msg.regs[1] as usize;
                let tsc = rdtsc();
                let mut seed = tsc;
                for i in 0..buflen {
                    seed ^= seed << 13; seed ^= seed >> 7; seed ^= seed << 17;
                    unsafe { *buf_ptr.add(i) = seed as u8; }
                }
                reply_val(ep_cap, buflen as i64);
            }

            // SYS_futex(uaddr, op, val, timeout, uaddr2, val3)
            202 => {
                let uaddr = msg.regs[0];
                let op = (msg.regs[1] & 0x7F) as u32; // mask off FUTEX_PRIVATE_FLAG
                let val = msg.regs[2] as u32;
                match op {
                    0 => { // FUTEX_WAIT
                        let result = futex_wait(uaddr, val);
                        reply_val(ep_cap, result);
                    }
                    1 => { // FUTEX_WAKE
                        let result = futex_wake(uaddr, val);
                        reply_val(ep_cap, result);
                    }
                    _ => reply_val(ep_cap, 0), // other ops: stub
                }
            }

            // SYS_sched_getaffinity — return 1 CPU
            204 => {
                let mask_ptr = msg.regs[2] as *mut u8;
                let len = msg.regs[1] as usize;
                if !mask_ptr.is_null() && len > 0 {
                    unsafe {
                        core::ptr::write_bytes(mask_ptr, 0, len.min(128));
                        *mask_ptr = 1; // CPU 0
                    }
                }
                reply_val(ep_cap, len.min(128) as i64);
            }

            // SYS_getdents64(fd, dirp, count)
            217 => {
                use sotos_common::linux_abi::{DT_REG, DT_DIR};
                let fd = msg.regs[0] as usize;
                let dirp = msg.regs[1];
                let count = msg.regs[2] as usize;

                if fd >= CHILD_MAX_FDS || child_fds[fd] != 14 {
                    // FD kind 14 = VFS directory (opened via openat with O_DIRECTORY)
                    // Also support kind 13 that turns out to be a dir
                    reply_val(ep_cap, -9); // -EBADF
                } else {
                    // Populate dir_buf on first call (dir_pos == 0 && dir_len == 0)
                    if *dir_pos >= *dir_len {
                        *dir_len = 0;
                        *dir_pos = 0;
                        // Find the directory OID from vfs_files
                        let mut dir_oid = 0u64;
                        for s in 0..MAX_VFS_FILES {
                            if vfs_files[s][3] == fd as u64 && vfs_files[s][0] != 0 {
                                dir_oid = vfs_files[s][0];
                                break;
                            }
                        }
                        if dir_oid != 0 {
                            vfs_lock();
                            if let Some(store) = unsafe { shared_store() } {
                                let mut entries = [sotos_objstore::DirEntry::zeroed(); 32];
                                let n = store.list_dir(dir_oid, &mut entries);
                                for i in 0..n {
                                    let entry = &entries[i];
                                    let ename = entry.name_as_str();
                                    let reclen = ((19 + ename.len() + 1 + 7) / 8) * 8;
                                    if *dir_len + reclen > dir_buf.len() { break; }
                                    let d = &mut dir_buf[*dir_len..*dir_len + reclen];
                                    for b in d.iter_mut() { *b = 0; }
                                    d[0..8].copy_from_slice(&entry.oid.to_le_bytes());
                                    d[8..16].copy_from_slice(&((*dir_len + reclen) as u64).to_le_bytes());
                                    d[16..18].copy_from_slice(&(reclen as u16).to_le_bytes());
                                    d[18] = if entry.is_dir() { DT_DIR } else { DT_REG };
                                    let nlen = ename.len().min(reclen - 19);
                                    d[19..19 + nlen].copy_from_slice(&ename[..nlen]);
                                    *dir_len += reclen;
                                }
                            }
                            vfs_unlock();
                        }
                    }

                    let remaining = if *dir_pos < *dir_len { *dir_len - *dir_pos } else { 0 };
                    if remaining == 0 {
                        reply_val(ep_cap, 0); // EOF
                    } else {
                        let copy_len = remaining.min(count);
                        unsafe {
                            core::ptr::copy_nonoverlapping(
                                dir_buf[*dir_pos..].as_ptr(),
                                dirp as *mut u8,
                                copy_len,
                            );
                        }
                        *dir_pos += copy_len;
                        reply_val(ep_cap, copy_len as i64);
                    }
                }
            }

            // SYS_fadvise64 — stub
            221 => reply_val(ep_cap, 0),

            // SYS_ppoll — like poll but with signal mask
            271 => {
                // Treat exactly like poll for now
                let fds_ptr = msg.regs[0] as *mut u8;
                let nfds = msg.regs[1] as usize;
                let mut ready = 0u32;
                for i in 0..nfds.min(16) {
                    let pfd = unsafe { fds_ptr.add(i * 8) };
                    let fd = unsafe { *(pfd as *const i32) };
                    let events = unsafe { *((pfd.add(4)) as *const i16) };
                    let mut revents: i16 = 0;
                    if fd >= 0 && (fd as usize) < CHILD_MAX_FDS && child_fds[fd as usize] != 0 {
                        if events & 1 != 0 {
                            if fd == 0 && child_fds[0] == 1 {
                                if unsafe { kb_has_char() } { revents |= 1; }
                            } else { revents |= 1; }
                        }
                        if events & 4 != 0 { revents |= 4; }
                    } else if fd >= 0 { revents = 0x20; }
                    unsafe { *((pfd.add(6)) as *mut i16) = revents; }
                    if revents != 0 { ready += 1; }
                }
                if ready > 0 {
                    reply_val(ep_cap, ready as i64);
                } else {
                    // Block waiting for input
                    let mut interrupted = false;
                    loop {
                        if unsafe { kb_has_char() } {
                            ready = 0;
                            for i in 0..nfds.min(16) {
                                let pfd = unsafe { fds_ptr.add(i * 8) };
                                let fd = unsafe { *(pfd as *const i32) };
                                let events = unsafe { *((pfd.add(4)) as *const i16) };
                                let mut revents: i16 = 0;
                                if fd == 0 && (events & 1 != 0) { revents |= 1; }
                                if events & 4 != 0 { revents |= 4; }
                                unsafe { *((pfd.add(6)) as *mut i16) = revents; }
                                if revents != 0 { ready += 1; }
                            }
                            break;
                        }
                        let s = sig_dequeue(pid);
                        if s != 0 && sig_dispatch(pid, s) >= 1 {
                            interrupted = true;
                            break;
                        }
                        sys::yield_now();
                    }
                    if interrupted {
                        reply_val(ep_cap, -4);
                    } else {
                        reply_val(ep_cap, ready as i64);
                    }
                }
            }

            // SYS_statx — not supported, force musl to fall back to fstatat
            332 => reply_val(ep_cap, -38), // -ENOSYS

            // SYS_rseq — restartable sequences (musl may use)
            334 => reply_val(ep_cap, -38), // -ENOSYS is fine

            // SYS_SIGNAL_TRAMPOLINE (0x7F00) — async signal delivery
            0x7F00 => {
                let child_tid = msg.regs[6];
                let sig = sig_dequeue(pid);
                if sig != 0 {
                    match sig_dispatch(pid, sig) {
                        1 => break, // terminated
                        3 => {
                            if signal_deliver(ep_cap, pid, sig, child_tid, 0, true) {
                                continue;
                            }
                        }
                        _ => {}
                    }
                }
                // No signal — resume with saved pre-interrupt state via rt_sigreturn
                let mut saved_regs = [0u64; 18];
                if sys::get_thread_regs(child_tid, &mut saved_regs).is_ok() {
                    let saved_rsp = saved_regs[15];
                    let frame_size = sotos_common::SIGNAL_FRAME_SIZE as u64;
                    let new_rsp = ((saved_rsp - frame_size) & !0xF) - 8;
                    let fp = new_rsp as *mut u64;
                    unsafe {
                        core::ptr::write_volatile(fp.add(0),  vdso::SIGRETURN_RESTORER_ADDR);
                        core::ptr::write_volatile(fp.add(1),  0);
                        core::ptr::write_volatile(fp.add(2),  saved_regs[0]);
                        core::ptr::write_volatile(fp.add(3),  saved_regs[1]);
                        core::ptr::write_volatile(fp.add(4),  saved_regs[2]);
                        core::ptr::write_volatile(fp.add(5),  saved_regs[3]);
                        core::ptr::write_volatile(fp.add(6),  saved_regs[4]);
                        core::ptr::write_volatile(fp.add(7),  saved_regs[5]);
                        core::ptr::write_volatile(fp.add(8),  saved_regs[6]);
                        core::ptr::write_volatile(fp.add(9),  saved_regs[7]);
                        core::ptr::write_volatile(fp.add(10), saved_regs[8]);
                        core::ptr::write_volatile(fp.add(11), saved_regs[9]);
                        core::ptr::write_volatile(fp.add(12), saved_regs[10]);
                        core::ptr::write_volatile(fp.add(13), saved_regs[11]);
                        core::ptr::write_volatile(fp.add(14), saved_regs[12]);
                        core::ptr::write_volatile(fp.add(15), saved_regs[13]);
                        core::ptr::write_volatile(fp.add(16), saved_regs[14]);
                        core::ptr::write_volatile(fp.add(17), saved_regs[2]);
                        core::ptr::write_volatile(fp.add(18), saved_rsp);
                        core::ptr::write_volatile(fp.add(19), saved_regs[10]);
                        core::ptr::write_volatile(fp.add(20), saved_regs[16]);
                        core::ptr::write_volatile(fp.add(21), 0);
                    }
                    let reply = sotos_common::IpcMsg {
                        tag: sotos_common::SIG_REDIRECT_TAG,
                        regs: [
                            vdso::SIGRETURN_RESTORER_ADDR, 0, 0, 0,
                            new_rsp, 0, 0, 0,
                        ],
                    };
                    let _ = sys::send(ep_cap, &reply);
                } else {
                    reply_val(ep_cap, 0);
                }
            }

            // SYS_socket(domain, type, protocol) — child socket proxy
            41 => {
                let domain = msg.regs[0] as u32;
                let sock_type = msg.regs[1] as u32;
                let base_type = sock_type & 0xFF;
                if domain == 2 && (base_type == 1 || base_type == 2 || base_type == 3) {
                    let net_cap = NET_EP_CAP.load(Ordering::Acquire);
                    if net_cap == 0 {
                        reply_val(ep_cap, -99);
                    } else {
                        // Find free FD (start from 3)
                        let mut fd = None;
                        for f in 3..CHILD_MAX_FDS {
                            if child_fds[f] == 0 { fd = Some(f); break; }
                        }
                        match fd {
                            Some(f) => {
                                if base_type == 1 {
                                    child_fds[f] = 16; // TCP
                                    sock_conn_id[f] = 0xFFFF;
                                } else {
                                    child_fds[f] = 17; // UDP
                                    // Auto-bind ephemeral port
                                    let port = NEXT_UDP_PORT.fetch_add(1, Ordering::SeqCst) as u16;
                                    sock_udp_local_port[f] = port;
                                    // Tell net service to bind
                                    let bind_req = sotos_common::IpcMsg {
                                        tag: NET_CMD_UDP_BIND,
                                        regs: [port as u64, 0, 0, 0, 0, 0, 0, 0],
                                    };
                                    let _ = sys::call_timeout(net_cap, &bind_req, 500);
                                }
                                reply_val(ep_cap, f as i64);
                            }
                            None => reply_val(ep_cap, -24), // -EMFILE
                        }
                    }
                } else {
                    reply_val(ep_cap, -97); // -EAFNOSUPPORT
                }
            }

            // SYS_connect(fd, sockaddr_ptr, addrlen) — child socket proxy
            42 => {
                let fd = msg.regs[0] as usize;
                let sockaddr_ptr = msg.regs[1];
                if fd >= CHILD_MAX_FDS || (child_fds[fd] != 16 && child_fds[fd] != 17) {
                    reply_val(ep_cap, -9);
                } else {
                    let sa = unsafe { core::slice::from_raw_parts(sockaddr_ptr as *const u8, 8) };
                    let port = u16::from_be_bytes([sa[2], sa[3]]);
                    let ip = u32::from_be_bytes([sa[4], sa[5], sa[6], sa[7]]);

                    if child_fds[fd] == 17 {
                        // UDP: store remote address
                        sock_udp_remote_ip[fd] = ip;
                        sock_udp_remote_port[fd] = port;
                        reply_val(ep_cap, 0);
                    } else {
                        // TCP connect
                        let net_cap = NET_EP_CAP.load(Ordering::Acquire);
                        if net_cap == 0 { reply_val(ep_cap, -99); continue; }
                        let req = sotos_common::IpcMsg {
                            tag: NET_CMD_TCP_CONNECT,
                            regs: [ip as u64, port as u64, 0, 0, 0, 0, 0, 0],
                        };
                        match sys::call_timeout(net_cap, &req, 500) {
                            Ok(resp) => {
                                let conn_id = resp.regs[0];
                                if conn_id as i64 >= 0 {
                                    sock_conn_id[fd] = conn_id as u32;
                                    reply_val(ep_cap, 0);
                                } else {
                                    reply_val(ep_cap, -111); // -ECONNREFUSED
                                }
                            }
                            Err(_) => reply_val(ep_cap, -111),
                        }
                    }
                }
            }

            // SYS_sendto / SYS_sendmsg — child socket proxy
            44 | 46 => {
                let fd = msg.regs[0] as usize;
                let buf_ptr = msg.regs[1];
                let len = msg.regs[2] as usize;
                let dest_ptr = msg.regs[4];

                if fd >= CHILD_MAX_FDS || (child_fds[fd] != 16 && child_fds[fd] != 17) {
                    reply_val(ep_cap, -9);
                } else if child_fds[fd] == 17 {
                    // UDP sendto
                    let net_cap = NET_EP_CAP.load(Ordering::Acquire);
                    if net_cap == 0 { reply_val(ep_cap, -99); continue; }
                    let (dst_ip, dst_port) = if dest_ptr != 0 {
                        let sa = unsafe { core::slice::from_raw_parts(dest_ptr as *const u8, 8) };
                        (u32::from_be_bytes([sa[4], sa[5], sa[6], sa[7]]),
                         u16::from_be_bytes([sa[2], sa[3]]))
                    } else {
                        (sock_udp_remote_ip[fd], sock_udp_remote_port[fd])
                    };
                    let src_port = sock_udp_local_port[fd];
                    let send_len = len.min(40);
                    let mut req = sotos_common::IpcMsg {
                        tag: NET_CMD_UDP_SENDTO,
                        regs: [dst_ip as u64, dst_port as u64, src_port as u64, send_len as u64, 0, 0, 0, 0],
                    };
                    let data = unsafe { core::slice::from_raw_parts(buf_ptr as *const u8, send_len) };
                    unsafe {
                        let dst = &mut req.regs[4] as *mut u64 as *mut u8;
                        core::ptr::copy_nonoverlapping(data.as_ptr(), dst, send_len);
                    }
                    match sys::call_timeout(net_cap, &req, 500) {
                        Ok(resp) => reply_val(ep_cap, resp.regs[0] as i64),
                        Err(_) => reply_val(ep_cap, -5),
                    }
                } else {
                    // TCP send
                    let net_cap = NET_EP_CAP.load(Ordering::Acquire);
                    let conn_id = sock_conn_id[fd] as u64;
                    let send_len = len.min(40);
                    let mut req = sotos_common::IpcMsg {
                        tag: NET_CMD_TCP_SEND,
                        regs: [conn_id, 0, send_len as u64, 0, 0, 0, 0, 0],
                    };
                    let data = unsafe { core::slice::from_raw_parts(buf_ptr as *const u8, send_len) };
                    unsafe {
                        let dst = &mut req.regs[3] as *mut u64 as *mut u8;
                        core::ptr::copy_nonoverlapping(data.as_ptr(), dst, send_len);
                    }
                    match sys::call_timeout(net_cap, &req, 500) {
                        Ok(resp) => reply_val(ep_cap, resp.regs[0] as i64),
                        Err(_) => reply_val(ep_cap, -5),
                    }
                }
            }

            // SYS_recvfrom / SYS_recvmsg — child socket proxy
            45 | 47 => {
                let fd = msg.regs[0] as usize;
                let buf_ptr = msg.regs[1];
                let len = msg.regs[2] as usize;

                if fd >= CHILD_MAX_FDS || (child_fds[fd] != 16 && child_fds[fd] != 17) {
                    reply_val(ep_cap, -9);
                } else if child_fds[fd] == 17 {
                    // UDP recvfrom
                    let net_cap = NET_EP_CAP.load(Ordering::Acquire);
                    if net_cap == 0 { reply_val(ep_cap, -99); continue; }
                    let src_port = sock_udp_local_port[fd];
                    let recv_len = len.min(48);
                    let req = sotos_common::IpcMsg {
                        tag: NET_CMD_UDP_RECV,
                        regs: [src_port as u64, recv_len as u64, 0, 0, 0, 0, 0, 0],
                    };
                    match sys::call_timeout(net_cap, &req, 500) {
                        Ok(resp) => {
                            let n = resp.regs[0] as usize;
                            if n > 0 && n <= recv_len {
                                unsafe {
                                    let src = &resp.regs[2] as *const u64 as *const u8;
                                    core::ptr::copy_nonoverlapping(src, buf_ptr as *mut u8, n);
                                }
                            }
                            reply_val(ep_cap, n as i64);
                        }
                        Err(_) => reply_val(ep_cap, 0),
                    }
                } else {
                    // TCP recvfrom
                    let net_cap = NET_EP_CAP.load(Ordering::Acquire);
                    let conn_id = sock_conn_id[fd] as u64;
                    let recv_len = len.min(56);
                    let req = sotos_common::IpcMsg {
                        tag: NET_CMD_TCP_RECV,
                        regs: [conn_id, recv_len as u64, 0, 0, 0, 0, 0, 0],
                    };
                    match sys::call_timeout(net_cap, &req, 500) {
                        Ok(resp) => {
                            let n = resp.regs[0] as usize;
                            if n > 0 && n <= recv_len {
                                unsafe {
                                    let src = &resp.regs[1] as *const u64 as *const u8;
                                    core::ptr::copy_nonoverlapping(src, buf_ptr as *mut u8, n);
                                }
                            }
                            reply_val(ep_cap, n as i64);
                        }
                        Err(_) => reply_val(ep_cap, 0),
                    }
                }
            }

            // SYS_bind(49), SYS_listen(50), SYS_getsockname(51), SYS_setsockopt(54), SYS_getsockopt(55) — stubs
            49 | 50 | 51 | 52 | 54 | 55 => {
                reply_val(ep_cap, 0);
            }

            // SYS_shutdown(48)
            48 => {
                reply_val(ep_cap, 0);
            }

            // Unknown → -ENOSYS (with logging)
            _ => {
                print(b"LUCAS child: unhandled syscall ");
                print_u64(syscall_nr);
                print(b" regs=[");
                print_u64(msg.regs[0]);
                print(b",");
                print_u64(msg.regs[1]);
                print(b",");
                print_u64(msg.regs[2]);
                print(b"]\n");
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
    // Capture boot TSC for /proc/uptime and vDSO
    let boot_tsc_val = rdtsc();
    BOOT_TSC.store(boot_tsc_val, Ordering::Release);

    // Map vDSO page (single page shared by all child processes)
    if let Ok(vf) = sys::frame_alloc() {
        if sys::map(vdso::VDSO_BASE, vf, MAP_WRITABLE).is_ok() {
            let vdso_page = unsafe {
                core::slice::from_raw_parts_mut(vdso::VDSO_BASE as *mut u8, 4096)
            };
            for b in vdso_page.iter_mut() { *b = 0; }
            vdso::forge(vdso_page, boot_tsc_val);
            let _ = sys::protect(vdso::VDSO_BASE, 0); // R+X
            print(b"LUCAS: vDSO forged at 0xB80000\n");
        }
    }

    // Register as PID 1 in process table
    let pid: u64 = NEXT_PID.fetch_add(1, Ordering::SeqCst);
    PROC_STATE[pid as usize - 1].store(1, Ordering::Release); // Running
    proc_group_init(pid as usize); // Initialize thread group state

    // --- VFS init: read VirtioBlk from storage page, mount ObjectStore ---
    let has_vfs = LUCAS_VFS_READY.load(Ordering::Acquire) != 0;
    let mut vfs_opt: Option<Vfs> = if has_vfs {
        let blk = unsafe { core::ptr::read(LUCAS_BLK_STORE as *const VirtioBlk) };
        match ObjectStore::mount(blk) {
            Ok(store) => {
                print(b"LUCAS: VFS bridge active\n");
                let vfs = Vfs::new(store);
                // Publish the ObjectStore pointer so child_handlers can access VFS
                let store_ptr = vfs.store() as *const _ as u64;
                SHARED_STORE_PTR.store(store_ptr, Ordering::Release);
                Some(vfs)
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
    fds[0] = FdEntry::new(FdKind::Stdin, 0, 0);
    fds[1] = FdEntry::new(FdKind::Stdout, 0, 0);
    fds[2] = FdEntry::new(FdKind::Stdout, 0, 0);

    // Directory listing buffer and state
    let mut dir_buf = [0u8; 1024];
    let mut dir_len: usize = 0;
    let mut dir_pos: usize = 0;

    // Current working directory OID
    let mut cwd_oid: u64 = sotos_objstore::ROOT_OID;

    // brk heap tracking
    let mut current_brk: u64 = BRK_BASE;

    // mmap tracking
    let mut mmaps = [MmapEntry::empty(); MAX_MMAPS];
    let mut mmap_next: u64 = MMAP_BASE;

    loop {
        // Poll mouse cursor between syscalls for responsive tracking.
        unsafe { poll_mouse(); }

        let msg = match sys::recv(ep_cap) {
            Ok(m) => m,
            Err(_) => break,
        };

        // Cache the kernel thread ID for async signal injection
        let kernel_tid = msg.regs[6];
        if kernel_tid != 0 {
            PROC_KERNEL_TID[pid as usize - 1].store(kernel_tid, Ordering::Release);
        }

        // Check for pending unblocked signals
        let sig = sig_dequeue(pid as usize);
        if sig != 0 {
            let child_tid = kernel_tid;
            match sig_dispatch(pid as usize, sig) {
                1 => break, // terminated
                2 => { reply_val(ep_cap, -4); continue; } // -EINTR
                3 => {
                    if signal_deliver(ep_cap, pid as usize, sig, child_tid, 0, false) {
                        continue;
                    }
                }
                _ => {} // ignored, continue
            }
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
                            let s = sig_dequeue(pid as usize);
                            if s != 0 && sig_dispatch(pid as usize, s) >= 1 {
                                reply_val(ep_cap, -4); // -EINTR
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
                                    // Also return byte in reply regs[1] so kernel
                                    // can write it (workaround for cross-thread visibility).
                                    let reply = sotos_common::IpcMsg {
                                        tag: 0,
                                        regs: [1, ch as u64, 0, 0, 0, 0, 0, 0],
                                    };
                                    let _ = sys::send(ep_cap, &reply);
                                    break;
                                }
                                None => {
                                    unsafe { poll_mouse(); }
                                    sys::yield_now();
                                }
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
                    FdKind::PipeRead => {
                        // Simple pipe: return 0 (EOF) — real data flow needs shared memory
                        reply_val(ep_cap, 0);
                    }
                    FdKind::PipeWrite => {
                        reply_val(ep_cap, -9); // can't read from write end
                    }
                    FdKind::Socket => {
                        // Read from socket → TCP recv via net service.
                        let net_cap = NET_EP_CAP.load(Ordering::Acquire);
                        let conn_id = fds[fd].net_conn_id as u64;
                        let recv_len = len.min(56); // 7 regs * 8 bytes
                        let req = sotos_common::IpcMsg {
                            tag: NET_CMD_TCP_RECV,
                            regs: [conn_id, recv_len as u64, 0, 0, 0, 0, 0, 0],
                        };
                        match sys::call_timeout(net_cap, &req, 500) {
                            Ok(resp) => {
                                let n = resp.regs[0] as usize;
                                if n > 0 && n <= recv_len {
                                    let dst = unsafe { core::slice::from_raw_parts_mut(buf_ptr as *mut u8, n) };
                                    unsafe {
                                        let src = &resp.regs[1] as *const u64 as *const u8;
                                        core::ptr::copy_nonoverlapping(src, dst.as_mut_ptr(), n);
                                    }
                                }
                                reply_val(ep_cap, n as i64);
                            }
                            Err(_) => reply_val(ep_cap, 0), // EOF
                        }
                    }
                    FdKind::SocketUdp => {
                        // Read from UDP socket → UDP recv via net service.
                        let net_cap = NET_EP_CAP.load(Ordering::Acquire);
                        let port = fds[fd].udp_local_port;
                        let recv_len = len.min(56);
                        if net_cap == 0 || port == 0 {
                            reply_val(ep_cap, -9);
                        } else {
                            let req = sotos_common::IpcMsg {
                                tag: NET_CMD_UDP_RECV,
                                regs: [port as u64, recv_len as u64, 0, 0, 0, 0, 0, 0],
                            };
                            match sys::call_timeout(net_cap, &req, 500) {
                                Ok(resp) => {
                                    let n = resp.regs[0] as usize;
                                    if n > 0 && n <= recv_len {
                                        let dst = unsafe { core::slice::from_raw_parts_mut(buf_ptr as *mut u8, n) };
                                        unsafe {
                                            let src = &resp.regs[1] as *const u64 as *const u8;
                                            core::ptr::copy_nonoverlapping(src, dst.as_mut_ptr(), n);
                                        }
                                    }
                                    reply_val(ep_cap, n as i64);
                                }
                                Err(_) => reply_val(ep_cap, 0),
                            }
                        }
                    }
                    _ => reply_val(ep_cap, -9),
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
                    FdKind::Socket => {
                        // Write to socket → TCP send via net service.
                        let net_cap = NET_EP_CAP.load(Ordering::Acquire);
                        let conn_id = fds[fd].net_conn_id as u64;
                        let send_len = len.min(40);
                        let mut req = sotos_common::IpcMsg {
                            tag: NET_CMD_TCP_SEND,
                            regs: [conn_id, 0, send_len as u64, 0, 0, 0, 0, 0],
                        };
                        let data = unsafe { core::slice::from_raw_parts(buf_ptr as *const u8, send_len) };
                        unsafe {
                            let dst = &mut req.regs[3] as *mut u64 as *mut u8;
                            core::ptr::copy_nonoverlapping(data.as_ptr(), dst, send_len);
                        }
                        match sys::call_timeout(net_cap, &req, 500) {
                            Ok(resp) => reply_val(ep_cap, resp.regs[0] as i64),
                            Err(_) => reply_val(ep_cap, -5),
                        }
                    }
                    FdKind::SocketUdp => {
                        // Write to UDP socket → sendto with stored remote address.
                        let net_cap = NET_EP_CAP.load(Ordering::Acquire);
                        let remote_ip = fds[fd].udp_remote_ip;
                        let remote_port = fds[fd].udp_remote_port;
                        let src_port = fds[fd].udp_local_port;
                        if net_cap == 0 || remote_ip == 0 {
                            reply_val(ep_cap, -89); // -EDESTADDRREQ
                        } else {
                            let send_len = len.min(32);
                            let mut req = sotos_common::IpcMsg {
                                tag: NET_CMD_UDP_SENDTO,
                                regs: [remote_ip as u64, remote_port as u64, src_port as u64, send_len as u64, 0, 0, 0, 0],
                            };
                            let data = unsafe { core::slice::from_raw_parts(buf_ptr as *const u8, send_len) };
                            unsafe {
                                let dst = &mut req.regs[4] as *mut u64 as *mut u8;
                                core::ptr::copy_nonoverlapping(data.as_ptr(), dst, send_len);
                            }
                            match sys::call_timeout(net_cap, &req, 500) {
                                Ok(resp) => reply_val(ep_cap, resp.regs[0] as i64),
                                Err(_) => reply_val(ep_cap, -5),
                            }
                        }
                    }
                    FdKind::PipeWrite => {
                        // Simple pipe write: pretend it succeeded (data is discarded)
                        reply_val(ep_cap, len as i64);
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

                // "." → directory listing of cwd; other paths may also be dirs
                if path_len == 1 && path[0] == b'.' {
                    dir_len = 0;
                    dir_pos = 0;
                    if let Some(vfs) = vfs_opt.as_ref() {
                        let mut entries = [DirEntry::zeroed(); DIR_ENTRY_COUNT];
                        let count = vfs.store().list_dir(cwd_oid, &mut entries);
                        for i in 0..count {
                            let ename = entries[i].name_as_str();
                            let elen = ename.len();
                            if dir_len + elen + 20 > dir_buf.len() {
                                break;
                            }
                            // Show d/ prefix for directories
                            if entries[i].is_dir() {
                                dir_buf[dir_len..dir_len + elen].copy_from_slice(ename);
                                dir_len += elen;
                                dir_buf[dir_len] = b'/';
                                dir_len += 1;
                            } else {
                                dir_buf[dir_len..dir_len + elen].copy_from_slice(ename);
                                dir_len += elen;
                            }
                            dir_buf[dir_len] = b' ';
                            dir_buf[dir_len + 1] = b' ';
                            dir_len += 2;
                            let n = format_u64_into(&mut dir_buf[dir_len..], entries[i].size);
                            dir_len += n;
                            dir_buf[dir_len] = b'\n';
                            dir_len += 1;
                        }
                    }
                    fds[new_fd] = FdEntry::new(FdKind::DirList, 0, 0);
                    reply_val(ep_cap, new_fd as i64);
                    continue;
                }

                // /etc/ virtual files (resolv.conf, hosts, nsswitch.conf, etc.)
                if starts_with(name, b"/etc/") {
                    dir_len = 0;
                    dir_pos = 0;
                    if name == b"/etc/resolv.conf" {
                        let content = b"nameserver 10.0.2.3\n";
                        dir_buf[..content.len()].copy_from_slice(content);
                        dir_len = content.len();
                    } else if name == b"/etc/hosts" {
                        let content = b"127.0.0.1 localhost\n::1 localhost\n";
                        dir_buf[..content.len()].copy_from_slice(content);
                        dir_len = content.len();
                    } else if name == b"/etc/nsswitch.conf" {
                        let content = b"hosts: files dns\n";
                        dir_buf[..content.len()].copy_from_slice(content);
                        dir_len = content.len();
                    } else if name == b"/etc/gai.conf" || name == b"/etc/host.conf" {
                        dir_len = 0; // empty file
                    } else if name == b"/etc/services" {
                        let content = b"http 80/tcp\nhttps 443/tcp\ndns 53/udp\n";
                        dir_buf[..content.len()].copy_from_slice(content);
                        dir_len = content.len();
                    } else if name == b"/etc/protocols" {
                        let content = b"tcp 6 TCP\nudp 17 UDP\nicmp 1 ICMP\n";
                        dir_buf[..content.len()].copy_from_slice(content);
                        dir_len = content.len();
                    } else {
                        reply_val(ep_cap, -2); // -ENOENT
                        continue;
                    }
                    fds[new_fd] = FdEntry::new(FdKind::DirList, 0, 0);
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

                    fds[new_fd] = FdEntry::new(FdKind::DirList, 0, 0);
                    reply_val(ep_cap, new_fd as i64);
                    continue;
                }

                // /snap virtual path for snapshot operations
                if starts_with(name, b"/snap/") {
                    let snap_cmd = &path[6..path_len];

                    if starts_with(snap_cmd, b"create/") && snap_cmd.len() > 7 {
                        let snap_name = &snap_cmd[7..];
                        match vfs_opt.as_mut() {
                            Some(vfs) => {
                                match vfs.store_mut().snap_create(snap_name) {
                                    Ok(_) => {
                                        dir_len = 0;
                                        dir_pos = 0;
                                        let msg_text = b"snapshot created\n";
                                        dir_buf[..msg_text.len()].copy_from_slice(msg_text);
                                        dir_len = msg_text.len();
                                        fds[new_fd] = FdEntry::new(FdKind::DirList, 0, 0);
                                        reply_val(ep_cap, new_fd as i64);
                                    }
                                    Err(_) => reply_val(ep_cap, -28), // -ENOSPC
                                }
                            }
                            None => reply_val(ep_cap, -2),
                        }
                        continue;
                    } else if snap_cmd == b"list" {
                        dir_len = 0;
                        dir_pos = 0;
                        match vfs_opt.as_ref() {
                            Some(vfs) => {
                                let mut snaps = [sotos_objstore::SnapMeta::zeroed(); sotos_objstore::MAX_SNAPSHOTS];
                                let count = vfs.store().snap_list(&mut snaps);
                                if count == 0 {
                                    let msg_text = b"no snapshots\n";
                                    dir_buf[..msg_text.len()].copy_from_slice(msg_text);
                                    dir_len = msg_text.len();
                                } else {
                                    for i in 0..count {
                                        let sname = snaps[i].name_as_str();
                                        if dir_len + sname.len() + 10 > dir_buf.len() { break; }
                                        dir_buf[dir_len..dir_len + sname.len()].copy_from_slice(sname);
                                        dir_len += sname.len();
                                        dir_buf[dir_len] = b'\n';
                                        dir_len += 1;
                                    }
                                }
                            }
                            None => {
                                let msg_text = b"no VFS\n";
                                dir_buf[..msg_text.len()].copy_from_slice(msg_text);
                                dir_len = msg_text.len();
                            }
                        }
                        fds[new_fd] = FdEntry::new(FdKind::DirList, 0, 0);
                        reply_val(ep_cap, new_fd as i64);
                        continue;
                    } else if starts_with(snap_cmd, b"restore/") && snap_cmd.len() > 8 {
                        let snap_name = &snap_cmd[8..];
                        match vfs_opt.as_mut() {
                            Some(vfs) => {
                                match vfs.store_mut().snap_find(snap_name) {
                                    Some(slot) => {
                                        match vfs.store_mut().snap_restore(slot) {
                                            Ok(()) => {
                                                dir_len = 0;
                                                dir_pos = 0;
                                                let msg_text = b"snapshot restored\n";
                                                dir_buf[..msg_text.len()].copy_from_slice(msg_text);
                                                dir_len = msg_text.len();
                                                fds[new_fd] = FdEntry::new(FdKind::DirList, 0, 0);
                                                reply_val(ep_cap, new_fd as i64);
                                            }
                                            Err(_) => reply_val(ep_cap, -5), // -EIO
                                        }
                                    }
                                    None => reply_val(ep_cap, -2), // -ENOENT
                                }
                            }
                            None => reply_val(ep_cap, -2),
                        }
                        continue;
                    } else if starts_with(snap_cmd, b"delete/") && snap_cmd.len() > 7 {
                        let snap_name = &snap_cmd[7..];
                        match vfs_opt.as_mut() {
                            Some(vfs) => {
                                match vfs.store_mut().snap_find(snap_name) {
                                    Some(slot) => {
                                        match vfs.store_mut().snap_delete(slot) {
                                            Ok(()) => {
                                                dir_len = 0;
                                                dir_pos = 0;
                                                let msg_text = b"snapshot deleted\n";
                                                dir_buf[..msg_text.len()].copy_from_slice(msg_text);
                                                dir_len = msg_text.len();
                                                fds[new_fd] = FdEntry::new(FdKind::DirList, 0, 0);
                                                reply_val(ep_cap, new_fd as i64);
                                            }
                                            Err(_) => reply_val(ep_cap, -5),
                                        }
                                    }
                                    None => reply_val(ep_cap, -2),
                                }
                            }
                            None => reply_val(ep_cap, -2),
                        }
                        continue;
                    } else {
                        reply_val(ep_cap, -2);
                        continue;
                    }
                }

                match vfs_opt.as_mut() {
                    Some(vfs) => {
                        // Sync cwd before path resolution
                        vfs.cwd = cwd_oid;

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
                                fds[new_fd] = FdEntry::new(FdKind::VfsFile, vfs_fd, 0);
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
                    FdKind::Socket => {
                        // Close TCP connection via net service (only if connected).
                        let net_cap = NET_EP_CAP.load(Ordering::Acquire);
                        let cid = fds[fd].net_conn_id;
                        if net_cap != 0 && cid != 0xFFFF {
                            let req = sotos_common::IpcMsg {
                                tag: NET_CMD_TCP_CLOSE,
                                regs: [cid as u64, 0, 0, 0, 0, 0, 0, 0],
                            };
                            let _ = sys::call_timeout(net_cap, &req, 500);
                        }
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

                // "." → current directory
                if path_len == 1 && path[0] == b'.' {
                    write_linux_stat(stat_ptr, cwd_oid, 0, true);
                    reply_val(ep_cap, 0);
                    continue;
                }

                match vfs_opt.as_ref() {
                    Some(vfs) => {
                        match vfs.store().resolve_path(name, cwd_oid) {
                            Ok(oid) => {
                                match vfs.store().stat(oid) {
                                    Some(entry) => {
                                        let is_dir = entry.is_dir();
                                        write_linux_stat(stat_ptr, oid, entry.size, is_dir);
                                        reply_val(ep_cap, 0);
                                    }
                                    None => reply_val(ep_cap, -2),
                                }
                            }
                            Err(_) => reply_val(ep_cap, -2),
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
                    FdKind::Socket => {
                        // Socket stat: report as socket type.
                        let buf = unsafe { core::slice::from_raw_parts_mut(stat_ptr as *mut u8, 144) };
                        for b in buf.iter_mut() { *b = 0; }
                        let mode: u32 = 0o140600; // S_IFSOCK | rw
                        buf[24..28].copy_from_slice(&mode.to_le_bytes());
                        reply_val(ep_cap, 0);
                    }
                    FdKind::PipeRead | FdKind::PipeWrite => {
                        // Pipe stat: report as FIFO
                        let buf = unsafe { core::slice::from_raw_parts_mut(stat_ptr as *mut u8, 144) };
                        for b in buf.iter_mut() { *b = 0; }
                        let mode: u32 = 0o10600; // S_IFIFO | rw
                        buf[24..28].copy_from_slice(&mode.to_le_bytes());
                        reply_val(ep_cap, 0);
                    }
                    FdKind::SocketUdp => {
                        // UDP socket stat: report as socket type.
                        let buf = unsafe { core::slice::from_raw_parts_mut(stat_ptr as *mut u8, 144) };
                        for b in buf.iter_mut() { *b = 0; }
                        let mode: u32 = 0o140600; // S_IFSOCK | rw
                        buf[24..28].copy_from_slice(&mode.to_le_bytes());
                        reply_val(ep_cap, 0);
                    }
                    FdKind::EpollFd | FdKind::Free => reply_val(ep_cap, -9),
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
                let mmap_fd = msg.regs[4] as usize; // r8
                let mmap_offset = msg.regs[5]; // r9
                let is_anon = flags & 0x20 != 0; // MAP_ANONYMOUS

                // Validate: file-backed mmap needs a valid VfsFile fd
                if !is_anon {
                    if mmap_fd >= MAX_FDS || fds[mmap_fd].kind != FdKind::VfsFile {
                        reply_val(ep_cap, -9); // -EBADF
                        continue;
                    }
                    if vfs_opt.is_none() {
                        reply_val(ep_cap, -19); // -ENODEV
                        continue;
                    }
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

                // Zero the mapped region first
                let region = unsafe { core::slice::from_raw_parts_mut(base as *mut u8, (pages as usize) * 0x1000) };
                for b in region.iter_mut() { *b = 0; }

                // For file-backed mmap: read file content into the mapped region
                if !is_anon {
                    if let Some(vfs) = vfs_opt.as_mut() {
                        let vfs_fd = fds[mmap_fd].vfs_fd;
                        // Save current position, seek to offset, read, restore
                        let saved_pos = vfs.tell(vfs_fd).unwrap_or(0);
                        let _ = vfs.seek(vfs_fd, mmap_offset);
                        let read_len = len as usize;
                        let dst = unsafe { core::slice::from_raw_parts_mut(base as *mut u8, read_len) };
                        let _ = vfs.read(vfs_fd, dst);
                        let _ = vfs.seek(vfs_fd, saved_pos);
                    }
                }

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
                } else if addr > current_brk && addr <= BRK_BASE + BRK_LIMIT {
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

                // Allocate child stacks: 1 page guest + 4 pages handler
                let stack_base = NEXT_CHILD_STACK.fetch_add(0x5000, Ordering::SeqCst);
                let guest_stack = stack_base;
                let handler_stack = stack_base + 0x1000;

                // Map guest stack (1 page)
                let gf = match sys::frame_alloc() {
                    Ok(f) => f,
                    Err(_) => { reply_val(ep_cap, -12); continue; }
                };
                if sys::map(guest_stack, gf, MAP_WRITABLE).is_err() {
                    reply_val(ep_cap, -12);
                    continue;
                }

                // Map handler stack (4 pages)
                let mut hok = true;
                for hp in 0..4u64 {
                    let hf = match sys::frame_alloc() {
                        Ok(f) => f,
                        Err(_) => { hok = false; break; }
                    };
                    if sys::map(handler_stack + hp * 0x1000, hf, MAP_WRITABLE).is_err() {
                        hok = false; break;
                    }
                }
                if !hok {
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
                // Initialize process group state (fork child = new process leader)
                proc_group_init(child_pid as usize);

                // Pass setup info to child handler
                CHILD_SETUP_EP.store(child_ep, Ordering::Release);
                CHILD_SETUP_PID.store(child_pid, Ordering::Release);
                CHILD_SETUP_FLAGS.store(0, Ordering::Release); // normal fork, no CLONE_ flags
                CHILD_SETUP_READY.store(1, Ordering::Release);

                // Spawn child handler thread (stack top = handler_stack + 4 pages)
                if sys::thread_create(
                    child_handler as *const () as u64,
                    handler_stack + 0x4000,
                ).is_err() {
                    CHILD_SETUP_READY.store(0, Ordering::Release);
                    reply_val(ep_cap, -12);
                    continue;
                }

                // Wait for child handler to consume setup
                while CHILD_SETUP_READY.load(Ordering::Acquire) != 0 {
                    sys::yield_now();
                }

                // Spawn child guest thread with redirect pre-set (no race)
                let child_thread = match sys::thread_create_redirected(child_fn, guest_stack + 0x1000, child_ep) {
                    Ok(t) => t,
                    Err(_) => { reply_val(ep_cap, -12); continue; }
                };
                let _ = sys::signal_entry(child_thread, vdso::SIGNAL_TRAMPOLINE_ADDR);

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
                sig_send(target, sig);
                reply_val(ep_cap, 0);
            }

            // SYS_getcwd(buf, size)
            79 => {
                let buf_ptr = msg.regs[0];
                let buf_size = msg.regs[1] as usize;

                match vfs_opt.as_ref() {
                    Some(vfs) => {
                        let mut cwd_buf = [0u8; 128];
                        let len = {
                            // Temporarily create a Vfs-like view for getcwd
                            // We need to walk the store's dir entries
                            let store = vfs.store();
                            let mut oids = [0u64; 16];
                            let mut depth = 0;
                            let mut cur = cwd_oid;
                            while cur != sotos_objstore::ROOT_OID && depth < 16 {
                                oids[depth] = cur;
                                depth += 1;
                                if let Some(entry) = store.stat(cur) {
                                    let parent = entry.parent_oid;
                                    cur = if parent == 0 { sotos_objstore::ROOT_OID } else { parent };
                                } else {
                                    break;
                                }
                            }
                            let mut pos = 0;
                            if depth == 0 {
                                cwd_buf[0] = b'/';
                                pos = 1;
                            } else {
                                let mut i = depth;
                                while i > 0 {
                                    i -= 1;
                                    if pos < cwd_buf.len() { cwd_buf[pos] = b'/'; pos += 1; }
                                    if let Some(entry) = store.stat(oids[i]) {
                                        let name = entry.name_as_str();
                                        let copy_len = name.len().min(cwd_buf.len() - pos);
                                        cwd_buf[pos..pos + copy_len].copy_from_slice(&name[..copy_len]);
                                        pos += copy_len;
                                    }
                                }
                            }
                            pos
                        };
                        let copy_len = len.min(buf_size);
                        let dst = unsafe { core::slice::from_raw_parts_mut(buf_ptr as *mut u8, copy_len) };
                        dst.copy_from_slice(&cwd_buf[..copy_len]);
                        if copy_len < buf_size {
                            unsafe { *((buf_ptr + copy_len as u64) as *mut u8) = 0; }
                        }
                        reply_val(ep_cap, buf_ptr as i64);
                    }
                    None => reply_val(ep_cap, -2),
                }
            }

            // SYS_chdir(path)
            80 => {
                let path_ptr = msg.regs[0];
                let mut path = [0u8; 48];
                let path_len = copy_guest_path(path_ptr, &mut path);
                let name = &path[..path_len];

                match vfs_opt.as_ref() {
                    Some(vfs) => {
                        match vfs.store().resolve_path(name, cwd_oid) {
                            Ok(oid) => {
                                match vfs.store().stat(oid) {
                                    Some(entry) if entry.is_dir() => {
                                        cwd_oid = oid;
                                        reply_val(ep_cap, 0);
                                    }
                                    _ => reply_val(ep_cap, -20), // -ENOTDIR
                                }
                            }
                            Err(_) => reply_val(ep_cap, -2), // -ENOENT
                        }
                    }
                    None => reply_val(ep_cap, -2),
                }
            }

            // SYS_mkdir(path, mode)
            83 => {
                let path_ptr = msg.regs[0];
                let mut path = [0u8; 48];
                let path_len = copy_guest_path(path_ptr, &mut path);
                let name = &path[..path_len];

                match vfs_opt.as_mut() {
                    Some(vfs) => {
                        vfs.cwd = cwd_oid;
                        match vfs.mkdir(name) {
                            Ok(_) => reply_val(ep_cap, 0),
                            Err(_) => reply_val(ep_cap, -2),
                        }
                    }
                    None => reply_val(ep_cap, -2),
                }
            }

            // SYS_rmdir(path)
            84 => {
                let path_ptr = msg.regs[0];
                let mut path = [0u8; 48];
                let path_len = copy_guest_path(path_ptr, &mut path);
                let name = &path[..path_len];

                match vfs_opt.as_mut() {
                    Some(vfs) => {
                        vfs.cwd = cwd_oid;
                        match vfs.rmdir(name) {
                            Ok(()) => reply_val(ep_cap, 0),
                            Err(_) => reply_val(ep_cap, -2),
                        }
                    }
                    None => reply_val(ep_cap, -2),
                }
            }

            // SYS_unlink(path)
            87 => {
                let path_ptr = msg.regs[0];
                let mut path = [0u8; 48];
                let path_len = copy_guest_path(path_ptr, &mut path);
                let name = &path[..path_len];

                match vfs_opt.as_mut() {
                    Some(vfs) => {
                        vfs.cwd = cwd_oid;
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

            // SYS_mprotect(addr, len, prot) — change page protections
            10 => {
                let addr = msg.regs[0];
                let len = msg.regs[1] as usize;
                let prot = msg.regs[2]; // PROT_READ=1, PROT_WRITE=2, PROT_EXEC=4
                if addr & 0xFFF != 0 {
                    reply_val(ep_cap, -22); // -EINVAL
                } else {
                    let pages = (len + 0xFFF) / 0x1000;
                    let mut flags: u64 = 0;
                    if prot & 2 != 0 { flags |= 2; }       // WRITABLE
                    if prot & 4 == 0 { flags |= 1u64 << 63; } // NO_EXECUTE if !PROT_EXEC
                    for i in 0..pages {
                        let _ = sys::protect(addr + (i as u64) * 0x1000, flags);
                    }
                    reply_val(ep_cap, 0);
                }
            }

            // SYS_ioctl(fd, request, arg)
            16 => {
                let _fd = msg.regs[0];
                let request = msg.regs[1];
                match request {
                    // TIOCGWINSZ — terminal window size
                    0x5413 => {
                        let arg = msg.regs[2];
                        if arg != 0 && arg < 0x0000_8000_0000_0000 {
                            // struct winsize { rows(u16), cols(u16), xpixel(u16), ypixel(u16) }
                            let ws = unsafe { core::slice::from_raw_parts_mut(arg as *mut u8, 8) };
                            ws[0..2].copy_from_slice(&25u16.to_le_bytes()); // rows
                            ws[2..4].copy_from_slice(&80u16.to_le_bytes()); // cols
                            ws[4..8].copy_from_slice(&[0; 4]); // xpixel, ypixel
                            reply_val(ep_cap, 0);
                        } else {
                            reply_val(ep_cap, -22);
                        }
                    }
                    // FIONREAD — bytes available for reading
                    0x541B => {
                        reply_val(ep_cap, 0);
                    }
                    _ => reply_val(ep_cap, -25), // -ENOTTY
                }
            }

            // SYS_writev(fd, iov_ptr, iovcnt)
            20 => {
                let fd = msg.regs[0] as usize;
                let iov_ptr = msg.regs[1];
                let iovcnt = msg.regs[2] as usize;
                if fd >= MAX_FDS || fds[fd].kind == FdKind::Free {
                    reply_val(ep_cap, -9); // -EBADF
                } else {
                    // struct iovec { iov_base: *mut u8, iov_len: usize } = 16 bytes each
                    let mut total: usize = 0;
                    let cnt = iovcnt.min(16); // limit scatter count
                    for i in 0..cnt {
                        let entry = iov_ptr + (i as u64) * 16;
                        if entry + 16 > 0x0000_8000_0000_0000 { break; }
                        let base = unsafe { *(entry as *const u64) };
                        let len = unsafe { *((entry + 8) as *const u64) } as usize;
                        if base == 0 || len == 0 { continue; }
                        if fds[fd].kind == FdKind::Stdout {
                            let data = unsafe { core::slice::from_raw_parts(base as *const u8, len) };
                            for &b in data { sys::debug_print(b); unsafe { fb_putchar(b); } }
                            total += len;
                        } else if fds[fd].kind == FdKind::VfsFile {
                            if let Some(vfs) = vfs_opt.as_mut() {
                                let data = unsafe { core::slice::from_raw_parts(base as *const u8, len) };
                                let vfd = fds[fd].vfs_fd;
                                let _ = vfs.store_mut().write_obj(vfd as u64, data);
                                total += len;
                            }
                        } else if fds[fd].kind == FdKind::Socket {
                            let net_cap = NET_EP_CAP.load(Ordering::Acquire);
                            let conn_id = fds[fd].net_conn_id as u64;
                            let send_len = len.min(40);
                            let mut req = sotos_common::IpcMsg {
                                tag: NET_CMD_TCP_SEND,
                                regs: [conn_id, 0, send_len as u64, 0, 0, 0, 0, 0],
                            };
                            let data = unsafe { core::slice::from_raw_parts(base as *const u8, send_len) };
                            unsafe {
                                let dst = &mut req.regs[3] as *mut u64 as *mut u8;
                                core::ptr::copy_nonoverlapping(data.as_ptr(), dst, send_len);
                            }
                            if let Ok(resp) = sys::call_timeout(net_cap, &req, 500) {
                                total += resp.regs[0] as usize;
                            }
                        } else if fds[fd].kind == FdKind::SocketUdp {
                            let net_cap = NET_EP_CAP.load(Ordering::Acquire);
                            let remote_ip = fds[fd].udp_remote_ip;
                            let remote_port = fds[fd].udp_remote_port;
                            let src_port = fds[fd].udp_local_port;
                            if net_cap != 0 && remote_ip != 0 {
                                let send_len = len.min(32);
                                let mut req = sotos_common::IpcMsg {
                                    tag: NET_CMD_UDP_SENDTO,
                                    regs: [remote_ip as u64, remote_port as u64, src_port as u64, send_len as u64, 0, 0, 0, 0],
                                };
                                let data = unsafe { core::slice::from_raw_parts(base as *const u8, send_len) };
                                unsafe {
                                    let dst = &mut req.regs[4] as *mut u64 as *mut u8;
                                    core::ptr::copy_nonoverlapping(data.as_ptr(), dst, send_len);
                                }
                                if let Ok(resp) = sys::call_timeout(net_cap, &req, 500) {
                                    total += resp.regs[0] as usize;
                                }
                            }
                        }
                    }
                    reply_val(ep_cap, total as i64);
                }
            }

            // SYS_access(path, mode) — check file accessibility
            21 => {
                let path_ptr = msg.regs[0];
                let _mode = msg.regs[1]; // F_OK=0, R_OK=4, W_OK=2, X_OK=1
                let mut path = [0u8; 48];
                let path_len = copy_guest_path(path_ptr, &mut path);
                let name = &path[..path_len];
                match vfs_opt.as_ref() {
                    Some(vfs) => {
                        match vfs.store().resolve_path(name, cwd_oid) {
                            Ok(_) => reply_val(ep_cap, 0),
                            Err(_) => reply_val(ep_cap, -2), // -ENOENT
                        }
                    }
                    None => reply_val(ep_cap, -2),
                }
            }

            // SYS_pipe(pipefd[2])
            22 => {
                let pfd_ptr = msg.regs[0];
                if pfd_ptr == 0 || pfd_ptr >= 0x0000_8000_0000_0000 {
                    reply_val(ep_cap, -14); // -EFAULT
                } else {
                    // Allocate two FDs pointing to a simple pipe
                    match (alloc_fd(&fds, 3), alloc_fd(&fds, 4)) {
                        (Some(rfd), Some(wfd)) if rfd != wfd => {
                            fds[rfd] = FdEntry::new(FdKind::PipeRead, wfd as u32, 0);
                            fds[wfd] = FdEntry::new(FdKind::PipeWrite, rfd as u32, 0);
                            let pfd = unsafe { core::slice::from_raw_parts_mut(pfd_ptr as *mut i32, 2) };
                            pfd[0] = rfd as i32;
                            pfd[1] = wfd as i32;
                            reply_val(ep_cap, 0);
                        }
                        _ => reply_val(ep_cap, -24), // -EMFILE
                    }
                }
            }

            // SYS_uname(buf) — system info
            63 => {
                let buf_ptr = msg.regs[0];
                if buf_ptr == 0 || buf_ptr >= 0x0000_8000_0000_0000 {
                    reply_val(ep_cap, -14);
                } else {
                    // struct utsname: 5 fields of 65 bytes each = 325 bytes
                    let buf = unsafe { core::slice::from_raw_parts_mut(buf_ptr as *mut u8, 325) };
                    for b in buf.iter_mut() { *b = 0; }
                    let fields: [&[u8]; 5] = [
                        b"sotOS",             // sysname
                        b"sotos",             // nodename
                        b"0.1.0",             // release
                        b"sotOS 0.1.0 LUCAS", // version
                        b"x86_64",            // machine
                    ];
                    for (i, field) in fields.iter().enumerate() {
                        let off = i * 65;
                        let len = field.len().min(64);
                        buf[off..off + len].copy_from_slice(&field[..len]);
                    }
                    reply_val(ep_cap, 0);
                }
            }

            // SYS_fcntl(fd, cmd, arg)
            72 => {
                let fd = msg.regs[0] as usize;
                let cmd = msg.regs[1] as u32;
                let _arg = msg.regs[2];
                if fd >= MAX_FDS || fds[fd].kind == FdKind::Free {
                    reply_val(ep_cap, -9); // -EBADF
                } else {
                    match cmd {
                        0 => { // F_DUPFD
                            match alloc_fd(&fds, _arg as usize) {
                                Some(newfd) => {
                                    fds[newfd] = fds[fd];
                                    reply_val(ep_cap, newfd as i64);
                                }
                                None => reply_val(ep_cap, -24),
                            }
                        }
                        1 => reply_val(ep_cap, 0), // F_GETFD → no FD_CLOEXEC
                        2 => reply_val(ep_cap, 0), // F_SETFD → ignore
                        3 => reply_val(ep_cap, 0), // F_GETFL → O_RDONLY
                        4 => reply_val(ep_cap, 0), // F_SETFL → ignore
                        _ => reply_val(ep_cap, -22), // -EINVAL
                    }
                }
            }

            // SYS_getuid / SYS_geteuid / SYS_getgid / SYS_getegid
            102 | 104 | 107 | 108 => {
                reply_val(ep_cap, 0); // root
            }

            // SYS_set_tid_address(tidptr) — store clear_child_tid, return TID
            218 => {
                // Just return the PID as TID (single-threaded LUCAS processes)
                reply_val(ep_cap, pid as i64);
            }

            // SYS_clock_gettime(clock_id, timespec)
            228 => {
                let _clock_id = msg.regs[0]; // CLOCK_REALTIME=0, CLOCK_MONOTONIC=1
                let tp_ptr = msg.regs[1];
                if tp_ptr == 0 || tp_ptr >= 0x0000_8000_0000_0000 {
                    reply_val(ep_cap, -14);
                } else {
                    // Approximate time from RDTSC (assume ~2GHz TSC)
                    let tsc = rdtsc();
                    let boot_tsc = BOOT_TSC.load(Ordering::Acquire);
                    let elapsed_ns = if tsc > boot_tsc { (tsc - boot_tsc) / 2 } else { 0 };
                    let secs = elapsed_ns / 1_000_000_000;
                    let nsecs = elapsed_ns % 1_000_000_000;
                    // struct timespec { tv_sec: i64, tv_nsec: i64 } = 16 bytes
                    let tp = unsafe { core::slice::from_raw_parts_mut(tp_ptr as *mut u8, 16) };
                    tp[0..8].copy_from_slice(&(secs as i64).to_le_bytes());
                    tp[8..16].copy_from_slice(&(nsecs as i64).to_le_bytes());
                    reply_val(ep_cap, 0);
                }
            }

            // SYS_gettimeofday(tv, tz)
            96 => {
                let tv_ptr = msg.regs[0];
                if tv_ptr != 0 && tv_ptr < 0x0000_8000_0000_0000 {
                    let tsc = rdtsc();
                    let boot_tsc = BOOT_TSC.load(Ordering::Acquire);
                    let elapsed_us = if tsc > boot_tsc { (tsc - boot_tsc) / 2000 } else { 0 };
                    let secs = elapsed_us / 1_000_000;
                    let usecs = elapsed_us % 1_000_000;
                    // struct timeval { tv_sec: i64, tv_usec: i64 } = 16 bytes
                    let tv = unsafe { core::slice::from_raw_parts_mut(tv_ptr as *mut u8, 16) };
                    tv[0..8].copy_from_slice(&(secs as i64).to_le_bytes());
                    tv[8..16].copy_from_slice(&(usecs as i64).to_le_bytes());
                }
                reply_val(ep_cap, 0);
            }

            // SYS_getdents64(fd, dirp, count) — read directory entries
            217 => {
                let fd = msg.regs[0] as usize;
                let dirp = msg.regs[1];
                let count = msg.regs[2] as usize;
                if fd >= MAX_FDS || fds[fd].kind != FdKind::DirList {
                    reply_val(ep_cap, -9); // -EBADF
                } else if dirp == 0 || dirp >= 0x0000_8000_0000_0000 {
                    reply_val(ep_cap, -14); // -EFAULT
                } else {
                    // If dir_buf is empty, populate it from the VFS
                    if dir_pos >= dir_len {
                        dir_len = 0;
                        dir_pos = 0;
                        let dir_oid = fds[fd].vfs_fd as u64;
                        if let Some(vfs) = vfs_opt.as_ref() {
                            let mut entries = [sotos_objstore::layout::DirEntry::zeroed(); 32];
                            let n = vfs.store().list_dir(dir_oid, &mut entries);
                            for i in 0..n {
                                let entry = &entries[i];
                                let ename = entry.name_as_str();
                                // linux_dirent64: d_ino(8) + d_off(8) + d_reclen(2) + d_type(1) + d_name(var+NUL)
                                let reclen = ((19 + ename.len() + 1 + 7) / 8) * 8; // align to 8
                                if dir_len + reclen > dir_buf.len() { break; }
                                let d = &mut dir_buf[dir_len..dir_len + reclen];
                                for b in d.iter_mut() { *b = 0; }
                                d[0..8].copy_from_slice(&entry.oid.to_le_bytes()); // d_ino
                                d[8..16].copy_from_slice(&((dir_len + reclen) as u64).to_le_bytes()); // d_off
                                d[16..18].copy_from_slice(&(reclen as u16).to_le_bytes()); // d_reclen
                                d[18] = if entry.is_dir() { 4 } else { 8 }; // d_type
                                let nlen = ename.len().min(reclen - 19);
                                d[19..19 + nlen].copy_from_slice(&ename[..nlen]);
                                dir_len += reclen;
                            }
                        }
                    }
                    let remaining = if dir_pos < dir_len { dir_len - dir_pos } else { 0 };
                    if remaining == 0 {
                        reply_val(ep_cap, 0); // EOF
                    } else {
                        let copy_len = remaining.min(count);
                        let src = &dir_buf[dir_pos..dir_pos + copy_len];
                        unsafe {
                            core::ptr::copy_nonoverlapping(src.as_ptr(), dirp as *mut u8, copy_len);
                        }
                        dir_pos += copy_len;
                        reply_val(ep_cap, copy_len as i64);
                    }
                }
            }

            // SYS_openat(dirfd, path, flags, mode) — open relative to dirfd
            257 => {
                // Treat AT_FDCWD (-100) or any dirfd as CWD-relative
                let path_ptr = msg.regs[1];
                let flags = msg.regs[2] as u32;
                let _mode = msg.regs[3];
                let mut path = [0u8; 48];
                let path_len = copy_guest_path(path_ptr, &mut path);
                let name = &path[..path_len];

                // Device files: /dev/null, /dev/zero, /dev/urandom
                let dev_kind = if name == b"/dev/null" { Some(FdKind::PipeWrite) }
                    else if name == b"/dev/zero" || name == b"/dev/urandom" || name == b"/dev/random" { Some(FdKind::PipeRead) }
                    else { None };
                if let Some(dk) = dev_kind {
                    match alloc_fd(&fds, 3) {
                        Some(newfd) => {
                            fds[newfd] = FdEntry::new(dk, 0, 0);
                            reply_val(ep_cap, newfd as i64);
                        }
                        None => reply_val(ep_cap, -24),
                    }
                    continue;
                }

                match vfs_opt.as_mut() {
                    Some(vfs) => {
                        vfs.cwd = cwd_oid;
                        match vfs.store().resolve_path(name, cwd_oid) {
                            Ok(oid) => {
                                match vfs.store().stat(oid) {
                                    Some(entry) => {
                                        if entry.is_dir() {
                                            match alloc_fd(&fds, 3) {
                                                Some(newfd) => {
                                                    fds[newfd] = FdEntry::new(FdKind::DirList, oid as u32, 0);
                                                    dir_len = 0; dir_pos = 0; // reset for getdents64
                                                    reply_val(ep_cap, newfd as i64);
                                                }
                                                None => reply_val(ep_cap, -24),
                                            }
                                        } else {
                                            match alloc_fd(&fds, 3) {
                                                Some(newfd) => {
                                                    fds[newfd] = FdEntry::new(FdKind::VfsFile, oid as u32, 0);
                                                    reply_val(ep_cap, newfd as i64);
                                                }
                                                None => reply_val(ep_cap, -24),
                                            }
                                        }
                                    }
                                    None => reply_val(ep_cap, -2),
                                }
                            }
                            Err(_) => {
                                if flags & 0x40 != 0 { // O_CREAT
                                    match vfs.create(name) {
                                        Ok(fd) => {
                                            let oid = vfs.file_oid(fd).unwrap_or(0);
                                            let _ = vfs.close(fd);
                                            match alloc_fd(&fds, 3) {
                                                Some(newfd) => {
                                                    fds[newfd] = FdEntry::new(FdKind::VfsFile, oid as u32, 0);
                                                    reply_val(ep_cap, newfd as i64);
                                                }
                                                None => reply_val(ep_cap, -24),
                                            }
                                        }
                                        Err(_) => reply_val(ep_cap, -2),
                                    }
                                } else {
                                    reply_val(ep_cap, -2);
                                }
                            }
                        }
                    }
                    None => reply_val(ep_cap, -2),
                }
            }

            // SYS_fstatat(dirfd, path, statbuf, flag) — stat relative to dirfd
            262 => {
                let path_ptr = msg.regs[1];
                let stat_ptr = msg.regs[2];
                let mut path = [0u8; 48];
                let path_len = copy_guest_path(path_ptr, &mut path);
                let name = &path[..path_len];
                match vfs_opt.as_ref() {
                    Some(vfs) => {
                        match vfs.store().resolve_path(name, cwd_oid) {
                            Ok(oid) => {
                                match vfs.store().stat(oid) {
                                    Some(entry) => {
                                        write_linux_stat(stat_ptr, oid, entry.size, entry.is_dir());
                                        reply_val(ep_cap, 0);
                                    }
                                    None => reply_val(ep_cap, -2),
                                }
                            }
                            Err(_) => reply_val(ep_cap, -2),
                        }
                    }
                    None => reply_val(ep_cap, -2),
                }
            }

            // SYS_readlinkat(dirfd, path, buf, bufsiz) — always -EINVAL (no symlinks)
            267 => {
                reply_val(ep_cap, -22); // -EINVAL: no symlinks
            }

            // SYS_faccessat(dirfd, path, mode, flags) — check file accessibility
            269 => {
                let path_ptr = msg.regs[1];
                let mut path = [0u8; 48];
                let path_len = copy_guest_path(path_ptr, &mut path);
                let name = &path[..path_len];
                match vfs_opt.as_ref() {
                    Some(vfs) => {
                        match vfs.store().resolve_path(name, cwd_oid) {
                            Ok(_) => reply_val(ep_cap, 0),
                            Err(_) => reply_val(ep_cap, -2),
                        }
                    }
                    None => reply_val(ep_cap, -2),
                }
            }

            // SYS_prlimit64(pid, resource, new_rlim, old_rlim) — get/set resource limits
            302 => {
                let old_rlim = msg.regs[3];
                if old_rlim != 0 && old_rlim < 0x0000_8000_0000_0000 {
                    // Return generous defaults: cur=RLIM_INFINITY, max=RLIM_INFINITY
                    let buf = unsafe { core::slice::from_raw_parts_mut(old_rlim as *mut u8, 16) };
                    let infinity: u64 = u64::MAX;
                    buf[0..8].copy_from_slice(&infinity.to_le_bytes());
                    buf[8..16].copy_from_slice(&infinity.to_le_bytes());
                }
                reply_val(ep_cap, 0);
            }

            // SYS_getrandom(buf, buflen, flags) — fill buffer with pseudo-random bytes
            318 => {
                let buf_ptr = msg.regs[0];
                let buflen = msg.regs[1] as usize;
                if buf_ptr == 0 || buf_ptr >= 0x0000_8000_0000_0000 {
                    reply_val(ep_cap, -14);
                } else {
                    let len = buflen.min(256); // cap to prevent huge writes
                    let buf = unsafe { core::slice::from_raw_parts_mut(buf_ptr as *mut u8, len) };
                    let mut rng = rdtsc();
                    for b in buf.iter_mut() {
                        rng ^= rng << 13;
                        rng ^= rng >> 7;
                        rng ^= rng << 17;
                        *b = rng as u8;
                    }
                    reply_val(ep_cap, len as i64);
                }
            }

            // SYS_socket(domain, type, protocol)
            41 => {
                let domain = msg.regs[0] as u32;
                let sock_type = msg.regs[1] as u32;
                let base_type = sock_type & 0xFF;
                let flags = sock_type & !0xFF; // SOCK_NONBLOCK=0x800, SOCK_CLOEXEC=0x80000
                // AF_INET=2, SOCK_STREAM=1, SOCK_DGRAM=2
                if domain == 2 && (base_type == 1 || base_type == 2) {
                    let net_cap = NET_EP_CAP.load(Ordering::Acquire);
                    if net_cap == 0 {
                        reply_val(ep_cap, -99); // -EADDRNOTAVAIL
                    } else {
                        match alloc_fd(&fds, 3) {
                            Some(fd) => {
                                if base_type == 1 {
                                    // TCP
                                    fds[fd] = FdEntry::new(FdKind::Socket, 0, 0xFFFF);
                                } else {
                                    // UDP
                                    let mut entry = FdEntry::new(FdKind::SocketUdp, 0, 0xFFFF);
                                    entry.sock_flags = (flags >> 8) as u16;
                                    fds[fd] = entry;
                                }
                                reply_val(ep_cap, fd as i64);
                            }
                            None => reply_val(ep_cap, -24), // -EMFILE
                        }
                    }
                } else if domain == 2 && base_type == 3 {
                    // SOCK_RAW — stub: return an FD but operations will fail
                    match alloc_fd(&fds, 3) {
                        Some(fd) => {
                            fds[fd] = FdEntry::new(FdKind::SocketUdp, 0, 0xFFFF);
                            reply_val(ep_cap, fd as i64);
                        }
                        None => reply_val(ep_cap, -24),
                    }
                } else {
                    reply_val(ep_cap, -97); // -EAFNOSUPPORT
                }
            }

            // SYS_connect(fd, sockaddr_ptr, addrlen)
            42 => {
                let fd = msg.regs[0] as usize;
                let sockaddr_ptr = msg.regs[1];
                let _addrlen = msg.regs[2];

                if fd >= MAX_FDS || (fds[fd].kind != FdKind::Socket && fds[fd].kind != FdKind::SocketUdp) {
                    reply_val(ep_cap, -9); // -EBADF
                } else {
                    // Parse sockaddr_in: family(2) + port(2) + ip(4)
                    let sa = unsafe { core::slice::from_raw_parts(sockaddr_ptr as *const u8, 8) };
                    let port = u16::from_be_bytes([sa[2], sa[3]]);
                    let ip = u32::from_be_bytes([sa[4], sa[5], sa[6], sa[7]]);

                    if fds[fd].kind == FdKind::SocketUdp {
                        // UDP connect: just store the remote address
                        fds[fd].udp_remote_ip = ip;
                        fds[fd].udp_remote_port = port;
                        reply_val(ep_cap, 0);
                    } else {
                        // TCP connect
                        let net_cap = NET_EP_CAP.load(Ordering::Acquire);
                        if net_cap == 0 {
                            reply_val(ep_cap, -99);
                        } else {
                            let req = sotos_common::IpcMsg {
                                tag: NET_CMD_TCP_CONNECT,
                                regs: [ip as u64, port as u64, 0, 0, 0, 0, 0, 0],
                            };
                            match sys::call_timeout(net_cap, &req, 500) {
                                Ok(resp) => {
                                    let conn_id = resp.regs[0];
                                    if conn_id as i64 >= 0 {
                                        fds[fd].net_conn_id = conn_id as u32;
                                        reply_val(ep_cap, 0);
                                    } else {
                                        reply_val(ep_cap, -111); // -ECONNREFUSED
                                    }
                                }
                                Err(_) => reply_val(ep_cap, -111),
                            }
                        }
                    }
                }
            }

            // SYS_sendto(fd, buf, len, flags, dest_addr, addrlen) = 44
            // SYS_sendmsg = 46 (treated as sendto for simple cases)
            44 | 46 => {
                let fd = msg.regs[0] as usize;
                let buf_ptr = msg.regs[1];
                let len = msg.regs[2] as usize;
                let _flags = msg.regs[3];
                let dest_ptr = msg.regs[4]; // sockaddr_in* (for UDP)

                if fd >= MAX_FDS || (fds[fd].kind != FdKind::Socket && fds[fd].kind != FdKind::SocketUdp) {
                    reply_val(ep_cap, -9);
                } else if fds[fd].kind == FdKind::SocketUdp {
                    // UDP sendto
                    let net_cap = NET_EP_CAP.load(Ordering::Acquire);
                    if net_cap == 0 { reply_val(ep_cap, -99); continue; }

                    // Determine destination: from dest_addr or from connect()
                    let (dst_ip, dst_port) = if dest_ptr != 0 {
                        let sa = unsafe { core::slice::from_raw_parts(dest_ptr as *const u8, 8) };
                        (u32::from_be_bytes([sa[4], sa[5], sa[6], sa[7]]),
                         u16::from_be_bytes([sa[2], sa[3]]))
                    } else {
                        (fds[fd].udp_remote_ip, fds[fd].udp_remote_port)
                    };
                    let src_port = fds[fd].udp_local_port;

                    let send_len = len.min(40);
                    let mut req = sotos_common::IpcMsg {
                        tag: NET_CMD_UDP_SENDTO,
                        regs: [dst_ip as u64, dst_port as u64, src_port as u64, send_len as u64, 0, 0, 0, 0],
                    };
                    let data = unsafe { core::slice::from_raw_parts(buf_ptr as *const u8, send_len) };
                    unsafe {
                        let dst = &mut req.regs[4] as *mut u64 as *mut u8;
                        core::ptr::copy_nonoverlapping(data.as_ptr(), dst, send_len);
                    }
                    match sys::call_timeout(net_cap, &req, 500) {
                        Ok(resp) => reply_val(ep_cap, resp.regs[0] as i64),
                        Err(_) => reply_val(ep_cap, -5),
                    }
                } else {
                    // TCP sendto (same as before)
                    let net_cap = NET_EP_CAP.load(Ordering::Acquire);
                    let conn_id = fds[fd].net_conn_id as u64;
                    let send_len = len.min(40);
                    let mut req = sotos_common::IpcMsg {
                        tag: NET_CMD_TCP_SEND,
                        regs: [conn_id, 0, send_len as u64, 0, 0, 0, 0, 0],
                    };
                    let data = unsafe { core::slice::from_raw_parts(buf_ptr as *const u8, send_len) };
                    unsafe {
                        let dst = &mut req.regs[3] as *mut u64 as *mut u8;
                        core::ptr::copy_nonoverlapping(data.as_ptr(), dst, send_len);
                    }
                    match sys::call_timeout(net_cap, &req, 500) {
                        Ok(resp) => reply_val(ep_cap, resp.regs[0] as i64),
                        Err(_) => reply_val(ep_cap, -5),
                    }
                }
            }

            // SYS_recvfrom(fd, buf, len, flags, src_addr, addrlen) = 45
            // SYS_recvmsg = 47
            45 | 47 => {
                let fd = msg.regs[0] as usize;
                let buf_ptr = msg.regs[1];
                let len = msg.regs[2] as usize;

                if fd >= MAX_FDS || (fds[fd].kind != FdKind::Socket && fds[fd].kind != FdKind::SocketUdp) {
                    reply_val(ep_cap, -9);
                } else if fds[fd].kind == FdKind::SocketUdp {
                    // UDP recvfrom
                    let net_cap = NET_EP_CAP.load(Ordering::Acquire);
                    if net_cap == 0 { reply_val(ep_cap, -99); continue; }
                    let src_port = fds[fd].udp_local_port;
                    let recv_len = len.min(48); // Max inline in 6 regs
                    let req = sotos_common::IpcMsg {
                        tag: NET_CMD_UDP_RECV,
                        regs: [src_port as u64, recv_len as u64, 0, 0, 0, 0, 0, 0],
                    };
                    match sys::call_timeout(net_cap, &req, 500) {
                        Ok(resp) => {
                            let n = resp.regs[0] as usize;
                            if n > 0 && n <= recv_len {
                                let dst = unsafe { core::slice::from_raw_parts_mut(buf_ptr as *mut u8, n) };
                                unsafe {
                                    let src = &resp.regs[2] as *const u64 as *const u8;
                                    core::ptr::copy_nonoverlapping(src, dst.as_mut_ptr(), n);
                                }
                            }
                            reply_val(ep_cap, n as i64);
                        }
                        Err(_) => reply_val(ep_cap, 0), // timeout = no data
                    }
                } else {
                    // TCP recvfrom (same as before)
                    let net_cap = NET_EP_CAP.load(Ordering::Acquire);
                    let conn_id = fds[fd].net_conn_id as u64;
                    let recv_len = len.min(56);
                    let req = sotos_common::IpcMsg {
                        tag: NET_CMD_TCP_RECV,
                        regs: [conn_id, recv_len as u64, 0, 0, 0, 0, 0, 0],
                    };
                    match sys::call_timeout(net_cap, &req, 500) {
                        Ok(resp) => {
                            let n = resp.regs[0] as usize;
                            if n > 0 && n <= recv_len {
                                let dst = unsafe { core::slice::from_raw_parts_mut(buf_ptr as *mut u8, n) };
                                unsafe {
                                    let src = &resp.regs[1] as *const u64 as *const u8;
                                    core::ptr::copy_nonoverlapping(src, dst.as_mut_ptr(), n);
                                }
                            }
                            reply_val(ep_cap, n as i64);
                        }
                        Err(_) => reply_val(ep_cap, 0), // EOF/timeout
                    }
                }
            }

            // Custom syscall 200: DNS resolve (hostname_ptr, hostname_len) → IP (big-endian u32)
            200 => {
                let name_ptr = msg.regs[0];
                let name_len = msg.regs[1] as usize;
                let net_cap = NET_EP_CAP.load(Ordering::Acquire);
                if net_cap == 0 || name_len == 0 || name_len > 48 {
                    reply_val(ep_cap, 0); // 0 = resolution failed
                } else {
                    // Pack hostname into IPC regs[2..] (up to 48 bytes).
                    let name = unsafe { core::slice::from_raw_parts(name_ptr as *const u8, name_len) };
                    let mut req = sotos_common::IpcMsg {
                        tag: NET_CMD_DNS_QUERY,
                        regs: [0, name_len as u64, 0, 0, 0, 0, 0, 0],
                    };
                    unsafe {
                        let dst = &mut req.regs[2] as *mut u64 as *mut u8;
                        core::ptr::copy_nonoverlapping(name.as_ptr(), dst, name_len);
                    }
                    match sys::call_timeout(net_cap, &req, 500) {
                        Ok(resp) => reply_val(ep_cap, resp.regs[0] as i64),
                        Err(_) => reply_val(ep_cap, 0),
                    }
                }
            }

            // Custom syscall 202: ICMP ping (dst_ip, seq) → 0=timeout, 1=reply | (ttl << 32)
            202 => {
                let dst_ip = msg.regs[0];
                let seq = msg.regs[1];
                let net_cap = NET_EP_CAP.load(Ordering::Acquire);
                if net_cap == 0 {
                    reply_val(ep_cap, 0);
                } else {
                    let req = sotos_common::IpcMsg {
                        tag: 1, // CMD_PING
                        regs: [dst_ip, seq, 0, 0, 0, 0, 0, 0],
                    };
                    match sys::call_timeout(net_cap, &req, 500) {
                        Ok(resp) => reply_val(ep_cap, resp.regs[0] as i64),
                        Err(_) => reply_val(ep_cap, 0),
                    }
                }
            }

            // Custom syscall 201: traceroute hop (dst_ip, ttl) → responder_ip | (reached << 32)
            201 => {
                let dst_ip = msg.regs[0];
                let ttl = msg.regs[1];
                let net_cap = NET_EP_CAP.load(Ordering::Acquire);
                if net_cap == 0 {
                    reply_val(ep_cap, 0);
                } else {
                    let req = sotos_common::IpcMsg {
                        tag: 7, // CMD_TRACEROUTE_HOP
                        regs: [dst_ip, ttl, 0, 0, 0, 0, 0, 0],
                    };
                    match sys::call_timeout(net_cap, &req, 500) {
                        Ok(resp) => reply_val(ep_cap, resp.regs[0] as i64),
                        Err(_) => reply_val(ep_cap, 0),
                    }
                }
            }

            // SYS_rt_sigaction(sig, act, oldact, sigsetsize)
            13 => {
                let signo = msg.regs[0] as usize;
                let act_ptr = msg.regs[1];
                let oldact = msg.regs[2];
                let sigsetsize = msg.regs[3].max(8) as usize;
                let ksa_size = (24 + sigsetsize).min(64);
                let idx = pid as usize - 1;
                // SIGKILL(9) and SIGSTOP(19) cannot be caught
                if signo == 9 || signo == 19 {
                    reply_val(ep_cap, -22); continue; // -EINVAL
                }
                // Write old handler to oldact
                if oldact != 0 && oldact < 0x0000_8000_0000_0000 {
                    let buf = unsafe { core::slice::from_raw_parts_mut(oldact as *mut u8, ksa_size) };
                    for b in buf.iter_mut() { *b = 0; }
                    if signo > 0 && signo < 32 {
                        let old_h = SIG_HANDLER[idx][signo].load(Ordering::Acquire);
                        let old_f = SIG_FLAGS[idx][signo].load(Ordering::Acquire);
                        let old_r = SIG_RESTORER[idx][signo].load(Ordering::Acquire);
                        buf[0..8].copy_from_slice(&old_h.to_le_bytes());
                        buf[8..16].copy_from_slice(&old_f.to_le_bytes());
                        buf[16..24].copy_from_slice(&old_r.to_le_bytes());
                    }
                }
                // Install new handler from act
                if act_ptr != 0 && act_ptr < 0x0000_8000_0000_0000 && signo > 0 && signo < 32 {
                    let handler = unsafe { *(act_ptr as *const u64) };
                    let flags = unsafe { *((act_ptr + 8) as *const u64) };
                    let restorer = unsafe { *((act_ptr + 16) as *const u64) };
                    SIG_HANDLER[idx][signo].store(handler, Ordering::Release);
                    SIG_FLAGS[idx][signo].store(flags, Ordering::Release);
                    SIG_RESTORER[idx][signo].store(restorer, Ordering::Release);
                }
                reply_val(ep_cap, 0);
            }

            // SYS_rt_sigprocmask(how, set, oldset, sigsetsize)
            14 => {
                let how = msg.regs[0];
                let set_ptr = msg.regs[1];
                let oldset = msg.regs[2];
                let idx = pid as usize - 1;
                let cur_mask = SIG_BLOCKED[idx].load(Ordering::Acquire);
                // Write old mask
                if oldset != 0 && oldset < 0x0000_8000_0000_0000 {
                    unsafe { *(oldset as *mut u64) = cur_mask; }
                }
                // Apply new mask
                if set_ptr != 0 && set_ptr < 0x0000_8000_0000_0000 {
                    let new_set = unsafe { *(set_ptr as *const u64) };
                    let safe_set = new_set & !((1 << SIGKILL) | (1 << 19));
                    match how {
                        0 => SIG_BLOCKED[idx].store(cur_mask | safe_set, Ordering::Release),  // SIG_BLOCK
                        1 => SIG_BLOCKED[idx].store(cur_mask & !safe_set, Ordering::Release), // SIG_UNBLOCK
                        2 => SIG_BLOCKED[idx].store(safe_set, Ordering::Release),             // SIG_SETMASK
                        _ => {}
                    }
                }
                reply_val(ep_cap, 0);
            }

            // SYS_nanosleep(req, rem) — sleep for specified time
            35 => {
                let req_ptr = msg.regs[0];
                if req_ptr != 0 && req_ptr < 0x0000_8000_0000_0000 {
                    let secs = unsafe { *(req_ptr as *const i64) };
                    let _nsecs = unsafe { *((req_ptr + 8) as *const i64) };
                    // Approximate: yield for a number of iterations
                    let iters = (secs as u64).saturating_mul(100).max(1).min(10000);
                    for _ in 0..iters { sys::yield_now(); }
                }
                reply_val(ep_cap, 0);
            }

            // SYS_sigaltstack(ss, old_ss) — set alternate signal stack
            131 => {
                let old_ss = msg.regs[1];
                if old_ss != 0 && old_ss < 0x0000_8000_0000_0000 {
                    // Return empty stack_t: ss_sp=0, ss_flags=SS_DISABLE(2), ss_size=0
                    let buf = unsafe { core::slice::from_raw_parts_mut(old_ss as *mut u8, 24) };
                    for b in buf.iter_mut() { *b = 0; }
                    buf[8..12].copy_from_slice(&2u32.to_le_bytes()); // SS_DISABLE
                }
                reply_val(ep_cap, 0);
            }

            // SYS_exit_group(status) — exit all threads in the process
            231 => {
                let status = msg.regs[0] as i32;
                PROC_EXIT[pid as usize - 1].store(status as u64, Ordering::Release);
                PROC_STATE[pid as usize - 1].store(2, Ordering::Release);
                // Deliver SIGCHLD to parent
                let ppid = PROC_PARENT[pid as usize - 1].load(Ordering::Acquire) as usize;
                if ppid > 0 && ppid <= MAX_PROCS {
                    sig_send(ppid, SIGCHLD);
                }
                break;
            }

            // SYS_readv(fd, iov, iovcnt) — scatter read
            19 => {
                let fd = msg.regs[0] as usize;
                let iov_ptr = msg.regs[1];
                let iovcnt = msg.regs[2] as usize;
                if fd >= MAX_FDS || fds[fd].kind == FdKind::Free {
                    reply_val(ep_cap, -9);
                } else if fds[fd].kind == FdKind::Stdin {
                    // Stdin readv: read into first iovec only
                    if iovcnt > 0 && iov_ptr < 0x0000_8000_0000_0000 {
                        let base = unsafe { *(iov_ptr as *const u64) };
                        let _len = unsafe { *((iov_ptr + 8) as *const u64) } as usize;
                        // Wait for one keystroke
                        loop {
                            match unsafe { kb_read_char() } {
                                Some(ch) => {
                                    if base != 0 { unsafe { *(base as *mut u8) = ch; } }
                                    reply_val(ep_cap, 1);
                                    break;
                                }
                                None => sys::yield_now(),
                            }
                        }
                    } else {
                        reply_val(ep_cap, 0);
                    }
                } else {
                    reply_val(ep_cap, -9); // other FD types: not yet
                }
            }

            // SYS_rename(oldpath, newpath) — rename file
            82 => {
                let old_ptr = msg.regs[0];
                let new_ptr = msg.regs[1];
                let mut old_path = [0u8; 48];
                let mut new_path = [0u8; 48];
                let old_len = copy_guest_path(old_ptr, &mut old_path);
                let new_len = copy_guest_path(new_ptr, &mut new_path);
                match vfs_opt.as_mut() {
                    Some(vfs) => {
                        vfs.cwd = cwd_oid;
                        // Read old file, create new, delete old
                        match vfs.store().resolve_path(&old_path[..old_len], cwd_oid) {
                            Ok(oid) => {
                                let mut buf = [0u8; 4096];
                                let size = vfs.store_mut().read_obj(oid, &mut buf).unwrap_or(0);
                                match vfs.store_mut().create_in(&new_path[..new_len], &buf[..size], cwd_oid) {
                                    Ok(_new_oid) => {
                                        let _ = vfs.store_mut().delete(oid);
                                        reply_val(ep_cap, 0);
                                    }
                                    Err(_) => reply_val(ep_cap, -2),
                                }
                            }
                            Err(_) => reply_val(ep_cap, -2),
                        }
                    }
                    None => reply_val(ep_cap, -2),
                }
            }

            // SYS_poll(fds_ptr, nfds, timeout) — wait for events on FDs
            7 => {
                let fds_ptr = msg.regs[0] as *mut u8;
                let nfds = msg.regs[1] as usize;
                let timeout = msg.regs[2] as i32;
                let mut ready = 0u32;
                // struct pollfd { int fd; short events; short revents; } = 8 bytes each
                for i in 0..nfds.min(16) {
                    let pfd = unsafe { fds_ptr.add(i * 8) };
                    let pfd_fd = unsafe { *(pfd as *const i32) };
                    let events = unsafe { *((pfd.add(4)) as *const i16) };
                    let mut revents: i16 = 0;
                    if pfd_fd >= 0 && (pfd_fd as usize) < MAX_FDS && fds[pfd_fd as usize].kind != FdKind::Free {
                        let k = fds[pfd_fd as usize].kind;
                        // POLLIN = 1, POLLOUT = 4, POLLHUP = 16, POLLERR = 8
                        match k {
                            FdKind::Stdin => {
                                if events & 1 != 0 {
                                    if unsafe { kb_has_char() } { revents |= 1; }
                                }
                            }
                            FdKind::Stdout | FdKind::PipeWrite => {
                                if events & 4 != 0 { revents |= 4; }
                            }
                            FdKind::Socket => {
                                // TCP: query net service for data availability
                                let net_cap = NET_EP_CAP.load(Ordering::Acquire);
                                let conn_id = fds[pfd_fd as usize].net_conn_id;
                                if net_cap != 0 && conn_id != 0xFFFF {
                                    let req = sotos_common::IpcMsg {
                                        tag: NET_CMD_TCP_STATUS,
                                        regs: [conn_id as u64, 0, 0, 0, 0, 0, 0, 0],
                                    };
                                    if let Ok(resp) = sys::call_timeout(net_cap, &req, 50) {
                                        let recv_avail = resp.regs[0]; // bytes available to read
                                        let connected = resp.regs[1]; // 1=connected, 0=closed/error
                                        if events & 1 != 0 && (recv_avail > 0 || connected == 0) {
                                            revents |= 1; // POLLIN
                                        }
                                        if events & 4 != 0 && connected != 0 {
                                            revents |= 4; // POLLOUT (writable if connected)
                                        }
                                        if connected == 0 {
                                            revents |= 16; // POLLHUP
                                        }
                                    } else {
                                        // Net service timeout — report as ready to avoid hang
                                        if events & 1 != 0 { revents |= 1; }
                                        if events & 4 != 0 { revents |= 4; }
                                    }
                                } else {
                                    if events & 4 != 0 { revents |= 4; }
                                }
                            }
                            FdKind::SocketUdp => {
                                // UDP: always writable, check for data via recv peek
                                if events & 4 != 0 { revents |= 4; }
                                if events & 1 != 0 { revents |= 1; } // optimistic: data may be available
                            }
                            FdKind::VfsFile | FdKind::DirList | FdKind::PipeRead => {
                                if events & 1 != 0 { revents |= 1; } // always readable
                                if events & 4 != 0 { revents |= 4; }
                            }
                            _ => {}
                        }
                    } else if pfd_fd >= 0 {
                        revents = 0x20; // POLLNVAL
                    }
                    unsafe { *((pfd.add(6)) as *mut i16) = revents; }
                    if revents != 0 { ready += 1; }
                }
                if ready > 0 || timeout == 0 {
                    reply_val(ep_cap, ready as i64);
                } else {
                    // Blocking poll — short spin then return (avoid long hangs)
                    let max_iters: u32 = if timeout > 0 { (timeout as u32).min(500) * 10 } else { 5000 };
                    for _ in 0..max_iters {
                        sys::yield_now();
                        // Quick re-check
                        let mut found = false;
                        for i in 0..nfds.min(16) {
                            let pfd = unsafe { fds_ptr.add(i * 8) };
                            let pfd_fd = unsafe { *(pfd as *const i32) };
                            if pfd_fd >= 0 && (pfd_fd as usize) < MAX_FDS {
                                let k = fds[pfd_fd as usize].kind;
                                if k == FdKind::Stdin && unsafe { kb_has_char() } { found = true; break; }
                                if k == FdKind::Socket {
                                    // Check TCP recv buffer
                                    let net_cap = NET_EP_CAP.load(Ordering::Acquire);
                                    let conn_id = fds[pfd_fd as usize].net_conn_id;
                                    if net_cap != 0 && conn_id != 0xFFFF {
                                        let req = sotos_common::IpcMsg {
                                            tag: NET_CMD_TCP_STATUS,
                                            regs: [conn_id as u64, 0, 0, 0, 0, 0, 0, 0],
                                        };
                                        if let Ok(resp) = sys::call_timeout(net_cap, &req, 20) {
                                            if resp.regs[0] > 0 || resp.regs[1] == 0 { found = true; break; }
                                        }
                                    }
                                }
                            }
                        }
                        if found {
                            // Re-run the full poll to set revents
                            ready = 0;
                            for i in 0..nfds.min(16) {
                                let pfd = unsafe { fds_ptr.add(i * 8) };
                                let pfd_fd = unsafe { *(pfd as *const i32) };
                                let events = unsafe { *((pfd.add(4)) as *const i16) };
                                let mut revents: i16 = 0;
                                if pfd_fd >= 0 && (pfd_fd as usize) < MAX_FDS && fds[pfd_fd as usize].kind != FdKind::Free {
                                    let k = fds[pfd_fd as usize].kind;
                                    match k {
                                        FdKind::Stdin => { if events & 1 != 0 && unsafe { kb_has_char() } { revents |= 1; } }
                                        FdKind::Stdout | FdKind::PipeWrite => { if events & 4 != 0 { revents |= 4; } }
                                        FdKind::Socket => {
                                            let net_cap = NET_EP_CAP.load(Ordering::Acquire);
                                            let conn_id = fds[pfd_fd as usize].net_conn_id;
                                            if net_cap != 0 && conn_id != 0xFFFF {
                                                let req = sotos_common::IpcMsg {
                                                    tag: NET_CMD_TCP_STATUS, regs: [conn_id as u64, 0, 0, 0, 0, 0, 0, 0],
                                                };
                                                if let Ok(resp) = sys::call_timeout(net_cap, &req, 20) {
                                                    if events & 1 != 0 && (resp.regs[0] > 0 || resp.regs[1] == 0) { revents |= 1; }
                                                    if events & 4 != 0 && resp.regs[1] != 0 { revents |= 4; }
                                                    if resp.regs[1] == 0 { revents |= 16; }
                                                }
                                            }
                                        }
                                        _ => { if events & 1 != 0 { revents |= 1; } }
                                    }
                                }
                                unsafe { *((pfd.add(6)) as *mut i16) = revents; }
                                if revents != 0 { ready += 1; }
                            }
                            break;
                        }
                    }
                    reply_val(ep_cap, ready as i64);
                }
            }

            // SYS_sysinfo(info) — system information
            99 => {
                let info_ptr = msg.regs[0];
                if info_ptr != 0 && info_ptr < 0x0000_8000_0000_0000 {
                    // struct sysinfo = 112 bytes
                    let buf = unsafe { core::slice::from_raw_parts_mut(info_ptr as *mut u8, 112) };
                    for b in buf.iter_mut() { *b = 0; }
                    // uptime (i64) at offset 0
                    let tsc = rdtsc();
                    let boot_tsc = BOOT_TSC.load(Ordering::Acquire);
                    let uptime = if tsc > boot_tsc { (tsc - boot_tsc) / 2_000_000_000 } else { 0 };
                    buf[0..8].copy_from_slice(&(uptime as i64).to_le_bytes());
                    // totalram at offset 32 (u64)
                    let ram: u64 = 256 * 1024 * 1024; // 256 MiB
                    buf[32..40].copy_from_slice(&ram.to_le_bytes());
                    // freeram at offset 40 (u64)
                    buf[40..48].copy_from_slice(&(ram / 2).to_le_bytes());
                    // mem_unit at offset 104 (u32)
                    buf[104..108].copy_from_slice(&1u32.to_le_bytes());
                }
                reply_val(ep_cap, 0);
            }

            // SYS_SIGNAL_TRAMPOLINE (0x7F00) — async signal delivery from timer interrupt.
            // The LAPIC timer handler redirected the thread to the vDSO trampoline,
            // which did syscall(0x7F00) to enter LUCAS for signal delivery.
            0x7F00 => {
                let child_tid = msg.regs[6];
                let pid_usize = pid as usize;
                let sig = sig_dequeue(pid_usize);
                if sig != 0 {
                    match sig_dispatch(pid_usize, sig) {
                        1 => break, // terminated
                        3 => {
                            if signal_deliver(ep_cap, pid_usize, sig, child_tid, 0, true) {
                                continue;
                            }
                        }
                        _ => {}
                    }
                }
                // No pending signal or delivery failed — resume the thread by
                // building a SignalFrame with the saved pre-interrupt state and
                // redirecting through the vDSO's rt_sigreturn restorer.
                let mut saved_regs = [0u64; 18];
                if sys::get_thread_regs(child_tid, &mut saved_regs).is_ok() {
                    let saved_rsp = saved_regs[15];
                    let frame_size = sotos_common::SIGNAL_FRAME_SIZE as u64;
                    let new_rsp = ((saved_rsp - frame_size) & !0xF) - 8;
                    let fp = new_rsp as *mut u64;
                    unsafe {
                        core::ptr::write_volatile(fp.add(0),  vdso::SIGRETURN_RESTORER_ADDR);
                        core::ptr::write_volatile(fp.add(1),  0); // signo = 0 (no signal)
                        core::ptr::write_volatile(fp.add(2),  saved_regs[0]);  // rax
                        core::ptr::write_volatile(fp.add(3),  saved_regs[1]);  // rbx
                        core::ptr::write_volatile(fp.add(4),  saved_regs[2]);  // rcx (=rip)
                        core::ptr::write_volatile(fp.add(5),  saved_regs[3]);  // rdx
                        core::ptr::write_volatile(fp.add(6),  saved_regs[4]);  // rsi
                        core::ptr::write_volatile(fp.add(7),  saved_regs[5]);  // rdi
                        core::ptr::write_volatile(fp.add(8),  saved_regs[6]);  // rbp
                        core::ptr::write_volatile(fp.add(9),  saved_regs[7]);  // r8
                        core::ptr::write_volatile(fp.add(10), saved_regs[8]);  // r9
                        core::ptr::write_volatile(fp.add(11), saved_regs[9]);  // r10
                        core::ptr::write_volatile(fp.add(12), saved_regs[10]); // r11 (=rflags)
                        core::ptr::write_volatile(fp.add(13), saved_regs[11]); // r12
                        core::ptr::write_volatile(fp.add(14), saved_regs[12]); // r13
                        core::ptr::write_volatile(fp.add(15), saved_regs[13]); // r14
                        core::ptr::write_volatile(fp.add(16), saved_regs[14]); // r15
                        core::ptr::write_volatile(fp.add(17), saved_regs[2]);  // rip
                        core::ptr::write_volatile(fp.add(18), saved_rsp);      // rsp
                        core::ptr::write_volatile(fp.add(19), saved_regs[10]); // rflags
                        core::ptr::write_volatile(fp.add(20), saved_regs[16]); // fs_base
                        core::ptr::write_volatile(fp.add(21), 0);              // old_sigmask
                    }
                    // Redirect thread to the restorer, which calls rt_sigreturn
                    let reply = sotos_common::IpcMsg {
                        tag: sotos_common::SIG_REDIRECT_TAG,
                        regs: [
                            vdso::SIGRETURN_RESTORER_ADDR, // RIP = restorer
                            0, 0, 0,
                            new_rsp, // RSP below signal frame
                            0, 0, 0,
                        ],
                    };
                    let _ = sys::send(ep_cap, &reply);
                } else {
                    reply_val(ep_cap, 0);
                }
            }

            // SYS_bind(fd, sockaddr_ptr, addrlen) = 49
            49 => {
                let fd = msg.regs[0] as usize;
                let sockaddr_ptr = msg.regs[1];
                if fd >= MAX_FDS || (fds[fd].kind != FdKind::Socket && fds[fd].kind != FdKind::SocketUdp) {
                    reply_val(ep_cap, -9);
                } else {
                    // For UDP: store the local port from sockaddr_in
                    let sa = unsafe { core::slice::from_raw_parts(sockaddr_ptr as *const u8, 8) };
                    let port = u16::from_be_bytes([sa[2], sa[3]]);
                    if fds[fd].kind == FdKind::SocketUdp && port != 0 {
                        fds[fd].udp_local_port = port;
                        // Tell net service to bind this UDP port
                        let net_cap = NET_EP_CAP.load(Ordering::Acquire);
                        if net_cap != 0 {
                            let req = sotos_common::IpcMsg {
                                tag: NET_CMD_UDP_BIND,
                                regs: [port as u64, 0, 0, 0, 0, 0, 0, 0],
                            };
                            let _ = sys::call_timeout(net_cap, &req, 100);
                        }
                    } else if fds[fd].kind == FdKind::SocketUdp {
                        // Bind to ephemeral port
                        static NEXT_UDP_PORT: AtomicU64 = AtomicU64::new(30000);
                        let p = NEXT_UDP_PORT.fetch_add(1, Ordering::SeqCst) as u16;
                        fds[fd].udp_local_port = p;
                        let net_cap = NET_EP_CAP.load(Ordering::Acquire);
                        if net_cap != 0 {
                            let req = sotos_common::IpcMsg {
                                tag: NET_CMD_UDP_BIND,
                                regs: [p as u64, 0, 0, 0, 0, 0, 0, 0],
                            };
                            let _ = sys::call_timeout(net_cap, &req, 100);
                        }
                    }
                    reply_val(ep_cap, 0);
                }
            }

            // SYS_listen(fd, backlog) = 50 — stub for TCP
            50 => reply_val(ep_cap, 0),

            // SYS_getsockname(fd, sockaddr_ptr, addrlen_ptr) = 51
            51 => {
                let fd = msg.regs[0] as usize;
                let sa_ptr = msg.regs[1];
                let alen_ptr = msg.regs[2];
                if fd >= MAX_FDS || (fds[fd].kind != FdKind::Socket && fds[fd].kind != FdKind::SocketUdp) {
                    reply_val(ep_cap, -9);
                } else {
                    // Return AF_INET, local port, 0.0.0.0
                    let sa = unsafe { core::slice::from_raw_parts_mut(sa_ptr as *mut u8, 16) };
                    for b in sa.iter_mut() { *b = 0; }
                    sa[0] = 2; sa[1] = 0; // AF_INET in little-endian sa_family
                    let port = if fds[fd].kind == FdKind::SocketUdp { fds[fd].udp_local_port } else { 0 };
                    sa[2..4].copy_from_slice(&port.to_be_bytes());
                    if alen_ptr != 0 {
                        unsafe { *(alen_ptr as *mut u32) = 16; }
                    }
                    reply_val(ep_cap, 0);
                }
            }

            // SYS_getpeername(fd, sockaddr_ptr, addrlen_ptr) = 52
            52 => {
                let fd = msg.regs[0] as usize;
                let sa_ptr = msg.regs[1];
                let alen_ptr = msg.regs[2];
                if fd >= MAX_FDS || (fds[fd].kind != FdKind::Socket && fds[fd].kind != FdKind::SocketUdp) {
                    reply_val(ep_cap, -9);
                } else {
                    let sa = unsafe { core::slice::from_raw_parts_mut(sa_ptr as *mut u8, 16) };
                    for b in sa.iter_mut() { *b = 0; }
                    sa[0] = 2; sa[1] = 0; // AF_INET
                    let port = fds[fd].udp_remote_port;
                    let ip = fds[fd].udp_remote_ip;
                    sa[2..4].copy_from_slice(&port.to_be_bytes());
                    sa[4..8].copy_from_slice(&ip.to_be_bytes());
                    if alen_ptr != 0 {
                        unsafe { *(alen_ptr as *mut u32) = 16; }
                    }
                    reply_val(ep_cap, 0);
                }
            }

            // SYS_shutdown(fd, how) = 48
            48 => reply_val(ep_cap, 0),

            // SYS_setsockopt(fd, level, optname, optval, optlen) = 54
            54 => reply_val(ep_cap, 0),

            // SYS_getsockopt(fd, level, optname, optval, optlen) = 55
            55 => {
                let optval_ptr = msg.regs[3];
                let optlen_ptr = msg.regs[4];
                // Return 0 (option value = 0, length = 4)
                if optval_ptr != 0 {
                    unsafe { *(optval_ptr as *mut u32) = 0; }
                }
                if optlen_ptr != 0 {
                    unsafe { *(optlen_ptr as *mut u32) = 4; }
                }
                reply_val(ep_cap, 0);
            }

            // SYS_epoll_create1(flags) = 291, SYS_epoll_create(size) = 213
            291 | 213 => {
                match alloc_fd(&fds, 3) {
                    Some(fd) => {
                        fds[fd] = FdEntry::new(FdKind::EpollFd, 0, 0);
                        reply_val(ep_cap, fd as i64);
                    }
                    None => reply_val(ep_cap, -24),
                }
            }

            // SYS_epoll_ctl(epfd, op, fd, event) = 233
            233 => reply_val(ep_cap, 0),

            // SYS_epoll_wait(epfd, events, maxevents, timeout) = 232
            // SYS_epoll_pwait(epfd, events, maxevents, timeout, sigmask, sigsetsize) = 281
            232 | 281 => {
                // Stub: return 0 events (timeout)
                reply_val(ep_cap, 0);
            }

            // SYS_ppoll(fds, nfds, tmo, sigmask, sigsetsize) = 271
            271 => {
                // Treat like poll with 0 timeout → return 0
                reply_val(ep_cap, 0);
            }

            // SYS_select(nfds, readfds, writefds, exceptfds, timeout) = 23
            // SYS_pselect6 = 270
            23 | 270 => reply_val(ep_cap, 0),

            // Unknown Linux syscall → -ENOSYS (with logging)
            _ => {
                print(b"LUCAS: unhandled syscall ");
                print_u64(syscall_nr);
                print(b"\n");
                reply_val(ep_cap, -38);
            }
        }
    }

    print(b"LUCAS: done\n");
    sys::thread_exit();
}

/// Set up LUCAS: create handler + guest threads, establish IPC redirect.
/// Reads guest_entry from BootInfo; if 0, skips LUCAS entirely.
/// If `blk` is provided, stores it for the handler to mount as VFS.
fn start_lucas(blk: Option<VirtioBlk>) {
    let boot_info = unsafe { &*(BOOT_INFO_ADDR as *const BootInfo) };

    // Framebuffer already initialized in _start().

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

    // 5. Create guest thread with redirect pre-set (atomic, no race with early syscalls).
    let guest_thread_cap = sys::thread_create_redirected(
        guest_entry,
        LUCAS_GUEST_STACK + LUCAS_GUEST_STACK_PAGES * 0x1000,
        ep_cap,
    ).unwrap_or_else(|_| panic_halt());
    let _ = sys::signal_entry(guest_thread_cap, vdso::SIGNAL_TRAMPOLINE_ADDR);
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
