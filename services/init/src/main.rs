#![no_std]
#![no_main]

extern crate alloc;

use sotos_common::sys;

// =============================================================================
// Bump allocator for goblin ELF parsing (128 KiB, resettable)
// =============================================================================
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

mod vdso;
#[allow(dead_code)]
mod framebuffer;
mod trace;
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
mod boot_tests;

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
const SPAWN_BUF_PAGES: u64 = 128;

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
    if boot_info.fb_addr != 0 {
        unsafe { fb_init(boot_info); }
        // Draw Tokyo Night desktop GUI (positions terminal in window)
        unsafe { framebuffer::fb_init_gui(); }
    }

    print(b"INIT: boot complete, ");
    print_u64(cap_count);
    print(b" caps received\n");

    // Diagnostic: print addresses of pipe state for corruption analysis
    print(b"PIPE-ADDRS: PWC=");
    print_u64(fd::PIPE_WRITE_CLOSED.as_ptr() as u64);
    print(b" WREFS=");
    print_u64(fd::PIPE_WRITE_REFS.as_ptr() as u64);
    print(b" RREFS=");
    print_u64(fd::PIPE_READ_REFS.as_ptr() as u64);
    print(b" TG=");
    print_u64(unsafe { fd::THREAD_GROUPS.as_ptr() as u64 });
    print(b"\n");

    // Store init's own AS cap for CoW fork support.
    if boot_info.self_as_cap != 0 {
        crate::process::INIT_SELF_AS_CAP.store(boot_info.self_as_cap, core::sync::atomic::Ordering::Release);
        print(b"INIT: self_as_cap=");
        print_u64(boot_info.self_as_cap);
        print(b"\n");
    }

    // --- Phase 2: SPSC channel test ---
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

    // --- Phase 3: Benchmarks ---
    run_benchmarks(ring);

    // --- Phase 4: Virtio-BLK + Object Store ---
    let mut blk = init_block_storage(boot_info);

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

    // --- Phase 8: WASM SFI interpreter test ---
    test_wasm();

    // --- Wait for spawned processes to finish ---
    for _ in 0..200 { sys::yield_now(); }

    // SKIP boot tests for git debugging — go straight to LUCAS shell
    // run_linux_test();
    // run_musl_test();
    // run_dynamic_test();
    // run_busybox_test();
    // if let Some(ref mut b) = blk { run_fat_test(b); }
    // run_phase_validation();

    // --- Phase 9: LUCAS shell ---
    start_lucas(blk);

    sys::thread_exit();
}

/// Spawn a new process from an initrd binary by name.
fn spawn_process(name: &[u8]) {
    use sotos_common::elf;

    print(b"SPAWN: loading '");
    print(name);
    print(b"' from initrd...\n");

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
            return;
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
            return;
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
            return;
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
                    return;
                }
            };

            let temp_vaddr = 0x5100000u64;
            if sys::map(temp_vaddr, frame_cap, MAP_WRITABLE).is_err() {
                print(b"SPAWN: temp map failed\n");
                return;
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
                return;
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
                return;
            }
        };
        if sys::map_into(as_cap, stack_base + i * 0x1000, frame_cap, MAP_WRITABLE).is_err() {
            print(b"SPAWN: map_into stack failed\n");
            return;
        }
    }
    let stack_top = stack_base + stack_pages * 0x1000;

    let caps: [u64; 0] = [];
    if sys::bootinfo_write(as_cap, caps.as_ptr() as u64, 0).is_err() {
        print(b"SPAWN: bootinfo_write failed\n");
        return;
    }

    match sys::thread_create_in(as_cap, elf_info.entry, stack_top, 0) {
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

    for i in 0..SPAWN_BUF_PAGES {
        let _ = sys::unmap_free(SPAWN_BUF_BASE + i * 0x1000);
    }
}

// ---------------------------------------------------------------------------
// Block storage initialization
// ---------------------------------------------------------------------------

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

fn panic_halt() -> ! {
    print(b"PANIC\n");
    loop {}
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
