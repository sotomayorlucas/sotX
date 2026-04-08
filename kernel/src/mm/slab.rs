//! Per-CPU slab allocator for kernel heap.
//!
//! 8 power-of-2 size classes (8..1024 bytes), each backed by 4 KiB slab pages
//! obtained from the physical frame allocator. Objects > 1024 bytes get a
//! whole page. Objects > 4096 bytes use contiguous frame allocation.
//!
//! Each CPU has its own `SlabAllocator` to minimize contention. The `cpu_owner`
//! field in each slab header routes frees to the owning CPU's cache.
//!
//! Lock ordering: SLAB → FRAME_ALLOCATOR (slab calls alloc_frame).

use core::alloc::{GlobalAlloc, Layout};
use core::ptr;
use core::sync::atomic::{AtomicBool, Ordering};

use spin::Mutex;

use super::frame::{PhysFrame, FRAME_SIZE};
use super::{alloc_contiguous, alloc_frame, free_frame, hhdm_offset};

const PAGE_SIZE: usize = FRAME_SIZE;
const NUM_CLASSES: usize = 8;
const SIZE_CLASSES: [usize; NUM_CLASSES] = [8, 16, 32, 64, 128, 256, 512, 1024];
use sotos_common::MAX_CPUS;

/// Set to true after percpu::init_bsp() completes.
static PERCPU_READY: AtomicBool = AtomicBool::new(false);

/// Mark percpu as ready (called from percpu::init_bsp).
pub fn mark_percpu_ready() {
    PERCPU_READY.store(true, Ordering::Release);
}

/// Check if percpu is ready (used by per-core IPC pools to determine current core).
pub fn is_percpu_ready() -> bool {
    PERCPU_READY.load(Ordering::Acquire)
}

/// Get the current CPU index (0 during early boot).
fn current_cpu_index() -> usize {
    if PERCPU_READY.load(Ordering::Acquire) {
        crate::arch::x86_64::percpu::current_percpu().cpu_index as usize
    } else {
        0 // BSP during early boot
    }
}

#[repr(C)]
struct SlabHeader {
    next: *mut SlabHeader,
    obj_size: u16,
    total: u16,
    used: u16,
    cpu_owner: u8,
    _pad: u8,
    free_list: *mut u8,
}

struct SizeClass {
    obj_size: usize,
    partial: *mut SlabHeader,
}

struct SlabAllocator {
    classes: [SizeClass; NUM_CLASSES],
    ready: bool,
}

unsafe impl Send for SlabAllocator {}

impl SlabAllocator {
    const fn new() -> Self {
        const fn make_class(size: usize) -> SizeClass {
            SizeClass {
                obj_size: size,
                partial: ptr::null_mut(),
            }
        }
        Self {
            classes: [
                make_class(8),
                make_class(16),
                make_class(32),
                make_class(64),
                make_class(128),
                make_class(256),
                make_class(512),
                make_class(1024),
            ],
            ready: false,
        }
    }

    fn init(&mut self) {
        self.ready = true;
    }

    fn class_index(size: usize) -> Option<usize> {
        SIZE_CLASSES.iter().position(|&s| s >= size)
    }

    fn alloc_page(&self) -> *mut u8 {
        let frame = alloc_frame().expect("slab: out of frames");
        (frame.addr() + hhdm_offset()) as *mut u8
    }

    fn free_page(&self, ptr: *mut u8) {
        let virt = ptr as u64;
        let phys = virt - hhdm_offset();
        free_frame(PhysFrame::from_addr(phys));
    }

    fn alloc_multi_page(&self, count: usize) -> *mut u8 {
        let frame = alloc_contiguous(count).expect("slab: out of frames for multi-page alloc");
        (frame.addr() + hhdm_offset()) as *mut u8
    }

    fn free_multi_page(&self, ptr: *mut u8, count: usize) {
        let virt = ptr as u64;
        let phys = virt - hhdm_offset();
        for i in 0..count {
            free_frame(PhysFrame::from_addr(phys + (i as u64 * PAGE_SIZE as u64)));
        }
    }

    fn init_slab(&self, page: *mut u8, obj_size: usize, cpu: u8) -> *mut SlabHeader {
        let header = page as *mut SlabHeader;
        let header_size = core::mem::size_of::<SlabHeader>();
        let data_start = (header_size + obj_size - 1) & !(obj_size - 1);
        let count = (PAGE_SIZE - data_start) / obj_size;

        unsafe {
            (*header).next = ptr::null_mut();
            (*header).obj_size = obj_size as u16;
            (*header).total = count as u16;
            (*header).used = 0;
            (*header).cpu_owner = cpu;
            (*header).free_list = ptr::null_mut();

            // Build free list (last object first so first object is at head)
            let base = page.add(data_start);
            for i in (0..count).rev() {
                let obj = base.add(i * obj_size);
                let next = (*header).free_list;
                (obj as *mut *mut u8).write(next);
                (*header).free_list = obj;
            }
        }

        header
    }

    fn allocate(&mut self, layout: Layout, cpu: u8) -> *mut u8 {
        if !self.ready {
            return ptr::null_mut();
        }

        let size = layout.size().max(layout.align());

        // Large allocation: multi-page or whole-page (bypass per-CPU caches)
        if size > 1024 {
            if size > PAGE_SIZE {
                let pages = (size + PAGE_SIZE - 1) / PAGE_SIZE;
                return self.alloc_multi_page(pages);
            }
            return self.alloc_page();
        }

        let idx = Self::class_index(size).unwrap();
        let obj_size = self.classes[idx].obj_size;

        // Need a new slab?
        if self.classes[idx].partial.is_null() {
            let page = self.alloc_page();
            let slab = self.init_slab(page, obj_size, cpu);
            self.classes[idx].partial = slab;
        }

        let slab = self.classes[idx].partial;
        unsafe {
            let obj = (*slab).free_list;
            debug_assert!(!obj.is_null());
            (*slab).free_list = (obj as *const *mut u8).read();
            (*slab).used += 1;

            // If slab is now full, remove from partial list
            if (*slab).free_list.is_null() {
                self.classes[idx].partial = (*slab).next;
                (*slab).next = ptr::null_mut();
            }

            obj
        }
    }

    fn deallocate(&mut self, ptr: *mut u8, layout: Layout) {
        if !self.ready {
            return;
        }

        let size = layout.size().max(layout.align());

        if size > 1024 {
            if size > PAGE_SIZE {
                let pages = (size + PAGE_SIZE - 1) / PAGE_SIZE;
                self.free_multi_page(ptr, pages);
            } else {
                self.free_page(ptr);
            }
            return;
        }

        let idx = Self::class_index(size).unwrap();

        // Find slab header: page-align the pointer
        let slab = (ptr as usize & !(PAGE_SIZE - 1)) as *mut SlabHeader;

        unsafe {
            let was_full = (*slab).free_list.is_null();

            // Push onto free list
            (ptr as *mut *mut u8).write((*slab).free_list);
            (*slab).free_list = ptr;
            (*slab).used -= 1;

            // If slab was full, re-insert into partial list
            if was_full {
                (*slab).next = self.classes[idx].partial;
                self.classes[idx].partial = slab;
            }
        }
    }
}

/// Per-CPU slab caches — one SlabAllocator per CPU.
static CPU_CACHES: [Mutex<SlabAllocator>; MAX_CPUS] = {
    const INIT: Mutex<SlabAllocator> = Mutex::new(SlabAllocator::new());
    [INIT; MAX_CPUS]
};

pub struct KernelAllocator;

unsafe impl GlobalAlloc for KernelAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let cpu = current_cpu_index();
        CPU_CACHES[cpu].lock().allocate(layout, cpu as u8)
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        let size = layout.size().max(layout.align());

        // Large allocs bypass per-CPU caches — free directly.
        if size > 1024 {
            let cpu = current_cpu_index();
            CPU_CACHES[cpu].lock().deallocate(ptr, layout);
            return;
        }

        // Determine owner CPU from slab header.
        let slab = (ptr as usize & !(PAGE_SIZE - 1)) as *mut SlabHeader;
        let owner = unsafe { (*slab).cpu_owner } as usize;

        // Free to the owner's cache (may be remote).
        CPU_CACHES[owner % MAX_CPUS].lock().deallocate(ptr, layout);
    }
}

#[global_allocator]
static ALLOCATOR: KernelAllocator = KernelAllocator;

pub fn init() {
    use crate::kdebug;
    // Initialize all CPU caches (only CPU 0 is active at this point).
    for cache in CPU_CACHES.iter() {
        cache.lock().init();
    }
    kdebug!(
        "  slab: {} size classes ({}..{}), per-CPU caches ({} CPUs), multi-page for >4096",
        NUM_CLASSES,
        SIZE_CLASSES[0],
        SIZE_CLASSES[NUM_CLASSES - 1],
        MAX_CPUS
    );
}
