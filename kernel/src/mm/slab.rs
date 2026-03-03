//! Slab allocator for kernel heap.
//!
//! 8 power-of-2 size classes (8..1024 bytes), each backed by 4 KiB slab pages
//! obtained from the physical frame allocator. Objects > 1024 bytes get a
//! whole page. Objects > 4096 bytes are unsupported (panic).
//!
//! Lock ordering: SLAB → FRAME_ALLOCATOR (slab calls alloc_frame).

use core::alloc::{GlobalAlloc, Layout};
use core::ptr;

use spin::Mutex;

use super::{alloc_frame, free_frame, hhdm_offset};
use super::frame::{PhysFrame, FRAME_SIZE};

const PAGE_SIZE: usize = FRAME_SIZE;
const NUM_CLASSES: usize = 8;
const SIZE_CLASSES: [usize; NUM_CLASSES] = [8, 16, 32, 64, 128, 256, 512, 1024];

#[repr(C)]
struct SlabHeader {
    next: *mut SlabHeader,
    obj_size: u16,
    total: u16,
    used: u16,
    _pad: u16,
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

    fn init_slab(&self, page: *mut u8, obj_size: usize) -> *mut SlabHeader {
        let header = page as *mut SlabHeader;
        let header_size = core::mem::size_of::<SlabHeader>();
        let data_start = (header_size + obj_size - 1) & !(obj_size - 1);
        let count = (PAGE_SIZE - data_start) / obj_size;

        unsafe {
            (*header).next = ptr::null_mut();
            (*header).obj_size = obj_size as u16;
            (*header).total = count as u16;
            (*header).used = 0;
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

    fn allocate(&mut self, layout: Layout) -> *mut u8 {
        if !self.ready {
            return ptr::null_mut();
        }

        let size = layout.size().max(layout.align());

        // Whole-page allocation for large objects
        if size > 1024 {
            assert!(size <= PAGE_SIZE, "slab: allocation > 4096 not supported");
            return self.alloc_page();
        }

        let idx = Self::class_index(size).unwrap();
        let obj_size = self.classes[idx].obj_size;

        // Need a new slab?
        if self.classes[idx].partial.is_null() {
            let page = self.alloc_page();
            let slab = self.init_slab(page, obj_size);
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
            self.free_page(ptr);
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

pub struct KernelAllocator(Mutex<SlabAllocator>);

unsafe impl GlobalAlloc for KernelAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        self.0.lock().allocate(layout)
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        self.0.lock().deallocate(ptr, layout);
    }
}

#[global_allocator]
static ALLOCATOR: KernelAllocator = KernelAllocator(Mutex::new(SlabAllocator::new()));

pub fn init() {
    use crate::kprintln;
    ALLOCATOR.0.lock().init();
    kprintln!("  slab: {} size classes ({}..{}), page alloc for >1024",
        NUM_CLASSES, SIZE_CLASSES[0], SIZE_CLASSES[NUM_CLASSES - 1]);
}
