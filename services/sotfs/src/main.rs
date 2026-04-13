//! # sotFS Native Service for sotX
//!
//! Userspace filesystem server implementing the sotFS type graph engine.
//! Receives VfsOp IPC messages and translates them to DPO graph rewriting
//! rules on an in-memory TypeGraph.
//!
//! Registers as service "sotfs" in the kernel service registry.
//! Other processes access it via `svc_lookup("sotfs")`.

#![no_std]
#![no_main]

extern crate alloc;

mod graph;

use alloc::string::String;
use alloc::vec::Vec;
use sotos_common::sys;
use sotos_common::IpcMsg;

use crate::graph::{SotFsGraph, VfsOp};

fn print(s: &[u8]) {
    for &b in s {
        sys::debug_print(b);
    }
}

fn print_num(mut n: u64) {
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
// Heap allocator (bump allocator on pre-mapped pages)
// ---------------------------------------------------------------------------

const HEAP_BASE: usize = 0xD00000;
const HEAP_SIZE: usize = 256 * 4096; // 1 MiB

#[global_allocator]
static ALLOC: BumpAlloc = BumpAlloc::new(HEAP_BASE, HEAP_SIZE);

struct BumpAlloc {
    base: usize,
    size: usize,
}

impl BumpAlloc {
    const fn new(base: usize, size: usize) -> Self {
        Self { base, size }
    }
}

static BUMP_POS: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);

unsafe impl alloc::alloc::GlobalAlloc for BumpAlloc {
    unsafe fn alloc(&self, layout: core::alloc::Layout) -> *mut u8 {
        let align = layout.align();
        let size = layout.size();
        loop {
            let pos = BUMP_POS.load(core::sync::atomic::Ordering::Relaxed);
            let aligned = (self.base + pos + align - 1) & !(align - 1);
            let new_pos = aligned - self.base + size;
            if new_pos > self.size {
                return core::ptr::null_mut();
            }
            if BUMP_POS
                .compare_exchange_weak(
                    pos,
                    new_pos,
                    core::sync::atomic::Ordering::SeqCst,
                    core::sync::atomic::Ordering::Relaxed,
                )
                .is_ok()
            {
                return aligned as *mut u8;
            }
        }
    }

    unsafe fn dealloc(&self, _ptr: *mut u8, _layout: core::alloc::Layout) {
        // Bump allocator: no deallocation (sufficient for prototype)
    }
}

// ---------------------------------------------------------------------------
// Panic handler
// ---------------------------------------------------------------------------

#[panic_handler]
fn panic(info: &core::panic::PanicInfo) -> ! {
    print(b"sotfs: PANIC\n");
    loop {
        sys::yield_now();
    }
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    print(b"sotfs: service starting\n");

    // Allocate heap pages
    for i in 0..(HEAP_SIZE / 4096) {
        let vaddr = HEAP_BASE + i * 4096;
        if let Ok(frame) = sys::frame_alloc() {
            let _ = sys::map(vaddr as u64, frame, 0x03); // RW
        }
    }

    // Create IPC endpoint
    let ep_cap = match sys::endpoint_create() {
        Ok(c) => c,
        Err(e) => {
            print(b"sotfs: endpoint_create failed\n");
            loop { sys::yield_now(); }
        }
    };

    // Register as "sotfs" service
    let name = b"sotfs";
    match sys::svc_register(name.as_ptr() as u64, name.len() as u64, ep_cap) {
        Ok(()) => print(b"sotfs: registered as 'sotfs'\n"),
        Err(_) => print(b"sotfs: svc_register failed\n"),
    }

    // Initialize the type graph (CREATE-ROOT DPO rule)
    let mut fs = SotFsGraph::new();
    print(b"sotfs: type graph initialized (root inode=1, root dir=1)\n");

    // Enter IPC loop
    ipc_loop(ep_cap, &mut fs);
}

// ---------------------------------------------------------------------------
// IPC dispatch loop — maps VfsOp tags to DPO rules
// ---------------------------------------------------------------------------

fn ipc_loop(ep_cap: u64, fs: &mut SotFsGraph) -> ! {
    loop {
        let req = match sys::recv(ep_cap) {
            Ok(msg) => msg,
            Err(_) => {
                sys::yield_now();
                continue;
            }
        };

        let op = VfsOp::from_tag(req.tag);
        let reply = match op {
            VfsOp::Open => handle_open(fs, &req),
            VfsOp::Close => handle_close(fs, &req),
            VfsOp::Read => handle_read(fs, &req),
            VfsOp::Write => handle_write(fs, &req),
            VfsOp::Stat => handle_stat(fs, &req),
            VfsOp::Readdir => handle_readdir(fs, &req),
            VfsOp::Mkdir => handle_mkdir(fs, &req),
            VfsOp::Rmdir => handle_rmdir(fs, &req),
            VfsOp::Unlink => handle_unlink(fs, &req),
            VfsOp::Rename => handle_rename(fs, &req),
            VfsOp::Fstat => handle_stat(fs, &req),
            VfsOp::Unknown => {
                IpcMsg {
                    tag: (-22i64) as u64, // EINVAL
                    regs: [0; 8],
                }
            }
        };

        let _ = sys::send(ep_cap, &reply);
    }
}

// ---------------------------------------------------------------------------
// VfsOp handlers — each maps to a DPO rule
// ---------------------------------------------------------------------------

/// Open: regs[0]=parent_inode, regs[1]=name_ptr, regs[2]=name_len, regs[3]=flags
fn handle_open(fs: &mut SotFsGraph, req: &IpcMsg) -> IpcMsg {
    let parent_inode = req.regs[0];
    // For now, just acknowledge. Full open requires file handle tracking.
    IpcMsg {
        tag: 0,
        regs: [parent_inode, 0, 0, 0, 0, 0, 0, 0],
    }
}

fn handle_close(_fs: &mut SotFsGraph, _req: &IpcMsg) -> IpcMsg {
    IpcMsg { tag: 0, regs: [0; 8] }
}

/// Read: regs[0]=inode_id, regs[1]=offset, regs[2]=len
fn handle_read(fs: &SotFsGraph, req: &IpcMsg) -> IpcMsg {
    let inode_id = req.regs[0];
    let offset = req.regs[1];
    let len = req.regs[2] as usize;

    match fs.read_data(inode_id, offset, len.min(56)) {
        Some(data) => {
            let mut regs = [0u64; 8];
            regs[0] = data.len() as u64;
            // Pack data bytes into regs[1..7] (up to 56 bytes via IPC)
            let mut buf = [0u8; 56];
            let copy_len = data.len().min(56);
            buf[..copy_len].copy_from_slice(&data[..copy_len]);
            for i in 0..7 {
                regs[i + 1] = u64::from_le_bytes([
                    buf[i * 8],
                    buf[i * 8 + 1],
                    buf[i * 8 + 2],
                    buf[i * 8 + 3],
                    buf[i * 8 + 4],
                    buf[i * 8 + 5],
                    buf[i * 8 + 6],
                    buf[i * 8 + 7],
                ]);
            }
            IpcMsg { tag: copy_len as u64, regs }
        }
        None => IpcMsg {
            tag: (-2i64) as u64, // ENOENT
            regs: [0; 8],
        },
    }
}

/// Write: regs[0]=inode_id, regs[1]=offset, regs[2]=data_len, regs[3..]=data
fn handle_write(fs: &mut SotFsGraph, req: &IpcMsg) -> IpcMsg {
    let inode_id = req.regs[0];
    let offset = req.regs[1];
    let data_len = req.regs[2] as usize;

    // Unpack data from regs[3..7] (up to 40 bytes)
    let mut buf = [0u8; 40];
    for i in 0..5 {
        let bytes = req.regs[i + 3].to_le_bytes();
        buf[i * 8..i * 8 + 8].copy_from_slice(&bytes);
    }
    let write_len = data_len.min(40);

    match fs.write_data(inode_id, offset, &buf[..write_len]) {
        Ok(n) => IpcMsg {
            tag: n as u64,
            regs: [0; 8],
        },
        Err(e) => IpcMsg {
            tag: e as u64,
            regs: [0; 8],
        },
    }
}

/// Stat: regs[0]=inode_id → reply: regs[0]=size, regs[1]=mode, regs[2]=nlink, regs[3]=uid, regs[4]=gid
fn handle_stat(fs: &SotFsGraph, req: &IpcMsg) -> IpcMsg {
    let inode_id = req.regs[0];
    match fs.stat(inode_id) {
        Some((size, mode, nlink, uid, gid)) => IpcMsg {
            tag: 0,
            regs: [size, mode as u64, nlink as u64, uid as u64, gid as u64, 0, 0, 0],
        },
        None => IpcMsg {
            tag: (-2i64) as u64,
            regs: [0; 8],
        },
    }
}

/// Readdir: regs[0]=dir_inode, regs[1]=offset → regs[0]=inode, regs[1..]=name
fn handle_readdir(fs: &SotFsGraph, req: &IpcMsg) -> IpcMsg {
    let dir_inode = req.regs[0];
    let offset = req.regs[1] as usize;

    match fs.readdir(dir_inode, offset) {
        Some((inode_id, name)) => {
            let mut regs = [0u64; 8];
            regs[0] = inode_id;
            // Pack name into regs[1..7]
            let name_bytes = name.as_bytes();
            let mut buf = [0u8; 56];
            let copy_len = name_bytes.len().min(56);
            buf[..copy_len].copy_from_slice(&name_bytes[..copy_len]);
            for i in 0..7 {
                regs[i + 1] = u64::from_le_bytes([
                    buf[i * 8],
                    buf[i * 8 + 1],
                    buf[i * 8 + 2],
                    buf[i * 8 + 3],
                    buf[i * 8 + 4],
                    buf[i * 8 + 5],
                    buf[i * 8 + 6],
                    buf[i * 8 + 7],
                ]);
            }
            IpcMsg { tag: copy_len as u64, regs }
        }
        None => IpcMsg {
            tag: 0, // EOF
            regs: [0; 8],
        },
    }
}

/// Mkdir: regs[0]=parent_inode, regs[1..]=name bytes
fn handle_mkdir(fs: &mut SotFsGraph, req: &IpcMsg) -> IpcMsg {
    let parent_inode = req.regs[0];
    let name = extract_name(&req.regs[1..]);

    match fs.mkdir(parent_inode, &name) {
        Ok(new_inode) => IpcMsg {
            tag: 0,
            regs: [new_inode, 0, 0, 0, 0, 0, 0, 0],
        },
        Err(e) => IpcMsg {
            tag: e as u64,
            regs: [0; 8],
        },
    }
}

/// Rmdir: regs[0]=parent_inode, regs[1..]=name bytes
fn handle_rmdir(fs: &mut SotFsGraph, req: &IpcMsg) -> IpcMsg {
    let parent_inode = req.regs[0];
    let name = extract_name(&req.regs[1..]);

    match fs.rmdir(parent_inode, &name) {
        Ok(()) => IpcMsg { tag: 0, regs: [0; 8] },
        Err(e) => IpcMsg { tag: e as u64, regs: [0; 8] },
    }
}

/// Unlink: regs[0]=parent_inode, regs[1..]=name bytes
fn handle_unlink(fs: &mut SotFsGraph, req: &IpcMsg) -> IpcMsg {
    let parent_inode = req.regs[0];
    let name = extract_name(&req.regs[1..]);

    match fs.unlink(parent_inode, &name) {
        Ok(()) => IpcMsg { tag: 0, regs: [0; 8] },
        Err(e) => IpcMsg { tag: e as u64, regs: [0; 8] },
    }
}

/// Rename: regs[0]=src_parent, regs[1]=dst_parent, regs[2..4]=src_name, regs[5..7]=dst_name
fn handle_rename(fs: &mut SotFsGraph, req: &IpcMsg) -> IpcMsg {
    let src_parent = req.regs[0];
    let dst_parent = req.regs[1];
    let src_name = extract_name(&req.regs[2..5]);
    let dst_name = extract_name(&req.regs[5..8]);

    match fs.rename(src_parent, &src_name, dst_parent, &dst_name) {
        Ok(()) => IpcMsg { tag: 0, regs: [0; 8] },
        Err(e) => IpcMsg { tag: e as u64, regs: [0; 8] },
    }
}

/// Extract a null-terminated string from IPC register data.
fn extract_name(regs: &[u64]) -> String {
    let mut buf = Vec::new();
    for &r in regs {
        let bytes = r.to_le_bytes();
        for &b in &bytes {
            if b == 0 {
                return String::from_utf8_lossy(&buf).into_owned();
            }
            buf.push(b);
        }
    }
    String::from_utf8_lossy(&buf).into_owned()
}
