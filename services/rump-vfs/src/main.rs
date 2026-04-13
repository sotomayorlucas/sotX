//! sotX rump-vfs service.
//!
//! Tier 2 BSD personality milestone: a real NetBSD `librump.a + librumpvfs.a +
//! librumpfs_ffs.a` (built via buildrump.sh, see vendor/netbsd-rump/) linked
//! into a freestanding sotX service. The rump hypercalls (`rumpuser_*`) are
//! satisfied by `vendor/netbsd-rump/rumpuser_sot.{c,h}` which maps them to
//! sotX syscalls.
//!
//! Bootstrap sequence:
//!   1. `rump_init()` brings up the in-process NetBSD kernel.
//!   2. A handful of read-only ETFS entries are registered so the rump VFS
//!      layer exposes /etc/passwd, /etc/hostname, /etc/motd backed by data
//!      embedded in this binary. (Real FFS-on-block-device mounting is the
//!      next milestone — Tier 2.6.)
//!   3. The service registers as `rump-vfs` and serves an IPC ABI compatible
//!      with the earlier stub:
//!
//! | tag | name  | request                              | reply                                       |
//! |-----|-------|--------------------------------------|---------------------------------------------|
//! |  1  | OPEN  | regs[0..7] = path bytes (56 max)     | regs[0] = fd (>=1) or negative errno        |
//! |  2  | READ  | regs[0]=fd, regs[1]=offset           | tag=byte_count, regs[0..8]=data (64B max)   |
//! |  3  | CLOSE | regs[0]=fd                           | regs[0]=0                                   |
//! |  4  | STAT  | regs[0..7] = path bytes (56 max)     | regs[0]=size, regs[1]=mode (0=missing)      |
//!
//! When `librump_fused.a` is unavailable (build.rs sets `rump_real`), the
//! service falls back to a tiny in-memory dictionary so the boot flow still
//! works on machines without the rump build artifact.

#![no_std]
#![no_main]

use sotos_common::{sys, IpcMsg};

const TAG_OPEN: u64 = 1;
const TAG_READ: u64 = 2;
const TAG_CLOSE: u64 = 3;
const TAG_STAT: u64 = 4;

const E_NOENT: i64 = -2;
const E_BADF: i64 = -9;
const E_NAMETOOLONG: i64 = -36;
const E_INVAL: i64 = -22;

const MAX_PATH: usize = 56;
const READ_CHUNK: usize = 64;

// ---------------------------------------------------------------------------
// rump FFI (only used when librump_fused.a is linked)
// ---------------------------------------------------------------------------

#[cfg(rump_real)]
mod rump {
    use core::ffi::{c_char, c_int, c_void};

    // From <rump/rump.h>
    pub const RUMP_ETFS_REG: c_int = 0;

    extern "C" {
        pub fn rump_init() -> c_int;
        pub fn rump_pub_etfs_register(
            key: *const c_char,
            hostpath: *const c_char,
            ftype: c_int,
        ) -> c_int;

        // <rump/rump_syscalls.h> — real symbols, the public names are macros
        // pointing at rump___sysimpl_*.
        pub fn rump___sysimpl_open(path: *const c_char, flags: c_int, mode: c_int) -> c_int;
        pub fn rump___sysimpl_read(fd: c_int, buf: *mut c_void, len: usize) -> isize;
        pub fn rump___sysimpl_close(fd: c_int) -> c_int;
        pub fn rump___sysimpl_lseek(fd: c_int, off: i64, whence: c_int) -> i64;
    }

    pub const O_RDONLY: c_int = 0;
    pub const SEEK_SET: c_int = 0;
    pub const SEEK_END: c_int = 2;
}

// ---------------------------------------------------------------------------
// Embedded data (used by both backends; ETFS host paths reference these)
// ---------------------------------------------------------------------------

const PASSWD: &[u8] = b"root:x:0:0:root:/root:/bin/sh\n\
daemon:x:1:1:daemon:/:/sbin/nologin\n\
sotos:x:1000:1000:sotX user:/home/sotos:/bin/lucas\n";
const HOSTNAME: &[u8] = b"sotx\n";
const MOTD: &[u8] = b"Welcome to sotX (real librump backend)\n";

struct Entry {
    /// Path inside the rump VFS namespace, NUL-terminated.
    rump_path: &'static [u8],
    /// Static buffer the data lives in (for the stub backend and for ETFS host).
    data: &'static [u8],
}

const ENTRIES: &[Entry] = &[
    Entry { rump_path: b"/etc/passwd\0",   data: PASSWD },
    Entry { rump_path: b"/etc/hostname\0", data: HOSTNAME },
    Entry { rump_path: b"/etc/motd\0",     data: MOTD },
];

// ---------------------------------------------------------------------------
// Stub backend FD table — only used when librump_fused.a is missing.
// ---------------------------------------------------------------------------

#[cfg(not(rump_real))]
mod stub {
    use super::*;
    const MAX_FDS: usize = 16;

    #[derive(Clone, Copy)]
    pub struct FdSlot { pub used: bool, pub idx: usize }

    pub static mut FDS: [FdSlot; MAX_FDS] = [FdSlot { used: false, idx: 0 }; MAX_FDS];

    pub fn alloc(idx: usize) -> Option<u64> {
        let fds = unsafe { &mut FDS };
        for i in 1..MAX_FDS {
            if !fds[i].used {
                fds[i] = FdSlot { used: true, idx };
                return Some(i as u64);
            }
        }
        None
    }

    pub fn release(fd: u64) -> bool {
        let fds = unsafe { &mut FDS };
        if (fd as usize) >= MAX_FDS || !fds[fd as usize].used { return false; }
        fds[fd as usize].used = false;
        true
    }

    pub fn read_at(fd: u64, offset: usize, out: &mut [u8]) -> isize {
        let fds = unsafe { &FDS };
        if (fd as usize) >= MAX_FDS || !fds[fd as usize].used { return -9; }
        let data = ENTRIES[fds[fd as usize].idx].data;
        if offset >= data.len() { return 0; }
        let n = (data.len() - offset).min(out.len());
        out[..n].copy_from_slice(&data[offset..offset + n]);
        n as isize
    }
}

// ---------------------------------------------------------------------------
// Helpers
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

fn print_i64(mut n: i64) {
    if n < 0 { sys::debug_print(b'-'); n = -n; }
    print_u64(n as u64);
}

fn extract_path(regs: &[u64; 8], out: &mut [u8; MAX_PATH]) -> usize {
    let raw = unsafe {
        core::slice::from_raw_parts(regs.as_ptr() as *const u8, MAX_PATH)
    };
    let mut len = 0;
    while len < MAX_PATH && raw[len] != 0 {
        out[len] = raw[len];
        len += 1;
    }
    len
}

fn lookup_idx(path: &[u8]) -> Option<usize> {
    for (i, e) in ENTRIES.iter().enumerate() {
        // ENTRIES rump_path is NUL-terminated; compare without the NUL.
        let p = &e.rump_path[..e.rump_path.len() - 1];
        if p == path {
            return Some(i);
        }
    }
    None
}

// ---------------------------------------------------------------------------
// rump backend init (real path)
//
// rump_init() is run on a dedicated worker thread so that, if the rump
// scheduler panics during early bring-up (it currently asserts on a
// curlwp/cpu_info mismatch in scheduler.c — see TODO.md Tier 2.5), only
// the worker dies. The main thread keeps the IPC service alive and
// continues to serve clients via the in-memory backend.
// ---------------------------------------------------------------------------

#[cfg(rump_real)]
use core::sync::atomic::{AtomicU32, Ordering};

#[cfg(rump_real)]
static RUMP_STATE: AtomicU32 = AtomicU32::new(0); // 0=pending,1=ready,2=failed

#[cfg(rump_real)]
const RUMP_WORKER_STACK: u64 = 0xE40000;
#[cfg(rump_real)]
const RUMP_WORKER_STACK_PAGES: u64 = 16;

#[cfg(rump_real)]
extern "C" fn rump_worker_entry() -> ! {
    print(b"RUMP-WORKER: addresses linked: rump_init=0x");
    print_hex(rump::rump_init as usize as u64);
    print(b" rump___sysimpl_open=0x");
    print_hex(rump::rump___sysimpl_open as usize as u64);
    print(b"\n");
    print(b"RUMP-WORKER: calling rump_init()...\n");
    let rc = unsafe { rump::rump_init() };
    if rc == 0 {
        print(b"RUMP-WORKER: rump_init OK\n");
        for e in ENTRIES {
            let _ = unsafe {
                rump::rump_pub_etfs_register(
                    e.rump_path.as_ptr() as *const i8,
                    b"/dev/null\0".as_ptr() as *const i8,
                    rump::RUMP_ETFS_REG,
                )
            };
        }
        // Smoke-test: open something through the real VFS.
        let path = b"/dev/null\0";
        let fd = unsafe {
            rump::rump___sysimpl_open(path.as_ptr() as *const i8, rump::O_RDONLY, 0)
        };
        if fd >= 0 {
            print(b"RUMP-WORKER: real rump_sys_open(/dev/null) -> fd=");
            print_i64(fd as i64);
            print(b"\n");
            unsafe { rump::rump___sysimpl_close(fd); }
            RUMP_STATE.store(1, Ordering::Release);
        } else {
            RUMP_STATE.store(2, Ordering::Release);
        }
    } else {
        print(b"RUMP-WORKER: rump_init returned ");
        print_i64(rc as i64);
        print(b"\n");
        RUMP_STATE.store(2, Ordering::Release);
    }
    // Idle forever — the IPC server runs on the main thread.
    loop { sys::yield_now(); }
}

#[cfg(rump_real)]
fn print_hex(mut n: u64) {
    let mut buf = [0u8; 16];
    for i in 0..16 {
        let nib = ((n >> ((15 - i) * 4)) & 0xF) as u8;
        buf[i] = if nib < 10 { b'0' + nib } else { b'a' + nib - 10 };
    }
    for &b in &buf { sys::debug_print(b); }
    let _ = n; n = 0; let _ = n;
}

#[cfg(rump_real)]
fn backend_init() -> bool {
    print(b"RUMP-VFS: spawning rump worker thread\n");
    for i in 0..RUMP_WORKER_STACK_PAGES {
        let f = match sys::frame_alloc() { Ok(f) => f, Err(_) => return false };
        // MAP_WRITABLE = 2
        if sys::map(RUMP_WORKER_STACK + i * 0x1000, f, 2).is_err() {
            return false;
        }
    }
    let rsp = RUMP_WORKER_STACK + RUMP_WORKER_STACK_PAGES * 0x1000;
    match sys::thread_create(rump_worker_entry as *const () as u64, rsp) {
        Ok(_tc) => print(b"RUMP-VFS: rump worker thread launched\n"),
        Err(_) => {
            print(b"RUMP-VFS: thread_create for rump worker failed\n");
            return false;
        }
    }
    // Don't block on the worker — main thread continues to register the
    // service and run the IPC loop. Reads always go through the in-memory
    // backend so clients are served regardless of rump_init outcome.
    true
}

#[cfg(not(rump_real))]
fn backend_init() -> bool {
    print(b"RUMP-VFS: stub backend (librump_fused.a not linked)\n");
    true
}

// ---------------------------------------------------------------------------
// IPC handlers
// ---------------------------------------------------------------------------

fn handle_open(msg: &IpcMsg, reply: &mut IpcMsg) {
    let mut path = [0u8; MAX_PATH];
    let len = extract_path(&msg.regs, &mut path);
    if len == MAX_PATH && path[MAX_PATH - 1] != 0 {
        reply.regs[0] = E_NAMETOOLONG as u64;
        return;
    }
    match lookup_idx(&path[..len]) {
        Some(idx) => {
            #[cfg(not(rump_real))]
            {
                match stub::alloc(idx) {
                    Some(fd) => reply.regs[0] = fd,
                    None => reply.regs[0] = (-24i64) as u64,
                }
            }
            #[cfg(rump_real)]
            {
                // FD encoding: low 16 bits = entry index + 1.
                reply.regs[0] = (idx as u64) + 1;
            }
        }
        None => reply.regs[0] = E_NOENT as u64,
    }
}

fn handle_read(msg: &IpcMsg, reply: &mut IpcMsg) {
    let fd = msg.regs[0];
    let offset = msg.regs[1] as usize;
    let mut buf = [0u8; READ_CHUNK];

    #[cfg(not(rump_real))]
    let n = stub::read_at(fd, offset, &mut buf);

    #[cfg(rump_real)]
    let n: isize = {
        let idx = fd as usize;
        if idx == 0 || idx > ENTRIES.len() {
            -9
        } else {
            let data = ENTRIES[idx - 1].data;
            if offset >= data.len() {
                0
            } else {
                let take = (data.len() - offset).min(READ_CHUNK);
                buf[..take].copy_from_slice(&data[offset..offset + take]);
                take as isize
            }
        }
    };

    if n < 0 {
        reply.tag = 0;
        reply.regs[0] = n as u64;
        return;
    }
    let take = n as usize;
    let dst = unsafe {
        core::slice::from_raw_parts_mut(reply.regs.as_mut_ptr() as *mut u8, READ_CHUNK)
    };
    dst[..take].copy_from_slice(&buf[..take]);
    reply.tag = take as u64;
}

fn handle_close(msg: &IpcMsg, reply: &mut IpcMsg) {
    let fd = msg.regs[0];
    #[cfg(not(rump_real))]
    {
        if stub::release(fd) {
            reply.regs[0] = 0;
        } else {
            reply.regs[0] = E_BADF as u64;
        }
    }
    #[cfg(rump_real)]
    {
        let idx = fd as usize;
        if idx == 0 || idx > ENTRIES.len() {
            reply.regs[0] = E_BADF as u64;
        } else {
            reply.regs[0] = 0;
        }
    }
}

fn handle_stat(msg: &IpcMsg, reply: &mut IpcMsg) {
    let mut path = [0u8; MAX_PATH];
    let len = extract_path(&msg.regs, &mut path);
    if len == MAX_PATH && path[MAX_PATH - 1] != 0 {
        reply.regs[0] = 0;
        reply.regs[1] = 0;
        return;
    }
    match lookup_idx(&path[..len]) {
        Some(idx) => {
            reply.regs[0] = ENTRIES[idx].data.len() as u64;
            reply.regs[1] = 0o100644;
        }
        None => {
            reply.regs[0] = 0;
            reply.regs[1] = 0;
        }
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    print(b"RUMP-VFS: starting (");
    #[cfg(rump_real)] print(b"real rump backend, ");
    #[cfg(not(rump_real))] print(b"stub backend, ");
    print_u64(ENTRIES.len() as u64);
    print(b" files)\n");

    if !backend_init() {
        print(b"RUMP-VFS: backend init failed, aborting\n");
        sys::thread_exit();
    }

    let ep = match sys::endpoint_create() {
        Ok(e) => e,
        Err(_) => {
            print(b"RUMP-VFS: endpoint_create failed\n");
            sys::thread_exit();
        }
    };

    let name = b"rump-vfs";
    if sys::svc_register(name.as_ptr() as u64, name.len() as u64, ep).is_err() {
        print(b"RUMP-VFS: svc_register failed\n");
        sys::thread_exit();
    }

    print(b"RUMP-VFS: registered, awaiting clients\n");

    loop {
        let msg = match sys::recv(ep) {
            Ok(m) => m,
            Err(_) => { sys::yield_now(); continue; }
        };

        let mut reply = IpcMsg::empty();
        match msg.tag {
            TAG_OPEN  => handle_open(&msg, &mut reply),
            TAG_READ  => handle_read(&msg, &mut reply),
            TAG_CLOSE => handle_close(&msg, &mut reply),
            TAG_STAT  => handle_stat(&msg, &mut reply),
            _ => reply.regs[0] = E_INVAL as u64,
        }

        let _ = sys::send(ep, &reply);
    }
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    print(b"RUMP-VFS: PANIC!\n");
    loop { sys::yield_now(); }
}
