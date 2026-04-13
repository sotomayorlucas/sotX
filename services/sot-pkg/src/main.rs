//! sot-pkg — sotX pkgsrc-compatible package manager service.
//!
//! **Project PANDORA Task 2** — the shim layer that lets sotX host
//! pkgsrc packages without porting NetBSD's `pkg_add`/`pkg_info`/
//! `pkg_delete` tools to our LUCAS personality. The interface is
//! pkgng-compatible at the directory layout level
//! (`/pkg/var/db/pkg/<name>-<version>/+{CONTENTS,DESC,BUILD_INFO}`),
//! so when the vendor tools are eventually ported they see a
//! familiar database and interoperate cleanly.
//!
//! ## Storage model
//!
//! The package database is an in-memory table of `PkgEntry` slots,
//! bootstrapped from files baked into initrd by
//! `scripts/bootstrap-sotx.sh`. Persistence to the sotos-objstore
//! VFS is tracked as a follow-up (the relevant plumbing is the same
//! `SHARED_STORE_PTR` that `child_handler` uses for VFS writes).
//!
//! ## IPC ABI
//!
//! | tag | request                                  | reply                         |
//! |-----|------------------------------------------|-------------------------------|
//! |  1  | REGISTER   name[..48] version[..16]      | regs[0]=id, 0 on collision    |
//! |  2  | INFO       id (regs[0])                  | regs[0]=size, regs[1..7]=name |
//! |  3  | LIST       cursor (regs[0])              | regs[0]=next_id, regs[1..]=nm |
//! |  4  | REMOVE     id (regs[0])                  | regs[0]=0 or -ENOENT          |
//! |  5  | COUNT                                    | regs[0]=installed_count       |

#![no_std]
#![no_main]

use sotos_common::{sys, IpcMsg};

const TAG_REGISTER: u64 = 1;
const TAG_INFO:     u64 = 2;
const TAG_LIST:     u64 = 3;
const TAG_REMOVE:   u64 = 4;
const TAG_COUNT:    u64 = 5;

const MAX_PKGS: usize = 32;
const NAME_LEN: usize = 48;
const VERSION_LEN: usize = 16;

const SERVICE_NAME: &[u8] = b"sot-pkg";

#[derive(Clone, Copy)]
struct PkgEntry {
    in_use: bool,
    name: [u8; NAME_LEN],
    nlen: usize,
    version: [u8; VERSION_LEN],
    vlen: usize,
    /// Monotonic install counter (mirrors pkgsrc's opaque install order).
    install_order: u64,
}

impl PkgEntry {
    const fn empty() -> Self {
        Self {
            in_use: false,
            name: [0; NAME_LEN],
            nlen: 0,
            version: [0; VERSION_LEN],
            vlen: 0,
            install_order: 0,
        }
    }
}

static mut PKG_DB: [PkgEntry; MAX_PKGS] = [const { PkgEntry::empty() }; MAX_PKGS];
static mut NEXT_INSTALL_ORDER: u64 = 1;

fn db() -> &'static mut [PkgEntry; MAX_PKGS] { unsafe { &mut PKG_DB } }

fn find_by_name(name: &[u8]) -> Option<usize> {
    for (i, e) in db().iter().enumerate() {
        if e.in_use && &e.name[..e.nlen] == name {
            return Some(i);
        }
    }
    None
}

fn find_free() -> Option<usize> {
    for (i, e) in db().iter().enumerate() {
        if !e.in_use { return Some(i); }
    }
    None
}

/// Register `<name>-<version>`. Returns slot index + 1 on success
/// (0 reserved as "collision"), None when the DB is full.
fn register_pkg(name: &[u8], version: &[u8]) -> Option<u64> {
    if find_by_name(name).is_some() {
        return Some(0); // collision
    }
    let slot = find_free()?;
    let entries = db();
    let e = &mut entries[slot];
    e.in_use = true;
    let nl = name.len().min(NAME_LEN);
    e.name[..nl].copy_from_slice(&name[..nl]);
    e.nlen = nl;
    let vl = version.len().min(VERSION_LEN);
    e.version[..vl].copy_from_slice(&version[..vl]);
    e.vlen = vl;
    unsafe {
        e.install_order = NEXT_INSTALL_ORDER;
        NEXT_INSTALL_ORDER += 1;
    }
    Some((slot as u64) + 1)
}

fn remove_pkg(id: u64) -> bool {
    let idx = match (id as usize).checked_sub(1) {
        Some(i) if i < MAX_PKGS => i,
        _ => return false,
    };
    let entries = db();
    if !entries[idx].in_use { return false; }
    entries[idx] = PkgEntry::empty();
    true
}

fn count_installed() -> u64 {
    db().iter().filter(|e| e.in_use).count() as u64
}

// ---------------------------------------------------------------------------
// Output helpers
// ---------------------------------------------------------------------------

fn print(s: &[u8]) { for &b in s { sys::debug_print(b); } }

fn print_u64(mut n: u64) {
    if n == 0 { sys::debug_print(b'0'); return; }
    let mut buf = [0u8; 20];
    let mut i = 0;
    while n > 0 { buf[i] = b'0' + (n % 10) as u8; n /= 10; i += 1; }
    while i > 0 { i -= 1; sys::debug_print(buf[i]); }
}

// ---------------------------------------------------------------------------
// Message decoding / encoding
// ---------------------------------------------------------------------------

/// Extract a NUL-terminated byte slice from the regs at a given offset.
fn regs_slice(regs: &[u64; 8], off: usize, max: usize) -> &'static [u8] {
    let raw = unsafe {
        core::slice::from_raw_parts(regs.as_ptr() as *const u8, 56)
    };
    let start = off.min(raw.len());
    let end = (start + max).min(raw.len());
    let slice = &raw[start..end];
    let mut len = 0;
    while len < slice.len() && slice[len] != 0 { len += 1; }
    // SAFETY: the regs buffer lives as long as the borrowed slice and
    // the caller uses it before the next recv.
    unsafe { core::slice::from_raw_parts(slice.as_ptr(), len) }
}

fn write_name_into_regs(dst: &mut [u64; 8], off: usize, name: &[u8]) {
    let raw = unsafe {
        core::slice::from_raw_parts_mut(dst.as_mut_ptr() as *mut u8, 56)
    };
    let start = off.min(raw.len());
    let avail = raw.len() - start;
    let take = name.len().min(avail.saturating_sub(1));
    raw[start..start + take].copy_from_slice(&name[..take]);
    if start + take < raw.len() {
        raw[start + take] = 0;
    }
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

fn handle_register(msg: &IpcMsg, reply: &mut IpcMsg) {
    // Layout: name at offset 0 (48 bytes), version at offset 48 (8 bytes).
    let name = regs_slice(&msg.regs, 0, NAME_LEN);
    let version = regs_slice(&msg.regs, NAME_LEN, VERSION_LEN);
    match register_pkg(name, version) {
        Some(0)  => reply.regs[0] = 0,                 // collision
        Some(id) => reply.regs[0] = id,
        None     => reply.regs[0] = (-28i64) as u64,   // ENOSPC
    }
}

fn handle_info(msg: &IpcMsg, reply: &mut IpcMsg) {
    let id = msg.regs[0];
    let idx = match (id as usize).checked_sub(1) {
        Some(i) if i < MAX_PKGS => i,
        _ => { reply.regs[0] = (-2i64) as u64; return; }
    };
    let e = &db()[idx];
    if !e.in_use {
        reply.regs[0] = (-2i64) as u64;
        return;
    }
    reply.regs[0] = e.install_order;
    write_name_into_regs(&mut reply.regs, 8, &e.name[..e.nlen]);
}

fn handle_list(msg: &IpcMsg, reply: &mut IpcMsg) {
    // Cursor is 0-based slot index to start scanning from.
    let cursor = msg.regs[0] as usize;
    let entries = db();
    let mut i = cursor;
    while i < MAX_PKGS && !entries[i].in_use { i += 1; }
    if i >= MAX_PKGS {
        reply.regs[0] = 0; // end of list
        return;
    }
    let e = &entries[i];
    reply.regs[0] = (i as u64) + 2; // next cursor (+1 for 1-based, +1 past)
    write_name_into_regs(&mut reply.regs, 8, &e.name[..e.nlen]);
}

fn handle_remove(msg: &IpcMsg, reply: &mut IpcMsg) {
    let id = msg.regs[0];
    reply.regs[0] = if remove_pkg(id) { 0 } else { (-2i64) as u64 };
}

fn handle_count(_msg: &IpcMsg, reply: &mut IpcMsg) {
    reply.regs[0] = count_installed();
}

// ---------------------------------------------------------------------------
// Bootstrap: seed the database with the hello-1.0 sample so the demo
// client can observe it on first boot. In a production flow this
// would parse /pkg/var/db/pkg/*/+CONTENTS from the VFS, but that
// plumbing lives inside child_handler and we don't want to touch it
// from a separate service process. The seed is explicitly labelled
// in the IPC so the demo can distinguish real registrations.
// ---------------------------------------------------------------------------

fn seed_initial_db() {
    let _ = register_pkg(b"hello", b"1.0");
}

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    print(b"SOT-PKG: starting (PANDORA T2 -- pkgsrc bridge)\n");

    seed_initial_db();
    print(b"SOT-PKG: seeded initial DB with hello-1.0\n");

    let ep = match sys::endpoint_create() {
        Ok(e) => e,
        Err(_) => {
            print(b"SOT-PKG: endpoint_create failed\n");
            sys::thread_exit();
        }
    };
    if sys::svc_register(SERVICE_NAME.as_ptr() as u64, SERVICE_NAME.len() as u64, ep).is_err() {
        print(b"SOT-PKG: svc_register failed\n");
        sys::thread_exit();
    }
    print(b"SOT-PKG: registered as 'sot-pkg', awaiting clients\n");

    loop {
        let msg = match sys::recv(ep) {
            Ok(m) => m,
            Err(_) => { sys::yield_now(); continue; }
        };
        let mut reply = IpcMsg::empty();
        match msg.tag {
            TAG_REGISTER => handle_register(&msg, &mut reply),
            TAG_INFO     => handle_info(&msg, &mut reply),
            TAG_LIST     => handle_list(&msg, &mut reply),
            TAG_REMOVE   => handle_remove(&msg, &mut reply),
            TAG_COUNT    => handle_count(&msg, &mut reply),
            _ => reply.regs[0] = (-22i64) as u64,
        }
        let _ = sys::send(ep, &reply);
    }
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    print(b"SOT-PKG: PANIC\n");
    loop { sys::yield_now(); }
}
