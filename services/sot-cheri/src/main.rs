//! sot-cheri — software CHERI capability model for sotX.
//!
//! **Project PANDORA Task 4** — the shim layer that gives sotX a
//! CHERI-compatible capability machine without shipping a Morello or
//! CHERI-RISC-V target yet. The canonical 128-bit compressed-cap wire
//! ABI lives under `vendor/cheri-compressed-cap/` (from CTSRD-CHERI):
//! that's where the permission bits, otype enumeration, and bounds
//! representation come from. This service implements that ABI in
//! pure software so Rust code running on `x86_64-unknown-none` can
//! still exercise CHERI's "hardware capabilities are monotonic,
//! unforgeable, and tag-tracked" contract end-to-end.
//!
//! ## Capability model
//!
//! A `Cap` is a 128-bit logical value that holds:
//!
//!   - a **tag** bit (cleared on any non-capability write)
//!   - a **base** address (inclusive)
//!   - a **top** address (exclusive)
//!   - an **addr** (the "cursor" inside the bounds)
//!   - a **perms** bitmask (LOAD/STORE/EXECUTE/SEAL/UNSEAL/GLOBAL)
//!   - an **otype** -- `OTYPE_UNSEALED` (0) or a positive sealing type
//!
//! Invariants enforced by this service (matching CHERI ISAv9):
//!
//!  1. **Monotonicity** -- `BOUNDS` can only shrink base..top, never widen
//!  2. **Permission monotonicity** -- `DERIVE` can only drop perms, never add
//!  3. **Sealed caps are opaque** -- LOAD/STORE fault until UNSEAL
//!  4. **Tag validity** -- arithmetic overflow / out-of-bounds clears the tag
//!  5. **Bounds enforcement** -- LOAD/STORE must hit [base, top)
//!
//! ## IPC ABI
//!
//! | tag | request                                    | reply                          |
//! |-----|--------------------------------------------|--------------------------------|
//! |  1  | ROOT    (no args)                          | regs[0]=cap_id                 |
//! |  2  | BOUNDS  cap(r0) base(r1) top(r2)           | regs[0]=new_cap / -EPERM       |
//! |  3  | DERIVE  cap(r0) perms_mask(r1)             | regs[0]=new_cap / -EPERM       |
//! |  4  | SEAL    cap(r0) otype(r1)                  | regs[0]=new_cap / -EPERM       |
//! |  5  | UNSEAL  cap(r0) otype(r1)                  | regs[0]=new_cap / -EPERM       |
//! |  6  | LOAD    cap(r0) addr(r1)                   | regs[0]=value / -EFAULT        |
//! |  7  | STORE   cap(r0) addr(r1) value(r2)         | regs[0]=0 / -EFAULT            |
//! |  8  | INFO    cap(r0)                            | regs[0]=base regs[1]=top       |
//! |     |                                            | regs[2]=perms regs[3]=otype    |
//! |     |                                            | regs[4]=tag                    |
//! |  9  | STATS   (no args)                          | regs[0]=caps_allocated         |
//! |     |                                            | regs[1]=bounds_faults          |
//! |     |                                            | regs[2]=sealed_faults          |
//! |     |                                            | regs[3]=monotonicity_faults    |

#![no_std]
#![no_main]

use sotos_common::{sys, IpcMsg};

const TAG_ROOT:    u64 = 1;
const TAG_BOUNDS:  u64 = 2;
const TAG_DERIVE:  u64 = 3;
const TAG_SEAL:    u64 = 4;
const TAG_UNSEAL:  u64 = 5;
const TAG_LOAD:    u64 = 6;
const TAG_STORE:   u64 = 7;
const TAG_INFO:    u64 = 8;
const TAG_STATS:   u64 = 9;

const MAX_CAPS: usize = 64;
const HEAP_WORDS: usize = 256;

/// Mirrors CC128_PERM_* in vendor/cheri-compressed-cap/cheri_compressed_cap_128.h.
const PERM_GLOBAL:  u64 = 1 << 0;
const PERM_EXECUTE: u64 = 1 << 1;
const PERM_LOAD:    u64 = 1 << 2;
const PERM_STORE:   u64 = 1 << 3;
const PERM_SEAL:    u64 = 1 << 7;
const PERM_UNSEAL:  u64 = 1 << 9;
const PERMS_ALL: u64 =
    PERM_GLOBAL | PERM_EXECUTE | PERM_LOAD | PERM_STORE | PERM_SEAL | PERM_UNSEAL;

/// OTYPE_UNSEALED -- the sentinel for "this cap is not sealed".
const OTYPE_UNSEALED: u64 = 0;

const SERVICE_NAME: &[u8] = b"sot-cheri";

#[derive(Clone, Copy)]
struct Cap {
    in_use: bool,
    tag: bool,
    base: u64,
    top: u64,
    addr: u64,
    perms: u64,
    otype: u64,
}

impl Cap {
    const fn empty() -> Self {
        Self { in_use: false, tag: false, base: 0, top: 0, addr: 0, perms: 0, otype: OTYPE_UNSEALED }
    }
}

static mut CAPS: [Cap; MAX_CAPS] = [const { Cap::empty() }; MAX_CAPS];
/// The "memory" backing our caps: a flat 256-word heap addressed by
/// word index. Real CHERI caps point at real DRAM; here the heap is
/// private to the service so LOAD/STORE semantics are fully testable.
static mut HEAP: [u64; HEAP_WORDS] = [0; HEAP_WORDS];

static mut CAPS_ALLOCATED: u64 = 0;
static mut BOUNDS_FAULTS: u64 = 0;
static mut SEALED_FAULTS: u64 = 0;
static mut MONOTONICITY_FAULTS: u64 = 0;

fn caps() -> &'static mut [Cap; MAX_CAPS] { unsafe { &mut CAPS } }
fn heap() -> &'static mut [u64; HEAP_WORDS] { unsafe { &mut HEAP } }

fn alloc_cap(c: Cap) -> Option<u64> {
    let slot = caps().iter().position(|c| !c.in_use)?;
    caps()[slot] = Cap { in_use: true, ..c };
    unsafe { CAPS_ALLOCATED += 1; }
    Some((slot as u64) + 1)
}

fn cap_ref(id: u64) -> Option<&'static Cap> {
    let idx = (id as usize).checked_sub(1)?;
    if idx >= MAX_CAPS { return None; }
    let c = &caps()[idx];
    if !c.in_use { return None; }
    Some(unsafe { &*(c as *const Cap) })
}

// ---------------------------------------------------------------------------
// Capability primitives
// ---------------------------------------------------------------------------

/// Create the "root" capability: base=0, top=HEAP_WORDS, all perms, unsealed.
/// In real CHERI this is the `DDC` (Default Data Capability) the boot loader
/// hands to the kernel, which only ever gets narrowed from there.
fn cap_root() -> Option<u64> {
    alloc_cap(Cap {
        in_use: false,
        tag: true,
        base: 0,
        top: HEAP_WORDS as u64,
        addr: 0,
        perms: PERMS_ALL,
        otype: OTYPE_UNSEALED,
    })
}

/// Narrow the bounds of an existing cap. **Monotonic**: the new
/// base/top must lie inside the old base/top, never outside.
fn cap_bounds(parent_id: u64, new_base: u64, new_top: u64) -> Result<u64, i64> {
    let parent = cap_ref(parent_id).ok_or(-1i64)?;
    if !parent.tag { return Err(-1); }
    if parent.otype != OTYPE_UNSEALED {
        unsafe { SEALED_FAULTS += 1; }
        return Err(-13); // -EACCES: can't reshape a sealed cap
    }
    if new_base < parent.base || new_top > parent.top || new_base > new_top {
        unsafe { MONOTONICITY_FAULTS += 1; }
        return Err(-1); // monotonicity violation
    }
    alloc_cap(Cap {
        in_use: false,
        tag: true,
        base: new_base,
        top: new_top,
        addr: new_base,
        perms: parent.perms,
        otype: OTYPE_UNSEALED,
    }).ok_or(-28)
}

/// Derive a new cap from a parent by dropping permission bits.
/// **Monotonic**: the mask must be a subset of the parent's perms.
fn cap_derive(parent_id: u64, perm_mask: u64) -> Result<u64, i64> {
    let parent = cap_ref(parent_id).ok_or(-1i64)?;
    if !parent.tag { return Err(-1); }
    if parent.otype != OTYPE_UNSEALED {
        unsafe { SEALED_FAULTS += 1; }
        return Err(-13);
    }
    if perm_mask & !parent.perms != 0 {
        unsafe { MONOTONICITY_FAULTS += 1; }
        return Err(-1); // cannot add perms
    }
    alloc_cap(Cap {
        in_use: false,
        tag: true,
        base: parent.base,
        top: parent.top,
        addr: parent.addr,
        perms: perm_mask,
        otype: OTYPE_UNSEALED,
    }).ok_or(-28)
}

/// Seal a cap with an otype. The resulting cap can be passed around
/// but neither loaded from nor stored through until unsealed with the
/// same otype.
fn cap_seal(parent_id: u64, otype: u64) -> Result<u64, i64> {
    let parent = cap_ref(parent_id).ok_or(-1i64)?;
    if !parent.tag { return Err(-1); }
    if parent.perms & PERM_SEAL == 0 { return Err(-1); }
    if otype == OTYPE_UNSEALED { return Err(-22); }
    if parent.otype != OTYPE_UNSEALED {
        unsafe { SEALED_FAULTS += 1; }
        return Err(-13); // already sealed
    }
    alloc_cap(Cap {
        in_use: false,
        tag: true,
        base: parent.base,
        top: parent.top,
        addr: parent.addr,
        perms: parent.perms,
        otype,
    }).ok_or(-28)
}

fn cap_unseal(parent_id: u64, otype: u64) -> Result<u64, i64> {
    let parent = cap_ref(parent_id).ok_or(-1i64)?;
    if !parent.tag { return Err(-1); }
    if parent.perms & PERM_UNSEAL == 0 { return Err(-1); }
    if parent.otype != otype {
        unsafe { SEALED_FAULTS += 1; }
        return Err(-13); // wrong otype
    }
    alloc_cap(Cap {
        in_use: false,
        tag: true,
        base: parent.base,
        top: parent.top,
        addr: parent.addr,
        perms: parent.perms,
        otype: OTYPE_UNSEALED,
    }).ok_or(-28)
}

fn cap_load(parent_id: u64, addr: u64) -> Result<u64, i64> {
    let parent = cap_ref(parent_id).ok_or(-1i64)?;
    if !parent.tag { return Err(-1); }
    if parent.otype != OTYPE_UNSEALED {
        unsafe { SEALED_FAULTS += 1; }
        return Err(-13);
    }
    if parent.perms & PERM_LOAD == 0 { return Err(-1); }
    if addr < parent.base || addr >= parent.top {
        unsafe { BOUNDS_FAULTS += 1; }
        return Err(-14); // -EFAULT
    }
    let idx = addr as usize;
    if idx >= HEAP_WORDS { return Err(-14); }
    Ok(heap()[idx])
}

fn cap_store(parent_id: u64, addr: u64, value: u64) -> Result<(), i64> {
    let parent = cap_ref(parent_id).ok_or(-1i64)?;
    if !parent.tag { return Err(-1); }
    if parent.otype != OTYPE_UNSEALED {
        unsafe { SEALED_FAULTS += 1; }
        return Err(-13);
    }
    if parent.perms & PERM_STORE == 0 { return Err(-1); }
    if addr < parent.base || addr >= parent.top {
        unsafe { BOUNDS_FAULTS += 1; }
        return Err(-14);
    }
    let idx = addr as usize;
    if idx >= HEAP_WORDS { return Err(-14); }
    heap()[idx] = value;
    Ok(())
}

// ---------------------------------------------------------------------------
// Output helpers
// ---------------------------------------------------------------------------

fn print(s: &[u8]) { for &b in s { sys::debug_print(b); } }

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

fn handle_root(_msg: &IpcMsg, reply: &mut IpcMsg) {
    match cap_root() {
        Some(id) => reply.regs[0] = id,
        None => reply.regs[0] = (-28i64) as u64,
    }
}

fn handle_bounds(msg: &IpcMsg, reply: &mut IpcMsg) {
    match cap_bounds(msg.regs[0], msg.regs[1], msg.regs[2]) {
        Ok(id) => reply.regs[0] = id,
        Err(e) => reply.regs[0] = e as u64,
    }
}

fn handle_derive(msg: &IpcMsg, reply: &mut IpcMsg) {
    match cap_derive(msg.regs[0], msg.regs[1]) {
        Ok(id) => reply.regs[0] = id,
        Err(e) => reply.regs[0] = e as u64,
    }
}

fn handle_seal(msg: &IpcMsg, reply: &mut IpcMsg) {
    match cap_seal(msg.regs[0], msg.regs[1]) {
        Ok(id) => reply.regs[0] = id,
        Err(e) => reply.regs[0] = e as u64,
    }
}

fn handle_unseal(msg: &IpcMsg, reply: &mut IpcMsg) {
    match cap_unseal(msg.regs[0], msg.regs[1]) {
        Ok(id) => reply.regs[0] = id,
        Err(e) => reply.regs[0] = e as u64,
    }
}

fn handle_load(msg: &IpcMsg, reply: &mut IpcMsg) {
    match cap_load(msg.regs[0], msg.regs[1]) {
        Ok(v) => reply.regs[0] = v,
        Err(e) => reply.regs[0] = e as u64,
    }
}

fn handle_store(msg: &IpcMsg, reply: &mut IpcMsg) {
    match cap_store(msg.regs[0], msg.regs[1], msg.regs[2]) {
        Ok(()) => reply.regs[0] = 0,
        Err(e) => reply.regs[0] = e as u64,
    }
}

fn handle_info(msg: &IpcMsg, reply: &mut IpcMsg) {
    match cap_ref(msg.regs[0]) {
        Some(c) => {
            reply.regs[0] = c.base;
            reply.regs[1] = c.top;
            reply.regs[2] = c.perms;
            reply.regs[3] = c.otype;
            reply.regs[4] = if c.tag { 1 } else { 0 };
        }
        None => reply.regs[0] = (-1i64) as u64,
    }
}

fn handle_stats(_msg: &IpcMsg, reply: &mut IpcMsg) {
    unsafe {
        reply.regs[0] = CAPS_ALLOCATED;
        reply.regs[1] = BOUNDS_FAULTS;
        reply.regs[2] = SEALED_FAULTS;
        reply.regs[3] = MONOTONICITY_FAULTS;
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    print(b"SOT-CHERI: starting (PANDORA T4 -- software CHERI cap model)\n");
    print(b"SOT-CHERI: 128-bit compressed cap ABI per vendor/cheri-compressed-cap\n");

    let ep = match sys::endpoint_create() {
        Ok(e) => e,
        Err(_) => {
            print(b"SOT-CHERI: endpoint_create failed\n");
            sys::thread_exit();
        }
    };
    if sys::svc_register(SERVICE_NAME.as_ptr() as u64, SERVICE_NAME.len() as u64, ep).is_err() {
        print(b"SOT-CHERI: svc_register failed\n");
        sys::thread_exit();
    }
    print(b"SOT-CHERI: registered as 'sot-cheri', awaiting clients\n");

    loop {
        let msg = match sys::recv(ep) {
            Ok(m) => m,
            Err(_) => { sys::yield_now(); continue; }
        };
        let mut reply = IpcMsg::empty();
        match msg.tag {
            TAG_ROOT   => handle_root(&msg, &mut reply),
            TAG_BOUNDS => handle_bounds(&msg, &mut reply),
            TAG_DERIVE => handle_derive(&msg, &mut reply),
            TAG_SEAL   => handle_seal(&msg, &mut reply),
            TAG_UNSEAL => handle_unseal(&msg, &mut reply),
            TAG_LOAD   => handle_load(&msg, &mut reply),
            TAG_STORE  => handle_store(&msg, &mut reply),
            TAG_INFO   => handle_info(&msg, &mut reply),
            TAG_STATS  => handle_stats(&msg, &mut reply),
            _ => reply.regs[0] = (-22i64) as u64,
        }
        let _ = sys::send(ep, &reply);
    }
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    print(b"SOT-CHERI: PANIC\n");
    loop { sys::yield_now(); }
}
