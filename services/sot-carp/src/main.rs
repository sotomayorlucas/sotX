//! sot-carp — sotX CARP + pfsync cluster service.
//!
//! **Project PANDORA Task 3** — the shim layer that lets sotX host
//! OpenBSD's carp(4) high-availability + pfsync(4) state replication
//! protocols without porting the in-kernel networking stack. The
//! vendor C sources live under `vendor/openbsd-carp/sys/` and define
//! the wire ABI (carp_header, pfsync_subheader, PFSYNC_ACT_*) that
//! this service mirrors bit-for-bit in its IPC layer, so a future
//! userspace port of `ifconfig carp0 vhid ...` / `pfsyncd` can talk
//! to it directly.
//!
//! ## Model
//!
//! A single process manages up to `MAX_VHIDS` virtual host IDs (VHIDs).
//! Each VHID has zero or more registered peers, each with an advskew
//! (lower = higher priority). At any moment exactly one peer per VHID
//! is MASTER; the rest are BACKUPs. When the MASTER leaves, the lowest-
//! advskew BACKUP is promoted. State-table entries are replicated from
//! MASTER to all BACKUPs via the SOT IPC channel (the stand-in for
//! pfsync's multicast group 224.0.0.240).
//!
//! ## IPC ABI
//!
//! | tag | request                                           | reply                        |
//! |-----|---------------------------------------------------|------------------------------|
//! |  1  | JOIN     vhid(r0) advskew(r1)                      | regs[0]=peer_id              |
//! |  2  | LEAVE    peer_id(r0)                               | regs[0]=0 / -ENOENT          |
//! |  3  | STATE    vhid(r0)                                  | regs[0]=master_peer_id       |
//! |     |                                                   | regs[1]=epoch regs[2]=nbackup|
//! |  4  | TICK                                              | regs[0]=promotions this call |
//! |  5  | INSERT   vhid(r0) src(r1) dst(r2) sport(r3)        | regs[0]=entry_id             |
//! |     |          dport(r4) proto(r5)                       |                              |
//! |  6  | DELETE   entry_id(r0)                              | regs[0]=0 / -ENOENT          |
//! |  7  | LIST     vhid(r0) cursor(r1)                       | regs[0]=next cursor          |
//! |     |                                                   | regs[1..=5]=5-tuple          |
//! |  8  | COUNT    vhid(r0)                                  | regs[0]=entries              |
//! |  9  | PROMOTE  peer_id(r0)                               | regs[0]=0 / -EPERM           |
//! | 10  | STATS                                             | regs[0]=carps_preempt        |
//! |     |                                                   | regs[1]=pfsync_ins           |
//! |     |                                                   | regs[2]=pfsync_del           |

#![no_std]
#![no_main]

use sotos_common::{sys, IpcMsg};

const TAG_JOIN:    u64 = 1;
const TAG_LEAVE:   u64 = 2;
const TAG_STATE:   u64 = 3;
const TAG_TICK:    u64 = 4;
const TAG_INSERT:  u64 = 5;
const TAG_DELETE:  u64 = 6;
const TAG_LIST:    u64 = 7;
const TAG_COUNT:   u64 = 8;
const TAG_PROMOTE: u64 = 9;
const TAG_STATS:   u64 = 10;

const MAX_VHIDS: usize = 8;
const MAX_PEERS: usize = 16;
const MAX_STATES: usize = 64;

/// Mirrors CARP_STATES in vendor/openbsd-carp/sys/netinet/ip_carp.h.
const CARP_INIT:   u8 = 0;
const CARP_BACKUP: u8 = 1;
const CARP_MASTER: u8 = 2;

const SERVICE_NAME: &[u8] = b"sot-carp";

#[derive(Clone, Copy)]
struct Peer {
    in_use: bool,
    vhid: u8,
    advskew: u8,
    state: u8,
}

impl Peer {
    const fn empty() -> Self {
        Self { in_use: false, vhid: 0, advskew: 0, state: CARP_INIT }
    }
}

#[derive(Clone, Copy)]
struct StateEntry {
    in_use: bool,
    vhid: u8,
    src: u32,
    dst: u32,
    sport: u16,
    dport: u16,
    proto: u8,
}

impl StateEntry {
    const fn empty() -> Self {
        Self { in_use: false, vhid: 0, src: 0, dst: 0, sport: 0, dport: 0, proto: 0 }
    }
}

static mut PEERS: [Peer; MAX_PEERS] = [const { Peer::empty() }; MAX_PEERS];
static mut STATES: [StateEntry; MAX_STATES] = [const { StateEntry::empty() }; MAX_STATES];
/// Per-VHID epoch counter: bumps on every master election.
static mut VHID_EPOCH: [u64; MAX_VHIDS] = [0; MAX_VHIDS];
/// Global stats (mirrors the fields sot-carp cares about from carpstats).
static mut CARPS_PREEMPT: u64 = 0;
static mut PFSYNC_INS: u64 = 0;
static mut PFSYNC_DEL: u64 = 0;

fn peers() -> &'static mut [Peer; MAX_PEERS] { unsafe { &mut PEERS } }
fn states() -> &'static mut [StateEntry; MAX_STATES] { unsafe { &mut STATES } }

// ---------------------------------------------------------------------------
// Election core
// ---------------------------------------------------------------------------

/// Find the best (lowest-advskew) in-use peer for `vhid`.
fn best_peer_for(vhid: u8) -> Option<usize> {
    let mut best: Option<usize> = None;
    for (i, p) in peers().iter().enumerate() {
        if p.in_use && p.vhid == vhid {
            match best {
                None => best = Some(i),
                Some(bi) if p.advskew < peers()[bi].advskew => best = Some(i),
                _ => {}
            }
        }
    }
    best
}

/// Run an election round for a single VHID: pick the lowest-advskew peer,
/// make it MASTER, force everyone else to BACKUP. Returns true if the
/// identity of the master changed.
fn elect(vhid: u8) -> bool {
    let new_master = match best_peer_for(vhid) { Some(i) => i, None => return false };
    let mut changed = false;
    for (i, p) in peers().iter_mut().enumerate() {
        if !p.in_use || p.vhid != vhid { continue; }
        let want = if i == new_master { CARP_MASTER } else { CARP_BACKUP };
        if p.state != want {
            if want == CARP_MASTER { changed = true; }
            p.state = want;
        }
    }
    if changed {
        if (vhid as usize) < MAX_VHIDS {
            unsafe { VHID_EPOCH[vhid as usize] += 1; }
        }
        unsafe { CARPS_PREEMPT += 1; }
    }
    changed
}

fn join_peer(vhid: u8, advskew: u8) -> Option<u64> {
    let slot = peers().iter().position(|p| !p.in_use)?;
    peers()[slot] = Peer { in_use: true, vhid, advskew, state: CARP_INIT };
    elect(vhid);
    Some((slot as u64) + 1)
}

fn leave_peer(peer_id: u64) -> bool {
    let idx = match (peer_id as usize).checked_sub(1) {
        Some(i) if i < MAX_PEERS => i,
        _ => return false,
    };
    if !peers()[idx].in_use { return false; }
    let vhid = peers()[idx].vhid;
    peers()[idx] = Peer::empty();
    elect(vhid);
    true
}

fn vhid_state(vhid: u8) -> (u64, u64, u64) {
    let mut master = 0u64;
    let mut backups = 0u64;
    for (i, p) in peers().iter().enumerate() {
        if p.in_use && p.vhid == vhid {
            if p.state == CARP_MASTER { master = (i as u64) + 1; }
            else if p.state == CARP_BACKUP { backups += 1; }
        }
    }
    let epoch = if (vhid as usize) < MAX_VHIDS {
        unsafe { VHID_EPOCH[vhid as usize] }
    } else { 0 };
    (master, epoch, backups)
}

// ---------------------------------------------------------------------------
// pfsync state table
// ---------------------------------------------------------------------------

fn state_insert(vhid: u8, src: u32, dst: u32, sport: u16, dport: u16, proto: u8) -> Option<u64> {
    let slot = states().iter().position(|s| !s.in_use)?;
    states()[slot] = StateEntry {
        in_use: true, vhid, src, dst, sport, dport, proto,
    };
    unsafe { PFSYNC_INS += 1; }
    Some((slot as u64) + 1)
}

fn state_delete(entry_id: u64) -> bool {
    let idx = match (entry_id as usize).checked_sub(1) {
        Some(i) if i < MAX_STATES => i,
        _ => return false,
    };
    if !states()[idx].in_use { return false; }
    states()[idx] = StateEntry::empty();
    unsafe { PFSYNC_DEL += 1; }
    true
}

fn state_count(vhid: u8) -> u64 {
    states().iter().filter(|s| s.in_use && s.vhid == vhid).count() as u64
}

/// Walk the state table starting at `cursor`, return the first entry
/// for `vhid` plus the next cursor (or 0 at end of list).
fn state_list(vhid: u8, cursor: u64) -> Option<(u64, StateEntry)> {
    let start = cursor as usize;
    for i in start..MAX_STATES {
        let s = states()[i];
        if s.in_use && s.vhid == vhid {
            return Some(((i as u64) + 1, s));
        }
    }
    None
}

// ---------------------------------------------------------------------------
// Output helpers
// ---------------------------------------------------------------------------

fn print(s: &[u8]) { for &b in s { sys::debug_print(b); } }

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

fn handle_join(msg: &IpcMsg, reply: &mut IpcMsg) {
    let vhid = msg.regs[0] as u8;
    let advskew = msg.regs[1] as u8;
    match join_peer(vhid, advskew) {
        Some(id) => reply.regs[0] = id,
        None => reply.regs[0] = (-28i64) as u64, // -ENOSPC
    }
}

fn handle_leave(msg: &IpcMsg, reply: &mut IpcMsg) {
    reply.regs[0] = if leave_peer(msg.regs[0]) { 0 } else { (-2i64) as u64 };
}

fn handle_state(msg: &IpcMsg, reply: &mut IpcMsg) {
    let vhid = msg.regs[0] as u8;
    let (master, epoch, backups) = vhid_state(vhid);
    reply.regs[0] = master;
    reply.regs[1] = epoch;
    reply.regs[2] = backups;
}

fn handle_tick(_msg: &IpcMsg, reply: &mut IpcMsg) {
    // A TICK walks every VHID and re-runs the election: this is
    // equivalent to the periodic carp advertisement timer firing.
    let mut promoted = 0u64;
    for vhid in 0..MAX_VHIDS {
        if elect(vhid as u8) { promoted += 1; }
    }
    reply.regs[0] = promoted;
}

fn handle_insert(msg: &IpcMsg, reply: &mut IpcMsg) {
    let vhid = msg.regs[0] as u8;
    let src = msg.regs[1] as u32;
    let dst = msg.regs[2] as u32;
    let sport = msg.regs[3] as u16;
    let dport = msg.regs[4] as u16;
    let proto = msg.regs[5] as u8;
    match state_insert(vhid, src, dst, sport, dport, proto) {
        Some(id) => reply.regs[0] = id,
        None => reply.regs[0] = (-28i64) as u64,
    }
}

fn handle_delete(msg: &IpcMsg, reply: &mut IpcMsg) {
    reply.regs[0] = if state_delete(msg.regs[0]) { 0 } else { (-2i64) as u64 };
}

fn handle_list(msg: &IpcMsg, reply: &mut IpcMsg) {
    let vhid = msg.regs[0] as u8;
    let cursor = msg.regs[1];
    match state_list(vhid, cursor) {
        Some((next, s)) => {
            reply.regs[0] = next;
            reply.regs[1] = s.src as u64;
            reply.regs[2] = s.dst as u64;
            reply.regs[3] = s.sport as u64;
            reply.regs[4] = s.dport as u64;
            reply.regs[5] = s.proto as u64;
        }
        None => reply.regs[0] = 0, // end of list
    }
}

fn handle_count(msg: &IpcMsg, reply: &mut IpcMsg) {
    reply.regs[0] = state_count(msg.regs[0] as u8);
}

fn handle_promote(msg: &IpcMsg, reply: &mut IpcMsg) {
    let peer_id = msg.regs[0];
    let idx = match (peer_id as usize).checked_sub(1) {
        Some(i) if i < MAX_PEERS => i,
        _ => { reply.regs[0] = (-1i64) as u64; return; }
    };
    if !peers()[idx].in_use {
        reply.regs[0] = (-1i64) as u64;
        return;
    }
    // CARP preempt: shrink this peer's advskew to 0 so it wins the
    // next election, then re-run election for its vhid immediately.
    let vhid = peers()[idx].vhid;
    peers()[idx].advskew = 0;
    elect(vhid);
    reply.regs[0] = 0;
}

fn handle_stats(_msg: &IpcMsg, reply: &mut IpcMsg) {
    unsafe {
        reply.regs[0] = CARPS_PREEMPT;
        reply.regs[1] = PFSYNC_INS;
        reply.regs[2] = PFSYNC_DEL;
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    print(b"SOT-CARP: starting (PANDORA T3 -- CARP + pfsync cluster)\n");

    let ep = match sys::endpoint_create() {
        Ok(e) => e,
        Err(_) => {
            print(b"SOT-CARP: endpoint_create failed\n");
            sys::thread_exit();
        }
    };
    if sys::svc_register(SERVICE_NAME.as_ptr() as u64, SERVICE_NAME.len() as u64, ep).is_err() {
        print(b"SOT-CARP: svc_register failed\n");
        sys::thread_exit();
    }
    print(b"SOT-CARP: registered as 'sot-carp', awaiting clients\n");

    loop {
        let msg = match sys::recv(ep) {
            Ok(m) => m,
            Err(_) => { sys::yield_now(); continue; }
        };
        let mut reply = IpcMsg::empty();
        match msg.tag {
            TAG_JOIN    => handle_join(&msg, &mut reply),
            TAG_LEAVE   => handle_leave(&msg, &mut reply),
            TAG_STATE   => handle_state(&msg, &mut reply),
            TAG_TICK    => handle_tick(&msg, &mut reply),
            TAG_INSERT  => handle_insert(&msg, &mut reply),
            TAG_DELETE  => handle_delete(&msg, &mut reply),
            TAG_LIST    => handle_list(&msg, &mut reply),
            TAG_COUNT   => handle_count(&msg, &mut reply),
            TAG_PROMOTE => handle_promote(&msg, &mut reply),
            TAG_STATS   => handle_stats(&msg, &mut reply),
            _ => reply.regs[0] = (-22i64) as u64,
        }
        let _ = sys::send(ep, &reply);
    }
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    print(b"SOT-CARP: PANIC\n");
    loop { sys::yield_now(); }
}
