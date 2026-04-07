//! SOT exokernel syscall handlers.
//!
//! Implements the 11 SOT primitive operations:
//! so_create, so_invoke, so_grant, so_revoke, so_observe,
//! domain_create, domain_enter, channel_create,
//! tx_begin, tx_commit, tx_abort.
//!
//! The key primitive here is `so_invoke` (syscall 301): it detects
//! interposed capabilities and routes invocations through a proxy
//! domain according to the interposition policy.

use crate::kdebug;
use crate::arch::x86_64::syscall::TrapFrame;
use crate::cap::{self, CapId, CapObject, Rights};
use crate::ipc::endpoint::{self, Message};
use crate::pool::PoolHandle;
use crate::sot::cap_epoch::InterpositionPolicy;
use crate::sot::provenance::{self, ProvenanceEntry};
use crate::sot::domain::{self, DomainPolicy};
use crate::sot::tx::{TxId, TxTier, TX_MANAGER};
use sotos_common::SysError;

use super::{
    SYS_SO_CREATE, SYS_SO_INVOKE, SYS_SO_GRANT, SYS_SO_REVOKE, SYS_SO_OBSERVE,
    SYS_SOT_DOMAIN_CREATE, SYS_SOT_DOMAIN_ENTER, SYS_SOT_CHANNEL_CREATE,
    SYS_TX_BEGIN, SYS_TX_COMMIT, SYS_TX_ABORT, SYS_TX_PREPARE,
};

// Provenance operation codes.
const OP_INVOKE_PASSTHROUGH: u16 = 0x10;
const OP_INVOKE_INSPECT: u16 = 0x11;
const OP_INVOKE_REDIRECT: u16 = 0x12;
const OP_INVOKE_FABRICATE: u16 = 0x13;
const OP_INVOKE_DIRECT: u16 = 0x14;
const OP_CREATE: u16 = 0x20;
const OP_GRANT: u16 = 0x30;
const OP_REVOKE: u16 = 0x40;
const OP_TX_COMMIT: u16 = 0x50;
const OP_TX_ABORT: u16 = 0x51;
// Reserved Tier 4 SoType: identifies tx events on the provenance ring.
// Userspace drainers (init's tier4_demo) translate so_id = TxId.
const SOTYPE_TX_EVENT: u8 = 0xF0;

/// IPC message tags for proxy domain communication.
const PROXY_INSPECT_TAG: u64 = 0xDE_C0_0001;
const PROXY_FABRICATE_TAG: u64 = 0xDE_C0_0003;

fn current_cpu() -> usize {
    if crate::mm::slab::is_percpu_ready() {
        crate::arch::x86_64::percpu::current_percpu().cpu_index as usize
    } else {
        0
    }
}

fn record_provenance(domain_id: u32, operation: u16, so_id: u64) {
    record_provenance_typed(domain_id, operation, 0, so_id);
}

fn record_provenance_typed(domain_id: u32, operation: u16, so_type: u8, so_id: u64) {
    let cpu = current_cpu();
    let epoch = cap::current_epoch();
    provenance::record(cpu, ProvenanceEntry {
        epoch,
        domain_id,
        operation,
        so_type,
        _pad: 0,
        so_id,
        version: 0,
        tx_id: 0,
        timestamp: unsafe { core::arch::x86_64::_rdtsc() },
    });
}

/// Write IPC reply registers back into the trap frame.
fn write_reply_to_frame(frame: &mut TrapFrame, reply: &Message) {
    frame.rax = reply.regs[0];
    frame.rdx = reply.regs[1];
    frame.r8  = reply.regs[2];
    frame.r9  = reply.regs[3];
}

/// Resolve a domain's entry endpoint to a raw endpoint id.
/// Returns the raw endpoint handle or writes an error to the frame.
fn resolve_domain_endpoint(frame: &mut TrapFrame, proxy_domain: u32) -> Option<u32> {
    let ep_cap = domain::domain_entry_cap(proxy_domain).ok()?;
    match cap::validate(ep_cap, Rights::READ.or(Rights::WRITE)) {
        Ok(CapObject::Endpoint { id }) => Some(id),
        _ => {
            frame.rax = SysError::InvalidCap as i64 as u64;
            None
        }
    }
}

/// Build args [arg0..arg3] from frame registers used by so_invoke.
fn invoke_args(frame: &TrapFrame) -> [u64; 4] {
    [frame.rdx, frame.rcx, frame.r8, frame.r9]
}

/// Call a proxy domain's endpoint and write the reply to frame.
fn call_proxy(frame: &mut TrapFrame, ep_raw: u32, msg: Message) {
    match endpoint::call(PoolHandle::from_raw(ep_raw), msg) {
        Ok(reply) => write_reply_to_frame(frame, &reply),
        Err(e) => frame.rax = e as i64 as u64,
    }
}

/// Handle SOT syscalls (300-310). Returns true if handled.
pub fn handle(frame: &mut TrapFrame, nr: u64) -> bool {
    match nr {
        SYS_SO_CREATE => { handle_so_create(frame); true }
        SYS_SO_INVOKE => { handle_so_invoke(frame); true }
        SYS_SO_GRANT => { handle_so_grant(frame); true }
        SYS_SO_REVOKE => { handle_so_revoke(frame); true }
        SYS_SO_OBSERVE => { handle_so_observe(frame); true }
        SYS_SOT_DOMAIN_CREATE => { handle_domain_create(frame); true }
        SYS_SOT_DOMAIN_ENTER => { handle_domain_enter(frame); true }
        SYS_SOT_CHANNEL_CREATE => { handle_channel_create(frame); true }
        SYS_TX_BEGIN => { handle_tx_begin(frame); true }
        SYS_TX_COMMIT => { handle_tx_commit(frame); true }
        SYS_TX_ABORT => { handle_tx_abort(frame); true }
        SYS_TX_PREPARE => { handle_tx_prepare(frame); true }
        _ => false,
    }
}

/// SYS_SO_CREATE (300) -- create a new SOT object.
/// rdi = so_type (u8), rsi = policy_bits, rdx = owner_domain
fn handle_so_create(frame: &mut TrapFrame) {
    let so_type = frame.rdi as u8;
    let owner_domain = frame.rdx as u32;

    kdebug!("so_create: type={} policy_bits={:#x} owner={}", so_type, frame.rsi, owner_domain);

    let cap_obj = match so_type {
        // Generic SO types (0,1,3,4,5) collapse to a Memory cap (placeholder).
        // Specific kernel object types map directly: 2=Channel, 6=Endpoint, 8=Notification.
        0 | 1 | 3 | 4 | 5 => CapObject::Memory { base: 0, size: 0 },
        2 => match crate::ipc::channel::create() {
            Some(ch_id) => CapObject::Channel { id: ch_id.0.raw() },
            None => { frame.rax = SysError::OutOfResources as i64 as u64; return; }
        },
        6 => match endpoint::create() {
            Some(ep_id) => CapObject::Endpoint { id: ep_id.0.raw() },
            None => { frame.rax = SysError::OutOfResources as i64 as u64; return; }
        },
        8 => match crate::ipc::notify::create() {
            Some(n_id) => CapObject::Notification { id: n_id.0.raw() },
            None => { frame.rax = SysError::OutOfResources as i64 as u64; return; }
        },
        _ => { frame.rax = SysError::InvalidArg as i64 as u64; return; }
    };

    match cap::insert(cap_obj, Rights::ALL, None) {
        Some(cap_id) => {
            record_provenance(owner_domain, OP_CREATE, cap_id.raw() as u64);
            frame.rax = cap_id.raw() as u64;
        }
        None => frame.rax = SysError::OutOfResources as i64 as u64,
    }
}

/// SYS_SO_INVOKE (301) -- invoke a method on a capability.
///
/// If the cap is interposed, route through the proxy domain according
/// to the interposition policy. Otherwise invoke the cap directly.
///
/// rdi = cap_id, rsi = method_id, rdx = arg0, rcx = arg1, r8 = arg2, r9 = arg3
fn handle_so_invoke(frame: &mut TrapFrame) {
    let cap_id = frame.rdi as u32;
    let method = frame.rsi as u32;

    let (obj, rights) = match cap::lookup(CapId::new(cap_id)) {
        Some(pair) => pair,
        None => { frame.rax = SysError::InvalidCap as i64 as u64; return; }
    };

    if !rights.contains(Rights::READ) {
        frame.rax = SysError::NoRights as i64 as u64;
        return;
    }

    match obj {
        CapObject::Interposed { original, proxy_domain, policy } => {
            match InterpositionPolicy::from_u8(policy) {
                Some(InterpositionPolicy::Passthrough) => {
                    record_provenance(proxy_domain, OP_INVOKE_PASSTHROUGH, original as u64);
                    invoke_original(frame, original, method);
                }
                Some(InterpositionPolicy::Inspect) => {
                    record_provenance(proxy_domain, OP_INVOKE_INSPECT, original as u64);
                    forward_to_proxy(frame, proxy_domain, original, method, PROXY_INSPECT_TAG);
                }
                Some(InterpositionPolicy::Redirect) => {
                    record_provenance(proxy_domain, OP_INVOKE_REDIRECT, original as u64);
                    redirect_to_proxy(frame, proxy_domain, method);
                }
                Some(InterpositionPolicy::Fabricate) => {
                    record_provenance(proxy_domain, OP_INVOKE_FABRICATE, original as u64);
                    forward_to_proxy(frame, proxy_domain, original, method, PROXY_FABRICATE_TAG);
                }
                None => frame.rax = SysError::InvalidArg as i64 as u64,
            }
        }
        _ => {
            record_provenance(0, OP_INVOKE_DIRECT, cap_id as u64);
            invoke_direct(frame, obj, method);
        }
    }
}

/// Invoke the original (unwrapped) capability directly.
fn invoke_original(frame: &mut TrapFrame, original_cap: u32, method: u32) {
    let (obj, _rights) = match cap::lookup(CapId::new(original_cap)) {
        Some(pair) => pair,
        None => { frame.rax = SysError::InvalidCap as i64 as u64; return; }
    };
    invoke_direct(frame, obj, method);
}

/// Direct dispatch by CapObject type.
///
/// For Endpoint/Channel caps, the method ID and args are forwarded as an IPC message.
fn invoke_direct(frame: &mut TrapFrame, obj: CapObject, method: u32) {
    let args = invoke_args(frame);
    match obj {
        CapObject::Endpoint { id } => {
            let msg = Message {
                tag: method as u64,
                regs: [args[0], args[1], args[2], args[3], 0, 0, 0, 0],
                cap_transfer: None,
            };
            call_proxy(frame, id, msg);
        }
        CapObject::Channel { id } => {
            let msg = Message {
                tag: method as u64,
                regs: [args[0], args[1], args[2], args[3], 0, 0, 0, 0],
                cap_transfer: None,
            };
            match crate::ipc::channel::send(PoolHandle::from_raw(id), msg) {
                Ok(()) => frame.rax = 0,
                Err(e) => frame.rax = e as i64 as u64,
            }
        }
        CapObject::Notification { id } => {
            let _ = crate::ipc::notify::signal(PoolHandle::from_raw(id));
            frame.rax = 0;
        }
        CapObject::Memory { base, size } => {
            frame.rax = 0;
            frame.rdx = base;
            frame.r8 = size;
        }
        CapObject::Thread { id } => {
            frame.rax = 0;
            frame.rdx = id as u64;
        }
        _ => frame.rax = 0,
    }
}

/// Forward an invocation to the proxy domain via IPC (used by Inspect and Fabricate).
///
/// The `tag` distinguishes the policy so the proxy knows whether to
/// inspect-and-forward or fabricate a synthetic response.
fn forward_to_proxy(frame: &mut TrapFrame, proxy_domain: u32, original_cap: u32, method: u32, tag: u64) {
    let ep_raw = match resolve_domain_endpoint(frame, proxy_domain) {
        Some(ep) => ep,
        None => {
            // No entry cap: Inspect falls back to direct; Fabricate returns NotFound.
            if tag == PROXY_INSPECT_TAG {
                kdebug!("so_invoke: proxy domain {} has no entry cap, falling back to direct", proxy_domain);
                invoke_original(frame, original_cap, method);
            } else {
                frame.rax = SysError::NotFound as i64 as u64;
            }
            return;
        }
    };

    let args = invoke_args(frame);
    let msg = Message {
        tag,
        regs: [original_cap as u64, method as u64, args[0], args[1], args[2], args[3], 0, 0],
        cap_transfer: None,
    };
    call_proxy(frame, ep_raw, msg);
}

/// Redirect: invoke the method on the proxy domain's endpoint directly,
/// without forwarding the original cap reference.
fn redirect_to_proxy(frame: &mut TrapFrame, proxy_domain: u32, method: u32) {
    let ep_raw = match resolve_domain_endpoint(frame, proxy_domain) {
        Some(ep) => ep,
        None => {
            if frame.rax == 0 { frame.rax = SysError::NotFound as i64 as u64; }
            return;
        }
    };

    let args = invoke_args(frame);
    let msg = Message {
        tag: method as u64,
        regs: [args[0], args[1], args[2], args[3], 0, 0, 0, 0],
        cap_transfer: None,
    };
    call_proxy(frame, ep_raw, msg);
}

/// SYS_SO_GRANT (302) -- grant/interpose a SOT capability.
/// rdi = cap, rsi = target_domain, rdx = rights_mask, rcx = interpose_policy (0xFF = no interpose)
fn handle_so_grant(frame: &mut TrapFrame) {
    let cap_id = frame.rdi as u32;
    let target_domain = frame.rsi as u32;
    let rights_mask = frame.rdx as u32;
    let interpose_policy = frame.rcx as u8;

    kdebug!("so_grant: cap={} target={} rights={:#x} policy={}", cap_id, target_domain, rights_mask, interpose_policy);

    if cap::validate(cap_id, Rights::GRANT).is_err() {
        frame.rax = SysError::NoRights as i64 as u64;
        return;
    }

    let result = if interpose_policy != 0xFF {
        cap::interpose(cap_id, target_domain, interpose_policy)
    } else {
        cap::grant(cap_id, rights_mask)
    };

    match result {
        Ok(new_cap) => {
            record_provenance(target_domain, OP_GRANT, cap_id as u64);
            frame.rax = new_cap.raw() as u64;
        }
        Err(e) => frame.rax = e as i64 as u64,
    }
}

/// SYS_SO_REVOKE (303) -- revoke a SOT capability and all derivatives.
/// rdi = cap
fn handle_so_revoke(frame: &mut TrapFrame) {
    let cap_id = frame.rdi as u32;

    kdebug!("so_revoke: cap={}", cap_id);

    if cap::validate(cap_id, Rights::REVOKE).is_err() {
        frame.rax = SysError::NoRights as i64 as u64;
        return;
    }

    record_provenance(0, OP_REVOKE, cap_id as u64);
    cap::revoke(CapId::new(cap_id));
    frame.rax = 0;
}

/// SYS_SO_OBSERVE (304) -- observe a SOT object (read-only inspection).
/// rdi = cap, rsi = query_id
fn handle_so_observe(frame: &mut TrapFrame) {
    let cap_id = frame.rdi as u32;
    let query_id = frame.rsi as u32;

    kdebug!("so_observe: cap={} query={}", cap_id, query_id);

    let (obj, rights) = match cap::lookup(CapId::new(cap_id)) {
        Some(pair) => pair,
        None => { frame.rax = SysError::InvalidCap as i64 as u64; return; }
    };

    match query_id {
        0 => {
            let type_tag: u64 = match obj {
                CapObject::Memory { .. } => 0,
                CapObject::Endpoint { .. } => 6,
                CapObject::Channel { .. } => 2,
                CapObject::Thread { .. } => 7,
                CapObject::Irq { .. } => 9,
                CapObject::IoPort { .. } => 10,
                CapObject::Notification { .. } => 8,
                CapObject::Domain { .. } => 3,
                CapObject::AddrSpace { .. } => 11,
                CapObject::Interposed { .. } => 5,
                CapObject::Null => 0xFF,
            };
            frame.rax = 0;
            frame.rdx = type_tag;
            frame.r8 = rights.raw() as u64;
            frame.r9 = matches!(obj, CapObject::Interposed { .. }) as u64;
        }
        _ => frame.rax = SysError::InvalidArg as i64 as u64,
    }
}

/// SYS_SOT_DOMAIN_CREATE (305) -- create a new SOT domain.
/// rdi = budget_ticks, rsi = period_ticks, rdx = parent_domain (0 = root)
fn handle_domain_create(frame: &mut TrapFrame) {
    let budget = frame.rdi as u32;
    let period = frame.rsi as u32;
    let parent = if frame.rdx == 0 { None } else { Some(frame.rdx as u32) };

    kdebug!("sot_domain_create: budget={} period={} parent={:?}", budget, period, parent);

    let policy = DomainPolicy {
        quantum_ticks: budget,
        period_ticks: period,
        ..DomainPolicy::default()
    };

    match domain::domain_create(policy, 0, parent) {
        Ok(domain_id) => {
            match cap::insert(CapObject::Domain { id: domain_id }, Rights::ALL, None) {
                Some(cap_id) => {
                    record_provenance(domain_id, OP_CREATE, domain_id as u64);
                    frame.rax = cap_id.raw() as u64;
                }
                None => frame.rax = SysError::OutOfResources as i64 as u64,
            }
        }
        Err(_) => frame.rax = SysError::OutOfResources as i64 as u64,
    }
}

/// SYS_SOT_DOMAIN_ENTER (306) -- enter (switch to) a SOT domain.
/// rdi = domain_cap
fn handle_domain_enter(frame: &mut TrapFrame) {
    let cap_id = frame.rdi as u32;

    kdebug!("sot_domain_enter: cap={}", cap_id);

    match cap::validate(cap_id, Rights::WRITE) {
        Ok(CapObject::Domain { id }) => {
            if domain::domain_lookup(id) {
                frame.rax = 0;
            } else {
                frame.rax = SysError::NotFound as i64 as u64;
            }
        }
        Ok(_) => frame.rax = SysError::InvalidCap as i64 as u64,
        Err(e) => frame.rax = e as i64 as u64,
    }
}

/// SYS_SOT_CHANNEL_CREATE (307) -- create a new SOT typed channel.
/// rdi = type_tag, rsi = buffer_pages
fn handle_channel_create(frame: &mut TrapFrame) {
    kdebug!("sot_channel_create: type={} pages={}", frame.rdi, frame.rsi);

    match crate::ipc::channel::create() {
        Some(ch_id) => {
            match cap::insert(CapObject::Channel { id: ch_id.0.raw() }, Rights::ALL, None) {
                Some(cap_id) => frame.rax = cap_id.raw() as u64,
                None => frame.rax = SysError::OutOfResources as i64 as u64,
            }
        }
        None => frame.rax = SysError::OutOfResources as i64 as u64,
    }
}

/// SYS_TX_BEGIN (308) -- begin a transaction.
/// rdi = domain_cap, rsi = tier (0=ReadOnly, 1=SingleObject)
fn handle_tx_begin(frame: &mut TrapFrame) {
    let domain_cap = frame.rdi as u32;
    let tier_val = frame.rsi as u8;

    kdebug!("tx_begin: domain_cap={} tier={}", domain_cap, tier_val);

    // domain_cap=0 means "root/null domain" — used by simple userspace tests
    // that have not yet created a real domain via SOT_DOMAIN_CREATE.
    let domain_id = if domain_cap == 0 {
        0u32
    } else {
        match cap::validate(domain_cap, Rights::WRITE) {
            Ok(CapObject::Domain { id }) => id,
            Ok(_) => { frame.rax = SysError::InvalidCap as i64 as u64; return; }
            Err(e) => { frame.rax = e as i64 as u64; return; }
        }
    };

    let tier = match tier_val {
        0 => TxTier::ReadOnly,
        1 => TxTier::SingleObject,
        2 => TxTier::MultiObject,
        _ => { frame.rax = SysError::InvalidArg as i64 as u64; return; }
    };

    match TX_MANAGER.lock().tx_begin(domain_id, tier) {
        Ok(tx_id) => frame.rax = tx_id.0,
        Err(_) => frame.rax = SysError::OutOfResources as i64 as u64,
    }
}

/// SYS_TX_COMMIT (309) -- commit current transaction.
/// rdi = tx_handle
fn handle_tx_commit(frame: &mut TrapFrame) {
    kdebug!("tx_commit: tx={}", frame.rdi);

    let tx_id = frame.rdi;
    match TX_MANAGER.lock().tx_commit(TxId(tx_id)) {
        Ok(()) => {
            // Tier 4 hook: emit a provenance event so userspace observers
            // (sot-zfs SnapshotManager, sot-hammer2 Hammer2SnapshotManager)
            // can drive auto-snapshots from a successful commit.
            record_provenance_typed(0, OP_TX_COMMIT, SOTYPE_TX_EVENT, tx_id);
            frame.rax = 0;
        }
        Err(_) => frame.rax = SysError::InvalidArg as i64 as u64,
    }
}

/// SYS_TX_PREPARE (311) -- 2PC prepare phase for MultiObject txns.
/// rdi = tx_handle
fn handle_tx_prepare(frame: &mut TrapFrame) {
    kdebug!("tx_prepare: tx={}", frame.rdi);

    match TX_MANAGER.lock().tx_prepare(TxId(frame.rdi)) {
        Ok(()) => frame.rax = 0,
        Err(_) => frame.rax = SysError::InvalidArg as i64 as u64,
    }
}

/// SYS_TX_ABORT (310) -- abort current transaction, rollback changes.
/// rdi = tx_handle
fn handle_tx_abort(frame: &mut TrapFrame) {
    kdebug!("tx_abort: tx={}", frame.rdi);

    let tx_id = frame.rdi;
    match TX_MANAGER.lock().tx_abort(TxId(tx_id)) {
        Ok(()) => {
            // Tier 4 hook: emit a provenance event so userspace observers
            // can locate the rollback target snapshot via on_tx_abort().
            record_provenance_typed(0, OP_TX_ABORT, SOTYPE_TX_EVENT, tx_id);
            frame.rax = 0;
        }
        Err(_) => frame.rax = SysError::InvalidArg as i64 as u64,
    }
}
