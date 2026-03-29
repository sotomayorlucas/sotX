//! SOT exokernel syscall handlers.
//!
//! Implements the 11 SOT primitive operations:
//! so_create, so_invoke, so_grant, so_revoke, so_observe,
//! domain_create, domain_enter, channel_create,
//! tx_begin, tx_commit, tx_abort.

use crate::kdebug;
use crate::arch::x86_64::syscall::TrapFrame;
use sotos_common::SysError;

use super::{
    SYS_SO_CREATE, SYS_SO_INVOKE, SYS_SO_GRANT, SYS_SO_REVOKE, SYS_SO_OBSERVE,
    SYS_SOT_DOMAIN_CREATE, SYS_SOT_DOMAIN_ENTER, SYS_SOT_CHANNEL_CREATE,
    SYS_TX_BEGIN, SYS_TX_COMMIT, SYS_TX_ABORT,
};

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
        _ => false,
    }
}

/// SYS_SO_CREATE (300) — create a new SOT object.
/// rdi = type_tag, rsi = initial_data_ptr, rdx = data_len
fn handle_so_create(frame: &mut TrapFrame) {
    kdebug!("so_create: type={} data={:#x} len={}", frame.rdi, frame.rsi, frame.rdx);
    frame.rax = SysError::InvalidArg as i64 as u64;
}

/// SYS_SO_INVOKE (301) — invoke a method on a SOT object.
/// rdi = cap, rsi = method_id, rdx = arg0, rcx = arg1, r8 = arg2, r9 = arg3
fn handle_so_invoke(frame: &mut TrapFrame) {
    kdebug!("so_invoke: cap={} method={} arg0={:#x}", frame.rdi, frame.rsi, frame.rdx);
    frame.rax = SysError::InvalidArg as i64 as u64;
}

/// SYS_SO_GRANT (302) — grant a SOT capability to another domain.
/// rdi = cap, rsi = target_domain, rdx = rights_mask
fn handle_so_grant(frame: &mut TrapFrame) {
    kdebug!("so_grant: cap={} target={} rights={:#x}", frame.rdi, frame.rsi, frame.rdx);
    frame.rax = SysError::InvalidArg as i64 as u64;
}

/// SYS_SO_REVOKE (303) — revoke a SOT capability.
/// rdi = cap
fn handle_so_revoke(frame: &mut TrapFrame) {
    kdebug!("so_revoke: cap={}", frame.rdi);
    frame.rax = SysError::InvalidArg as i64 as u64;
}

/// SYS_SO_OBSERVE (304) — observe a SOT object (read-only inspection).
/// rdi = cap, rsi = query_id, rdx = out_buf_ptr, rcx = out_buf_len
fn handle_so_observe(frame: &mut TrapFrame) {
    kdebug!("so_observe: cap={} query={} buf={:#x}", frame.rdi, frame.rsi, frame.rdx);
    frame.rax = SysError::InvalidArg as i64 as u64;
}

/// SYS_SOT_DOMAIN_CREATE (305) — create a new SOT scheduling/isolation domain.
/// rdi = budget_ticks, rsi = period_ticks
fn handle_domain_create(frame: &mut TrapFrame) {
    kdebug!("sot_domain_create: budget={} period={}", frame.rdi, frame.rsi);
    frame.rax = SysError::InvalidArg as i64 as u64;
}

/// SYS_SOT_DOMAIN_ENTER (306) — enter (switch to) a SOT domain.
/// rdi = domain_cap
fn handle_domain_enter(frame: &mut TrapFrame) {
    kdebug!("sot_domain_enter: cap={}", frame.rdi);
    frame.rax = SysError::InvalidArg as i64 as u64;
}

/// SYS_SOT_CHANNEL_CREATE (307) — create a new SOT typed channel.
/// rdi = type_tag, rsi = buffer_pages
fn handle_channel_create(frame: &mut TrapFrame) {
    kdebug!("sot_channel_create: type={} pages={}", frame.rdi, frame.rsi);
    frame.rax = SysError::InvalidArg as i64 as u64;
}

/// SYS_TX_BEGIN (308) — begin a transaction.
/// rdi = domain_cap (scope)
fn handle_tx_begin(frame: &mut TrapFrame) {
    kdebug!("tx_begin: domain={}", frame.rdi);
    frame.rax = SysError::InvalidArg as i64 as u64;
}

/// SYS_TX_COMMIT (309) — commit current transaction.
/// rdi = tx_handle
fn handle_tx_commit(frame: &mut TrapFrame) {
    kdebug!("tx_commit: tx={}", frame.rdi);
    frame.rax = SysError::InvalidArg as i64 as u64;
}

/// SYS_TX_ABORT (310) — abort current transaction, rollback changes.
/// rdi = tx_handle
fn handle_tx_abort(frame: &mut TrapFrame) {
    kdebug!("tx_abort: tx={}", frame.rdi);
    frame.rax = SysError::InvalidArg as i64 as u64;
}
