//! Per-core synchronous IPC endpoints.
//!
//! Each CPU core maintains its own endpoint pool, eliminating the global
//! TicketMutex bottleneck. Endpoints are created on the current core's
//! pool, and the core ID is encoded in the endpoint handle. Cross-core
//! IPC locks only the target core's pool (no global contention).
//!
//! Handle encoding (32 bits):
//!   bits [31:28] = core ID (4 bits, max 16 cores)
//!   bits [27:20] = generation (8 bits, ABA protection)
//!   bits [19:0]  = slot index (20 bits, max 64 per core)
//!
//! The protocol is synchronous rendezvous: the sender blocks until a
//! receiver is ready (or vice versa), and the message is transferred
//! directly via register state — no intermediate buffer.

use sotos_common::SysError;

use crate::cap;
use crate::pool::PoolHandle;
use crate::sched;
use crate::sync::ticket::TicketMutex;

/// Maximum threads that can be queued waiting to send on one endpoint.
const MAX_SEND_QUEUE: usize = 16;

/// Number of message registers (64-bit words).
pub const MSG_REGS: usize = 8;

/// Bit flag in send queue entries to mark a caller (send+wait-for-reply).
const CALLER_BIT: u32 = 0x8000_0000;

// --- Per-core pool constants ---
use sotos_common::MAX_CPUS;
const MAX_EP_PER_CORE: usize = 64;

/// Handle encoding constants.
const CORE_SHIFT: u32 = 28;
const CORE_MASK: u32 = 0xF;
const GEN_SHIFT: u32 = 20;
const GEN_MASK_8: u32 = 0xFF;
const IDX_MASK: u32 = 0xFFFFF;

/// Endpoint identifier (wraps a PoolHandle for syscall compatibility).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EndpointId(pub PoolHandle);

/// A fixed-size message that fits in registers.
#[derive(Debug, Clone, Copy)]
pub struct Message {
    /// Message tag: identifies the operation/type.
    pub tag: u64,
    /// Payload registers.
    pub regs: [u64; MSG_REGS],
    /// Optional capability to transfer (requires GRANT right on source).
    pub cap_transfer: Option<u32>,
}

impl Message {
    pub const fn empty() -> Self {
        Self {
            tag: 0,
            regs: [0; MSG_REGS],
            cap_transfer: None,
        }
    }
}

/// Thread ID (local alias to avoid circular dep).
type ThreadId = u32;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EndpointState {
    /// No one waiting.
    Idle,
    /// A receiver is waiting for a message.
    RecvWait,
    /// Sender(s) waiting for a receiver.
    SendWait,
}

#[derive(Clone, Copy)]
struct Endpoint {
    state: EndpointState,
    /// Thread currently waiting to receive.
    receiver: Option<ThreadId>,
    /// Queue of threads waiting to send (high bit = CALLER_BIT).
    send_queue: [Option<ThreadId>; MAX_SEND_QUEUE],
    send_queue_len: usize,
    /// Thread that has sent a message and is waiting for a reply (from call()).
    caller: Option<ThreadId>,
    /// Set when cancel_caller clears a caller — the next send() should discard
    /// its reply instead of blocking (the server doesn't know the caller left).
    reply_cancelled: bool,
}

impl Endpoint {
    const fn new() -> Self {
        Self {
            state: EndpointState::Idle,
            receiver: None,
            send_queue: [None; MAX_SEND_QUEUE],
            send_queue_len: 0,
            caller: None,
            reply_cancelled: false,
        }
    }

    fn enqueue_sender(&mut self, tid: ThreadId) -> bool {
        if self.send_queue_len >= MAX_SEND_QUEUE {
            return false;
        }
        self.send_queue[self.send_queue_len] = Some(tid);
        self.send_queue_len += 1;
        true
    }

    fn dequeue_sender(&mut self) -> Option<ThreadId> {
        if self.send_queue_len == 0 {
            return None;
        }
        let tid = self.send_queue[0];
        for i in 1..self.send_queue_len {
            self.send_queue[i - 1] = self.send_queue[i];
        }
        self.send_queue_len -= 1;
        self.send_queue[self.send_queue_len] = None;
        tid
    }
}

// ---------------------------------------------------------------------------
// Per-core endpoint pool (inline fixed-size, no heap dependency)
// ---------------------------------------------------------------------------

struct CoreEndpointPool {
    slots: [Option<Endpoint>; MAX_EP_PER_CORE],
    gens: [u8; MAX_EP_PER_CORE],
    next_scan: usize,
}

impl CoreEndpointPool {
    const fn new() -> Self {
        Self {
            slots: [None; MAX_EP_PER_CORE],
            gens: [0; MAX_EP_PER_CORE],
            next_scan: 0,
        }
    }

    /// Allocate a new endpoint. Returns the full 32-bit handle encoding core ID.
    fn alloc(&mut self, core_id: u32) -> Option<u32> {
        for i in 0..MAX_EP_PER_CORE {
            let idx = (self.next_scan + i) % MAX_EP_PER_CORE;
            if self.slots[idx].is_none() {
                self.slots[idx] = Some(Endpoint::new());
                self.next_scan = idx + 1;
                let gen = self.gens[idx];
                return Some(
                    ((core_id & CORE_MASK) << CORE_SHIFT)
                        | ((gen as u32 & GEN_MASK_8) << GEN_SHIFT)
                        | (idx as u32 & IDX_MASK),
                );
            }
        }
        None
    }

    /// Look up an endpoint by local handle bits (gen + idx).
    fn get_mut(&mut self, local_bits: u32) -> Option<&mut Endpoint> {
        let idx = (local_bits & IDX_MASK) as usize;
        let gen = ((local_bits >> GEN_SHIFT) & GEN_MASK_8) as u8;
        if idx >= MAX_EP_PER_CORE {
            return None;
        }
        if self.gens[idx] != gen {
            return None;
        }
        self.slots[idx].as_mut()
    }

    /// Free an endpoint slot and bump its generation.
    #[allow(dead_code)]
    fn free(&mut self, local_bits: u32) -> bool {
        let idx = (local_bits & IDX_MASK) as usize;
        let gen = ((local_bits >> GEN_SHIFT) & GEN_MASK_8) as u8;
        if idx >= MAX_EP_PER_CORE || self.gens[idx] != gen {
            return false;
        }
        self.slots[idx] = None;
        self.gens[idx] = gen.wrapping_add(1);
        true
    }
}

/// Per-core endpoint pools — each core has its own lock.
static PER_CORE_ENDPOINTS: [TicketMutex<CoreEndpointPool>; MAX_CPUS] = {
    const INIT: TicketMutex<CoreEndpointPool> = TicketMutex::new(CoreEndpointPool::new());
    [INIT; MAX_CPUS]
};

/// Get the current CPU core index (0 during early boot).
fn current_core() -> usize {
    if crate::mm::slab::is_percpu_ready() {
        crate::arch::x86_64::percpu::current_percpu().cpu_index as usize
    } else {
        0
    }
}

/// Decode a 32-bit handle into (core_id, local_bits).
fn decode_handle(raw: u32) -> (usize, u32) {
    let core_id = ((raw >> CORE_SHIFT) & CORE_MASK) as usize;
    let local = raw & !(CORE_MASK << CORE_SHIFT);
    (core_id.min(MAX_CPUS - 1), local)
}

// ---------------------------------------------------------------------------
// Capability transfer
// ---------------------------------------------------------------------------

/// Process capability transfer: if the message carries a cap ID, derive a new cap
/// for the receiver (GRANT right required on source). Replaces the cap_transfer
/// field with the newly created cap ID.
fn process_cap_transfer(msg: &mut Message) {
    if let Some(src_cap_id) = msg.cap_transfer {
        match cap::grant(src_cap_id, cap::Rights::ALL.raw()) {
            Ok(new_cap) => {
                msg.cap_transfer = Some(new_cap.raw());
            }
            Err(_) => {
                msg.cap_transfer = None;
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Create a new endpoint on the current core's pool.
pub fn create() -> Option<EndpointId> {
    let core = current_core();
    let mut pool = PER_CORE_ENDPOINTS[core].lock();
    let raw = pool.alloc(core as u32)?;
    Some(EndpointId(PoolHandle::from_raw(raw)))
}

/// Synchronous send: block until a receiver is ready, transfer message.
///
/// The endpoint's core pool lock is acquired (not a global lock).
/// Cross-core delivery uses the per-core mailbox + IPI for wake.
pub fn send(ep_handle: PoolHandle, msg: Message) -> Result<(), SysError> {
    let my_tid = sched::current_tid().ok_or(SysError::InvalidArg)?;
    let raw = ep_handle.raw();

    // Check for remote routing first.
    if crate::ipc::route::try_remote_send(raw, &msg) {
        return Ok(());
    }

    let (core_id, local) = decode_handle(raw);

    let action = {
        let mut pool = PER_CORE_ENDPOINTS[core_id].lock();
        let ep = pool.get_mut(local).ok_or(SysError::NotFound)?;

        if let Some(caller_tid) = ep.caller.take() {
            SendAction::ReplyToCaller(caller_tid)
        } else if ep.reply_cancelled {
            // The caller timed out and was removed by cancel_caller.
            ep.reply_cancelled = false;
            SendAction::Discard
        } else {
            match ep.state {
                EndpointState::RecvWait => {
                    let recv_tid = ep.receiver.take().unwrap();
                    ep.state = EndpointState::Idle;
                    SendAction::Rendezvous(recv_tid)
                }
                EndpointState::Idle | EndpointState::SendWait => {
                    if !ep.enqueue_sender(my_tid.0) {
                        return Err(SysError::OutOfResources);
                    }
                    ep.state = EndpointState::SendWait;
                    SendAction::Block
                }
            }
        }
    };
    // Core pool lock dropped here.

    let mut msg = msg;
    process_cap_transfer(&mut msg);

    match action {
        SendAction::ReplyToCaller(tid) => {
            #[cfg(feature = "ipc-audit")]
            crate::ipc::audit::record(my_tid.0, tid, raw);
            sched::write_ipc_msg(sched::ThreadId(tid), msg);
            sched::wake(sched::ThreadId(tid));
        }
        SendAction::Rendezvous(tid) => {
            #[cfg(feature = "ipc-audit")]
            crate::ipc::audit::record(my_tid.0, tid, raw);
            sched::write_ipc_msg(sched::ThreadId(tid), msg);
            sched::wake(sched::ThreadId(tid));
        }
        SendAction::Block => {
            sched::set_current_ipc(ep_handle.raw(), sched::IpcRole::Sender, msg);
            sched::block_current();
            sched::clear_current_ipc();
        }
        SendAction::Discard => {
            // Late reply to a cancelled caller — silently drop it.
        }
    }
    Ok(())
}

/// Synchronous receive: block until a sender is ready, receive message.
pub fn recv(ep_handle: PoolHandle) -> Result<Message, SysError> {
    let raw = ep_handle.raw();
    let (core_id, local) = decode_handle(raw);

    let action = {
        let mut pool = PER_CORE_ENDPOINTS[core_id].lock();
        let ep = pool.get_mut(local).ok_or(SysError::NotFound)?;

        match ep.state {
            EndpointState::SendWait => {
                let raw_tid = ep.dequeue_sender().unwrap();
                let is_caller = raw_tid & CALLER_BIT != 0;
                let send_tid = raw_tid & !CALLER_BIT;

                if is_caller {
                    ep.caller = Some(send_tid);
                    if ep.send_queue_len == 0 {
                        ep.state = EndpointState::Idle;
                    }
                    RecvAction::RendezvousCaller(send_tid)
                } else {
                    if ep.send_queue_len == 0 {
                        ep.state = EndpointState::Idle;
                    }
                    RecvAction::Rendezvous(send_tid)
                }
            }
            EndpointState::Idle => {
                let my_tid = sched::current_tid().ok_or(SysError::InvalidArg)?;
                ep.receiver = Some(my_tid.0);
                ep.state = EndpointState::RecvWait;
                RecvAction::Block
            }
            EndpointState::RecvWait => {
                return Err(SysError::OutOfResources);
            }
        }
    };
    // Core pool lock dropped here.

    match action {
        RecvAction::Rendezvous(send_tid) => {
            let msg = sched::read_ipc_msg(sched::ThreadId(send_tid));
            sched::wake(sched::ThreadId(send_tid));
            Ok(msg)
        }
        RecvAction::RendezvousCaller(send_tid) => {
            let msg = sched::read_ipc_msg(sched::ThreadId(send_tid));
            Ok(msg)
        }
        RecvAction::Block => {
            sched::set_current_ipc(ep_handle.raw(), sched::IpcRole::Receiver, Message::empty());
            sched::block_current();
            let msg = sched::current_ipc_msg();
            sched::clear_current_ipc();
            Ok(msg)
        }
    }
}

/// Synchronous receive with timeout: block until a sender is ready or timeout expires.
pub fn recv_timeout(ep_handle: PoolHandle, timeout_ticks: u64) -> Result<Message, SysError> {
    let raw = ep_handle.raw();
    let (core_id, local) = decode_handle(raw);

    let action = {
        let mut pool = PER_CORE_ENDPOINTS[core_id].lock();
        let ep = pool.get_mut(local).ok_or(SysError::NotFound)?;

        match ep.state {
            EndpointState::SendWait => {
                let raw_tid = ep.dequeue_sender().unwrap();
                let is_caller = raw_tid & CALLER_BIT != 0;
                let send_tid = raw_tid & !CALLER_BIT;

                if is_caller {
                    ep.caller = Some(send_tid);
                    if ep.send_queue_len == 0 {
                        ep.state = EndpointState::Idle;
                    }
                    RecvAction::RendezvousCaller(send_tid)
                } else {
                    if ep.send_queue_len == 0 {
                        ep.state = EndpointState::Idle;
                    }
                    RecvAction::Rendezvous(send_tid)
                }
            }
            EndpointState::Idle => {
                let my_tid = sched::current_tid().ok_or(SysError::InvalidArg)?;
                ep.receiver = Some(my_tid.0);
                ep.state = EndpointState::RecvWait;
                RecvAction::Block
            }
            EndpointState::RecvWait => {
                return Err(SysError::OutOfResources);
            }
        }
    };
    // Core pool lock dropped here.

    let deadline = sched::global_ticks() + timeout_ticks;

    match action {
        RecvAction::Rendezvous(send_tid) => {
            let msg = sched::read_ipc_msg(sched::ThreadId(send_tid));
            sched::wake(sched::ThreadId(send_tid));
            Ok(msg)
        }
        RecvAction::RendezvousCaller(send_tid) => {
            let msg = sched::read_ipc_msg(sched::ThreadId(send_tid));
            Ok(msg)
        }
        RecvAction::Block => {
            sched::set_current_ipc(ep_handle.raw(), sched::IpcRole::Receiver, Message::empty());
            sched::set_current_ipc_timeout(deadline);
            sched::block_current();
            if sched::check_and_clear_ipc_timeout() {
                cancel_receiver(raw);
                sched::clear_current_ipc();
                return Err(SysError::Timeout);
            }
            let msg = sched::current_ipc_msg();
            sched::clear_current_ipc();
            Ok(msg)
        }
    }
}

/// Remove a timed-out receiver from an endpoint's state.
fn cancel_receiver(ep_raw: u32) {
    let (core_id, local) = decode_handle(ep_raw);
    let mut pool = PER_CORE_ENDPOINTS[core_id].lock();
    if let Some(ep) = pool.get_mut(local) {
        ep.receiver = None;
        if ep.state == EndpointState::RecvWait {
            ep.state = EndpointState::Idle;
        }
    }
}

/// Synchronous call: send a message, then wait for a reply on the same endpoint.
pub fn call(ep_handle: PoolHandle, msg: Message) -> Result<Message, SysError> {
    let my_tid = sched::current_tid().ok_or(SysError::InvalidArg)?;
    let raw = ep_handle.raw();
    let (core_id, local) = decode_handle(raw);

    let action = {
        let mut pool = PER_CORE_ENDPOINTS[core_id].lock();
        let ep = pool.get_mut(local).ok_or(SysError::NotFound)?;

        match ep.state {
            EndpointState::RecvWait => {
                let recv_tid = ep.receiver.take().unwrap();
                ep.caller = Some(my_tid.0);
                ep.state = EndpointState::Idle;
                CallAction::RendezvousThenWait(recv_tid)
            }
            EndpointState::Idle | EndpointState::SendWait => {
                if !ep.enqueue_sender(my_tid.0 | CALLER_BIT) {
                    return Err(SysError::OutOfResources);
                }
                ep.state = EndpointState::SendWait;
                CallAction::Block
            }
        }
    };
    // Core pool lock dropped here.

    match action {
        CallAction::RendezvousThenWait(recv_tid) => {
            #[cfg(feature = "ipc-audit")]
            crate::ipc::audit::record(my_tid.0, recv_tid, raw);
            let mut msg = msg;
            process_cap_transfer(&mut msg);
            sched::write_ipc_msg(sched::ThreadId(recv_tid), msg);
            sched::wake(sched::ThreadId(recv_tid));
            sched::set_current_ipc(ep_handle.raw(), sched::IpcRole::Caller, Message::empty());
            sched::block_current();
            let reply = sched::current_ipc_msg();
            sched::clear_current_ipc();
            Ok(reply)
        }
        CallAction::Block => {
            let mut msg = msg;
            process_cap_transfer(&mut msg);
            sched::set_current_ipc(ep_handle.raw(), sched::IpcRole::Caller, msg);
            sched::block_current();
            let reply = sched::current_ipc_msg();
            sched::clear_current_ipc();
            Ok(reply)
        }
    }
}

/// Synchronous call with timeout: send a message, wait for reply up to `timeout_ticks`.
/// Returns `Err(SysError::Timeout)` if the reply doesn't arrive in time.
/// `timeout_ticks` is relative (number of ticks from now).
pub fn call_timeout(ep_handle: PoolHandle, msg: Message, timeout_ticks: u64) -> Result<Message, SysError> {
    let my_tid = sched::current_tid().ok_or(SysError::InvalidArg)?;
    let raw = ep_handle.raw();
    let (core_id, local) = decode_handle(raw);

    let action = {
        let mut pool = PER_CORE_ENDPOINTS[core_id].lock();
        let ep = pool.get_mut(local).ok_or(SysError::NotFound)?;

        match ep.state {
            EndpointState::RecvWait => {
                let recv_tid = ep.receiver.take().unwrap();
                ep.caller = Some(my_tid.0);
                ep.state = EndpointState::Idle;
                CallAction::RendezvousThenWait(recv_tid)
            }
            EndpointState::Idle | EndpointState::SendWait => {
                if !ep.enqueue_sender(my_tid.0 | CALLER_BIT) {
                    return Err(SysError::OutOfResources);
                }
                ep.state = EndpointState::SendWait;
                CallAction::Block
            }
        }
    };

    // Set timeout deadline before blocking.
    let deadline = sched::global_ticks() + timeout_ticks;

    match action {
        CallAction::RendezvousThenWait(recv_tid) => {
            let mut msg = msg;
            process_cap_transfer(&mut msg);
            sched::write_ipc_msg(sched::ThreadId(recv_tid), msg);
            sched::wake(sched::ThreadId(recv_tid));
            sched::set_current_ipc(ep_handle.raw(), sched::IpcRole::Caller, Message::empty());
            sched::set_current_ipc_timeout(deadline);
            sched::block_current();
            if sched::check_and_clear_ipc_timeout() {
                cancel_caller(raw, my_tid.0);
                sched::clear_current_ipc();
                return Err(SysError::Timeout);
            }
            let reply = sched::current_ipc_msg();
            sched::clear_current_ipc();
            Ok(reply)
        }
        CallAction::Block => {
            let mut msg = msg;
            process_cap_transfer(&mut msg);
            sched::set_current_ipc(ep_handle.raw(), sched::IpcRole::Caller, msg);
            sched::set_current_ipc_timeout(deadline);
            sched::block_current();
            if sched::check_and_clear_ipc_timeout() {
                cancel_caller(raw, my_tid.0);
                sched::clear_current_ipc();
                return Err(SysError::Timeout);
            }
            let reply = sched::current_ipc_msg();
            sched::clear_current_ipc();
            Ok(reply)
        }
    }
}

/// Remove a timed-out caller from an endpoint's state.
fn cancel_caller(ep_raw: u32, tid: ThreadId) {
    let (core_id, local) = decode_handle(ep_raw);
    let mut pool = PER_CORE_ENDPOINTS[core_id].lock();
    if let Some(ep) = pool.get_mut(local) {
        // Clear from caller slot. Mark reply_cancelled so the server's
        // subsequent send() discards its reply instead of blocking forever.
        if ep.caller == Some(tid) {
            ep.caller = None;
            ep.reply_cancelled = true;
        }
        // Remove from send queue.
        let mut i = 0;
        while i < ep.send_queue_len {
            if let Some(qtid) = ep.send_queue[i] {
                if (qtid & !CALLER_BIT) == tid {
                    for j in (i + 1)..ep.send_queue_len {
                        ep.send_queue[j - 1] = ep.send_queue[j];
                    }
                    ep.send_queue_len -= 1;
                    ep.send_queue[ep.send_queue_len] = None;
                    break;
                }
            }
            i += 1;
        }
        // Fix endpoint state if queue is now empty.
        if ep.send_queue_len == 0 && ep.state == EndpointState::SendWait {
            ep.state = EndpointState::Idle;
        }
    }
}

/// Fused IPC call for the syscall redirect hot path (ρ_fuse + ρ_ooo).
/// Batches lock acquisitions: endpoint pool → per-thread IPC → scheduler.
/// `caller_tid` avoids an extra SCHEDULER.lock() for current_tid().
///
/// Lock profile per syscall (rendezvous path):
///   1× endpoint pool lock, 2× per-thread IPC lock, 1× SCHEDULER.lock()
/// vs. original call(): 1× endpoint + 7× SCHEDULER.lock()
pub fn call_fused(ep_handle: PoolHandle, msg: Message, caller_tid: sched::ThreadId) -> Result<Message, SysError> {
    let raw = ep_handle.raw();

    // Check for remote routing first.
    if crate::ipc::route::try_remote_send(raw, &msg) {
        // Remote route doesn't support call semantics, fall back to regular call.
        return call(ep_handle, msg);
    }

    let (core_id, local) = decode_handle(raw);

    // Process cap transfer before taking any scheduler locks.
    let mut msg = msg;
    process_cap_transfer(&mut msg);

    let action = {
        let mut pool = PER_CORE_ENDPOINTS[core_id].lock();
        let ep = pool.get_mut(local).ok_or(SysError::NotFound)?;

        match ep.state {
            EndpointState::RecvWait => {
                let recv_tid = ep.receiver.take().unwrap();
                ep.caller = Some(caller_tid.0);
                ep.state = EndpointState::Idle;
                CallAction::RendezvousThenWait(recv_tid)
            }
            EndpointState::Idle | EndpointState::SendWait => {
                if !ep.enqueue_sender(caller_tid.0 | CALLER_BIT) {
                    return Err(SysError::OutOfResources);
                }
                ep.state = EndpointState::SendWait;
                CallAction::Block
            }
        }
    };
    // Endpoint pool lock dropped here.

    match action {
        CallAction::RendezvousThenWait(recv_tid) => {
            #[cfg(feature = "ipc-audit")]
            crate::ipc::audit::record(caller_tid.0, recv_tid, raw);
            sched::call_fused_preblock_rendezvous(
                sched::ThreadId(recv_tid), msg, raw,
            );
            Ok(sched::call_fused_postwake())
        }
        CallAction::Block => {
            sched::call_fused_preblock(msg, raw);
            Ok(sched::call_fused_postwake())
        }
    }
}

/// Internal action after inspecting endpoint state in send().
enum SendAction {
    ReplyToCaller(ThreadId),
    Rendezvous(ThreadId),
    Block,
    /// Caller timed out — discard the reply silently.
    Discard,
}

/// Internal action after inspecting endpoint state in recv().
enum RecvAction {
    Rendezvous(ThreadId),
    RendezvousCaller(ThreadId),
    Block,
}

/// Internal action after inspecting endpoint state in call().
enum CallAction {
    RendezvousThenWait(ThreadId),
    Block,
}
