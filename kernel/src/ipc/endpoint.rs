//! Synchronous IPC endpoints.
//!
//! An endpoint is a kernel object through which threads exchange small
//! messages. The protocol is synchronous rendezvous: the sender blocks
//! until a receiver is ready (or vice versa), and the message is
//! transferred directly via register state — no intermediate buffer.
//!
//! This is the "slow path" IPC for control/setup operations.
//! High-throughput data flows use shared-memory channels instead.

use sotos_common::SysError;

use crate::cap;
use crate::pool::{Pool, PoolHandle};
use crate::sched;
use crate::sync::ticket::TicketMutex;

/// Maximum threads that can be queued waiting to send on one endpoint.
const MAX_SEND_QUEUE: usize = 16;

/// Number of message registers (64-bit words).
pub const MSG_REGS: usize = 8;

/// Bit flag in send queue entries to mark a caller (send+wait-for-reply).
const CALLER_BIT: u32 = 0x8000_0000;

/// Endpoint identifier (wraps a generation-checked PoolHandle).
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

struct Endpoint {
    state: EndpointState,
    /// Thread currently waiting to receive.
    receiver: Option<ThreadId>,
    /// Queue of threads waiting to send (high bit = CALLER_BIT).
    send_queue: [Option<ThreadId>; MAX_SEND_QUEUE],
    send_queue_len: usize,
    /// Thread that has sent a message and is waiting for a reply (from call()).
    /// When present, the next send() on this endpoint delivers to the caller
    /// instead of following normal state machine logic.
    caller: Option<ThreadId>,
}

impl Endpoint {
    fn new() -> Self {
        Self {
            state: EndpointState::Idle,
            receiver: None,
            send_queue: [None; MAX_SEND_QUEUE],
            send_queue_len: 0,
            caller: None,
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
        // Shift remaining entries left.
        for i in 1..self.send_queue_len {
            self.send_queue[i - 1] = self.send_queue[i];
        }
        self.send_queue_len -= 1;
        self.send_queue[self.send_queue_len] = None;
        tid
    }
}

static ENDPOINTS: TicketMutex<Pool<Endpoint>> = TicketMutex::new(Pool::new());

/// Process capability transfer: if the message carries a cap ID, derive a new cap
/// for the receiver (GRANT right required on source). Replaces the cap_transfer
/// field with the newly created cap ID.
fn process_cap_transfer(msg: &mut Message) {
    if let Some(src_cap_id) = msg.cap_transfer {
        // Grant with ALL rights — the receiver gets a derived cap.
        match cap::grant(src_cap_id, cap::Rights::ALL.raw()) {
            Ok(new_cap) => {
                msg.cap_transfer = Some(new_cap.raw());
            }
            Err(_) => {
                // Cap transfer failed — clear the field silently.
                msg.cap_transfer = None;
            }
        }
    }
}

/// Create a new endpoint.
pub fn create() -> Option<EndpointId> {
    let mut eps = ENDPOINTS.lock();
    let handle = eps.alloc(Endpoint::new());
    Some(EndpointId(handle))
}

/// Synchronous send: block until a receiver is ready, transfer message.
///
/// Lock ordering: acquire ENDPOINTS, inspect state, drop ENDPOINTS,
/// then call scheduler helpers (which acquire SCHEDULER independently).
pub fn send(ep_handle: PoolHandle, msg: Message) -> Result<(), SysError> {
    let my_tid = sched::current_tid().ok_or(SysError::InvalidArg)?;

    let action = {
        let mut eps = ENDPOINTS.lock();
        let ep = eps.get_mut(ep_handle).ok_or(SysError::NotFound)?;

        // Check for a caller waiting for a reply (takes priority).
        // This is the reply path: the handler sends a reply to a call().
        if let Some(caller_tid) = ep.caller.take() {
            SendAction::ReplyToCaller(caller_tid)
        } else {
            match ep.state {
                EndpointState::RecvWait => {
                    // Rendezvous: receiver already waiting — deliver directly.
                    let recv_tid = ep.receiver.take().unwrap();
                    ep.state = EndpointState::Idle;
                    SendAction::Rendezvous(recv_tid)
                }
                EndpointState::Idle | EndpointState::SendWait => {
                    // No receiver — enqueue self and block.
                    if !ep.enqueue_sender(my_tid.0) {
                        return Err(SysError::OutOfResources);
                    }
                    ep.state = EndpointState::SendWait;
                    SendAction::Block
                }
            }
        }
    };
    // ENDPOINTS lock dropped here.

    match action {
        SendAction::ReplyToCaller(caller_tid) => {
            // Deliver reply to the caller that used call().
            let mut msg = msg;
            process_cap_transfer(&mut msg);
            sched::write_ipc_msg(sched::ThreadId(caller_tid), msg);
            sched::wake(sched::ThreadId(caller_tid));
            Ok(())
        }
        SendAction::Rendezvous(recv_tid) => {
            // Process cap transfer before delivering.
            let mut msg = msg;
            process_cap_transfer(&mut msg);
            // Write our message into the receiver's buffer, then wake it.
            sched::write_ipc_msg(sched::ThreadId(recv_tid), msg);
            sched::wake(sched::ThreadId(recv_tid));
            Ok(())
        }
        SendAction::Block => {
            // Process cap transfer before storing.
            let mut msg = msg;
            process_cap_transfer(&mut msg);
            // Store our message and block.
            sched::set_current_ipc(ep_handle.raw(), sched::IpcRole::Sender, msg);
            sched::block_current();
            // Woken by a receiver that consumed our message.
            sched::clear_current_ipc();
            Ok(())
        }
    }
}

/// Synchronous receive: block until a sender is ready, receive message.
pub fn recv(ep_handle: PoolHandle) -> Result<Message, SysError> {
    let action = {
        let mut eps = ENDPOINTS.lock();
        let ep = eps.get_mut(ep_handle).ok_or(SysError::NotFound)?;

        match ep.state {
            EndpointState::SendWait => {
                // Rendezvous: sender(s) already waiting — take the first.
                let raw_tid = ep.dequeue_sender().unwrap();
                let is_caller = raw_tid & CALLER_BIT != 0;
                let send_tid = raw_tid & !CALLER_BIT;

                if is_caller {
                    // This sender used call() — don't wake it after reading.
                    // Register it as waiting for a reply.
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
                // No sender — register self as receiver and block.
                let my_tid = sched::current_tid().ok_or(SysError::InvalidArg)?;
                ep.receiver = Some(my_tid.0);
                ep.state = EndpointState::RecvWait;
                RecvAction::Block
            }
            EndpointState::RecvWait => {
                // Another receiver already waiting — error.
                return Err(SysError::OutOfResources);
            }
        }
    };
    // ENDPOINTS lock dropped here.

    match action {
        RecvAction::Rendezvous(send_tid) => {
            // Read the sender's message, then wake it.
            let msg = sched::read_ipc_msg(sched::ThreadId(send_tid));
            sched::wake(sched::ThreadId(send_tid));
            Ok(msg)
        }
        RecvAction::RendezvousCaller(send_tid) => {
            // Read the caller's message but DON'T wake it — it stays blocked
            // waiting for the reply (which will be delivered by send()).
            let msg = sched::read_ipc_msg(sched::ThreadId(send_tid));
            Ok(msg)
        }
        RecvAction::Block => {
            // Block — a sender will write to our ipc_msg and wake us.
            sched::set_current_ipc(ep_handle.raw(), sched::IpcRole::Receiver, Message::empty());
            sched::block_current();
            // Woken by a sender that wrote into our buffer.
            let msg = sched::current_ipc_msg();
            sched::clear_current_ipc();
            Ok(msg)
        }
    }
}

/// Synchronous call: send a message, then wait for a reply on the same endpoint.
///
/// Atomic: the caller is registered for the reply in the same lock acquisition
/// as the send, preventing a race where the handler replies before the caller
/// reaches recv().
pub fn call(ep_handle: PoolHandle, msg: Message) -> Result<Message, SysError> {
    let my_tid = sched::current_tid().ok_or(SysError::InvalidArg)?;

    let action = {
        let mut eps = ENDPOINTS.lock();
        let ep = eps.get_mut(ep_handle).ok_or(SysError::NotFound)?;

        match ep.state {
            EndpointState::RecvWait => {
                // Handler is already waiting in recv(). Deliver our message
                // and atomically register ourselves as the caller waiting
                // for a reply.
                let recv_tid = ep.receiver.take().unwrap();
                ep.caller = Some(my_tid.0);
                ep.state = EndpointState::Idle;
                CallAction::RendezvousThenWait(recv_tid)
            }
            EndpointState::Idle | EndpointState::SendWait => {
                // No receiver yet — enqueue with CALLER_BIT so recv() knows
                // to keep us blocked for the reply.
                if !ep.enqueue_sender(my_tid.0 | CALLER_BIT) {
                    return Err(SysError::OutOfResources);
                }
                ep.state = EndpointState::SendWait;
                CallAction::Block
            }
        }
    };
    // ENDPOINTS lock dropped here.

    match action {
        CallAction::RendezvousThenWait(recv_tid) => {
            let mut msg = msg;
            process_cap_transfer(&mut msg);
            // Deliver message to handler and wake it.
            sched::write_ipc_msg(sched::ThreadId(recv_tid), msg);
            sched::wake(sched::ThreadId(recv_tid));
            // Block waiting for the reply. The handler's send() will find
            // ep.caller and deliver directly to us.
            sched::set_current_ipc(ep_handle.raw(), sched::IpcRole::Caller, Message::empty());
            sched::block_current();
            let reply = sched::current_ipc_msg();
            sched::clear_current_ipc();
            Ok(reply)
        }
        CallAction::Block => {
            // Store our message and block. When recv() picks us up from the
            // send queue, it sees CALLER_BIT, reads our message, registers
            // us as ep.caller, and doesn't wake us. The handler's reply
            // send() then delivers to us.
            let mut msg = msg;
            process_cap_transfer(&mut msg);
            sched::set_current_ipc(ep_handle.raw(), sched::IpcRole::Caller, msg);
            sched::block_current();
            // Woken when the reply is delivered to our ipc_msg.
            let reply = sched::current_ipc_msg();
            sched::clear_current_ipc();
            Ok(reply)
        }
    }
}

/// Internal action after inspecting endpoint state in send().
enum SendAction {
    /// Reply to a caller waiting from call().
    ReplyToCaller(ThreadId),
    /// Receiver was waiting — rendezvous immediately.
    Rendezvous(ThreadId),
    /// No receiver — caller must block.
    Block,
}

/// Internal action after inspecting endpoint state in recv().
enum RecvAction {
    /// Sender was waiting — rendezvous immediately.
    Rendezvous(ThreadId),
    /// Caller was waiting — rendezvous but don't wake (stays blocked for reply).
    RendezvousCaller(ThreadId),
    /// No sender — caller must block.
    Block,
}

/// Internal action after inspecting endpoint state in call().
enum CallAction {
    /// Handler was in recv() — deliver and wait for reply.
    RendezvousThenWait(ThreadId),
    /// No handler ready — enqueue and block.
    Block,
}
