//! Synchronous IPC endpoints.
//!
//! An endpoint is a kernel object through which threads exchange small
//! messages. The protocol is synchronous rendezvous: the sender blocks
//! until a receiver is ready (or vice versa), and the message is
//! transferred directly via register state — no intermediate buffer.
//!
//! This is the "slow path" IPC for control/setup operations.
//! High-throughput data flows use shared-memory channels instead.

use spin::Mutex;
use sotos_common::SysError;

use crate::pool::Pool;
use crate::sched;

/// Maximum threads that can be queued waiting to send on one endpoint.
const MAX_SEND_QUEUE: usize = 16;

/// Number of message registers (64-bit words).
pub const MSG_REGS: usize = 8;

/// Endpoint identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EndpointId(pub u32);

/// A fixed-size message that fits in registers.
#[derive(Debug, Clone, Copy)]
pub struct Message {
    /// Message tag: identifies the operation/type.
    pub tag: u64,
    /// Payload registers.
    pub regs: [u64; MSG_REGS],
}

impl Message {
    pub const fn empty() -> Self {
        Self {
            tag: 0,
            regs: [0; MSG_REGS],
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
    /// Queue of threads waiting to send.
    send_queue: [Option<ThreadId>; MAX_SEND_QUEUE],
    send_queue_len: usize,
}

impl Endpoint {
    fn new() -> Self {
        Self {
            state: EndpointState::Idle,
            receiver: None,
            send_queue: [None; MAX_SEND_QUEUE],
            send_queue_len: 0,
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

static ENDPOINTS: Mutex<Pool<Endpoint>> = Mutex::new(Pool::new());

/// Create a new endpoint.
pub fn create() -> Option<EndpointId> {
    let mut eps = ENDPOINTS.lock();
    let id = eps.alloc(Endpoint::new());
    Some(EndpointId(id))
}

/// Synchronous send: block until a receiver is ready, transfer message.
///
/// Lock ordering: acquire ENDPOINTS, inspect state, drop ENDPOINTS,
/// then call scheduler helpers (which acquire SCHEDULER independently).
pub fn send(ep_id: u32, msg: Message) -> Result<(), SysError> {
    let my_tid = sched::current_tid().ok_or(SysError::InvalidArg)?;

    let action = {
        let mut eps = ENDPOINTS.lock();
        let ep = eps.get_mut(ep_id).ok_or(SysError::NotFound)?;

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
    };
    // ENDPOINTS lock dropped here.

    match action {
        SendAction::Rendezvous(recv_tid) => {
            // Write our message into the receiver's buffer, then wake it.
            sched::write_ipc_msg(sched::ThreadId(recv_tid), msg);
            sched::wake(sched::ThreadId(recv_tid));
            Ok(())
        }
        SendAction::Block => {
            // Store our message and block.
            sched::set_current_ipc(ep_id, sched::IpcRole::Sender, msg);
            sched::block_current();
            // Woken by a receiver that consumed our message.
            sched::clear_current_ipc();
            Ok(())
        }
    }
}

/// Synchronous receive: block until a sender is ready, receive message.
pub fn recv(ep_id: u32) -> Result<Message, SysError> {
    let action = {
        let mut eps = ENDPOINTS.lock();
        let ep = eps.get_mut(ep_id).ok_or(SysError::NotFound)?;

        match ep.state {
            EndpointState::SendWait => {
                // Rendezvous: sender(s) already waiting — take the first.
                let send_tid = ep.dequeue_sender().unwrap();
                if ep.send_queue_len == 0 {
                    ep.state = EndpointState::Idle;
                }
                RecvAction::Rendezvous(send_tid)
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
        RecvAction::Block => {
            // Block — a sender will write to our ipc_msg and wake us.
            sched::set_current_ipc(ep_id, sched::IpcRole::Receiver, Message::empty());
            sched::block_current();
            // Woken by a sender that wrote into our buffer.
            let msg = sched::current_ipc_msg();
            sched::clear_current_ipc();
            Ok(msg)
        }
    }
}

/// Synchronous call: send a message, then receive a reply on the same endpoint.
/// Simplified as send() + recv() — non-atomic but correct for the 2-thread test.
/// TODO: atomic caller role transition for multi-threaded scenarios.
pub fn call(ep_id: u32, msg: Message) -> Result<Message, SysError> {
    send(ep_id, msg)?;
    recv(ep_id)
}

/// Internal action after inspecting endpoint state in send().
enum SendAction {
    /// Receiver was waiting — rendezvous immediately.
    Rendezvous(ThreadId),
    /// No receiver — caller must block.
    Block,
}

/// Internal action after inspecting endpoint state in recv().
enum RecvAction {
    /// Sender was waiting — rendezvous immediately.
    Rendezvous(ThreadId),
    /// No sender — caller must block.
    Block,
}
