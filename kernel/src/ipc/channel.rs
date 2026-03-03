//! Asynchronous IPC channels — bounded ring buffers.
//!
//! Channels decouple producers and consumers: senders enqueue without
//! blocking (unless full), receivers dequeue without blocking (unless empty).
//! When a thread must block, it is suspended and woken when space/data appears.
//!
//! Lock ordering: CHANNELS → drop → SCHEDULER helpers (same as ENDPOINTS).

use spin::Mutex;
use sotos_common::SysError;

use crate::ipc::endpoint::Message;
use crate::pool::Pool;
use crate::sched::{self, ThreadId};

const CHANNEL_CAPACITY: usize = 16;

/// Channel identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChannelId(pub u32);

struct Channel {
    buffer: [Message; CHANNEL_CAPACITY],
    head: usize,
    tail: usize,
    len: usize,
    waiting_sender: Option<u32>,
    waiting_receiver: Option<u32>,
}

impl Channel {
    fn new() -> Self {
        Self {
            buffer: [Message::empty(); CHANNEL_CAPACITY],
            head: 0,
            tail: 0,
            len: 0,
            waiting_sender: None,
            waiting_receiver: None,
        }
    }

    fn is_full(&self) -> bool {
        self.len == CHANNEL_CAPACITY
    }

    fn is_empty(&self) -> bool {
        self.len == 0
    }

    fn enqueue(&mut self, msg: Message) {
        self.buffer[self.tail] = msg;
        self.tail = (self.tail + 1) % CHANNEL_CAPACITY;
        self.len += 1;
    }

    fn dequeue(&mut self) -> Message {
        let msg = self.buffer[self.head];
        self.head = (self.head + 1) % CHANNEL_CAPACITY;
        self.len -= 1;
        msg
    }
}

static CHANNELS: Mutex<Pool<Channel>> = Mutex::new(Pool::new());

/// Allocate a new channel.
pub fn create() -> Option<ChannelId> {
    let mut chs = CHANNELS.lock();
    let id = chs.alloc(Channel::new());
    Some(ChannelId(id))
}

/// Action decided under CHANNELS lock, executed after drop.
enum SendAction {
    /// Buffer had space, message enqueued. No one to wake.
    Enqueued,
    /// Buffer was empty and a receiver was waiting — deliver directly.
    WakeReceiver(u32, Message),
    /// Buffer full — caller must block.
    Block,
}

/// Send a message on a channel.
pub fn send(ch_id: u32, msg: Message) -> Result<(), SysError> {
    let action = {
        let mut chs = CHANNELS.lock();
        let ch = chs.get_mut(ch_id).ok_or(SysError::NotFound)?;

        if !ch.is_full() {
            if ch.is_empty() {
                if let Some(recv_tid) = ch.waiting_receiver.take() {
                    // Buffer was empty and receiver is waiting — deliver directly.
                    SendAction::WakeReceiver(recv_tid, msg)
                } else {
                    ch.enqueue(msg);
                    SendAction::Enqueued
                }
            } else {
                ch.enqueue(msg);
                SendAction::Enqueued
            }
        } else {
            // Full — store in sender's ipc_msg and block.
            SendAction::Block
        }
    };
    // CHANNELS lock dropped.

    match action {
        SendAction::Enqueued => Ok(()),
        SendAction::WakeReceiver(recv_tid, msg) => {
            sched::write_ipc_msg(ThreadId(recv_tid), msg);
            sched::wake(ThreadId(recv_tid));
            Ok(())
        }
        SendAction::Block => {
            sched::set_current_msg(msg);
            sched::block_current();
            // Woken by recv() which consumed our message from ipc_msg.
            Ok(())
        }
    }
}

/// Action decided under CHANNELS lock, executed after drop.
enum RecvAction {
    /// Got a message from the buffer, no one to wake.
    GotMessage(Message),
    /// Got a message; buffer was full and a sender is waiting.
    GotMessageWakeSender(Message, u32),
    /// Buffer empty — caller must block.
    Block,
}

/// Receive a message from a channel.
pub fn recv(ch_id: u32) -> Result<Message, SysError> {
    let action = {
        let mut chs = CHANNELS.lock();
        let ch = chs.get_mut(ch_id).ok_or(SysError::NotFound)?;

        if !ch.is_empty() {
            let msg = ch.dequeue();
            if let Some(send_tid) = ch.waiting_sender.take() {
                // Was full, sender blocked — need to enqueue sender's msg.
                RecvAction::GotMessageWakeSender(msg, send_tid)
            } else {
                RecvAction::GotMessage(msg)
            }
        } else {
            // Empty — block.
            let my_tid = sched::current_tid().ok_or(SysError::InvalidArg)?;
            ch.waiting_receiver = Some(my_tid.0);
            RecvAction::Block
        }
    };
    // CHANNELS lock dropped.

    match action {
        RecvAction::GotMessage(msg) => Ok(msg),
        RecvAction::GotMessageWakeSender(msg, send_tid) => {
            // Read the blocked sender's message from its ipc_msg.
            let sender_msg = sched::read_ipc_msg(ThreadId(send_tid));
            // Re-acquire CHANNELS to enqueue sender's message.
            {
                let mut chs = CHANNELS.lock();
                if let Some(ch) = chs.get_mut(ch_id) {
                    ch.enqueue(sender_msg);
                }
            }
            // Wake sender (acquires SCHEDULER).
            sched::wake(ThreadId(send_tid));
            Ok(msg)
        }
        RecvAction::Block => {
            sched::block_current();
            // Woken by send() which wrote msg into our ipc_msg.
            let msg = sched::current_ipc_msg();
            Ok(msg)
        }
    }
}

/// Close a channel — free slot, wake any blocked threads.
pub fn close(ch_id: u32) -> Result<(), SysError> {
    let (wake_sender, wake_receiver) = {
        let mut chs = CHANNELS.lock();
        let ch = chs.get_mut(ch_id).ok_or(SysError::NotFound)?;
        let s = ch.waiting_sender.take();
        let r = ch.waiting_receiver.take();
        chs.free(ch_id);
        (s, r)
    };

    if let Some(tid) = wake_sender {
        sched::wake(ThreadId(tid));
    }
    if let Some(tid) = wake_receiver {
        sched::wake(ThreadId(tid));
    }
    Ok(())
}
