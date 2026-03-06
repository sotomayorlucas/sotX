//! Per-core IPC mailbox for cross-core message delivery.
//!
//! Each CPU core has a bounded mailbox queue. When a thread on core A
//! needs to wake a thread on core B (e.g., IPC delivery), it posts a
//! request to core B's mailbox and sends an IPI. Core B's IPI handler
//! drains the mailbox and processes pending wake-ups.
//!
//! This eliminates the need for a global lock on IPC delivery —
//! only the target core's mailbox lock is taken.

use crate::ipc::endpoint::Message;
use crate::sync::ticket::TicketMutex;
use core::sync::atomic::{AtomicU32, Ordering};

use sotos_common::MAX_CPUS;
const MAILBOX_SIZE: usize = 32;

/// A cross-core IPC request deposited into a target core's mailbox.
#[derive(Clone, Copy)]
pub enum IpcRequest {
    /// Wake a thread (identified by raw thread ID).
    WakeThread { tid: u32 },
    /// Deliver a message to a thread's IPC buffer, then wake it.
    DeliverAndWake { tid: u32, msg: Message },
    /// Signal a notification object (by raw handle).
    SignalNotify { handle_raw: u32 },
}

/// Bounded FIFO queue for cross-core IPC requests.
struct Mailbox {
    queue: [Option<IpcRequest>; MAILBOX_SIZE],
    head: usize,
    tail: usize,
    len: usize,
}

impl Mailbox {
    const fn new() -> Self {
        Self {
            queue: [None; MAILBOX_SIZE],
            head: 0,
            tail: 0,
            len: 0,
        }
    }

    fn push(&mut self, req: IpcRequest) -> bool {
        if self.len >= MAILBOX_SIZE {
            return false;
        }
        self.queue[self.tail] = Some(req);
        self.tail = (self.tail + 1) % MAILBOX_SIZE;
        self.len += 1;
        true
    }

    fn pop(&mut self) -> Option<IpcRequest> {
        if self.len == 0 {
            return None;
        }
        let req = self.queue[self.head].take();
        self.head = (self.head + 1) % MAILBOX_SIZE;
        self.len -= 1;
        req
    }
}

/// Per-core mailboxes.
static PER_CORE_MAILBOXES: [TicketMutex<Mailbox>; MAX_CPUS] = {
    const INIT: TicketMutex<Mailbox> = TicketMutex::new(Mailbox::new());
    [INIT; MAX_CPUS]
};

/// Counter of pending requests per core (for fast empty check).
static PENDING_COUNT: [AtomicU32; MAX_CPUS] = {
    const INIT: AtomicU32 = AtomicU32::new(0);
    [INIT; MAX_CPUS]
};

/// Post a request to a target core's mailbox and send an IPI.
pub fn post(target_core: usize, req: IpcRequest) -> bool {
    let core = target_core % MAX_CPUS;
    let mut mbox = PER_CORE_MAILBOXES[core].lock();
    if mbox.push(req) {
        PENDING_COUNT[core].fetch_add(1, Ordering::Release);
        drop(mbox);
        // Send reschedule IPI to target core to drain the mailbox.
        send_ipi_to_core(core);
        true
    } else {
        false
    }
}

/// Drain the current core's mailbox and process all pending requests.
/// Called from the IPI handler or timer interrupt.
pub fn drain_current() {
    let core = current_core();
    if PENDING_COUNT[core].load(Ordering::Acquire) == 0 {
        return;
    }

    let mut mbox = PER_CORE_MAILBOXES[core].lock();
    while let Some(req) = mbox.pop() {
        PENDING_COUNT[core].fetch_sub(1, Ordering::Release);
        process_request(req);
    }
}

/// Process a single mailbox request.
fn process_request(req: IpcRequest) {
    use crate::sched;

    match req {
        IpcRequest::WakeThread { tid } => {
            sched::wake(sched::ThreadId(tid));
        }
        IpcRequest::DeliverAndWake { tid, msg } => {
            sched::write_ipc_msg(sched::ThreadId(tid), msg);
            sched::wake(sched::ThreadId(tid));
        }
        IpcRequest::SignalNotify { handle_raw } => {
            let _ = crate::ipc::notify::signal(crate::pool::PoolHandle::from_raw(handle_raw));
        }
    }
}

/// Get the current CPU core index.
fn current_core() -> usize {
    if crate::mm::slab::is_percpu_ready() {
        crate::arch::x86_64::percpu::current_percpu().cpu_index as usize
    } else {
        0
    }
}

/// Send an IPI (Inter-Processor Interrupt) to a specific core.
/// Uses the LAPIC reschedule vector to trigger mailbox drain.
fn send_ipi_to_core(target_core: usize) {
    // Only send IPI if target is a different core and we're past early boot.
    let my_core = current_core();
    if target_core != my_core && crate::mm::slab::is_percpu_ready() {
        crate::arch::x86_64::lapic::send_ipi(target_core as u32, crate::arch::x86_64::lapic::RESCHEDULE_VECTOR);
    }
}
