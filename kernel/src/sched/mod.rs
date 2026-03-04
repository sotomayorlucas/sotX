//! Scheduler — Preemptive Round-Robin with Per-Core Run Queues.
//!
//! **Level 1 (kernel)**: Preemptive round-robin with per-core queues and
//! work stealing. Each CPU has its own run queue (FIFO, ticket-locked).
//! When a CPU's queue is empty it steals from other CPUs (round-robin victim
//! selection, steal oldest for cache warmth on the stealer).
//!
//! **Level 2 (userspace)**: Scheduling Domains (future).
//!
//! Per-CPU state (current thread index) lives in `PerCpu` accessed via GS base.
//! The global `Scheduler` holds the thread pool; run queues are per-CPU.

pub mod domain;
pub mod thread;

pub use thread::{IpcRole, ThreadId, ThreadState};
use thread::Thread;

use alloc::collections::VecDeque;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};
use crate::arch::x86_64::percpu;
use crate::ipc::endpoint::Message;
use crate::pool::{Pool, PoolHandle};
use crate::sync::ticket::TicketMutex;

use crate::kprintln;
use domain::{DomainState, SchedDomain};
use spin::Mutex;
use x86_64::VirtAddr;

/// Global tick counter — incremented unconditionally on every timer tick.
/// Used as the clock source for domain period refills.
static GLOBAL_TICKS: AtomicU64 = AtomicU64::new(0);

/// Timeslice in ticks (100 ms at 100 Hz).
const TIMESLICE: u32 = 10;

// ---------------------------------------------------------------------------
// Context switch — assembly trampoline
// ---------------------------------------------------------------------------

extern "C" {
    /// Switch CPU context from the current thread to a new thread.
    ///
    /// Saves callee-saved registers on the current stack, stores RSP into
    /// `*old_rsp_ptr`, loads RSP from `new_rsp`, restores callee-saved regs,
    /// and returns (into the new thread's continuation point).
    fn context_switch(old_rsp_ptr: *mut u64, new_rsp: u64);
}

core::arch::global_asm!(
    ".global context_switch",
    "context_switch:",
    "    push rbp",
    "    push rbx",
    "    push r12",
    "    push r13",
    "    push r14",
    "    push r15",
    "    mov [rdi], rsp",    // save old RSP
    "    mov rsp, rsi",      // load new RSP
    "    pop r15",
    "    pop r14",
    "    pop r13",
    "    pop r12",
    "    pop rbx",
    "    pop rbp",
    "    ret",
);

// ---------------------------------------------------------------------------
// Thread trampolines — call finish_switch() before entering thread code
// ---------------------------------------------------------------------------

/// Trampoline for kernel threads. Called after context_switch pops regs.
/// r12 = entry function pointer.
#[unsafe(naked)]
unsafe extern "C" fn thread_trampoline() -> ! {
    core::arch::naked_asm!(
        "mov rdi, r12",             // pass entry fn as arg
        "jmp {finish_kernel}",
        finish_kernel = sym finish_switch_and_enter_kernel,
    );
}

/// Trampoline for user threads. Called after context_switch pops regs.
/// r12 = user RIP, r13 = user RSP, r14 = CR3.
#[unsafe(naked)]
unsafe extern "C" fn user_thread_trampoline() -> ! {
    core::arch::naked_asm!(
        "mov rdi, r12",             // user RIP
        "mov rsi, r13",             // user RSP
        "mov rdx, r14",             // CR3
        "jmp {finish_user}",
        finish_user = sym finish_switch_and_enter_user,
    );
}

/// Post-switch handler for kernel threads: finish_switch, then sti + call entry.
extern "C" fn finish_switch_and_enter_kernel(entry: u64) -> ! {
    let entry: fn() -> ! = unsafe { core::mem::transmute(entry) };
    finish_switch();
    unsafe { core::arch::asm!("sti", options(nomem, nostack)); }
    entry()
}

/// Post-switch handler for user threads: finish_switch, then sysretq.
extern "C" fn finish_switch_and_enter_user(user_rip: u64, user_rsp: u64, cr3: u64) -> ! {
    finish_switch();
    unsafe {
        core::arch::asm!(
            "mov cr3, {cr3}",
            "mov rcx, {rip}",
            "mov r11, 0x202",       // RFLAGS with IF=1
            "mov rsp, {rsp}",
            "sysretq",
            cr3 = in(reg) cr3,
            rip = in(reg) user_rip,
            rsp = in(reg) user_rsp,
            options(noreturn),
        );
    }
}

/// Complete the post-switch protocol: if the old thread needs re-enqueue,
/// lock the scheduler and enqueue it now (after context_switch returned,
/// so the old thread's RSP is safely saved).
fn finish_switch() {
    let percpu = percpu::current_percpu();
    if percpu.switch_needs_enqueue {
        percpu.switch_needs_enqueue = false;
        let old_idx = percpu.switch_old_idx;
        if old_idx != usize::MAX {
            let sched = SCHEDULER.lock();
            sched.enqueue(old_idx);
        }
    }
}

// ---------------------------------------------------------------------------
// Per-core run queues
// ---------------------------------------------------------------------------

const MAX_CPUS: usize = 16;

struct CpuQueue {
    queue: VecDeque<usize>,
}

impl CpuQueue {
    const fn new() -> Self {
        Self { queue: VecDeque::new() }
    }
}

/// Per-core run queues, each protected by a ticket lock for FIFO fairness.
static PER_CPU_QUEUES: [TicketMutex<CpuQueue>; MAX_CPUS] = {
    const INIT: TicketMutex<CpuQueue> = TicketMutex::new(CpuQueue::new());
    [INIT; MAX_CPUS]
};

/// Enqueue a thread index to a specific CPU's run queue.
fn enqueue_to_cpu(cpu: usize, idx: usize) {
    PER_CPU_QUEUES[cpu % MAX_CPUS].lock().queue.push_back(idx);
}

/// Dequeue from the current CPU's queue, or work-steal from others.
fn dequeue_from_any(my_cpu: usize) -> Option<usize> {
    // Try own queue first.
    if let Some(idx) = PER_CPU_QUEUES[my_cpu % MAX_CPUS].lock().queue.pop_front() {
        return Some(idx);
    }
    // Work stealing: try other CPUs, steal oldest (pop_back = LIFO steal).
    for offset in 1..MAX_CPUS {
        let victim = (my_cpu + offset) % MAX_CPUS;
        if let Some(mut q) = PER_CPU_QUEUES[victim].try_lock() {
            if let Some(idx) = q.queue.pop_back() {
                return Some(idx);
            }
        }
    }
    None
}

/// Dequeue a non-depleted thread. If a dequeued thread belongs to a depleted
/// domain, park it in the domain's suspended list and try the next one.
fn dequeue_non_depleted(my_cpu: usize, sched: &mut Scheduler) -> Option<usize> {
    // Limit iterations to prevent infinite loop if all threads are depleted.
    for _ in 0..MAX_THREADS {
        let idx = dequeue_from_any(my_cpu)?;
        let domain_idx = sched.threads.get_by_index(idx as u32)
            .and_then(|t| t.domain_idx);

        match domain_idx {
            None => return Some(idx), // No domain — always runnable
            Some(dom_idx) => {
                let is_active = sched.domains.get_by_index(dom_idx)
                    .map_or(true, |d| d.state == DomainState::Active);
                if is_active {
                    return Some(idx);
                }
                // Domain is depleted — park this thread.
                if let Some(dom) = sched.domains.get_mut_by_index(dom_idx) {
                    dom.suspended.push(idx);
                }
            }
        }
    }
    None
}

// ---------------------------------------------------------------------------
// Scheduler state (thread pool + ID generator)
// ---------------------------------------------------------------------------

/// Maximum threads the scheduler can track.
const MAX_THREADS: usize = 256;

pub struct Scheduler {
    pub threads: Pool<Thread>,
    pub domains: Pool<SchedDomain>,
    next_id: u32,
    /// O(1) lookup: tid_to_slot[tid] = Some(pool_index) for live threads.
    tid_to_slot: [Option<u32>; MAX_THREADS],
}

impl Scheduler {
    const fn new() -> Self {
        Self {
            threads: Pool::new(),
            domains: Pool::new(),
            next_id: 0,
            tid_to_slot: [None; MAX_THREADS],
        }
    }

    /// Enqueue a thread to its preferred CPU's queue (or current CPU if no preference).
    pub fn enqueue(&self, idx: usize) {
        let target_cpu = self.threads.get_by_index(idx as u32)
            .and_then(|t| t.preferred_cpu)
            .unwrap_or_else(|| percpu::current_percpu().cpu_index) as usize;
        enqueue_to_cpu(target_cpu, idx);
    }

    /// Get pool slot index for a ThreadId. O(1).
    pub fn slot_of(&self, tid: ThreadId) -> Option<u32> {
        if (tid.0 as usize) < MAX_THREADS {
            self.tid_to_slot[tid.0 as usize]
        } else {
            None
        }
    }

    /// Register a tid→slot mapping.
    fn register_tid(&mut self, tid: ThreadId, slot: usize) {
        if (tid.0 as usize) < MAX_THREADS {
            self.tid_to_slot[tid.0 as usize] = Some(slot as u32);
        }
    }

    /// Unregister a tid→slot mapping (on thread death).
    fn unregister_tid(&mut self, tid: ThreadId) {
        if (tid.0 as usize) < MAX_THREADS {
            self.tid_to_slot[tid.0 as usize] = None;
        }
    }
}

pub static SCHEDULER: Mutex<Scheduler> = Mutex::new(Scheduler::new());

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Initialize the scheduler and create the idle thread (thread 0) for the BSP.
pub fn init() {
    let mut sched = SCHEDULER.lock();
    let percpu = percpu::current_percpu();

    // Thread 0 = BSP idle thread.
    let idle = Thread {
        id: ThreadId(sched.next_id),
        state: ThreadState::Running,
        priority: 255, // lowest priority
        context: thread::CpuContext::zero(),
        cap_space: None,
        kernel_stack_base: 0,
        kernel_stack_top: 0,
        timeslice: TIMESLICE,
        is_user: false,
        user_rip: 0,
        user_rsp: 0,
        cr3: 0,
        ipc_msg: Message::empty(),
        ipc_endpoint: None,
        ipc_role: IpcRole::None,
        preferred_cpu: None,
        domain_idx: None,
        redirect_ep: None,
    };
    let tid = ThreadId(sched.next_id);
    let handle = sched.threads.alloc(idle);
    let slot = handle.index();
    sched.register_tid(tid, slot);
    sched.next_id += 1;

    percpu.idle_thread = slot;
    percpu.current_thread = slot;

    kprintln!("  scheduler: per-core queues with work stealing (SMP)");
}

/// Create an idle thread for an AP. Returns the pool index.
pub fn create_idle_thread() -> usize {
    let mut sched = SCHEDULER.lock();
    let tid = ThreadId(sched.next_id);
    let idle = Thread {
        id: tid,
        state: ThreadState::Running,
        priority: 255,
        context: thread::CpuContext::zero(),
        cap_space: None,
        kernel_stack_base: 0,
        kernel_stack_top: 0,
        timeslice: TIMESLICE,
        is_user: false,
        user_rip: 0,
        user_rsp: 0,
        cr3: 0,
        ipc_msg: Message::empty(),
        ipc_endpoint: None,
        ipc_role: IpcRole::None,
        preferred_cpu: None,
        domain_idx: None,
        redirect_ep: None,
    };
    let handle = sched.threads.alloc(idle);
    let slot = handle.index();
    sched.register_tid(tid, slot);
    sched.next_id += 1;
    slot
}

/// Spawn a new kernel thread.
pub fn spawn(entry: fn() -> !) -> ThreadId {
    let mut sched = SCHEDULER.lock();
    let id = sched.next_id;
    sched.next_id += 1;

    let mut t = Thread::new(id, entry, 128, thread_trampoline);
    t.timeslice = TIMESLICE;
    let tid = t.id;

    let handle = sched.threads.alloc(t);
    let slot = handle.index();
    sched.register_tid(tid, slot);
    sched.enqueue(slot);
    tid
}

/// Spawn a new user thread that enters Ring 3 at `user_rip`.
pub fn spawn_user(user_rip: u64, user_rsp: u64, cr3: u64) -> ThreadId {
    let mut sched = SCHEDULER.lock();
    let id = sched.next_id;
    sched.next_id += 1;

    let mut t = Thread::new_user(id, user_rip, user_rsp, cr3, user_thread_trampoline);
    t.timeslice = TIMESLICE;
    let tid = t.id;

    let handle = sched.threads.alloc(t);
    let slot = handle.index();
    sched.register_tid(tid, slot);
    sched.enqueue(slot);
    tid
}

/// Terminate the current thread and switch away.
pub fn exit_current() -> ! {
    {
        let percpu = percpu::current_percpu();
        let idx = percpu.current_thread;
        if idx != usize::MAX {
            let mut sched = SCHEDULER.lock();
            if let Some(t) = sched.threads.get_mut_by_index(idx as u32) {
                t.state = ThreadState::Dead;
            }
        }
    }
    schedule();
    crate::arch::halt_loop();
}

/// Return the current thread's ID.
pub fn current_tid() -> Option<ThreadId> {
    let percpu = percpu::current_percpu();
    let idx = percpu.current_thread;
    if idx == usize::MAX {
        return None;
    }
    let sched = SCHEDULER.lock();
    sched.threads.get_by_index(idx as u32).map(|t| t.id)
}

/// Block the current thread (set to Blocked) and switch away.
pub fn block_current() {
    {
        let percpu = percpu::current_percpu();
        let idx = percpu.current_thread;
        if idx != usize::MAX {
            let mut sched = SCHEDULER.lock();
            if let Some(t) = sched.threads.get_mut_by_index(idx as u32) {
                t.state = ThreadState::Blocked;
            }
        }
    }
    schedule();
}

/// Suspend the current thread due to a page fault and switch away.
pub fn fault_current() {
    {
        let percpu = percpu::current_percpu();
        let idx = percpu.current_thread;
        if idx != usize::MAX {
            let mut sched = SCHEDULER.lock();
            if let Some(t) = sched.threads.get_mut_by_index(idx as u32) {
                t.state = ThreadState::Faulted;
            }
        }
    }
    schedule();
}

/// Resume a faulted thread: set to Ready, reset timeslice, enqueue. O(1).
pub fn resume_faulted(tid: ThreadId) -> bool {
    let mut sched = SCHEDULER.lock();
    if let Some(slot) = sched.slot_of(tid) {
        if let Some(t) = sched.threads.get_mut_by_index(slot) {
            if t.state == ThreadState::Faulted {
                t.state = ThreadState::Ready;
                t.timeslice = TIMESLICE;
                sched.enqueue(slot as usize);
                return true;
            }
        }
    }
    false
}

/// Wake a blocked thread: set to Ready, reset timeslice, enqueue. O(1).
pub fn wake(tid: ThreadId) {
    let mut sched = SCHEDULER.lock();
    if let Some(slot) = sched.slot_of(tid) {
        if let Some(t) = sched.threads.get_mut_by_index(slot) {
            if t.state == ThreadState::Blocked {
                t.state = ThreadState::Ready;
                t.timeslice = TIMESLICE;
                sched.enqueue(slot as usize);
            }
        }
    }
}

/// Store IPC state on the current thread before blocking.
pub fn set_current_ipc(ep_id: u32, role: IpcRole, msg: Message) {
    let percpu = percpu::current_percpu();
    let idx = percpu.current_thread;
    if idx != usize::MAX {
        let mut sched = SCHEDULER.lock();
        if let Some(t) = sched.threads.get_mut_by_index(idx as u32) {
            t.ipc_endpoint = Some(ep_id);
            t.ipc_role = role;
            t.ipc_msg = msg;
        }
    }
}

/// Clear IPC state on the current thread after waking.
pub fn clear_current_ipc() {
    let percpu = percpu::current_percpu();
    let idx = percpu.current_thread;
    if idx != usize::MAX {
        let mut sched = SCHEDULER.lock();
        if let Some(t) = sched.threads.get_mut_by_index(idx as u32) {
            t.ipc_endpoint = None;
            t.ipc_role = IpcRole::None;
        }
    }
}

/// Write a message into a specific thread's IPC buffer. O(1).
pub fn write_ipc_msg(tid: ThreadId, msg: Message) {
    let mut sched = SCHEDULER.lock();
    if let Some(slot) = sched.slot_of(tid) {
        if let Some(t) = sched.threads.get_mut_by_index(slot) {
            t.ipc_msg = msg;
        }
    }
}

/// Read the message from a specific thread's IPC buffer. O(1).
pub fn read_ipc_msg(tid: ThreadId) -> Message {
    let sched = SCHEDULER.lock();
    if let Some(slot) = sched.slot_of(tid) {
        if let Some(t) = sched.threads.get_by_index(slot) {
            return t.ipc_msg;
        }
    }
    Message::empty()
}

/// Write a message into the current thread's IPC buffer (without touching endpoint/role).
pub fn set_current_msg(msg: Message) {
    let percpu = percpu::current_percpu();
    let idx = percpu.current_thread;
    if idx != usize::MAX {
        let mut sched = SCHEDULER.lock();
        if let Some(t) = sched.threads.get_mut_by_index(idx as u32) {
            t.ipc_msg = msg;
        }
    }
}

/// Read the current thread's own IPC message buffer (after being woken).
pub fn current_ipc_msg() -> Message {
    let percpu = percpu::current_percpu();
    let idx = percpu.current_thread;
    if idx != usize::MAX {
        let sched = SCHEDULER.lock();
        if let Some(t) = sched.threads.get_by_index(idx as u32) {
            return t.ipc_msg;
        }
    }
    Message::empty()
}

// ---------------------------------------------------------------------------
// Syscall Redirect (LUCAS)
// ---------------------------------------------------------------------------

/// Get the current thread's syscall redirect endpoint (if set).
pub fn get_current_redirect_ep() -> Option<u32> {
    let percpu = percpu::current_percpu();
    let idx = percpu.current_thread;
    if idx != usize::MAX {
        let sched = SCHEDULER.lock();
        if let Some(t) = sched.threads.get_by_index(idx as u32) {
            return t.redirect_ep;
        }
    }
    None
}

/// Set a thread's syscall redirect endpoint.
pub fn set_thread_redirect_ep(tid: ThreadId, ep_id: u32) {
    let mut sched = SCHEDULER.lock();
    if let Some(slot) = sched.slot_of(tid) {
        if let Some(t) = sched.threads.get_mut_by_index(slot) {
            t.redirect_ep = Some(ep_id);
        }
    }
}

// ---------------------------------------------------------------------------
// Scheduling Domain API
// ---------------------------------------------------------------------------

/// Create a new scheduling domain. Returns its pool handle.
pub fn create_domain(quantum_ticks: u32, period_ticks: u32) -> Option<PoolHandle> {
    let global_now = GLOBAL_TICKS.load(Ordering::Relaxed);
    let dom = SchedDomain::new(quantum_ticks, period_ticks, global_now);
    let mut sched = SCHEDULER.lock();
    let handle = sched.domains.alloc(dom);
    kprintln!("  domain: created (quantum={} period={} ticks)", quantum_ticks, period_ticks);
    Some(handle)
}

/// Attach a thread to a domain.
pub fn attach_to_domain(domain_handle: PoolHandle, tid: ThreadId) -> Result<(), sotos_common::SysError> {
    let mut sched = SCHEDULER.lock();
    let slot = sched.slot_of(tid).ok_or(sotos_common::SysError::InvalidArg)?;
    let dom = sched.domains.get_mut(domain_handle).ok_or(sotos_common::SysError::InvalidArg)?;
    if !dom.add_member(slot) {
        return Err(sotos_common::SysError::OutOfResources);
    }
    let dom_idx = domain_handle.index() as u32;
    let t = sched.threads.get_mut_by_index(slot).ok_or(sotos_common::SysError::InvalidArg)?;
    t.domain_idx = Some(dom_idx);
    Ok(())
}

/// Detach a thread from a domain.
pub fn detach_from_domain(domain_handle: PoolHandle, tid: ThreadId) -> Result<(), sotos_common::SysError> {
    let mut sched = SCHEDULER.lock();
    let slot = sched.slot_of(tid).ok_or(sotos_common::SysError::InvalidArg)?;
    let dom_idx = domain_handle.index() as u32;

    // Remove from suspended list and re-enqueue if needed.
    let mut re_enqueue = false;
    if let Some(dom) = sched.domains.get_mut(domain_handle) {
        let was_suspended = dom.suspended.iter().any(|&s| s == slot as usize);
        dom.remove_member(slot);
        if was_suspended {
            re_enqueue = true;
        }
    } else {
        return Err(sotos_common::SysError::InvalidArg);
    }

    let t = sched.threads.get_mut_by_index(slot).ok_or(sotos_common::SysError::InvalidArg)?;
    if t.domain_idx == Some(dom_idx) {
        t.domain_idx = None;
    }

    if re_enqueue && t.state == ThreadState::Ready {
        sched.enqueue(slot as usize);
    }

    Ok(())
}

/// Adjust a domain's quantum.
pub fn adjust_domain(domain_handle: PoolHandle, new_quantum: u32) -> Result<(), sotos_common::SysError> {
    let mut sched = SCHEDULER.lock();
    let dom = sched.domains.get_mut(domain_handle).ok_or(sotos_common::SysError::InvalidArg)?;
    dom.quantum_ticks = new_quantum;
    Ok(())
}

/// Query domain info: (quantum_ticks, consumed_ticks, period_ticks).
pub fn domain_info(domain_handle: PoolHandle) -> Option<(u32, u32, u32)> {
    let sched = SCHEDULER.lock();
    let dom = sched.domains.get(domain_handle)?;
    Some((dom.quantum_ticks, dom.consumed_ticks, dom.period_ticks))
}

/// Called from the timer interrupt handler on every tick.
/// Uses try_lock to avoid deadlock if the timer fires while SCHEDULER is held.
pub fn tick() {
    // Always increment global tick counter (even if lock contended).
    let global_now = GLOBAL_TICKS.fetch_add(1, Ordering::Relaxed) + 1;

    let needs_reschedule = {
        let mut sched = match SCHEDULER.try_lock() {
            Some(s) => s,
            None => return, // Lock contended — skip this tick
        };
        let percpu = percpu::current_percpu();
        let idx = percpu.current_thread;
        let mut resched = false;

        if idx != usize::MAX {
            if let Some(t) = sched.threads.get_mut_by_index(idx as u32) {
                if t.timeslice > 0 {
                    t.timeslice -= 1;
                }
                if t.timeslice == 0 {
                    resched = true;
                }

                // Domain budget tracking.
                if let Some(dom_idx) = t.domain_idx {
                    if let Some(dom) = sched.domains.get_mut_by_index(dom_idx) {
                        dom.consumed_ticks += 1;
                        if dom.consumed_ticks >= dom.quantum_ticks && dom.state == DomainState::Active {
                            dom.state = DomainState::Depleted;
                            kprintln!("  domain: depleted (consumed={}/{})", dom.consumed_ticks, dom.quantum_ticks);
                            resched = true;
                        }
                    }
                }
            }
        }

        // Check all domain refills.
        check_domain_refills(&mut sched, global_now);

        resched
    };

    if needs_reschedule {
        schedule();
    }
}

/// Check all domains for period refills. Re-enqueue suspended threads.
fn check_domain_refills(sched: &mut Scheduler, global_now: u64) {
    // Iterate domain pool by raw index (small, bounded).
    for idx in 0..64u32 {
        let re_enqueue = if let Some(dom) = sched.domains.get_mut_by_index(idx) {
            if global_now >= dom.next_refill_tick {
                dom.consumed_ticks = 0;
                dom.state = DomainState::Active;
                dom.next_refill_tick += dom.period_ticks as u64;
                // Drain suspended list.
                let suspended: Vec<usize> = dom.suspended.drain(..).collect();
                if !suspended.is_empty() {
                    kprintln!("  domain: refilled, {} threads re-enqueued", suspended.len());
                }
                Some(suspended)
            } else {
                None
            }
        } else {
            None
        };

        // Re-enqueue outside the domain borrow.
        if let Some(threads) = re_enqueue {
            for tidx in threads {
                if let Some(t) = sched.threads.get_mut_by_index(tidx as u32) {
                    if t.state == ThreadState::Ready {
                        sched.enqueue(tidx);
                    }
                }
            }
        }
    }
}

/// Pick the next thread and switch to it.
///
/// Uses the post-switch re-enqueue pattern: the old thread is NOT put back
/// in the run queue until after context_switch completes (when finish_switch
/// is called by the new thread). This avoids a race where another CPU could
/// dequeue and run the old thread before its RSP is saved.
pub fn schedule() {
    // Stack-local dummy for dead threads (whose slot is freed before switch).
    let mut dummy_rsp: u64 = 0;

    let switch_info: Option<(*mut u64, u64)> = {
        let mut sched = SCHEDULER.lock();
        let percpu = percpu::current_percpu();

        let old_idx = percpu.current_thread;
        if old_idx == usize::MAX {
            return;
        }

        // Try to dequeue a non-depleted thread from per-core queue (with work stealing).
        let my_cpu = percpu.cpu_index as usize;
        let new_idx = match dequeue_non_depleted(my_cpu, &mut sched) {
            Some(idx) => idx,
            None => {
                // No other thread ready.
                let old_t = match sched.threads.get_mut_by_index(old_idx as u32) {
                    Some(t) => t,
                    None => return,
                };

                if old_t.state == ThreadState::Running {
                    // Still running, just reset timeslice.
                    old_t.timeslice = TIMESLICE;
                    return;
                }

                // Current thread is blocked/dead/faulted but run queue is empty.
                // Switch to idle thread.
                let idle_idx = percpu.idle_thread;
                if old_idx == idle_idx {
                    // Already idle, nothing to do.
                    return;
                }
                idle_idx
            }
        };

        // Handle old thread state.
        let old_is_dead = sched.threads.get_by_index(old_idx as u32)
            .map_or(false, |t| t.state == ThreadState::Dead);

        let old_rsp_ptr = if old_is_dead {
            // Dead thread: remove from domain, unregister tid, free the slot.
            if let Some(dead_t) = sched.threads.get_by_index(old_idx as u32) {
                if let Some(dom_idx) = dead_t.domain_idx {
                    if let Some(dom) = sched.domains.get_mut_by_index(dom_idx) {
                        dom.remove_member(old_idx as u32);
                    }
                }
            }
            let dead_tid = sched.threads.get_by_index(old_idx as u32).map(|t| t.id);
            if let Some(tid) = dead_tid {
                sched.unregister_tid(tid);
            }
            sched.threads.free_by_index(old_idx as u32);
            percpu.switch_needs_enqueue = false;
            percpu.switch_old_idx = usize::MAX;
            &mut dummy_rsp as *mut u64
        } else {
            let old_rsp_ptr = &mut sched.threads.get_mut_by_index(old_idx as u32).unwrap().context.rsp as *mut u64;
            let is_idle = old_idx == percpu.idle_thread;
            if let Some(old_t) = sched.threads.get_mut_by_index(old_idx as u32) {
                if old_t.state == ThreadState::Running && !is_idle {
                    old_t.state = ThreadState::Ready;
                    old_t.timeslice = TIMESLICE;
                    // Deferred enqueue — finish_switch() will do it
                    percpu.switch_old_idx = old_idx;
                    percpu.switch_needs_enqueue = true;
                } else {
                    // Idle/Blocked/Faulted — don't re-enqueue
                    percpu.switch_needs_enqueue = false;
                    percpu.switch_old_idx = usize::MAX;
                }
            }
            old_rsp_ptr
        };

        let new_t = sched.threads.get_mut_by_index(new_idx as u32).unwrap();
        new_t.state = ThreadState::Running;
        new_t.timeslice = TIMESLICE;
        let new_kstack_top = new_t.kernel_stack_top;
        let new_cr3 = new_t.cr3;
        let new_rsp = new_t.context.rsp;

        // Update percpu with new thread info
        percpu.current_thread = new_idx;

        // Update kernel stack for TSS (Ring 3 → Ring 0 on interrupt)
        // and for SYSCALL entry via percpu.
        if new_kstack_top != 0 {
            unsafe {
                (*percpu.tss).privilege_stack_table[0] = VirtAddr::new(new_kstack_top);
            }
            percpu.kernel_stack_top = new_kstack_top;
        }

        // Switch address space if the new thread has a different CR3.
        let target_cr3 = if new_cr3 != 0 {
            new_cr3
        } else {
            crate::mm::paging::boot_cr3()
        };
        if target_cr3 != 0 {
            let current_cr3 = crate::mm::paging::read_cr3();
            if target_cr3 != current_cr3 {
                unsafe {
                    core::arch::asm!(
                        "mov cr3, {}",
                        in(reg) target_cr3,
                        options(nostack, preserves_flags)
                    );
                }
            }
        }

        Some((old_rsp_ptr, new_rsp))
    };
    // Lock is dropped here ^

    if let Some((old_rsp_ptr, new_rsp)) = switch_info {
        unsafe {
            context_switch(old_rsp_ptr, new_rsp);
        }
        // After context_switch returns, we're running as the NEW thread
        // that was previously switched away from. Call finish_switch.
        finish_switch();
    }
}
