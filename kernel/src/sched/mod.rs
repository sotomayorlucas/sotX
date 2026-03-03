//! Scheduler — Preemptive Round-Robin.
//!
//! **Level 1 (kernel)**: Preemptive, priority-based with deadline awareness.
//! Currently implements simple round-robin as the foundation.
//!
//! **Level 2 (userspace)**: Scheduling Domains (future).

pub mod thread;

pub use thread::{IpcRole, ThreadId, ThreadState};
use thread::Thread;

use alloc::collections::VecDeque;
use crate::ipc::endpoint::Message;
use crate::pool::Pool;

use crate::kprintln;
use spin::Mutex;

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
// Thread trampolines
// ---------------------------------------------------------------------------

/// Trampoline for kernel threads. Enables interrupts and jumps to entry.
#[unsafe(naked)]
unsafe extern "C" fn thread_trampoline() -> ! {
    core::arch::naked_asm!(
        "sti",
        "jmp r12",
    );
}

/// Trampoline for user threads. Switches to user address space and
/// enters Ring 3 via sysretq.
///
/// Registers from initial stack frame:
///   r12 = user RIP, r13 = user RSP, r14 = CR3
#[unsafe(naked)]
unsafe extern "C" fn user_thread_trampoline() -> ! {
    core::arch::naked_asm!(
        "mov cr3, r14",         // switch to user address space
        "mov rcx, r12",         // user RIP → RCX for sysretq
        "mov r11, 0x202",       // user RFLAGS (IF=1) → R11 for sysretq
        "mov rsp, r13",         // user RSP
        "sysretq",              // enter Ring 3
    );
}

// ---------------------------------------------------------------------------
// Scheduler state
// ---------------------------------------------------------------------------

struct Scheduler {
    threads: Pool<Thread>,
    /// Run queue of pool indices.
    run_queue: VecDeque<usize>,
    /// Index of the currently running thread in `threads` (None before first schedule).
    current: Option<usize>,
    next_id: u32,
}

impl Scheduler {
    const fn new() -> Self {
        Self {
            threads: Pool::new(),
            run_queue: VecDeque::new(),
            current: None,
            next_id: 0,
        }
    }

    fn enqueue(&mut self, idx: usize) {
        self.run_queue.push_back(idx);
    }

    fn dequeue(&mut self) -> Option<usize> {
        self.run_queue.pop_front()
    }
}

static SCHEDULER: Mutex<Scheduler> = Mutex::new(Scheduler::new());

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Initialize the scheduler and create the idle thread (thread 0).
pub fn init() {
    let mut sched = SCHEDULER.lock();

    // Thread 0 = idle thread.
    // It doesn't get a real stack via Thread::new — it will run on the
    // boot stack. We just need a slot to save its context into.
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
    };
    let slot = sched.threads.alloc(idle) as usize;
    sched.next_id += 1;
    sched.current = Some(slot);

    kprintln!("  scheduler: preemptive round-robin (single core)");
}

/// Spawn a new kernel thread.
pub fn spawn(entry: fn() -> !) -> ThreadId {
    let mut sched = SCHEDULER.lock();
    let id = sched.next_id;
    sched.next_id += 1;

    let mut t = Thread::new(id, entry, 128, thread_trampoline);
    t.timeslice = TIMESLICE;
    let tid = t.id;

    let slot = sched.threads.alloc(t) as usize;
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

    let slot = sched.threads.alloc(t) as usize;
    sched.enqueue(slot);
    tid
}

/// Terminate the current thread and switch away.
///
/// Marks the current thread as Dead (so `schedule()` won't re-enqueue it),
/// then calls `schedule()` to switch to the next runnable thread.
/// The dead thread's pool slot is freed after the context switch completes.
pub fn exit_current() -> ! {
    {
        let mut sched = SCHEDULER.lock();
        if let Some(idx) = sched.current {
            if let Some(t) = sched.threads.get_mut(idx as u32) {
                t.state = ThreadState::Dead;
            }
        }
    }
    schedule();
    // Safety net if run queue was empty (idle thread should always be present).
    crate::arch::halt_loop();
}

/// Return the current thread's ID.
pub fn current_tid() -> Option<ThreadId> {
    let sched = SCHEDULER.lock();
    sched.current.and_then(|idx| sched.threads.get(idx as u32).map(|t| t.id))
}

/// Block the current thread (set to Blocked) and switch away.
/// The caller must have already set the IPC state via `set_current_ipc()`.
pub fn block_current() {
    {
        let mut sched = SCHEDULER.lock();
        if let Some(idx) = sched.current {
            if let Some(t) = sched.threads.get_mut(idx as u32) {
                t.state = ThreadState::Blocked;
            }
        }
    }
    schedule();
}

/// Suspend the current thread due to a page fault and switch away.
/// The VMM server will resolve the fault and call `resume_faulted()`.
pub fn fault_current() {
    {
        let mut sched = SCHEDULER.lock();
        if let Some(idx) = sched.current {
            if let Some(t) = sched.threads.get_mut(idx as u32) {
                t.state = ThreadState::Faulted;
            }
        }
    }
    schedule();
}

/// Resume a faulted thread: set to Ready, reset timeslice, enqueue.
/// Returns true if the thread was found in Faulted state.
pub fn resume_faulted(tid: ThreadId) -> bool {
    let mut sched = SCHEDULER.lock();
    let mut found = None;
    for (i, t) in sched.threads.iter() {
        if t.id == tid && t.state == ThreadState::Faulted {
            found = Some(i);
            break;
        }
    }
    if let Some(i) = found {
        let t = sched.threads.get_mut(i).unwrap();
        t.state = ThreadState::Ready;
        t.timeslice = TIMESLICE;
        sched.enqueue(i as usize);
        true
    } else {
        false
    }
}

/// Wake a blocked thread: set to Ready, reset timeslice, enqueue.
pub fn wake(tid: ThreadId) {
    let mut sched = SCHEDULER.lock();
    // Find index first to avoid borrow conflict.
    let mut found = None;
    for (i, t) in sched.threads.iter() {
        if t.id == tid && t.state == ThreadState::Blocked {
            found = Some(i);
            break;
        }
    }
    if let Some(i) = found {
        let t = sched.threads.get_mut(i).unwrap();
        t.state = ThreadState::Ready;
        t.timeslice = TIMESLICE;
        sched.enqueue(i as usize);
    }
}

/// Store IPC state on the current thread before blocking.
pub fn set_current_ipc(ep_id: u32, role: IpcRole, msg: Message) {
    let mut sched = SCHEDULER.lock();
    if let Some(idx) = sched.current {
        if let Some(t) = sched.threads.get_mut(idx as u32) {
            t.ipc_endpoint = Some(ep_id);
            t.ipc_role = role;
            t.ipc_msg = msg;
        }
    }
}

/// Clear IPC state on the current thread after waking.
pub fn clear_current_ipc() {
    let mut sched = SCHEDULER.lock();
    if let Some(idx) = sched.current {
        if let Some(t) = sched.threads.get_mut(idx as u32) {
            t.ipc_endpoint = None;
            t.ipc_role = IpcRole::None;
        }
    }
}

/// Write a message into a specific thread's IPC buffer.
pub fn write_ipc_msg(tid: ThreadId, msg: Message) {
    let mut sched = SCHEDULER.lock();
    let mut found = None;
    for (i, t) in sched.threads.iter() {
        if t.id == tid {
            found = Some(i);
            break;
        }
    }
    if let Some(i) = found {
        sched.threads.get_mut(i).unwrap().ipc_msg = msg;
    }
}

/// Read the message from a specific thread's IPC buffer.
pub fn read_ipc_msg(tid: ThreadId) -> Message {
    let sched = SCHEDULER.lock();
    for (_, t) in sched.threads.iter() {
        if t.id == tid {
            return t.ipc_msg;
        }
    }
    Message::empty()
}

/// Write a message into the current thread's IPC buffer (without touching endpoint/role).
/// Used by async channels before blocking a sender.
pub fn set_current_msg(msg: Message) {
    let mut sched = SCHEDULER.lock();
    if let Some(idx) = sched.current {
        if let Some(t) = sched.threads.get_mut(idx as u32) {
            t.ipc_msg = msg;
        }
    }
}

/// Read the current thread's own IPC message buffer (after being woken).
pub fn current_ipc_msg() -> Message {
    let sched = SCHEDULER.lock();
    if let Some(idx) = sched.current {
        if let Some(t) = sched.threads.get(idx as u32) {
            return t.ipc_msg;
        }
    }
    Message::empty()
}

/// Called from the timer interrupt handler on every tick.
pub fn tick() {
    let needs_reschedule = {
        let mut sched = SCHEDULER.lock();
        if let Some(idx) = sched.current {
            if let Some(t) = sched.threads.get_mut(idx as u32) {
                if t.timeslice > 0 {
                    t.timeslice -= 1;
                }
                t.timeslice == 0
            } else {
                false
            }
        } else {
            false
        }
    };

    if needs_reschedule {
        schedule();
    }
}

/// Pick the next thread and switch to it.
///
/// **Callers are responsible for interrupt state.** This function does NOT
/// enable or disable interrupts — each call site restores IF naturally:
/// - Timer handler: iretq restores RFLAGS (IF=1)
/// - Syscall yield: sysretq restores R11 (IF=1)
/// - New thread trampoline: sti / sysretq
pub fn schedule() {
    let switch_info: Option<(*mut u64, u64)> = {
        let mut sched = SCHEDULER.lock();

        let old_idx = match sched.current {
            Some(idx) => idx,
            None => return,
        };

        // Try to dequeue a ready thread.
        let new_idx = match sched.dequeue() {
            Some(idx) => idx,
            None => {
                // No other thread ready — reset timeslice and continue.
                if let Some(t) = sched.threads.get_mut(old_idx as u32) {
                    t.timeslice = TIMESLICE;
                }
                return;
            }
        };

        // Grab old_rsp_ptr before any slot manipulation (Dead threads may be freed).
        let old_is_dead = sched.threads.get(old_idx as u32)
            .map_or(false, |t| t.state == ThreadState::Dead);
        let old_rsp_ptr = &mut sched.threads.get_mut(old_idx as u32).unwrap().context.rsp as *mut u64;

        // Re-enqueue the old thread if it's still runnable.
        // Dead threads get their slot freed to reclaim pool space.
        if old_is_dead {
            sched.threads.free(old_idx as u32);
        } else if let Some(old_t) = sched.threads.get_mut(old_idx as u32) {
            if old_t.state == ThreadState::Running {
                old_t.state = ThreadState::Ready;
                old_t.timeslice = TIMESLICE;
                sched.enqueue(old_idx);
            }
        }

        let new_t = sched.threads.get_mut(new_idx as u32).unwrap();
        new_t.state = ThreadState::Running;
        new_t.timeslice = TIMESLICE;
        let new_kstack_top = new_t.kernel_stack_top;
        let new_cr3 = new_t.cr3;
        let new_rsp = new_t.context.rsp;
        // Done reading new_t fields — safe to reassign current.
        sched.current = Some(new_idx);

        // Update kernel stack for TSS (Ring 3 → Ring 0 on interrupt)
        // and for SYSCALL entry.
        if new_kstack_top != 0 {
            unsafe {
                crate::arch::gdt::set_tss_rsp0(new_kstack_top);
                crate::arch::syscall::set_kernel_stack_top(new_kstack_top);
            }
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
    }
}
