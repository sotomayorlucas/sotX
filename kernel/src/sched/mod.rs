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

pub use thread::{ComputeTarget, IpcRole, ThreadId, ThreadState};
use thread::Thread;

use alloc::collections::VecDeque;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use crate::arch::x86_64::percpu;
use crate::ipc::endpoint::Message;
use crate::pool::{Pool, PoolHandle};
use crate::sync::ticket::TicketMutex;

use crate::kdebug;
use domain::{DomainState, SchedDomain};
use spin::Mutex;
use x86_64::VirtAddr;

/// MSR number for IA32_FS_BASE — used for TLS (Thread-Local Storage).
const IA32_FS_BASE: u32 = 0xC000_0100;

/// MSR number for IA32_KERNEL_GS_BASE — holds user GS while in kernel mode.
const IA32_KERNEL_GS_BASE: u32 = 0xC000_0102;

/// Write the IA32_FS_BASE MSR.
#[inline]
fn write_fs_base_msr(value: u64) {
    unsafe {
        core::arch::asm!(
            "wrmsr",
            in("ecx") IA32_FS_BASE,
            in("eax") value as u32,
            in("edx") (value >> 32) as u32,
            options(nomem, nostack, preserves_flags),
        );
    }
}

/// Write the IA32_KERNEL_GS_BASE MSR (user's GS value while in kernel mode).
#[inline]
fn write_kernel_gs_base_msr(value: u64) {
    unsafe {
        core::arch::asm!(
            "wrmsr",
            in("ecx") IA32_KERNEL_GS_BASE,
            in("eax") value as u32,
            in("edx") (value >> 32) as u32,
            options(nomem, nostack, preserves_flags),
        );
    }
}

/// Global tick counter — incremented unconditionally on every timer tick.
/// Used as the clock source for domain period refills.
static GLOBAL_TICKS: AtomicU64 = AtomicU64::new(0);

/// Timeslice in ticks (100 ms at 100 Hz).
const TIMESLICE: u32 = 10;

/// Number of priority classes for multi-level feedback queues.
/// 0 = realtime (0-63), 1 = high (64-127), 2 = normal (128-191), 3 = low (192-255).
const PRIORITY_CLASSES: usize = 4;

/// Map a thread's priority (0-255) to a priority class index (0-3).
fn priority_class(priority: u8) -> usize {
    (priority as usize / 64).min(PRIORITY_CLASSES - 1)
}

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
#[allow(dead_code)]
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
#[allow(dead_code)]
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
            // Swap kernel GS → user GS before entering Ring 3.
            // After this: GS_BASE = user value, KERNEL_GS_BASE = percpu.
            "swapgs",
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

use sotos_common::MAX_CPUS;

struct CpuQueue {
    /// Multi-level priority queues: index 0 = highest priority (realtime).
    levels: [VecDeque<usize>; PRIORITY_CLASSES],
}

impl CpuQueue {
    const fn new() -> Self {
        Self {
            levels: [
                VecDeque::new(),
                VecDeque::new(),
                VecDeque::new(),
                VecDeque::new(),
            ],
        }
    }

    /// Dequeue from highest priority non-empty level.
    fn pop_front(&mut self) -> Option<usize> {
        for level in self.levels.iter_mut() {
            if let Some(idx) = level.pop_front() {
                return Some(idx);
            }
        }
        None
    }

    /// Steal from lowest priority non-empty level (steal cold/low-priority work).
    fn pop_back_lowest(&mut self) -> Option<usize> {
        for level in self.levels.iter_mut().rev() {
            if let Some(idx) = level.pop_back() {
                return Some(idx);
            }
        }
        None
    }

    #[allow(dead_code)]
    fn is_empty(&self) -> bool {
        self.levels.iter().all(|l| l.is_empty())
    }
}

/// Per-core run queues, each protected by a ticket lock for FIFO fairness.
static PER_CPU_QUEUES: [TicketMutex<CpuQueue>; MAX_CPUS] = {
    const INIT: TicketMutex<CpuQueue> = TicketMutex::new(CpuQueue::new());
    [INIT; MAX_CPUS]
};

/// Global ready queue for unaffinitized threads (Graham's list scheduling).
/// Dequeue order: local CPU → global queue → work-steal from other CPUs.
/// Provides (2-1/p) competitive ratio for makespan minimization.
static GLOBAL_READY: TicketMutex<CpuQueue> = TicketMutex::new(CpuQueue::new());

/// Enqueue a thread index to a specific CPU's run queue at the given priority class.
fn enqueue_to_cpu_pri(cpu: usize, idx: usize, pri_class: usize) {
    let target = cpu % MAX_CPUS;
    PER_CPU_QUEUES[target].lock().levels[pri_class].push_back(idx);
    // Wake idle CPUs: send reschedule IPI if enqueueing on a remote CPU.
    let my_cpu = percpu::current_percpu().cpu_index as usize;
    if target != my_cpu && crate::mm::slab::is_percpu_ready() {
        crate::arch::x86_64::lapic::send_ipi(
            target as u32,
            crate::arch::x86_64::lapic::RESCHEDULE_VECTOR,
        );
    }
}

/// Enqueue a thread index to a specific CPU's run queue (default: normal priority).
#[allow(dead_code)]
fn enqueue_to_cpu(cpu: usize, idx: usize) {
    enqueue_to_cpu_pri(cpu, idx, 2); // normal priority
}

/// Dequeue from the current CPU's queue, or work-steal from others.
/// Priority-aware: always dequeues highest priority available.
/// Lock ordering: local PER_CPU → GLOBAL_READY → remote PER_CPU (steal).
fn dequeue_from_any(my_cpu: usize) -> Option<usize> {
    // 1. Try own queue first (highest priority first).
    if let Some(idx) = PER_CPU_QUEUES[my_cpu % MAX_CPUS].lock().pop_front() {
        return Some(idx);
    }
    // 2. Graham: try global ready queue (unaffinitized threads).
    if let Some(mut gq) = GLOBAL_READY.try_lock() {
        if let Some(idx) = gq.pop_front() {
            return Some(idx);
        }
    }
    // 3. Work stealing: try other CPUs, steal lowest-priority work.
    for offset in 1..MAX_CPUS {
        let victim = (my_cpu + offset) % MAX_CPUS;
        if let Some(mut q) = PER_CPU_QUEUES[victim].try_lock() {
            if let Some(idx) = q.pop_back_lowest() {
                return Some(idx);
            }
        }
    }
    None
}

/// Dequeue a non-depleted, CPU-targeted thread. If a dequeued thread belongs
/// to a depleted domain, park it in the domain's suspended list and try the
/// next one. GPU/NPU-targeted threads are re-enqueued (they await offload).
///
/// Dequeue a runnable thread, respecting compute targets and scheduling domains.
/// EDF deadline scheduling fields exist on threads (deadline_ticks, period_ticks)
/// and are managed by set_deadline() / tick(), but the dequeue path uses the
/// standard priority MLQ to avoid locking all PER_CPU_QUEUES under SCHEDULER
/// (which causes re-entrant lock issues with timer interrupts on SMP).
fn dequeue_non_depleted(my_cpu: usize, sched: &mut Scheduler) -> Option<usize> {
    for _ in 0..MAX_THREADS {
        let idx = dequeue_from_any(my_cpu)?;

        // Skip non-CPU compute targets (GPU/NPU threads wait for offload).
        let compute_target = sched.threads.get_by_index(idx as u32)
            .map(|t| t.compute_target);
        if compute_target != Some(ComputeTarget::Cpu) && compute_target.is_some() {
            // Re-enqueue: this thread targets a different compute unit.
            sched.enqueue(idx);
            continue;
        }

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

// ---------------------------------------------------------------------------
// Per-thread IPC state (Phase 2: ρ_ooo — false dependency elimination)
// ---------------------------------------------------------------------------

/// Per-thread IPC message buffer and role, protected by per-slot spinlocks.
/// Eliminates SCHEDULER.lock() for IPC message read/write operations.
pub struct ThreadIpcState {
    pub msg: Message,
    pub role: IpcRole,
    pub endpoint: Option<u32>,
}

impl ThreadIpcState {
    const fn new() -> Self {
        Self {
            msg: Message::empty(),
            role: IpcRole::None,
            endpoint: None,
        }
    }
}

/// Per-thread IPC state indexed by pool slot (0..MAX_THREADS).
/// Each slot has its own spinlock — zero cross-thread contention.
pub static THREAD_IPC: [Mutex<ThreadIpcState>; MAX_THREADS] = {
    const INIT: Mutex<ThreadIpcState> = Mutex::new(ThreadIpcState::new());
    [INIT; MAX_THREADS]
};

/// Lock-free TID → pool slot mapping (0xFFFF_FFFF = unmapped).
/// Enables O(1) tid→slot lookup without SCHEDULER.lock().
static TID_TO_SLOT: [AtomicU32; MAX_THREADS] = {
    const INIT: AtomicU32 = AtomicU32::new(0xFFFF_FFFF);
    [INIT; MAX_THREADS]
};

/// Lock-free TID → slot lookup. Returns None if TID is unmapped.
pub fn tid_to_slot_external(tid: ThreadId) -> Option<u32> {
    if (tid.0 as usize) >= MAX_THREADS { return None; }
    let slot = TID_TO_SLOT[tid.0 as usize].load(Ordering::Acquire);
    if slot == 0xFFFF_FFFF { None } else { Some(slot) }
}

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

    /// Enqueue a thread to its preferred CPU's queue, or to the global ready
    /// queue if the thread has no CPU affinity (Graham's list scheduling).
    /// Uses the thread's priority to select the correct multi-level queue.
    pub fn enqueue(&self, idx: usize) {
        let (target_cpu, pri_class, has_affinity) = self.threads.get_by_index(idx as u32)
            .map(|t| {
                let has_aff = t.preferred_cpu.is_some();
                let cpu = t.preferred_cpu.unwrap_or(0) as usize;
                (cpu, priority_class(t.priority), has_aff)
            })
            .unwrap_or_else(|| (percpu::current_percpu().cpu_index as usize, 2, false));

        if has_affinity {
            enqueue_to_cpu_pri(target_cpu, idx, pri_class);
        } else {
            // Graham's list scheduling: unaffinitized threads go to global queue.
            GLOBAL_READY.lock().levels[pri_class].push_back(idx);
        }
    }

    /// Get pool slot index for a ThreadId. O(1).
    pub fn slot_of(&self, tid: ThreadId) -> Option<u32> {
        if (tid.0 as usize) < MAX_THREADS {
            self.tid_to_slot[tid.0 as usize]
        } else {
            None
        }
    }

    /// Register a tid→slot mapping (both internal + lock-free external).
    fn register_tid(&mut self, tid: ThreadId, slot: usize) {
        if (tid.0 as usize) < MAX_THREADS {
            self.tid_to_slot[tid.0 as usize] = Some(slot as u32);
            TID_TO_SLOT[tid.0 as usize].store(slot as u32, Ordering::Release);
        }
    }

    /// Unregister a tid→slot mapping (on thread death).
    fn unregister_tid(&mut self, tid: ThreadId) {
        if (tid.0 as usize) < MAX_THREADS {
            self.tid_to_slot[tid.0 as usize] = None;
            TID_TO_SLOT[tid.0 as usize].store(0xFFFF_FFFF, Ordering::Release);
        }
    }
}

// SMP: TicketMutex ensures FIFO ordering — prevents starvation where one CPU
// repeatedly wins the spin::Mutex while the other starves forever.
pub static SCHEDULER: TicketMutex<Scheduler> = TicketMutex::new(Scheduler::new());

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Initialize the scheduler and create the idle thread (thread 0) for the BSP.
pub fn init() {
    let mut sched = SCHEDULER.lock();
    let percpu = percpu::current_percpu();

    // Tier 5 KARL: seed next_id from the per-boot offset (mod a small
    // safe range so the first allocations stay well inside MAX_THREADS).
    // Boot 1 might assign tids 0x40..0x4F, boot 2 0x73..0x82, etc.
    sched.next_id = crate::karl::thread_id_offset() & 0x7F;

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
        cpu_ticks: 0,
        cpu_tick_limit: 0,
        mem_pages: 0,
        mem_page_limit: 0,
        compute_target: ComputeTarget::Cpu,
        deadline_ticks: 0,
        period_ticks: 0,
        ipc_timeout: 0,
        ipc_timed_out: false,
        fs_base: 0,
        gs_base: 0,
        redirect_saved_regs: [0; 18],
        signal_saved_regs: [0; 18],
        signal_ctx_valid: false,
        signal_trampoline: 0,
        pending_signals: 0,
        kernel_signal: 0,
        fpu_state: thread::FpuState::zeroed(),
        last_fault_rip: 0,
        fault_addr: 0,
        fault_code: 0,
        signal_saved_rip: 0,
        signal_saved_rflags: 0,
    };
    let tid = ThreadId(sched.next_id);
    let handle = sched.threads.alloc(idle);
    let slot = handle.index();
    sched.register_tid(tid, slot);
    sched.next_id += 1;

    percpu.idle_thread = slot;
    percpu.current_thread = slot;

    kdebug!("  scheduler: priority MLQ with work stealing + EDF (SMP)");
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
        cpu_ticks: 0,
        cpu_tick_limit: 0,
        mem_pages: 0,
        mem_page_limit: 0,
        compute_target: ComputeTarget::Cpu,
        deadline_ticks: 0,
        period_ticks: 0,
        ipc_timeout: 0,
        ipc_timed_out: false,
        fs_base: 0,
        gs_base: 0,
        redirect_saved_regs: [0; 18],
        signal_saved_regs: [0; 18],
        signal_ctx_valid: false,
        signal_trampoline: 0,
        pending_signals: 0,
        kernel_signal: 0,
        fpu_state: thread::FpuState::zeroed(),
        last_fault_rip: 0,
        fault_addr: 0,
        fault_code: 0,
        signal_saved_rip: 0,
        signal_saved_rflags: 0,
    };
    let handle = sched.threads.alloc(idle);
    let slot = handle.index();
    sched.register_tid(tid, slot);
    sched.next_id += 1;
    slot
}

/// Spawn a new kernel thread.
#[allow(dead_code)]
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
    spawn_user_opt(user_rip, user_rsp, cr3, None, 0)
}

/// Spawn a new user thread with an optional pre-set redirect endpoint.
/// The redirect is set atomically before the thread is enqueued, avoiding
/// race conditions where the thread runs before redirect_set is called.
pub fn spawn_user_with_redirect(user_rip: u64, user_rsp: u64, cr3: u64, ep_id: u32) -> ThreadId {
    spawn_user_opt(user_rip, user_rsp, cr3, Some(ep_id), 0)
}

/// Spawn a new user thread with redirect endpoint AND signal trampoline
/// set atomically before enqueue. Prevents the race where the thread
/// faults before signal_entry() is called.
pub fn spawn_user_with_redirect_and_signal(
    user_rip: u64, user_rsp: u64, cr3: u64, ep_id: u32, signal_tramp: u64,
) -> ThreadId {
    spawn_user_opt(user_rip, user_rsp, cr3, Some(ep_id), signal_tramp)
}

fn spawn_user_opt(user_rip: u64, user_rsp: u64, cr3: u64, redirect_ep: Option<u32>, signal_tramp: u64) -> ThreadId {
    let mut sched = SCHEDULER.lock();
    let id = sched.next_id;
    sched.next_id += 1;

    let mut t = Thread::new_user(id, user_rip, user_rsp, cr3, user_thread_trampoline);
    t.timeslice = TIMESLICE;
    t.redirect_ep = redirect_ep;
    if signal_tramp != 0 {
        t.signal_trampoline = signal_tramp;
    }
    let tid = t.id;

    let handle = sched.threads.alloc(t);
    let slot = handle.index();
    sched.register_tid(tid, slot);
    sched.enqueue(slot);
    tid
}

/// Terminate the current thread and switch away.
pub fn exit_current() -> ! {
    // Check for redirect endpoint BEFORE acquiring scheduler lock,
    // since send() acquires the endpoint lock (avoid nesting).
    let redirect_ep = {
        let percpu = percpu::current_percpu();
        let idx = percpu.current_thread;
        if idx != usize::MAX {
            let sched = SCHEDULER.lock();
            let rep = sched.threads.get_by_index(idx as u32)
                .and_then(|t| t.redirect_ep);
            rep
        } else {
            None
        }
    };
    // Diagnostic: log thread death (lock-free serial write)
    {
        use crate::arch::serial;
        for b in b"EXIT-T " { serial::write_byte(*b); }
        let percpu = percpu::current_percpu();
        let idx = percpu.current_thread as u64;
        // Write index as decimal
        if idx >= 10 { serial::write_byte(b'0' + ((idx / 10) % 10) as u8); }
        serial::write_byte(b'0' + (idx % 10) as u8);
        if redirect_ep.is_some() {
            for b in b" redir=Y\n" { serial::write_byte(*b); }
        } else {
            for b in b" redir=N\n" { serial::write_byte(*b); }
        }
    }
    // Send synthetic SYS_EXIT_GROUP to the handler so it can clean up
    // (pipe refs, memory, etc.) instead of blocking on recv forever.
    if let Some(ep_raw) = redirect_ep {
        let exit_msg = crate::ipc::endpoint::Message {
            tag: 231, // SYS_EXIT_GROUP
            regs: [139, 0, 0, 0, 0, 0, 0, 0], // status=139 (SIGSEGV-like)
            cap_transfer: None,
        };
        let ep_handle = crate::pool::PoolHandle::from_raw(ep_raw);
        let _ = crate::ipc::endpoint::send(ep_handle, exit_msg);
    }
    // Now mark the thread as Dead.
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
    let saved_idx;
    {
        let percpu = percpu::current_percpu();
        saved_idx = percpu.current_thread;
        if saved_idx != usize::MAX {
            let mut sched = SCHEDULER.lock();
            if let Some(t) = sched.threads.get_mut_by_index(saved_idx as u32) {
                t.state = ThreadState::Blocked;
            }
        }
    }
    schedule();
}

/// Set state to Blocked WITHOUT calling schedule(). Used when the caller
/// must hold an outer lock (e.g., NOTIFICATIONS) during the state transition
/// to prevent missed-wakeup races on SMP. The caller must call schedule()
/// after releasing the outer lock.
pub fn block_current_state_only() {
    let percpu = percpu::current_percpu();
    let idx = percpu.current_thread;
    if idx != usize::MAX {
        let mut sched = SCHEDULER.lock();
        if let Some(t) = sched.threads.get_mut_by_index(idx as u32) {
            t.state = ThreadState::Blocked;
        }
    }
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
            t.ipc_timed_out = false;
            if t.state == ThreadState::Blocked {
                t.state = ThreadState::Ready;
                t.timeslice = TIMESLICE;
                sched.enqueue(slot as usize);
            }
        }
    }
}

/// Store IPC state on the current thread before blocking.
/// Uses per-thread IPC lock (no SCHEDULER.lock() needed).
pub fn set_current_ipc(ep_id: u32, role: IpcRole, msg: Message) {
    let percpu = percpu::current_percpu();
    let idx = percpu.current_thread;
    if idx != usize::MAX && idx < MAX_THREADS {
        let mut ipc = THREAD_IPC[idx].lock();
        ipc.endpoint = Some(ep_id);
        ipc.role = role;
        ipc.msg = msg;
    }
}

/// Clear IPC state on the current thread after waking.
/// Uses per-thread IPC lock (no SCHEDULER.lock() needed).
pub fn clear_current_ipc() {
    let percpu = percpu::current_percpu();
    let idx = percpu.current_thread;
    if idx != usize::MAX && idx < MAX_THREADS {
        let mut ipc = THREAD_IPC[idx].lock();
        ipc.endpoint = None;
        ipc.role = IpcRole::None;
    }
}

/// Write a message into a specific thread's IPC buffer. O(1).
/// Uses per-thread IPC lock + lock-free TID→slot lookup.
pub fn write_ipc_msg(tid: ThreadId, msg: Message) -> bool {
    if let Some(slot) = tid_to_slot_external(tid) {
        let mut ipc = THREAD_IPC[slot as usize].lock();
        ipc.msg = msg;
        return true;
    }
    false
}

/// Set IPC timeout on the current thread. `deadline` is an absolute tick count.
pub fn set_current_ipc_timeout(deadline: u64) {
    let percpu = percpu::current_percpu();
    let idx = percpu.current_thread;
    if idx != usize::MAX {
        let mut sched = SCHEDULER.lock();
        if let Some(t) = sched.threads.get_mut_by_index(idx as u32) {
            t.ipc_timeout = deadline;
            t.ipc_timed_out = false;
        }
    }
}

/// Check and clear the IPC timeout flag on the current thread.
/// Returns true if the thread was woken by timeout rather than a reply.
pub fn check_and_clear_ipc_timeout() -> bool {
    let percpu = percpu::current_percpu();
    let idx = percpu.current_thread;
    if idx != usize::MAX {
        let mut sched = SCHEDULER.lock();
        if let Some(t) = sched.threads.get_mut_by_index(idx as u32) {
            let timed_out = t.ipc_timed_out;
            t.ipc_timed_out = false;
            t.ipc_timeout = 0;
            return timed_out;
        }
    }
    false
}

/// Get the current global tick counter.
pub fn global_ticks() -> u64 {
    GLOBAL_TICKS.load(Ordering::Relaxed)
}

/// Read the message from a specific thread's IPC buffer. O(1).
/// Uses per-thread IPC lock + lock-free TID→slot lookup.
pub fn read_ipc_msg(tid: ThreadId) -> Message {
    if let Some(slot) = tid_to_slot_external(tid) {
        let ipc = THREAD_IPC[slot as usize].lock();
        return ipc.msg;
    }
    Message::empty()
}

/// Write a message into the current thread's IPC buffer (without touching endpoint/role).
/// Uses per-thread IPC lock (no SCHEDULER.lock() needed).
pub fn set_current_msg(msg: Message) {
    let percpu = percpu::current_percpu();
    let idx = percpu.current_thread;
    if idx != usize::MAX && idx < MAX_THREADS {
        let mut ipc = THREAD_IPC[idx].lock();
        ipc.msg = msg;
    }
}

/// Read the current thread's own IPC message buffer (after being woken).
/// Uses per-thread IPC lock (no SCHEDULER.lock() needed).
pub fn current_ipc_msg() -> Message {
    let percpu = percpu::current_percpu();
    let idx = percpu.current_thread;
    if idx != usize::MAX && idx < MAX_THREADS {
        let ipc = THREAD_IPC[idx].lock();
        return ipc.msg;
    }
    Message::empty()
}

// ---------------------------------------------------------------------------
// Resource Limits
// ---------------------------------------------------------------------------

/// Set resource limits for a thread.
pub fn set_resource_limits(tid: ThreadId, cpu_limit: u64, mem_limit: u32) {
    let mut sched = SCHEDULER.lock();
    if let Some(slot) = sched.slot_of(tid) {
        if let Some(t) = sched.threads.get_mut_by_index(slot) {
            t.cpu_tick_limit = cpu_limit;
            t.mem_page_limit = mem_limit;
        }
    }
}

/// Get thread info: (tid, state, priority, cpu_ticks, mem_pages, is_user).
pub fn thread_info(idx: u32) -> Option<(u32, u8, u8, u64, u32, bool)> {
    let sched = SCHEDULER.lock();
    sched.threads.get_by_index(idx).map(|t| {
        let state_byte = match t.state {
            ThreadState::Ready => 0,
            ThreadState::Running => 1,
            ThreadState::Blocked => 2,
            ThreadState::Faulted => 3,
            ThreadState::Dead => 4,
        };
        (t.id.0, state_byte, t.priority, t.cpu_ticks, t.mem_pages, t.is_user)
    })
}

/// Track a memory page allocation for the current thread.
pub fn track_mem_alloc() -> bool {
    let percpu = percpu::current_percpu();
    let idx = percpu.current_thread;
    if idx == usize::MAX { return true; }
    let mut sched = SCHEDULER.lock();
    if let Some(t) = sched.threads.get_mut_by_index(idx as u32) {
        if t.mem_page_limit > 0 && t.mem_pages >= t.mem_page_limit {
            return false; // limit reached
        }
        t.mem_pages += 1;
    }
    true
}

/// Track a memory page free for the current thread.
pub fn track_mem_free() {
    let percpu = percpu::current_percpu();
    let idx = percpu.current_thread;
    if idx == usize::MAX { return; }
    let mut sched = SCHEDULER.lock();
    if let Some(t) = sched.threads.get_mut_by_index(idx as u32) {
        if t.mem_pages > 0 {
            t.mem_pages -= 1;
        }
    }
}

/// Set the compute target for a thread.
pub fn set_compute_target(tid: ThreadId, target: ComputeTarget) {
    let mut sched = SCHEDULER.lock();
    if let Some(slot) = sched.slot_of(tid) {
        if let Some(t) = sched.threads.get_mut_by_index(slot) {
            t.compute_target = target;
        }
    }
}

/// Set deadline scheduling parameters for a thread.
///
/// `deadline` is the absolute tick count by which the thread must complete.
/// `period` is the repetition interval (0 = aperiodic / one-shot deadline).
/// When a periodic deadline expires, the next deadline = old + period.
/// Setting deadline=0 removes the thread from EDF scheduling.
pub fn set_deadline(tid: ThreadId, deadline: u64, period: u64) {
    let mut sched = SCHEDULER.lock();
    if let Some(slot) = sched.slot_of(tid) {
        if let Some(t) = sched.threads.get_mut_by_index(slot) {
            t.deadline_ticks = deadline;
            t.period_ticks = period;
            kdebug!("  sched: tid {} deadline={} period={}", tid.0, deadline, period);
        }
    }
}

/// Get the total number of live threads.
pub fn thread_count() -> u32 {
    let sched = SCHEDULER.lock();
    let mut count = 0u32;
    for i in 0..MAX_THREADS as u32 {
        if sched.threads.get_by_index(i).is_some() {
            count += 1;
        }
    }
    count
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

/// Fused redirect preparation (ρ_fuse): get redirect endpoint + save regs +
/// get tid in ONE SCHEDULER.lock() acquisition (replaces 3 separate locks).
/// Returns (ep_raw, tid) or None if no redirect endpoint set.
pub fn prepare_redirect(frame: &TrapFrame, user_rsp: u64) -> Option<(u32, ThreadId)> {
    let percpu = percpu::current_percpu();
    let idx = percpu.current_thread;
    if idx == usize::MAX { return None; }
    let mut sched = SCHEDULER.lock();
    let t = sched.threads.get_mut_by_index(idx as u32)?;
    let ep = t.redirect_ep?;
    // Save full register state so LUCAS can read via SYS_GET_THREAD_REGS
    t.redirect_saved_regs = [
        frame.rax, frame.rbx, frame.rcx, frame.rdx,
        frame.rsi, frame.rdi, frame.rbp, frame.r8,
        frame.r9,  frame.r10, frame.r11, frame.r12,
        frame.r13, frame.r14, frame.r15, user_rsp,
        t.fs_base, t.gs_base,
    ];
    Some((ep, t.id))
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
// FS_BASE (TLS) API
// ---------------------------------------------------------------------------

/// Set the current thread's FS_BASE value and write the MSR immediately.
pub fn set_current_fs_base(value: u64) {
    let percpu = percpu::current_percpu();
    let idx = percpu.current_thread;
    if idx != usize::MAX {
        let mut sched = SCHEDULER.lock();
        if let Some(t) = sched.threads.get_mut_by_index(idx as u32) {
            t.fs_base = value;
        }
    }
    write_fs_base_msr(value);
}

/// Set a thread's FS_BASE by TID (for CoW fork — child inherits parent's TLS).
pub fn set_thread_fs_base(tid: ThreadId, value: u64) {
    let mut sched = SCHEDULER.lock();
    if let Some(slot) = sched.slot_of(tid) {
        if let Some(t) = sched.threads.get_mut_by_index(slot) {
            t.fs_base = value;
        }
    }
}

/// Get the current thread's FS_BASE value.
pub fn get_current_fs_base() -> u64 {
    let percpu = percpu::current_percpu();
    let idx = percpu.current_thread;
    if idx != usize::MAX {
        let sched = SCHEDULER.lock();
        if let Some(t) = sched.threads.get_by_index(idx as u32) {
            return t.fs_base;
        }
    }
    0
}

// ---------------------------------------------------------------------------
// GS_BASE (user GS) API
// ---------------------------------------------------------------------------

/// Set the current thread's user GS_BASE and write KERNEL_GS_BASE MSR.
/// Called from arch_prctl(ARCH_SET_GS). In kernel mode after swapgs,
/// the user's GS value lives in KERNEL_GS_BASE.
pub fn set_current_gs_base(value: u64) {
    let percpu = percpu::current_percpu();
    let idx = percpu.current_thread;
    if idx != usize::MAX {
        let mut sched = SCHEDULER.lock();
        if let Some(t) = sched.threads.get_mut_by_index(idx as u32) {
            t.gs_base = value;
        }
    }
    write_kernel_gs_base_msr(value);
}

/// Set a thread's GS_BASE by TID (for CoW fork — child inherits parent's GS).
pub fn set_thread_gs_base(tid: ThreadId, value: u64) {
    let mut sched = SCHEDULER.lock();
    if let Some(slot) = sched.slot_of(tid) {
        if let Some(t) = sched.threads.get_mut_by_index(slot) {
            t.gs_base = value;
        }
    }
}

/// Get the current thread's user GS_BASE value.
pub fn get_current_gs_base() -> u64 {
    let percpu = percpu::current_percpu();
    let idx = percpu.current_thread;
    if idx != usize::MAX {
        let sched = SCHEDULER.lock();
        if let Some(t) = sched.threads.get_by_index(idx as u32) {
            return t.gs_base;
        }
    }
    0
}

// ---------------------------------------------------------------------------
// Signal delivery support
// ---------------------------------------------------------------------------

use crate::arch::x86_64::syscall::TrapFrame;

/// Save the current thread's full register state during a syscall redirect.
/// Called in syscall_dispatch before endpoint::call() so LUCAS can later
/// read the registers via SYS_GET_THREAD_REGS.
pub fn save_current_redirect_regs(frame: &TrapFrame, user_rsp: u64) {
    let percpu = percpu::current_percpu();
    let idx = percpu.current_thread;
    if idx == usize::MAX { return; }
    let mut sched = SCHEDULER.lock();
    if let Some(t) = sched.threads.get_mut_by_index(idx as u32) {
        t.redirect_saved_regs = [
            frame.rax, frame.rbx, frame.rcx, frame.rdx,
            frame.rsi, frame.rdi, frame.rbp, frame.r8,
            frame.r9,  frame.r10, frame.r11, frame.r12,
            frame.r13, frame.r14, frame.r15, user_rsp,
            t.fs_base, t.gs_base,
        ];
    }
}

/// Read the saved redirect registers for a given thread (by tid).
/// Returns [rax,rbx,rcx,rdx,rsi,rdi,rbp,r8..r15,rsp,fs_base,gs_base] or None.
pub fn get_thread_redirect_regs(tid: ThreadId) -> Option<[u64; 18]> {
    let sched = SCHEDULER.lock();
    if let Some(slot) = sched.slot_of(tid) {
        if let Some(t) = sched.threads.get_by_index(slot) {
            return Some(t.redirect_saved_regs);
        }
    }
    None
}

/// Read the saved async signal context for a given thread (by tid).
/// Falls back to redirect_saved_regs if no async context is available.
/// Returns 20 u64s: [0..14]=GPRs, [15]=RSP, [16]=fs_base, [17]=kernel_signal,
/// [18]=real_rip, [19]=real_rflags.
/// When signal_ctx_valid, regs[17] is overridden with kernel_signal (consumed on read),
/// and [18]/[19] contain the real user RIP/RFLAGS from the interrupt frame.
/// When not signal_ctx_valid: [18]/[19] = 0 (use rcx/r11 as rip/rflags per SYSCALL ABI).
pub fn get_thread_signal_regs(tid: ThreadId) -> Option<[u64; 20]> {
    let mut sched = SCHEDULER.lock();
    if let Some(slot) = sched.slot_of(tid) {
        if let Some(t) = sched.threads.get_mut_by_index(slot) {
            if t.signal_ctx_valid {
                let mut regs = [0u64; 20];
                regs[..18].copy_from_slice(&t.signal_saved_regs);
                // Override regs[17] with kernel_signal.
                regs[17] = t.kernel_signal;
                t.kernel_signal = 0; // Consume: only deliver once
                // Real RIP/RFLAGS from interrupt frame (not clobbered by SYSCALL)
                regs[18] = t.signal_saved_rip;
                regs[19] = t.signal_saved_rflags;
                // Auto-clear: context consumed. Next timer interrupt can save
                // fresh context. Without this, signal_ctx_valid stays true
                // forever, and all future get_thread_regs calls return this
                // stale RIP — causing Wine to jump to garbage addresses.
                t.signal_ctx_valid = false;
                return Some(regs);
            }
            let mut regs = [0u64; 20];
            regs[..18].copy_from_slice(&t.redirect_saved_regs);
            // [18]/[19] stay 0 → init should use rcx/r11 as rip/rflags
            return Some(regs);
        }
    }
    None
}

/// Clear the signal_ctx_valid flag after LUCAS has consumed the async context.
pub fn clear_signal_ctx(tid: ThreadId) {
    let mut sched = SCHEDULER.lock();
    if let Some(slot) = sched.slot_of(tid) {
        if let Some(t) = sched.threads.get_mut_by_index(slot) {
            t.signal_ctx_valid = false;
        }
    }
}

/// Set the signal trampoline address for a thread.
pub fn set_signal_trampoline(tid: ThreadId, addr: u64) {
    let mut sched = SCHEDULER.lock();
    if let Some(slot) = sched.slot_of(tid) {
        if let Some(t) = sched.threads.get_mut_by_index(slot) {
            t.signal_trampoline = addr;
        }
    }
}

/// Get the signal trampoline address for a thread.
pub fn get_signal_trampoline_by_idx(idx: u32) -> u64 {
    let sched = SCHEDULER.lock();
    if let Some(t) = sched.threads.get_by_index(idx) {
        t.signal_trampoline
    } else {
        0
    }
}

/// Get the last fault RIP for a thread (by index, no lock needed for read).
pub fn get_last_fault_rip_by_idx(idx: u32) -> u64 {
    let sched = SCHEDULER.lock();
    if let Some(t) = sched.threads.get_by_index(idx) {
        t.last_fault_rip
    } else {
        0
    }
}

/// Set the last fault RIP for a thread (by index).
pub fn set_last_fault_rip_by_idx(idx: u32, rip: u64) {
    let mut sched = SCHEDULER.lock();
    if let Some(t) = sched.threads.get_mut_by_index(idx) {
        t.last_fault_rip = rip;
    }
}

/// Set a pending signal bit on a thread.
/// Signal 0 is rejected (not a real signal).
pub fn set_pending_signal(tid: ThreadId, sig: u64) {
    if sig == 0 || sig >= 64 { return; }
    let mut sched = SCHEDULER.lock();
    if let Some(slot) = sched.slot_of(tid) {
        if let Some(t) = sched.threads.get_mut_by_index(slot) {
            t.pending_signals |= 1 << sig;
        }
    }
}

/// Get pending signals for a thread (by pool index).
pub fn get_pending_signals_by_idx(idx: u32) -> u64 {
    let sched = SCHEDULER.lock();
    if let Some(t) = sched.threads.get_by_index(idx) {
        t.pending_signals
    } else {
        0
    }
}

/// Clear a pending signal bit for a thread (by pool index).
pub fn clear_pending_signal_by_idx(idx: u32, sig: u64) {
    let mut sched = SCHEDULER.lock();
    if let Some(t) = sched.threads.get_mut_by_index(idx) {
        t.pending_signals &= !(1 << sig);
    }
}

/// Save the async signal context (from timer interrupt) for the current thread.
/// Called from the custom timer handler when redirecting a user thread.
/// Returns true if context was saved, false if already saved (by #PF handler).
pub fn save_signal_context_current(gprs: &[u64; 15], rip: u64, rsp: u64, rflags: u64) -> bool {
    let percpu = percpu::current_percpu();
    let idx = percpu.current_thread;
    if idx == usize::MAX { return false; }
    let mut sched = SCHEDULER.lock();
    if let Some(t) = sched.threads.get_mut_by_index(idx as u32) {
        // If #PF handler already saved context, don't overwrite
        if t.signal_ctx_valid {
            return false;
        }
        t.signal_saved_regs = [
            gprs[0],  gprs[1],  gprs[2],  gprs[3],   // rax, rbx, rcx, rdx
            gprs[4],  gprs[5],  gprs[6],  gprs[7],   // rsi, rdi, rbp, r8
            gprs[8],  gprs[9],  gprs[10], gprs[11],  // r9, r10, r11, r12
            gprs[12], gprs[13], gprs[14], rsp,        // r13, r14, r15, rsp
            t.fs_base, t.gs_base,
        ];
        // Store the real user RIP/RFLAGS separately — do NOT clobber the
        // original RCX/R11 slots, which Wine needs in the ucontext.
        t.signal_saved_rip = rip;
        t.signal_saved_rflags = rflags;
        t.signal_ctx_valid = true;
        return true;
    }
    false
}

/// Set kernel-generated signal for the current thread (e.g., SIGSEGV from #PF).
pub fn set_kernel_signal_current(sig: u64) {
    let percpu = percpu::current_percpu();
    let idx = percpu.current_thread;
    if idx == usize::MAX { return; }
    let mut sched = SCHEDULER.lock();
    if let Some(t) = sched.threads.get_mut_by_index(idx as u32) {
        t.kernel_signal = sig;
    }
}

/// Set fault address and error code for the current thread (from #PF handler).
/// Init reads these via get_thread_signal_regs to populate siginfo/ucontext.
pub fn set_fault_info_current(addr: u64, code: u64) {
    let percpu = percpu::current_percpu();
    let idx = percpu.current_thread;
    if idx == usize::MAX { return; }
    let mut sched = SCHEDULER.lock();
    if let Some(t) = sched.threads.get_mut_by_index(idx as u32) {
        t.fault_addr = addr;
        t.fault_code = code;
    }
}

/// Check if current thread is a user thread (for timer handler).
pub fn is_current_user_thread() -> bool {
    let percpu = percpu::current_percpu();
    let idx = percpu.current_thread;
    if idx == usize::MAX { return false; }
    let sched = SCHEDULER.lock();
    if let Some(t) = sched.threads.get_by_index(idx as u32) {
        t.is_user
    } else {
        false
    }
}

// ---------------------------------------------------------------------------
// Fused IPC helpers (ρ_fuse + ρ_ooo: batched lock acquisitions for hot path)
// ---------------------------------------------------------------------------

/// Fused call pre-block (rendezvous): write msg to receiver, wake it,
/// set caller IPC state, block caller.
/// Uses per-thread IPC locks for message access, SCHEDULER.lock() only for
/// run-queue mutation (wake + block). Replaces 5 separate lock acquisitions.
pub fn call_fused_preblock_rendezvous(
    recv_tid: ThreadId, msg: Message, ep_raw: u32,
) {
    let caller_slot = percpu::current_percpu().current_thread;
    let recv_slot = tid_to_slot_external(recv_tid)
        .unwrap_or_else(|| {
            SCHEDULER.lock().slot_of(recv_tid).unwrap_or(0)
        }) as usize;

    // Step 1: Write message to receiver (per-thread lock, zero cross-thread contention)
    {
        let mut recv_ipc = THREAD_IPC[recv_slot].lock();
        recv_ipc.msg = msg;
    }

    // Step 2: Set caller IPC state (per-thread lock)
    if caller_slot != usize::MAX && caller_slot < MAX_THREADS {
        let mut caller_ipc = THREAD_IPC[caller_slot].lock();
        caller_ipc.endpoint = Some(ep_raw);
        caller_ipc.role = IpcRole::Caller;
        caller_ipc.msg = Message::empty();
    }

    // Step 3: Wake receiver + block caller (SCHEDULER.lock() for run-queue only)
    {
        let mut sched = SCHEDULER.lock();
        if let Some(t) = sched.threads.get_mut_by_index(recv_slot as u32) {
            t.ipc_timed_out = false;
            if t.state == ThreadState::Blocked {
                t.state = ThreadState::Ready;
                t.timeslice = TIMESLICE;
                sched.enqueue(recv_slot);
            }
        }
        if caller_slot != usize::MAX {
            if let Some(t) = sched.threads.get_mut_by_index(caller_slot as u32) {
                t.state = ThreadState::Blocked;
            }
        }
    }
    schedule();
}

/// Fused call pre-block (no receiver ready): store msg in own IPC buffer, block.
/// Uses per-thread IPC lock for message, SCHEDULER.lock() only for state change.
pub fn call_fused_preblock(msg: Message, ep_raw: u32) {
    let caller_slot = percpu::current_percpu().current_thread;

    // Set caller IPC state (per-thread lock)
    if caller_slot != usize::MAX && caller_slot < MAX_THREADS {
        let mut ipc = THREAD_IPC[caller_slot].lock();
        ipc.endpoint = Some(ep_raw);
        ipc.role = IpcRole::Caller;
        ipc.msg = msg;
    }

    // Block (SCHEDULER.lock() for run-queue)
    {
        if caller_slot != usize::MAX {
            let mut sched = SCHEDULER.lock();
            if let Some(t) = sched.threads.get_mut_by_index(caller_slot as u32) {
                t.state = ThreadState::Blocked;
            }
        }
    }
    schedule();
}

/// Fused call post-wakeup: read reply + clear IPC state (per-thread lock only).
/// No SCHEDULER.lock() needed.
pub fn call_fused_postwake() -> Message {
    let idx = percpu::current_percpu().current_thread;
    if idx != usize::MAX && idx < MAX_THREADS {
        let mut ipc = THREAD_IPC[idx].lock();
        let msg = ipc.msg;
        ipc.endpoint = None;
        ipc.role = IpcRole::None;
        return msg;
    }
    Message::empty()
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
    kdebug!("  domain: created (quantum={} period={} ticks)", quantum_ticks, period_ticks);
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
            None => {
                // Lock contended. If we're the idle thread, check local queue
                // directly — don't skip, or idle CPUs miss enqueued threads.
                let percpu = percpu::current_percpu();
                let my_cpu = percpu.cpu_index as usize;
                if percpu.current_thread == percpu.idle_thread {
                    if let Some(q) = PER_CPU_QUEUES[my_cpu % MAX_CPUS].try_lock() {
                        if !q.is_empty() {
                            drop(q);
                            // Queue has work — force reschedule ASAP.
                            // Can't call schedule() here (needs SCHEDULER lock),
                            // but the next timer tick will pick it up since we
                            // won't be contended forever.
                        }
                    }
                }
                return;
            }
        };
        let percpu = percpu::current_percpu();
        let idx = percpu.current_thread;
        let mut resched = false;
        // If running idle thread and local queue has work, force reschedule.
        if idx == percpu.idle_thread {
            let my_cpu = percpu.cpu_index as usize;
            if let Some(q) = PER_CPU_QUEUES[my_cpu % MAX_CPUS].try_lock() {
                if !q.is_empty() {
                    resched = true;
                }
            }
        }

        if idx != usize::MAX {
            if let Some(t) = sched.threads.get_mut_by_index(idx as u32) {
                // Track CPU usage.
                t.cpu_ticks += 1;

                // Check CPU tick limit.
                if t.cpu_tick_limit > 0 && t.cpu_ticks >= t.cpu_tick_limit {
                    t.state = ThreadState::Dead;
                    resched = true;
                }

                if t.timeslice > 0 {
                    t.timeslice -= 1;
                }
                if t.timeslice == 0 {
                    resched = true;
                }

                // Deadline check: if this thread has a deadline and it has passed,
                // renew periodic deadlines or clear aperiodic ones.
                if t.deadline_ticks > 0 && global_now >= t.deadline_ticks {
                    if t.period_ticks > 0 {
                        // Periodic: advance deadline to the next period.
                        t.deadline_ticks += t.period_ticks;
                    } else {
                        // Aperiodic: deadline expired, clear it.
                        t.deadline_ticks = 0;
                    }
                }

                // Domain budget tracking.
                if let Some(dom_idx) = t.domain_idx {
                    if let Some(dom) = sched.domains.get_mut_by_index(dom_idx) {
                        dom.consumed_ticks += 1;
                        if dom.consumed_ticks >= dom.quantum_ticks && dom.state == DomainState::Active {
                            dom.state = DomainState::Depleted;
                            kdebug!("  domain: depleted (consumed={}/{})", dom.consumed_ticks, dom.quantum_ticks);
                            resched = true;
                        }
                    }
                }
            }
        }

        // Check all domain refills.
        check_domain_refills(&mut sched, global_now);

        // Check IPC timeouts on blocked threads.
        check_ipc_timeouts(&mut sched, global_now);

        resched
    };

    if needs_reschedule {
        // Use try_schedule instead of schedule: tick() runs from interrupt
        // context where blocking on SCHEDULER lock causes thundering herd
        // on TCG with 4+ vCPUs. If lock is contended, next tick will retry.
        try_schedule();
    }
}

/// Wake any blocked threads whose IPC timeout has expired.
fn check_ipc_timeouts(sched: &mut Scheduler, global_now: u64) {
    for idx in 0..MAX_THREADS as u32 {
        if let Some(t) = sched.threads.get_mut_by_index(idx) {
            if t.state == ThreadState::Blocked && t.ipc_timeout > 0 && global_now >= t.ipc_timeout {
                t.ipc_timeout = 0;
                t.ipc_timed_out = true;
                t.state = ThreadState::Ready;
                t.timeslice = TIMESLICE;
                sched.enqueue(idx as usize);
            }
        }
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
                    kdebug!("  domain: refilled, {} threads re-enqueued", suspended.len());
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
///
/// Non-blocking schedule attempt for interrupt context (reschedule IPI).
/// Non-blocking reschedule for IPI context. If SCHEDULER lock is contended,
/// returns immediately — next timer tick will retry.
///
/// IMPORTANT: Does NOT dequeue before try_lock. The old approach (try_lock →
/// drop → schedule → lock) had a TOCTOU: between drop and lock, another CPU
/// grabs the lock, causing all IPIs to pile up on a blocking lock(). With 4+
/// CPUs on TCG this causes a thundering herd and apparent hang.
pub fn try_schedule() {
    let percpu = percpu::current_percpu();
    let old_idx = percpu.current_thread;
    if old_idx == usize::MAX { return; }

    // Only proceed if we can get the lock without spinning.
    // If contended, bail — the timer tick will call schedule() with the
    // blocking lock, which is safe because timer ticks are serialized per-CPU.
    if SCHEDULER.try_lock().is_none() {
        return;
    }
    // Lock was acquired and immediately dropped by try_lock().
    // Call schedule() which will re-acquire it. Since we JUST released it,
    // TicketMutex guarantees minimal contention (we're likely next in line).
    schedule();
}

/// ρ_buf optimization: per-CPU queue dequeue happens BEFORE taking
/// SCHEDULER.lock(), eliminating O(p) contention on the global lock for
/// queue operations. SCHEDULER.lock() is only held for thread state
/// validation and context-switch setup.
pub fn schedule() {
    // Discard target for dead threads (slot freed before context switch).
    let mut discard_rsp: u64 = 0;

    // Phase 1: Dequeue candidate from per-CPU queues (per-CPU locks only,
    // NO global SCHEDULER.lock()). This is the ρ_buf decoupling buffer.
    let percpu_early = percpu::current_percpu();
    let old_idx_early = percpu_early.current_thread;
    if old_idx_early == usize::MAX {
        return;
    }
    let my_cpu = percpu_early.cpu_index as usize;
    let candidate = dequeue_from_any(my_cpu);

    // Fast path: idle CPU with empty queues → skip SCHEDULER.lock() entirely.
    // This eliminates O(p) contention from idle cores on the global lock,
    // which starves active threads on QEMU TCG with 4+ vCPUs.
    if candidate.is_none() && old_idx_early == percpu_early.idle_thread {
        return;
    }

    // Phase 2: Lock SCHEDULER for thread state + context-switch setup.
    let switch_info: Option<(*mut u64, u64, usize, *const u8)> = {
        let mut sched = SCHEDULER.lock();
        let percpu = percpu::current_percpu();

        let old_idx = percpu.current_thread;
        if old_idx == usize::MAX {
            // If candidate was dequeued, put it back.
            if let Some(idx) = candidate {
                sched.enqueue(idx);
            }
            return;
        }

        // Validate candidate against state + domain/compute constraints.
        // SMP fix: between Phase 1 (dequeue without SCHEDULER lock) and Phase 2
        // (here, with lock), another CPU may have changed the thread's state
        // (e.g., Blocked via notify_wait). Re-enqueue if no longer Ready.
        let new_idx = if let Some(idx) = candidate {
            let valid = {
                match sched.threads.get_by_index(idx as u32) {
                    None => false, // Thread gone
                    Some(t) => {
                        // SMP race guard: reject threads that became Blocked/Dead
                        // between Phase 1 dequeue and Phase 2 lock acquisition.
                        if t.state == ThreadState::Blocked || t.state == ThreadState::Dead {
                            false
                        } else if t.compute_target != ComputeTarget::Cpu {
                            false // GPU/NPU thread — re-enqueue
                        } else {
                            match t.domain_idx {
                                None => true,
                                Some(di) => {
                                    let is_active = sched.domains.get_by_index(di)
                                        .map_or(true, |d| d.state == DomainState::Active);
                                    if !is_active {
                                        if let Some(dom) = sched.domains.get_mut_by_index(di) {
                                            dom.suspended.push(idx);
                                        }
                                    }
                                    is_active
                                }
                            }
                        }
                    }
                }
            };
            if valid {
                idx
            } else {
                // Invalid candidate. Re-enqueue if not suspended.
                let was_suspended = sched.threads.get_by_index(idx as u32)
                    .and_then(|t| t.domain_idx).is_some();
                if !was_suspended {
                    sched.enqueue(idx);
                }
                // Fall through to idle/stay logic
                let old_t = match sched.threads.get_mut_by_index(old_idx as u32) {
                    Some(t) => t,
                    None => return,
                };
                if old_t.state == ThreadState::Running {
                    old_t.timeslice = TIMESLICE;
                    return;
                }
                let idle_idx = percpu.idle_thread;
                if old_idx == idle_idx { return; }
                idle_idx
            }
        } else {
            // No candidate from any queue.
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
        };

        // Self-switch guard: if we dequeued ourselves (e.g., woken between
        // block_current_state_only and schedule on SMP), skip context switch.
        if new_idx == old_idx {
            if let Some(t) = sched.threads.get_mut_by_index(new_idx as u32) {
                t.state = ThreadState::Running;
                t.timeslice = TIMESLICE;
            }
            return;
        }

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
            &mut discard_rsp as *mut u64
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
                // Sanity check: verify PML4 entry 511 (kernel code) is present.
                // A missing entry causes a triple fault on the next interrupt.
                let hhdm = crate::mm::hhdm_offset();
                let pml4_ptr = (target_cr3 + hhdm) as *const u64;
                let entry_511 = unsafe { *pml4_ptr.add(511) };
                if entry_511 & 1 == 0 {
                    // PML4[511] not present — kernel code would be unmapped!
                    // Re-copy from boot CR3 to repair.
                    let boot = crate::mm::paging::boot_cr3();
                    let boot_pml4 = (boot + hhdm) as *const u64;
                    let dst_pml4 = (target_cr3 + hhdm) as *mut u64;
                    unsafe {
                        for i in 256..512 {
                            let src_val = *boot_pml4.add(i);
                            if *dst_pml4.add(i) & 1 == 0 && src_val & 1 != 0 {
                                *dst_pml4.add(i) = src_val;
                            }
                        }
                    }
                    crate::kprintln!("SCHED: repaired PML4 high entries for cr3={:#x}", target_cr3);
                }
                unsafe {
                    core::arch::asm!(
                        "mov cr3, {}",
                        in(reg) target_cr3,
                        options(nostack, preserves_flags)
                    );
                }
            }
        }

        // Restore FS_BASE MSR for TLS support.
        let new_fs_base = new_t.fs_base;
        if new_fs_base != 0 {
            write_fs_base_msr(new_fs_base);
        }

        // Restore user GS_BASE (held in KERNEL_GS_BASE while in kernel mode).
        // Wine uses GS for the Thread Environment Block (TEB).
        let new_gs_base = new_t.gs_base;
        write_kernel_gs_base_msr(new_gs_base);

        // Save the FPU area addresses as raw pointers (avoids double-borrow).
        // old_rsp_ptr already gives us a pointer into the old thread's CpuContext.
        // We go from rsp field → Thread struct → fpu_state via byte offset.
        // Simpler: just store old_idx and compute later from the pool.
        let old_fpu_idx = old_idx;
        let new_fpu_ptr = new_t.fpu_state.data.as_ptr();

        Some((old_rsp_ptr, new_rsp, old_fpu_idx, new_fpu_ptr))
    };
    // Lock is dropped here ^

    if let Some((old_rsp_ptr, new_rsp, old_fpu_idx, new_fpu)) = switch_info {
        unsafe {
            // Save current thread's FPU/SSE state before switching.
            // Re-acquire the old thread's fpu_state pointer from the pool.
            {
                let sched = SCHEDULER.lock();
                if let Some(old_t) = sched.threads.get_by_index(old_fpu_idx as u32) {
                    let fpu_ptr = old_t.fpu_state.data.as_ptr() as *mut u8;
                    core::arch::asm!("fxsave64 [{}]", in(reg) fpu_ptr, options(nostack));
                }
            }
            context_switch(old_rsp_ptr, new_rsp);
            // After context_switch: we're the NEW thread. Restore FPU.
            // Check if the state was ever saved (first u16 = FCW; 0 means uninitialized).
            let fcw = *(new_fpu as *const u16);
            if fcw != 0 {
                core::arch::asm!("fxrstor64 [{}]", in(reg) new_fpu, options(nostack));
            } else {
                // First context switch for this thread — initialize FPU to default state.
                core::arch::asm!("fninit", options(nostack));
            }
        }
        finish_switch();
    }
}
