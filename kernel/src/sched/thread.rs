//! Thread management.
//!
//! Each thread has a Thread Control Block (TCB) with saved CPU state,
//! priority, and a reference to its capability space.

use crate::cap::CapId;
use crate::ipc::endpoint::Message;
use crate::mm;

/// IPC role of a thread (when blocked on an endpoint).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpcRole {
    /// Not participating in IPC.
    None,
    /// Blocked waiting to send.
    Sender,
    /// Blocked waiting to receive.
    Receiver,
    /// Blocked in a call (send then receive).
    #[allow(dead_code)]
    Caller,
}

/// Thread identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ThreadId(pub u32);

/// Thread lifecycle states.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ThreadState {
    /// Ready to run, in the run queue.
    Ready,
    /// Currently executing on a CPU.
    Running,
    /// Blocked waiting for IPC, I/O, or a lock.
    Blocked,
    /// Faulted — waiting for VMM to resolve page fault.
    Faulted,
    /// Terminated — slot will be freed after context switch.
    Dead,
}

/// Saved CPU context for context switching.
///
/// Only the stack pointer is stored here — callee-saved registers
/// (rbp, rbx, r12-r15) are pushed/popped on the kernel stack
/// by the context_switch assembly routine.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct CpuContext {
    pub rsp: u64,
}

impl CpuContext {
    pub const fn zero() -> Self {
        Self { rsp: 0 }
    }
}

/// Kernel stack: 4 frames = 16 KiB.
const STACK_FRAMES: usize = 4;
const STACK_SIZE: usize = STACK_FRAMES * 4096;

/// Thread Control Block.
#[derive(Clone, Copy)]
#[allow(dead_code)]
pub struct Thread {
    pub id: ThreadId,
    pub state: ThreadState,
    /// Scheduling priority (0 = highest, 255 = lowest).
    pub priority: u8,
    /// Saved register context for this thread.
    pub context: CpuContext,
    /// Handle to this thread's capability space.
    pub cap_space: Option<CapId>,
    /// Kernel stack base virtual address (bottom of allocation).
    pub kernel_stack_base: u64,
    /// Top of kernel stack (used for TSS.rsp0 and SYSCALL entry).
    pub kernel_stack_top: u64,
    /// Remaining ticks in this thread's timeslice.
    pub timeslice: u32,
    /// Whether this thread runs in Ring 3.
    pub is_user: bool,
    /// User-mode RIP (only meaningful if is_user).
    pub user_rip: u64,
    /// User-mode RSP (only meaningful if is_user).
    pub user_rsp: u64,
    /// Physical address of PML4 (0 = kernel thread, use boot CR3).
    pub cr3: u64,
    /// IPC message buffer (carried by the thread while blocked).
    pub ipc_msg: Message,
    /// Endpoint this thread is blocked on (if any).
    pub ipc_endpoint: Option<u32>,
    /// IPC role while blocked.
    pub ipc_role: IpcRole,
    /// Preferred CPU for scheduling (None = any CPU).
    pub preferred_cpu: Option<u32>,
    /// Scheduling domain this thread belongs to (raw pool index).
    pub domain_idx: Option<u32>,
    /// Endpoint for syscall redirection (LUCAS). When set, unknown syscalls
    /// are forwarded as IPC messages to this endpoint.
    pub redirect_ep: Option<u32>,
}

impl Thread {
    /// Create a new kernel thread with an allocated kernel stack.
    ///
    /// The initial stack frame is set up so that `context_switch` into this thread
    /// will pop callee-saved registers and `ret` into `trampoline`, which reads
    /// the entry function from r12 and calls it.
    #[allow(dead_code)]
    pub fn new(id: u32, entry: fn() -> !, priority: u8, trampoline: unsafe extern "C" fn() -> !) -> Self {
        let (stack_virt, stack_top) = alloc_kernel_stack();

        // Build initial stack frame (grows downward).
        // context_switch pops: r15, r14, r13, r12, rbx, rbp, then ret.
        unsafe {
            let top = stack_top as *mut u64;
            top.offset(-1).write(trampoline as u64); // return address
            top.offset(-2).write(0);                  // rbp
            top.offset(-3).write(0);                  // rbx
            top.offset(-4).write(entry as u64);       // r12
            top.offset(-5).write(0);                  // r13
            top.offset(-6).write(0);                  // r14
            top.offset(-7).write(0);                  // r15
        }

        Self {
            id: ThreadId(id),
            state: ThreadState::Ready,
            priority,
            context: CpuContext {
                rsp: stack_top - 7 * 8,
            },
            cap_space: None,
            kernel_stack_base: stack_virt,
            kernel_stack_top: stack_top,
            timeslice: 0,
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
        }
    }

    /// Create a new user thread.
    ///
    /// Allocates a kernel stack and builds an initial frame so that
    /// context_switch → user_thread_trampoline → sysretq enters Ring 3.
    pub fn new_user(
        id: u32,
        user_rip: u64,
        user_rsp: u64,
        cr3: u64,
        trampoline: unsafe extern "C" fn() -> !,
    ) -> Self {
        let (stack_virt, stack_top) = alloc_kernel_stack();

        // Initial stack frame for context_switch:
        //   r15=0, r14=cr3, r13=user_rsp, r12=user_rip, rbx=0, rbp=0, ret=trampoline
        unsafe {
            let top = stack_top as *mut u64;
            top.offset(-1).write(trampoline as u64); // return address
            top.offset(-2).write(0);                  // rbp
            top.offset(-3).write(0);                  // rbx
            top.offset(-4).write(user_rip);           // r12 → user RIP
            top.offset(-5).write(user_rsp);           // r13 → user RSP
            top.offset(-6).write(cr3);                // r14 → CR3
            top.offset(-7).write(0);                  // r15
        }

        Self {
            id: ThreadId(id),
            state: ThreadState::Ready,
            priority: 128,
            context: CpuContext {
                rsp: stack_top - 7 * 8,
            },
            cap_space: None,
            kernel_stack_base: stack_virt,
            kernel_stack_top: stack_top,
            timeslice: 0,
            is_user: true,
            user_rip,
            user_rsp,
            cr3,
            ipc_msg: Message::empty(),
            ipc_endpoint: None,
            ipc_role: IpcRole::None,
            preferred_cpu: None,
            domain_idx: None,
            redirect_ep: None,
        }
    }
}

/// Allocate a kernel stack (STACK_FRAMES contiguous frames).
/// Returns (stack_virt_base, stack_top).
fn alloc_kernel_stack() -> (u64, u64) {
    let hhdm = mm::hhdm_offset();

    let base = mm::alloc_contiguous(STACK_FRAMES).expect("out of frames for thread stack");
    let stack_phys = base.addr();

    let stack_virt = stack_phys + hhdm;
    let stack_top = stack_virt + STACK_SIZE as u64;
    (stack_virt, stack_top)
}
