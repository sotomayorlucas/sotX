//! Deception query IPC server (B1.5d).
//!
//! Spec: `docs/sotsh-ipc-protocols.md` Part B. Registers as `"deception"`
//! and answers a single operation — `DECEPTION_QUERY_ARMS` (tag=1) —
//! which returns the list of builtin deception profiles together with
//! their current `active` flag. The `arm` builtin in sotsh
//! (`services/sotsh/src/builtins/arm.rs`) consumes this list (B2d) to
//! stop hard-coding profile names in the shell.
//!
//! ## Wire format (see design doc for full detail)
//!
//! Request: tag=1, no args (regs=[0; 8]). Per-client cursor lives
//! server-side, keyed by sender IPC endpoint — since the current IPC
//! surface does not expose a caller identity, we model the cursor as a
//! **single global cursor** that auto-advances on each `QUERY_ARMS`
//! call and snaps back to 0 after the end-of-list sentinel is emitted.
//! That is safe because sotsh is the only planned consumer and always
//! walks the list sequentially. Real multi-client support is a
//! post-MVP hardening: see design doc Part D.
//!
//! Reply (one IpcMsg per profile):
//!   tag = index (0..=3) on a data row, or 0xFFFF_FFFF on end-of-list
//!   regs[0]        = active flag (0 or 1)
//!   regs[1..=4]    = up to 32 bytes of name (NUL-padded, little-endian)
//!   regs[5]        = name_len (<= 32)
//!   regs[6..=7]    = reserved, 0

use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

use sotos_common::sys;
use sotos_common::IpcMsg;
use sotos_deception::ProfileRegistry;

use crate::framebuffer::print;

/// Operation tag for the query op. Must stay in sync with the client
/// wrapper in `sotos_common::sys::deception_query_arms()`.
pub const DECEPTION_QUERY_ARMS: u64 = 1;

/// End-of-list marker used in reply `tag`.
pub const DECEPTION_EOT: u64 = 0xFFFF_FFFF;

/// Shared endpoint cap, published by `start()` and read by the handler
/// thread. Zero means "not yet registered".
pub(crate) static DECEPTION_EP_CAP: AtomicU64 = AtomicU64::new(0);

/// Global walk cursor. See module docs for the single-client caveat.
static CURSOR: AtomicUsize = AtomicUsize::new(0);

/// Singleton registry backing the service. `ProfileRegistry` is
/// `const`-constructible so we can put it in a `static` without a
/// `Mutex` for the read path. Writes to `active` come from
/// `set_active(...)` which uses relaxed stores into an inner cell;
/// for B1.5d we only read, so this stays `static` without locks.
///
/// NOTE: we keep the registry mutable via `static mut` + raw pointer
/// access rather than a spinlock. The deception service thread is the
/// only writer today, and reads see a consistent snapshot because each
/// entry's `active` field is a single byte.
static mut REGISTRY: ProfileRegistry = ProfileRegistry::with_builtins();

/// Stack for the deception service thread. 4 pages = 16 KiB is plenty
/// for a `recv`-loop handler that allocates no locals of note.
const DECEPTION_STACK: u64 = 0xEF0000;
const DECEPTION_STACK_PAGES: u64 = 4;

/// Spawn the deception service thread. Called from `_start` after
/// other services (`blk`, `net`, etc.) have had a chance to register.
/// Prints a single boot marker on success so the framebuffer shows
/// `deception: registered` right next to other service banners.
pub fn start() {
    // Create the IPC endpoint we will register as "deception".
    let ep = match sys::endpoint_create() {
        Ok(e) => e,
        Err(_) => {
            print(b"deception: endpoint_create failed\n");
            return;
        }
    };
    DECEPTION_EP_CAP.store(ep, Ordering::Release);

    // Register the name.
    let name = b"deception";
    match sys::svc_register(name.as_ptr() as u64, name.len() as u64, ep) {
        Ok(()) => print(b"deception: registered\n"),
        Err(_) => {
            print(b"deception: svc_register failed\n");
            return;
        }
    }

    // Map the handler stack.
    for i in 0..DECEPTION_STACK_PAGES {
        let frame = match sys::frame_alloc() {
            Ok(f) => f,
            Err(_) => {
                print(b"deception: frame_alloc for stack failed\n");
                return;
            }
        };
        let _ = sys::map(DECEPTION_STACK + i * 0x1000, frame, 2 /* MAP_WRITABLE */);
    }

    let _ = sys::thread_create(
        deception_handler as *const () as u64,
        DECEPTION_STACK + DECEPTION_STACK_PAGES * 0x1000,
    );
}

/// Flip the `active` bit of a builtin by name. Safe wrapper around the
/// `static mut REGISTRY`. Called from `deception_demo.rs` when a demo
/// profile is installed; unused for the basic IPC path but kept public
/// so the registry truly owns the active-flag state.
#[allow(dead_code)]
pub fn set_active(name: &[u8], active: bool) -> bool {
    // SAFETY: single-writer discipline — only `deception_demo` and
    // `set_active_at` call this, never concurrently with the service
    // thread's read path (which only touches the immutable `name`
    // field + one-byte `active` flag).
    unsafe { (&mut *core::ptr::addr_of_mut!(REGISTRY)).set_active(name, active) }
}

/// Handler thread entry point. Pulls requests off the registered
/// endpoint and replies with one IpcMsg per list entry, appending an
/// EOT sentinel after the last profile. The cursor is global (see
/// module docs).
extern "C" fn deception_handler() -> ! {
    let ep = DECEPTION_EP_CAP.load(Ordering::Acquire);
    loop {
        let req = match sys::recv(ep) {
            Ok(m) => m,
            Err(_) => {
                sys::yield_now();
                continue;
            }
        };

        let reply = match req.tag {
            DECEPTION_QUERY_ARMS => build_query_reply(),
            _ => IpcMsg {
                tag: (-22i64) as u64, // EINVAL
                regs: [0; 8],
            },
        };

        let _ = sys::send(ep, &reply);
    }
}

/// Build one reply IpcMsg using the current cursor. Advances the
/// cursor on success and resets to 0 after the EOT sentinel.
fn build_query_reply() -> IpcMsg {
    // SAFETY: reads only; see REGISTRY docs for single-writer rationale.
    let reg = unsafe { &*core::ptr::addr_of!(REGISTRY) };

    let idx = CURSOR.load(Ordering::Acquire);
    let entry = match reg.get(idx) {
        Some(e) => e,
        None => {
            // Past the end of the list: emit EOT, reset cursor so the
            // next `arm` invocation restarts from 0.
            CURSOR.store(0, Ordering::Release);
            return IpcMsg {
                tag: DECEPTION_EOT,
                regs: [0; 8],
            };
        }
    };

    // Pack name into 4 regs (regs[1..=4] = 32 bytes).
    let mut regs = [0u64; 8];
    regs[0] = if entry.active { 1 } else { 0 };
    for chunk in 0..4 {
        let base = chunk * 8;
        let mut bytes = [0u8; 8];
        bytes.copy_from_slice(&entry.name[base..base + 8]);
        regs[1 + chunk] = u64::from_le_bytes(bytes);
    }
    regs[5] = entry.name_len as u64;

    CURSOR.store(idx + 1, Ordering::Release);

    IpcMsg {
        tag: idx as u64,
        regs,
    }
}
