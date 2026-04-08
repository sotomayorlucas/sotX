//! sot-dtrace — DTrace-compatible probe consumer for sotBSD.
//!
//! **Project PANDORA Task 1** — first deliverable of the DTrace
//! integration. Architecture aligned with the FreeBSD/Solaris DTrace
//! model so the vendor `libdtrace` sources in
//! `vendor/freebsd-dtrace/` can be linked in as a follow-up without
//! rearchitecting the Rust side.
//!
//! # Architecture
//!
//! DTrace's model is:
//!   1. **Providers** register probes (tuples of
//!      `provider:module:function:name`).
//!   2. When instrumented events fire in the kernel, providers invoke
//!      `dtrace_probe(probe_id, arg0..arg4)`.
//!   3. **Consumers** attach to the probe IDs via a D-script filter
//!      and receive probe firings.
//!   4. `libdtrace` on the user side compiles D scripts, loads them
//!      into the kernel module, and streams back matches.
//!
//! sot-dtrace plugs into this at the **probe source** layer: instead
//! of being invoked by scattered provider hooks throughout the
//! kernel, the entire sotBSD provenance ring (every SOT operation
//! recorded by `kernel/src/sot/provenance.rs`) is drained and
//! translated into probe firings under the `sotbsd:::` provider
//! namespace. Each `ProvenanceEntry` becomes one probe:
//!
//! ```text
//!   sotbsd:::tx_commit        args: tx_id, epoch, _, _
//!   sotbsd:::tx_abort         args: tx_id, epoch, _, _
//!   sotbsd:::so_create        args: so_id, so_type, domain, _
//!   sotbsd:::so_invoke        args: so_id, so_type, domain, version
//!   sotbsd:::so_grant         args: so_id, _, domain, _
//!   sotbsd:::so_revoke        args: so_id, _, domain, _
//!   sotbsd:::provenance       args: operation, so_type, so_id, domain
//! ```
//!
//! The service exposes an IPC endpoint `sot-dtrace` that a DTrace
//! CLI client connects to. The client sends a D-script filter (or
//! the raw probe-matching triple string like `sotbsd:::tx_commit`),
//! and the server streams back matching probe firings. A minimal
//! D-script subset is implemented inline until the vendor libdtrace
//! link lands.
//!
//! # IPC ABI
//!
//! Request tags from the client:
//!
//! | tag | request                          | reply                         |
//! |-----|----------------------------------|-------------------------------|
//! |  1  | SUBSCRIBE path_pattern (bytes)   | regs[0] = session_id          |
//! |  2  | POLL session_id (in regs[0])     | tag=n, regs[0..6] = probe_evt |
//! |  3  | UNSUBSCRIBE session_id (regs[0]) | regs[0] = 0                   |
//! |  4  | LIST_PROVIDERS                   | tag=n, regs[0..6] = ascii     |
//!
//! The POLL reply packs a probe event into 7 u64 registers:
//!   regs[0] = probe_id (sotbsd provider + DTrace name)
//!   regs[1] = epoch
//!   regs[2] = domain_id
//!   regs[3] = so_id
//!   regs[4] = version
//!   regs[5] = tx_id
//!   regs[6] = timestamp (TSC)

#![no_std]
#![no_main]

use sotos_common::{sys, IpcMsg};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const TAG_SUBSCRIBE:    u64 = 1;
const TAG_POLL:         u64 = 2;
const TAG_UNSUBSCRIBE:  u64 = 3;
const TAG_LIST:         u64 = 4;

const MAX_SESSIONS: usize = 8;
const RING_BUF: usize = 64;

const SERVICE_NAME: &[u8] = b"sot-dtrace";

// Kernel provenance operation codes -- mirror kernel/src/syscall/sot.rs.
const OP_INVOKE_PASSTHROUGH: u16 = 0x10;
const OP_INVOKE_INSPECT:     u16 = 0x11;
const OP_INVOKE_REDIRECT:    u16 = 0x12;
const OP_INVOKE_FABRICATE:   u16 = 0x13;
const OP_INVOKE_DIRECT:      u16 = 0x14;
const OP_CREATE:             u16 = 0x20;
const OP_GRANT:              u16 = 0x30;
const OP_REVOKE:             u16 = 0x40;
const OP_TX_COMMIT:          u16 = 0x50;
const OP_TX_ABORT:           u16 = 0x51;

// Probe IDs (encoded as ASCII tuples would be in D, but for the wire
// protocol we use compact u64 codes).
const PROBE_TX_COMMIT:  u64 = 0x0001_0001;
const PROBE_TX_ABORT:   u64 = 0x0001_0002;
const PROBE_SO_CREATE:  u64 = 0x0002_0001;
const PROBE_SO_INVOKE:  u64 = 0x0002_0002;
const PROBE_SO_GRANT:   u64 = 0x0002_0003;
const PROBE_SO_REVOKE:  u64 = 0x0002_0004;
const PROBE_GENERIC:    u64 = 0x000F_0001;

// ---------------------------------------------------------------------------
// Kernel provenance entry mirror
// ---------------------------------------------------------------------------

#[repr(C)]
#[derive(Clone, Copy)]
struct KernelProvEntry {
    epoch: u64,
    domain_id: u32,
    operation: u16,
    so_type: u8,
    _pad: u8,
    so_id: u64,
    version: u64,
    tx_id: u64,
    timestamp: u64,
}
const _: () = assert!(core::mem::size_of::<KernelProvEntry>() == 48);

fn entry_to_probe_id(e: &KernelProvEntry) -> u64 {
    match e.operation {
        OP_TX_COMMIT => PROBE_TX_COMMIT,
        OP_TX_ABORT  => PROBE_TX_ABORT,
        OP_CREATE    => PROBE_SO_CREATE,
        OP_INVOKE_PASSTHROUGH
        | OP_INVOKE_INSPECT
        | OP_INVOKE_REDIRECT
        | OP_INVOKE_FABRICATE
        | OP_INVOKE_DIRECT => PROBE_SO_INVOKE,
        OP_GRANT     => PROBE_SO_GRANT,
        OP_REVOKE    => PROBE_SO_REVOKE,
        _            => PROBE_GENERIC,
    }
}

// ---------------------------------------------------------------------------
// D-script filter: minimal probe-matching subset
//
// Supports `provider:module:function:name` with `*` wildcards and the
// bare `sotbsd:::` form (equivalent to `sotbsd:*:*:*`). The full D
// language (aggregations, predicates, variables) is not implemented --
// the vendor libdtrace will cover it when linked.
// ---------------------------------------------------------------------------

const MAX_PATTERN: usize = 64;

#[derive(Clone, Copy)]
struct Filter {
    pattern: [u8; MAX_PATTERN],
    plen: usize,
}

impl Filter {
    const fn empty() -> Self {
        Self { pattern: [0; MAX_PATTERN], plen: 0 }
    }

    fn from_bytes(src: &[u8]) -> Self {
        let mut f = Self::empty();
        let n = src.len().min(MAX_PATTERN);
        f.pattern[..n].copy_from_slice(&src[..n]);
        f.plen = n;
        f
    }

    fn as_str(&self) -> &[u8] {
        &self.pattern[..self.plen]
    }

    /// Match a probe id against this filter. The current encoding
    /// walks the colon-separated fields and compares each against
    /// the probe's provider/module/function/name. For the MVP we
    /// support the bare `sotbsd:::` form (empty module/function/name
    /// => wildcards) and the exact form `sotbsd:::<name>`.
    fn matches(&self, probe: u64) -> bool {
        let p = self.as_str();
        if p.is_empty() {
            return false;
        }
        // First field must be "sotbsd" (anything else is unsupported).
        if p.len() < 7 || &p[..7] != b"sotbsd:" {
            return false;
        }
        // Walk past the 3 colons.
        let rest = &p[7..];
        // Find the fourth field = probe name.
        let mut colons = 0;
        let mut name_start = 0;
        for (i, &c) in rest.iter().enumerate() {
            if c == b':' {
                colons += 1;
                if colons == 2 {
                    name_start = i + 1;
                    break;
                }
            }
        }
        if colons < 2 {
            return false;
        }
        let name = &rest[name_start..];
        // Empty name = wildcard, matches any sotbsd probe.
        if name.is_empty() {
            return true;
        }
        // Exact match by probe id.
        match probe {
            PROBE_TX_COMMIT  => name == b"tx_commit",
            PROBE_TX_ABORT   => name == b"tx_abort",
            PROBE_SO_CREATE  => name == b"so_create",
            PROBE_SO_INVOKE  => name == b"so_invoke",
            PROBE_SO_GRANT   => name == b"so_grant",
            PROBE_SO_REVOKE  => name == b"so_revoke",
            PROBE_GENERIC    => name == b"provenance",
            _ => false,
        }
    }
}

// ---------------------------------------------------------------------------
// Session table
// ---------------------------------------------------------------------------

#[derive(Clone, Copy)]
struct Session {
    active: bool,
    filter: Filter,
    /// Per-session ring buffer of pending probe firings.
    pending: [KernelProvEntry; RING_BUF],
    head: usize,
    tail: usize,
}

impl Session {
    const fn empty() -> Self {
        Self {
            active: false,
            filter: Filter::empty(),
            pending: [KernelProvEntry {
                epoch: 0, domain_id: 0, operation: 0, so_type: 0, _pad: 0,
                so_id: 0, version: 0, tx_id: 0, timestamp: 0,
            }; RING_BUF],
            head: 0,
            tail: 0,
        }
    }

    fn push(&mut self, e: KernelProvEntry) {
        let next = (self.head + 1) % RING_BUF;
        if next == self.tail {
            // Session ring full -- drop oldest.
            self.tail = (self.tail + 1) % RING_BUF;
        }
        self.pending[self.head] = e;
        self.head = next;
    }

    fn pop(&mut self) -> Option<KernelProvEntry> {
        if self.head == self.tail {
            return None;
        }
        let e = self.pending[self.tail];
        self.tail = (self.tail + 1) % RING_BUF;
        Some(e)
    }
}

static mut SESSIONS: [Session; MAX_SESSIONS] = [const { Session::empty() }; MAX_SESSIONS];

fn alloc_session(filter: Filter) -> Option<u64> {
    let sessions = unsafe { &mut SESSIONS };
    for (i, s) in sessions.iter_mut().enumerate() {
        if !s.active {
            *s = Session::empty();
            s.active = true;
            s.filter = filter;
            return Some((i as u64) + 1);
        }
    }
    None
}

fn release_session(id: u64) -> bool {
    let sessions = unsafe { &mut SESSIONS };
    let idx = (id as usize).wrapping_sub(1);
    if idx >= MAX_SESSIONS { return false; }
    if !sessions[idx].active { return false; }
    sessions[idx].active = false;
    true
}

fn session_pop(id: u64) -> Option<KernelProvEntry> {
    let sessions = unsafe { &mut SESSIONS };
    let idx = (id as usize).wrapping_sub(1);
    if idx >= MAX_SESSIONS { return None; }
    if !sessions[idx].active { return None; }
    sessions[idx].pop()
}

/// Drain the kernel provenance ring and route each entry to every
/// active session whose filter matches. Called at the top of the IPC
/// loop on every request.
fn drain_and_route() {
    let mut buf = [KernelProvEntry {
        epoch: 0, domain_id: 0, operation: 0, so_type: 0, _pad: 0,
        so_id: 0, version: 0, tx_id: 0, timestamp: 0,
    }; 32];
    let n = unsafe {
        sys::provenance_drain(buf.as_mut_ptr() as *mut u8, buf.len() as u64, 0) as usize
    };
    if n == 0 { return; }
    let sessions = unsafe { &mut SESSIONS };
    for i in 0..n {
        let probe = entry_to_probe_id(&buf[i]);
        for s in sessions.iter_mut() {
            if s.active && s.filter.matches(probe) {
                s.push(buf[i]);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Output helpers
// ---------------------------------------------------------------------------

fn print(s: &[u8]) { for &b in s { sys::debug_print(b); } }

fn print_u64(mut n: u64) {
    if n == 0 { sys::debug_print(b'0'); return; }
    let mut buf = [0u8; 20];
    let mut i = 0;
    while n > 0 { buf[i] = b'0' + (n % 10) as u8; n /= 10; i += 1; }
    while i > 0 { i -= 1; sys::debug_print(buf[i]); }
}

// ---------------------------------------------------------------------------
// IPC handlers
// ---------------------------------------------------------------------------

fn handle_subscribe(msg: &IpcMsg, reply: &mut IpcMsg) {
    let raw = unsafe {
        core::slice::from_raw_parts(msg.regs.as_ptr() as *const u8, 56)
    };
    let mut end = 0;
    while end < 56 && raw[end] != 0 { end += 1; }
    let filter = Filter::from_bytes(&raw[..end]);
    match alloc_session(filter) {
        Some(id) => reply.regs[0] = id,
        None => reply.regs[0] = (-23i64) as u64, // -ENFILE
    }
}

fn handle_poll(msg: &IpcMsg, reply: &mut IpcMsg) {
    let id = msg.regs[0];
    drain_and_route();
    match session_pop(id) {
        Some(e) => {
            reply.tag = entry_to_probe_id(&e);
            reply.regs[0] = entry_to_probe_id(&e);
            reply.regs[1] = e.epoch;
            reply.regs[2] = e.domain_id as u64;
            reply.regs[3] = e.so_id;
            reply.regs[4] = e.version;
            reply.regs[5] = e.tx_id;
            reply.regs[6] = e.timestamp;
        }
        None => {
            reply.tag = 0;
            reply.regs[0] = 0;
        }
    }
}

fn handle_unsubscribe(msg: &IpcMsg, reply: &mut IpcMsg) {
    let id = msg.regs[0];
    reply.regs[0] = if release_session(id) { 0 } else { (-22i64) as u64 };
}

fn handle_list(_msg: &IpcMsg, reply: &mut IpcMsg) {
    // Return the built-in provider list as an ASCII blob. The client
    // prints it verbatim. Format: null-delimited entries.
    let list =
        b"sotbsd:::tx_commit\0sotbsd:::tx_abort\0sotbsd:::so_create\0\
          sotbsd:::so_invoke\0sotbsd:::so_grant\0sotbsd:::so_revoke\0\
          sotbsd:::provenance\0";
    let dst = unsafe {
        core::slice::from_raw_parts_mut(reply.regs.as_mut_ptr() as *mut u8, 64)
    };
    let n = list.len().min(64);
    dst[..n].copy_from_slice(&list[..n]);
    reply.tag = n as u64;
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    print(b"SOT-DTRACE: starting (PANDORA T1 -- DTrace probe consumer)\n");

    let ep = match sys::endpoint_create() {
        Ok(e) => e,
        Err(_) => {
            print(b"SOT-DTRACE: endpoint_create failed\n");
            sys::thread_exit();
        }
    };

    if sys::svc_register(SERVICE_NAME.as_ptr() as u64, SERVICE_NAME.len() as u64, ep).is_err() {
        print(b"SOT-DTRACE: svc_register failed\n");
        sys::thread_exit();
    }
    print(b"SOT-DTRACE: registered as 'sot-dtrace', awaiting clients\n");

    loop {
        let msg = match sys::recv(ep) {
            Ok(m) => m,
            Err(_) => { sys::yield_now(); continue; }
        };

        let mut reply = IpcMsg::empty();
        match msg.tag {
            TAG_SUBSCRIBE   => handle_subscribe(&msg, &mut reply),
            TAG_POLL        => handle_poll(&msg, &mut reply),
            TAG_UNSUBSCRIBE => handle_unsubscribe(&msg, &mut reply),
            TAG_LIST        => handle_list(&msg, &mut reply),
            _ => reply.regs[0] = (-22i64) as u64,
        }
        let _ = sys::send(ep, &reply);
    }
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    print(b"SOT-DTRACE: PANIC\n");
    loop { sys::yield_now(); }
}
