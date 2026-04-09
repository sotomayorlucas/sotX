//! Phase F — in-kernel device model for the bhyve VT-x guest.
//!
//! Routes guest IN/OUT instructions trapped via VM-exit reason 30
//! (`REASON_IO_INSTRUCTION`) to a small set of emulated devices.
//! Phase F.1+F.2 only ships **COM1 TX** — the Phase B/C/D test
//! payload writes to port 0x3F8 to drive the host serial console
//! through `kprint!`. Subsequent sub-phases will add 8259 PIC
//! (F.3), PIT (F.3), CMOS/RTC (F.3), and PCI config space stubs
//! as Linux's tinyconfig boot needs them.
//!
//! ## Why in-kernel
//!
//! Bouncing every guest I/O exit out to userspace via an IPC round
//! trip would be a context-switch disaster — the Linux boot path
//! issues hundreds of port reads/writes in the first millisecond,
//! one per `outb` to the 8259/PIT/CMOS/COM1. We mirror what KVM
//! does: a tiny kernel-resident dispatcher handles the hot-path
//! ports inline, and any port we don't recognise terminates the
//! vCPU with a kprintln (eventually: bounce to userspace via
//! `SYS_VM_IO_WAIT`).

use super::{KernelVCpuState, VmIntrospectEvent};
use crate::pool::PoolHandle;

/// I/O instruction direction, decoded from `EXIT_QUALIFICATION`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IoDir {
    Out,
    In,
}

/// Result returned by `handle_io`. The dispatcher uses this to
/// either resume the guest after spoofing the result or terminate
/// the vCPU when the access is unsupported.
#[derive(Debug, Clone, Copy)]
pub enum IoResult {
    /// Operation handled. For `OUT`, no further action required.
    /// For `IN`, the dispatcher must write `value` into `state.gprs.rax`
    /// (low `width` bytes).
    Ok { value: u32 },
    /// Port not modeled — the dispatcher should `Terminate` the vCPU
    /// after logging.
    Unhandled,
}

/// Routing decision for a single guest I/O exit. The fields are the
/// already-decoded form of `EXIT_QUALIFICATION` (Intel SDM Vol 3C
/// 27.2.1 / Table 27-5).
#[derive(Debug, Clone, Copy)]
pub struct IoAccess {
    pub port: u16,
    /// 1, 2, or 4 bytes.
    pub width: u8,
    pub direction: IoDir,
    /// For OUT: the value the guest is writing (low `width` bytes
    /// of `state.gprs.rax`). For IN: undefined.
    pub value: u32,
}

// COM1 register offsets relative to its 0x3F8 base. Phase F.2 only
// implements TX-side ports; the rest return `0x00` for IN and drop
// OUT silently (matching a "not connected" UART well enough for
// printk-only Linux output).
const COM1_BASE: u16 = 0x3F8;
const COM1_END: u16 = 0x3FF;
const COM1_TX_RX: u16 = 0x3F8; // TX register on write, RX on read
const COM1_LINE_STATUS: u16 = 0x3FD; // bit 5 (THR empty) + bit 6 (TX shift empty) = 0x60

/// Hot-path entry called from `vm::exit::handle_io_instruction`.
/// Looks at `access.port` and dispatches to the right device.
pub fn handle_io(
    _state: &mut KernelVCpuState,
    vm_handle: Option<PoolHandle>,
    access: IoAccess,
) -> IoResult {
    let result = match access.port {
        // COM1 — Phase F.2.
        COM1_TX_RX..=COM1_END => handle_com1(access),
        // Anything else: unmodeled.
        _ => IoResult::Unhandled,
    };

    // Push an introspection event so userspace can verify which
    // ports the guest hit. The Phase F.1 test asserts on the
    // count + content of these events.
    if let Some(handle) = vm_handle {
        let kind = match access.direction {
            IoDir::Out => VmIntrospectEvent::KIND_IO_OUT,
            IoDir::In => VmIntrospectEvent::KIND_IO_IN,
        };
        let read_value = if let IoResult::Ok { value } = result {
            value as u64
        } else {
            0
        };
        super::push_introspect_event(
            handle,
            VmIntrospectEvent {
                kind,
                _pad: 0,
                a: access.port as u64,
                b: access.width as u64,
                c: access.value as u64,
                d: read_value,
            },
        );
    }

    result
}

/// Phase F.2 — minimal COM1 (16550 UART) emulation. Only the TX
/// path is wired through to the host serial; everything else
/// returns canned values that satisfy a polling driver.
fn handle_com1(access: IoAccess) -> IoResult {
    match (access.port, access.direction) {
        (COM1_TX_RX, IoDir::Out) => {
            // TX byte → host serial. Prefix the line with [GUEST]
            // so the boot log clearly distinguishes guest output
            // from host output. We carry a small static line
            // accumulator to coalesce per-byte writes into a
            // single kprintln line on '\n'.
            push_guest_byte(access.value as u8);
            IoResult::Ok { value: 0 }
        }
        (COM1_LINE_STATUS, IoDir::In) => {
            // Bit 5 (THR empty) + bit 6 (TX shift empty) tells the
            // guest "ready to send". Bit 0 (data ready) clear so the
            // guest doesn't try to read.
            IoResult::Ok { value: 0x60 }
        }
        (COM1_TX_RX, IoDir::In) => {
            // RX register read with no data — return 0.
            IoResult::Ok { value: 0 }
        }
        // Other COM1 registers (IER, FCR, LCR, MCR, MSR, SCR):
        // accept writes silently, return 0 on reads. Good enough
        // for a polling printk that never enables interrupts.
        (_, IoDir::Out) => IoResult::Ok { value: 0 },
        (_, IoDir::In) => IoResult::Ok { value: 0 },
    }
}

/// Per-VM line accumulator for guest COM1 output. We buffer bytes
/// until '\n' or a soft cap, then flush as a single `kprint!` line
/// prefixed with `[GUEST]`. Phase F is single-vCPU only so a global
/// buffer behind a spinlock is safe; Phase G will move this into
/// the per-VM struct once we have multiple guests.
const LINE_CAP: usize = 256;

struct GuestLine {
    buf: [u8; LINE_CAP],
    len: usize,
}

impl GuestLine {
    const fn new() -> Self {
        Self {
            buf: [0; LINE_CAP],
            len: 0,
        }
    }
}

static GUEST_LINE: spin::Mutex<GuestLine> = spin::Mutex::new(GuestLine::new());

fn push_guest_byte(byte: u8) {
    use crate::arch::x86_64::serial::write_byte;
    let mut line = GUEST_LINE.lock();
    if byte == b'\r' {
        return; // CR ignored — kprintln adds CRLF on its own
    }
    let should_flush = byte == b'\n' || line.len == LINE_CAP - 1;
    if byte != b'\n' {
        let idx = line.len;
        line.buf[idx] = byte;
        line.len += 1;
    }
    if should_flush && line.len > 0 {
        // Snapshot buffer + length, drop guard, then write to serial
        // outside the lock so any reentrant logging path can't
        // deadlock. The serial driver itself has its own lock.
        let mut copy = [0u8; LINE_CAP];
        let len = line.len;
        copy[..len].copy_from_slice(&line.buf[..len]);
        line.len = 0;
        drop(line);
        for &b in b"[GUEST] " {
            write_byte(b);
        }
        for i in 0..len {
            write_byte(copy[i]);
        }
        write_byte(b'\r');
        write_byte(b'\n');
    }
}
