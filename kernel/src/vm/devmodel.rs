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

// ---------------------------------------------------------------------------
// Port range constants
// ---------------------------------------------------------------------------

// COM1 — Phase F.2.
#[allow(dead_code)] const COM1_BASE: u16 = 0x3F8;
const COM1_END: u16 = 0x3FF;
const COM1_TX_RX: u16 = 0x3F8;
const COM1_LINE_STATUS: u16 = 0x3FD;

// 8259 PIC — Phase F.3.
const PIC1_CMD: u16 = 0x20;
const PIC1_DATA: u16 = 0x21;
const PIC2_CMD: u16 = 0xA0;
const PIC2_DATA: u16 = 0xA1;

// PIT — Phase F.3.
const PIT_CH0: u16 = 0x40;
#[allow(dead_code)] const PIT_CH1: u16 = 0x41;
#[allow(dead_code)] const PIT_CH2: u16 = 0x42;
const PIT_MODE: u16 = 0x43;

// CMOS / RTC — Phase F.3.
const CMOS_INDEX: u16 = 0x70;
const CMOS_DATA: u16 = 0x71;

// POST diagnostic — Phase F.3.
const POST_DIAG: u16 = 0x80;

// PCI config space — Phase F.3.
const PCI_CONFIG_ADDR: u16 = 0xCF8;
const PCI_CONFIG_DATA: u16 = 0xCFC;

// ---------------------------------------------------------------------------
// Per-VM device state
// ---------------------------------------------------------------------------
//
// Phase F is single-VM only — every test runs one guest at a time —
// so a global `Mutex<DeviceState>` is enough. Phase G+ will move the
// state into `VmObject` once we run multiple guests concurrently.

struct DeviceState {
    pic1_imr: u8,
    pic2_imr: u8,
    pit_counters: [u16; 3],
    pit_mode: u8,
    cmos_index: u8,
    pci_config_addr: u32,
}

impl DeviceState {
    const fn new() -> Self {
        Self {
            pic1_imr: 0xFF, // start with everything masked (Linux's first state too)
            pic2_imr: 0xFF,
            pit_counters: [0xFFFF; 3],
            pit_mode: 0,
            cmos_index: 0,
            pci_config_addr: 0,
        }
    }
}

static DEVICE_STATE: spin::Mutex<DeviceState> = spin::Mutex::new(DeviceState::new());

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
        // 8259 PIC master/slave — Phase F.3.
        PIC1_CMD | PIC1_DATA | PIC2_CMD | PIC2_DATA => handle_pic(access),
        // PIT — Phase F.3.
        PIT_CH0..=PIT_MODE => handle_pit(access),
        // CMOS / RTC — Phase F.3.
        CMOS_INDEX | CMOS_DATA => handle_cmos(access),
        // POST diagnostic — Phase F.3.
        POST_DIAG => handle_post(access),
        // PCI config space — Phase F.3.
        PCI_CONFIG_ADDR..=0xCFF => handle_pci_config(access),
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

// ---------------------------------------------------------------------------
// Phase F.3 — 8259 PIC emulation
// ---------------------------------------------------------------------------
//
// Linux's early init writes ICW1 (`out 0x20, 0x11`), then ICW2/3/4
// to the data port, then masks every line with `out 0x21, 0xFF`.
// Subsequent `in al, 0x21` reads return the IMR. We don't model the
// ICW state machine — we just accept ICW writes as no-ops, latch the
// IMR on data-port writes, and return the IMR on data-port reads.

fn handle_pic(access: IoAccess) -> IoResult {
    let mut state = DEVICE_STATE.lock();
    match (access.port, access.direction) {
        // Master command — ICW1, OCW2 (EOI), OCW3. We accept silently.
        (PIC1_CMD, IoDir::Out) => IoResult::Ok { value: 0 },
        // Master data — IMR or ICW2/3/4. Latch into the master IMR
        // for the OCW1 case; ICW2/3/4 are accepted as no-ops because
        // we don't model the state machine.
        (PIC1_DATA, IoDir::Out) => {
            state.pic1_imr = access.value as u8;
            IoResult::Ok { value: 0 }
        }
        (PIC1_DATA, IoDir::In) => IoResult::Ok { value: state.pic1_imr as u32 },
        (PIC1_CMD, IoDir::In) => IoResult::Ok { value: 0 },
        // Slave — same shape as master.
        (PIC2_CMD, IoDir::Out) => IoResult::Ok { value: 0 },
        (PIC2_DATA, IoDir::Out) => {
            state.pic2_imr = access.value as u8;
            IoResult::Ok { value: 0 }
        }
        (PIC2_DATA, IoDir::In) => IoResult::Ok { value: state.pic2_imr as u32 },
        (PIC2_CMD, IoDir::In) => IoResult::Ok { value: 0 },
        _ => IoResult::Unhandled,
    }
}

// ---------------------------------------------------------------------------
// Phase F.3 — PIT (8254) emulation
// ---------------------------------------------------------------------------
//
// We don't run a real timer for the guest — instead we return a
// monotonically-decreasing counter for channel 0 reads so any
// calibration loop in the guest sees "time passing" and converges.
// The mode register at 0x43 just latches the most-recent write.

fn handle_pit(access: IoAccess) -> IoResult {
    let mut state = DEVICE_STATE.lock();
    match (access.port, access.direction) {
        (PIT_CH0..=PIT_CH2, IoDir::Out) => {
            let ch = (access.port - PIT_CH0) as usize;
            // 16-bit counter loaded as two 8-bit halves; we collapse
            // them into the low 16 bits of `value` and store directly.
            state.pit_counters[ch] = access.value as u16;
            IoResult::Ok { value: 0 }
        }
        (PIT_CH0..=PIT_CH2, IoDir::In) => {
            let ch = (access.port - PIT_CH0) as usize;
            // Decrement the latched counter so successive reads see
            // the timer "ticking down" — Linux's PIT calibration
            // measures the delta between two reads.
            let cur = state.pit_counters[ch];
            let next = cur.wrapping_sub(0x100);
            state.pit_counters[ch] = next;
            IoResult::Ok { value: cur as u32 }
        }
        (PIT_MODE, IoDir::Out) => {
            state.pit_mode = access.value as u8;
            IoResult::Ok { value: 0 }
        }
        (PIT_MODE, IoDir::In) => IoResult::Ok { value: state.pit_mode as u32 },
        _ => IoResult::Unhandled,
    }
}

// ---------------------------------------------------------------------------
// Phase F.3 — CMOS / RTC emulation
// ---------------------------------------------------------------------------
//
// Linux reads CMOS registers 0x00..0x09 to bootstrap its time-of-day
// clock and 0x0A/0x0B for RTC status. We return canned BCD values
// (epoch ≈ 2024-01-01 00:00:00) and Status A bit 7 cleared (UIP not
// in progress). Anything else returns 0.

fn handle_cmos(access: IoAccess) -> IoResult {
    let mut state = DEVICE_STATE.lock();
    match (access.port, access.direction) {
        (CMOS_INDEX, IoDir::Out) => {
            // Bit 7 = NMI disable; we don't model NMI delivery so
            // just keep the index value.
            state.cmos_index = (access.value & 0x7F) as u8;
            IoResult::Ok { value: 0 }
        }
        (CMOS_INDEX, IoDir::In) => IoResult::Ok { value: 0 },
        (CMOS_DATA, IoDir::In) => {
            let v = match state.cmos_index {
                0x00 => 0x00, // seconds
                0x02 => 0x00, // minutes
                0x04 => 0x00, // hours (24h)
                0x06 => 0x02, // day of week (Monday)
                0x07 => 0x01, // day of month
                0x08 => 0x01, // month
                0x09 => 0x24, // year (BCD 24 = 2024)
                0x0A => 0x26, // status A: 32 KHz divider, no UIP
                0x0B => 0x02, // status B: 24-hour mode, BCD
                0x0C => 0x00, // status C: no pending interrupts
                0x0D => 0x80, // status D: valid RAM/time
                0x32 => 0x20, // century (BCD 20 = 2000s)
                _ => 0,
            };
            IoResult::Ok { value: v as u32 }
        }
        (CMOS_DATA, IoDir::Out) => {
            // Phase F.3 doesn't need write-side persistence — Linux
            // mostly writes to clear interrupts or program the alarm,
            // neither of which matters for our boot path.
            IoResult::Ok { value: 0 }
        }
        _ => IoResult::Unhandled,
    }
}

// ---------------------------------------------------------------------------
// Phase F.3 — POST diagnostic port
// ---------------------------------------------------------------------------
//
// Linux uses `outb(0x80, 0)` as a ~1µs delay between bus operations
// (the BIOS POST card behaviour is "the chipset will hold the bus
// for one cycle"). Accept any byte silently.

fn handle_post(access: IoAccess) -> IoResult {
    match access.direction {
        IoDir::Out => IoResult::Ok { value: 0 },
        IoDir::In => IoResult::Ok { value: 0 },
    }
}

// ---------------------------------------------------------------------------
// Phase F.3 — PCI configuration space
// ---------------------------------------------------------------------------
//
// We pretend "no PCI device exists" by always returning 0xFFFFFFFF
// (the bus-line idle pattern) for any vendor-ID read. Linux's PCI
// scan terminates after the first failed probe per slot. The
// address register at 0xCF8 is just latched.

fn handle_pci_config(access: IoAccess) -> IoResult {
    let mut state = DEVICE_STATE.lock();
    match (access.port, access.direction) {
        (PCI_CONFIG_ADDR, IoDir::Out) => {
            state.pci_config_addr = access.value;
            IoResult::Ok { value: 0 }
        }
        (PCI_CONFIG_ADDR, IoDir::In) => IoResult::Ok { value: state.pci_config_addr },
        // 0xCFC..0xCFF — data-port window. Reads return the no-device
        // value; writes are accepted but discarded.
        (PCI_CONFIG_DATA..=0xCFF, IoDir::Out) => IoResult::Ok { value: 0 },
        (PCI_CONFIG_DATA..=0xCFF, IoDir::In) => IoResult::Ok { value: 0xFFFF_FFFF },
        _ => IoResult::Unhandled,
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
