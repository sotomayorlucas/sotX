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

// 8042 PS/2 keyboard controller — Phase F.6 (stub).
const KBC_DATA: u16 = 0x60;
const KBC_STATUS_CMD: u16 = 0x64;

// NMI Status & Control / Refresh toggle (Port B) — Phase F.6.
const NMI_STATUS_CONTROL: u16 = 0x61;

// CMOS / RTC — Phase F.3.
const CMOS_INDEX: u16 = 0x70;
const CMOS_DATA: u16 = 0x71;

// POST diagnostic — Phase F.3.
const POST_DIAG: u16 = 0x80;

// PCI config space — Phase F.3.
const PCI_CONFIG_ADDR: u16 = 0xCF8;
const PCI_CONFIG_DATA: u16 = 0xCFC;

// PIC ELCR (edge/level trigger) — Phase F.6.
const PIC_ELCR_MASTER: u16 = 0x4D0;
const PIC_ELCR_SLAVE: u16 = 0x4D1;

// ---------------------------------------------------------------------------
// Per-VM device state
// ---------------------------------------------------------------------------
//
// Phase F is single-VM only — every test runs one guest at a time —
// so a global `Mutex<DeviceState>` is enough. Phase G+ will move the
// state into `VmObject` once we run multiple guests concurrently.

/// PIT byte-access state per channel. The 8254 has an "access mode"
/// (LOBYTE_ONLY / HIBYTE_ONLY / LOBYTE_HIBYTE) that the guest selects
/// via the mode register at 0x43. For LOBYTE_HIBYTE the channel
/// alternates between low and high byte on every read/write — a
/// per-channel toggle is enough to track that.
#[derive(Clone, Copy)]
struct PitChannel {
    /// Reload value latched by the most recent OUT sequence. CH2's
    /// reads use a synthetic free-running counter, so this only
    /// matters for CH0 if a guest ever cares.
    reload: u16,
    /// Synthetic counter for reads: decremented on every full
    /// (lo+hi) read so Linux's tsc_calibrate_pit sees time pass.
    counter: u16,
    /// Access mode bits from the mode register: 0b01=lo only,
    /// 0b10=hi only, 0b11=lo then hi (the common one).
    access_mode: u8,
    /// Toggle for LOBYTE_HIBYTE mode: false=next is lo, true=next is hi.
    next_is_hi_read: bool,
    next_is_hi_write: bool,
}

impl PitChannel {
    const fn new() -> Self {
        Self {
            reload: 0xFFFF,
            counter: 0xFFFF,
            access_mode: 0b11, // default to lo+hi
            next_is_hi_read: false,
            next_is_hi_write: false,
        }
    }
}

struct DeviceState {
    pic1_imr: u8,
    pic2_imr: u8,
    pic1_elcr: u8,
    pic2_elcr: u8,
    pit_channels: [PitChannel; 3],
    cmos_index: u8,
    pci_config_addr: u32,
    /// Port 0x61 NMI Status & Control bit 4 (refresh toggle): toggles
    /// roughly every 15 µs on real hardware (the DMA refresh strobe).
    /// Linux's `tsc_calibrate_pit` reads it in a tight loop expecting
    /// the bit to flip; we just XOR a counter so each read sees a
    /// different value.
    port_61_toggle: u8,
    /// Port 0x61 bit 5 (PIT channel 2 OUT) emulation. Linux's LAPIC
    /// calibration programs PIT channel 2 and then spin-reads
    /// `port 0x61 & 0x20` until the bit is set, meaning counter 2
    /// reached terminal count. We don't run a real PIT, so we fake
    /// it: this counts up on each `IN 0x61` while the bit is clear,
    /// and flips bit 5 to 1 after ~4 reads. The count resets when
    /// Linux writes to PIT channel 2 (via port 0x42) to reload.
    port_61_ch2_out_count: u32,
}

impl DeviceState {
    const fn new() -> Self {
        Self {
            pic1_imr: 0xFF, // start with everything masked (Linux's first state too)
            pic2_imr: 0xFF,
            pic1_elcr: 0x00,
            pic2_elcr: 0x00,
            pit_channels: [PitChannel::new(); 3],
            cmos_index: 0,
            pci_config_addr: 0,
            port_61_toggle: 0,
            port_61_ch2_out_count: 0,
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
    // F.6 trace — print one line per NEW non-COM1 port. COM1 is
    // noisy (one I/O per byte of printk) so we skip it, everything
    // else is interesting.
    {
        use core::sync::atomic::{AtomicU16, Ordering};
        static LAST_NON_COM1_PORT: AtomicU16 = AtomicU16::new(0xFFFF);
        let p = access.port;
        let is_com1 = (COM1_TX_RX..=COM1_END).contains(&p);
        if !is_com1 {
            let prev = LAST_NON_COM1_PORT.swap(p, Ordering::Relaxed);
            if prev != p {
                crate::kprintln!(
                    "  vm/io: port={:#06x} w={} dir={:?} v={:#x}",
                    p, access.width, access.direction, access.value
                );
            }
        }
    }

    let result = match access.port {
        // COM1 — Phase F.2.
        COM1_TX_RX..=COM1_END => handle_com1(access),
        // 8259 PIC master/slave — Phase F.3.
        PIC1_CMD | PIC1_DATA | PIC2_CMD | PIC2_DATA => handle_pic(access),
        // PIT — Phase F.3.
        PIT_CH0..=PIT_MODE => handle_pit(access),
        // 8042 keyboard controller stub — Phase F.6.
        KBC_DATA | KBC_STATUS_CMD => handle_kbc(access),
        // NMI Status & Control / Port B — Phase F.6.
        NMI_STATUS_CONTROL => handle_port_61(access),
        // CMOS / RTC — Phase F.3.
        CMOS_INDEX | CMOS_DATA => handle_cmos(access),
        // POST diagnostic — Phase F.3.
        POST_DIAG => handle_post(access),
        // PIC ELCR (edge/level trigger registers) — Phase F.6.
        PIC_ELCR_MASTER | PIC_ELCR_SLAVE => handle_pic_elcr(access),
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

/// PIT (8254) emulation, F.6 — supports the LOBYTE_HIBYTE access
/// mode that Linux's `tsc_calibrate_pit` uses on channel 2.
///
/// The 8254 mode register at 0x43 has the layout:
///   bits 6..7  channel select (0/1/2)
///   bits 4..5  access mode (01=lo, 10=hi, 11=lo+hi)
///   bits 1..3  operating mode
///   bit  0     BCD/binary
///
/// Linux issues `outb(0xB0, 0x43)` for channel 2 latch:
///   ch=2 (10), access=lo+hi (11), mode=0 (rate generator), bin (0)
///   = 0b1011_0000 = 0xB0
///
/// Then writes the LATCH value as two bytes to 0x42 (lo first, then
/// hi). After arming via port 0x61, Linux reads 0x42 in pairs to
/// observe the counter going down. We emulate that by giving CH2
/// a synthetic counter that decrements by a sizeable step on every
/// FULL (lo+hi) read so the calibration loop converges in O(1)
/// iterations.
fn handle_pit(access: IoAccess) -> IoResult {
    let mut state = DEVICE_STATE.lock();
    match (access.port, access.direction) {
        (PIT_CH0..=PIT_CH2, IoDir::Out) => {
            let ch = (access.port - PIT_CH0) as usize;
            // If Linux is reloading channel 2, reset the 0x61 bit 5
            // fake OUT counter so the next poll sequence waits the
            // full 4 reads again.
            if ch == 2 {
                state.port_61_ch2_out_count = 0;
            }
            let chan = &mut state.pit_channels[ch];
            let byte = (access.value & 0xFF) as u16;
            match chan.access_mode {
                0b01 => {
                    chan.reload = (chan.reload & 0xFF00) | byte;
                    chan.counter = chan.reload;
                }
                0b10 => {
                    chan.reload = (chan.reload & 0x00FF) | (byte << 8);
                    chan.counter = chan.reload;
                }
                _ => {
                    // 0b11 — lo then hi
                    if !chan.next_is_hi_write {
                        chan.reload = (chan.reload & 0xFF00) | byte;
                        chan.next_is_hi_write = true;
                    } else {
                        chan.reload = (chan.reload & 0x00FF) | (byte << 8);
                        chan.next_is_hi_write = false;
                        chan.counter = chan.reload;
                    }
                }
            }
            IoResult::Ok { value: 0 }
        }
        (PIT_CH0..=PIT_CH2, IoDir::In) => {
            let ch = (access.port - PIT_CH0) as usize;
            let chan = &mut state.pit_channels[ch];
            let byte = match chan.access_mode {
                0b01 => {
                    let v = (chan.counter & 0xFF) as u32;
                    chan.counter = chan.counter.wrapping_sub(0x100);
                    v
                }
                0b10 => {
                    let v = (chan.counter >> 8) as u32;
                    chan.counter = chan.counter.wrapping_sub(0x100);
                    v
                }
                _ => {
                    // 0b11 — lo then hi
                    if !chan.next_is_hi_read {
                        chan.next_is_hi_read = true;
                        (chan.counter & 0xFF) as u32
                    } else {
                        chan.next_is_hi_read = false;
                        let v = (chan.counter >> 8) as u32;
                        // Decrement the synthetic counter on each full
                        // read pair so successive samples differ.
                        // Step = 0x100 keeps the value monotonically
                        // decreasing for ~256 calibration iterations
                        // before it wraps, which is plenty.
                        chan.counter = chan.counter.wrapping_sub(0x100);
                        v
                    }
                }
            };
            IoResult::Ok { value: byte }
        }
        (PIT_MODE, IoDir::Out) => {
            // Decode the mode-register byte and stash the access mode
            // into the addressed channel. We don't model operating
            // modes (rate generator, square wave, etc.) — they only
            // matter if the guest expects accurate timing semantics.
            let v = access.value as u8;
            let ch = ((v >> 6) & 0b11) as usize;
            let amode = (v >> 4) & 0b11;
            if ch < 3 && amode != 0 {
                let chan = &mut state.pit_channels[ch];
                chan.access_mode = amode;
                chan.next_is_hi_read = false;
                chan.next_is_hi_write = false;
                // Counter latch (amode=0b00) is technically distinct
                // from setting access mode, but we collapse them — the
                // next read returns the current counter value.
            }
            IoResult::Ok { value: 0 }
        }
        (PIT_MODE, IoDir::In) => IoResult::Ok { value: 0 },
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

// ---------------------------------------------------------------------------
// Phase F.6 — NMI Status & Control / Port B (port 0x61)
// ---------------------------------------------------------------------------
//
// Bit layout (per ISA / PIIX docs):
//   0  Tim Counter 2 enable      (R/W)
//   1  Speaker data enable        (R/W)
//   2  Parity check enable        (R/W)
//   3  IO check enable            (R/W)
//   4  Refresh cycle toggle       (RO — toggles ~every 15 us)
//   5  Counter 2 OUT              (RO)
//   6  IOCHK NMI source           (RO)
//   7  SERR NMI source            (RO)
//
// Linux's `tsc_calibrate_pit` uses bit 4 to detect that "time is
// passing" — it polls until the bit flips. We toggle it on every
// read so the calibration loop converges in O(1) reads.
fn handle_port_61(access: IoAccess) -> IoResult {
    let mut state = DEVICE_STATE.lock();
    match access.direction {
        IoDir::In => {
            // Bit 4 (refresh toggle) — flip on every read.
            state.port_61_toggle ^= 0x10;
            // Bit 5 (PIT channel 2 OUT): Linux's `pit_calibrate_tsc`
            // spins on `(inb(0x61) & 0x20) == 0` after arming PIT
            // channel 2 and counts loop iterations. If the loop
            // count is below `loopmin` (~10-20 per arch/x86/kernel/
            // tsc.c), Linux rejects the calibration as "SMI hit us"
            // and retries or marks TSC unstable.
            //
            // We therefore return bit 5 CLEAR for the first N reads
            // and latch HIGH afterwards so Linux sees both "time
            // passing" (TSC delta > 0) and "enough iterations"
            // (loopcount >= loopmin). N = 64 gives ~6x loopmin so
            // Linux accepts the calibration even if one or two
            // reads are skipped by preemption.
            //
            // The count resets on writes to PIT channel 2 reload
            // (port 0x42), meaning each retry gets a fresh 64-read
            // window.
            const PIT_CH2_OUT_DELAY: u32 = 64;
            let mut byte = state.port_61_toggle;
            if state.port_61_ch2_out_count < PIT_CH2_OUT_DELAY {
                state.port_61_ch2_out_count += 1;
            } else {
                byte |= 0x20;
            }
            IoResult::Ok { value: byte as u32 }
        }
        IoDir::Out => {
            // Writes update bits 0..3 (timer/speaker/parity/iochk).
            // We don't model any of those side effects, but the
            // gate bit (bit 0) transitioning 0->1 is the canonical
            // "start counter 2" signal — reset the OUT-count so
            // the next poll sequence goes through the fresh 4-read
            // delay.
            if access.value & 0x1 != 0 {
                state.port_61_ch2_out_count = 0;
            }
            IoResult::Ok { value: 0 }
        }
    }
}

// ---------------------------------------------------------------------------
// Phase F.6 — 8042 PS/2 keyboard controller stub
// ---------------------------------------------------------------------------
//
// Linux's `i8042_controller_check` writes 0x20 (read CCB) to 0x64
// then reads 0x60 expecting a status byte. If the controller is
// truly absent the BIOS reports it via ACPI; for now we report
// "no keyboard": status read returns 0 (no output buffer full),
// data read returns 0, command writes silently accepted. Linux
// will time out waiting for an ACK and disable the i8042 driver,
// which is fine — our guest doesn't have a keyboard.
fn handle_kbc(access: IoAccess) -> IoResult {
    match (access.port, access.direction) {
        // Status register (read) — bit 0 = output buffer full (0 = empty),
        // bit 1 = input buffer full (0 = ready). We always report
        // "empty / ready / no parity error" so Linux can poll quickly.
        (KBC_STATUS_CMD, IoDir::In) => IoResult::Ok { value: 0 },
        // Command register (write) — accept silently.
        (KBC_STATUS_CMD, IoDir::Out) => IoResult::Ok { value: 0 },
        // Data register (read) — return 0 (no scan code).
        (KBC_DATA, IoDir::In) => IoResult::Ok { value: 0 },
        // Data register (write) — accept silently.
        (KBC_DATA, IoDir::Out) => IoResult::Ok { value: 0 },
        _ => IoResult::Unhandled,
    }
}

// ---------------------------------------------------------------------------
// Phase F.6 — PIC ELCR (edge/level trigger registers)
// ---------------------------------------------------------------------------
//
// 0x4D0/0x4D1 select edge vs level triggering for each IRQ. Linux
// reads them as part of `pcibios_irq_init` to discover the trigger
// mode of each line. We never deliver virtual IRQs through the PIC
// path so trigger mode is irrelevant — return whatever was last
// written, or 0 by default.
fn handle_pic_elcr(access: IoAccess) -> IoResult {
    let mut state = DEVICE_STATE.lock();
    match (access.port, access.direction) {
        (PIC_ELCR_MASTER, IoDir::Out) => {
            state.pic1_elcr = access.value as u8;
            IoResult::Ok { value: 0 }
        }
        (PIC_ELCR_MASTER, IoDir::In) => IoResult::Ok { value: state.pic1_elcr as u32 },
        (PIC_ELCR_SLAVE, IoDir::Out) => {
            state.pic2_elcr = access.value as u8;
            IoResult::Ok { value: 0 }
        }
        (PIC_ELCR_SLAVE, IoDir::In) => IoResult::Ok { value: state.pic2_elcr as u32 },
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
