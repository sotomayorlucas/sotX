//! xHCI Transfer Request Block (TRB) structures and ring buffers.

// ---------------------------------------------------------------------------
// TRB structure (16 bytes, 16-byte aligned)
// ---------------------------------------------------------------------------

/// xHCI Transfer Request Block — 16 bytes, `repr(C, align(16))`.
///
/// The unit of work exchanged between host and controller on every
/// ring (command, transfer, event). Layout matches xHCI 1.2 §4.11:
/// a 64-bit parameter, a 32-bit status/length word, and a 32-bit
/// control word carrying the TRB type, cycle bit, and flags.
#[repr(C, align(16))]
#[derive(Clone, Copy)]
pub struct Trb {
    /// Parameter (DW0/DW1). Meaning depends on [`trb_type`](Self::trb_type):
    /// e.g. data buffer physical address, input context pointer, or
    /// immediate setup-packet bytes.
    pub param: u64,
    /// Status word (DW2). For transfer TRBs holds the TRB Transfer Length;
    /// for event TRBs the upper byte holds the completion code.
    pub status: u32,
    /// Control word (DW3): cycle bit (0), flags, TRB type (15:10),
    /// endpoint/slot id (31:16), and type-specific bits.
    pub control: u32,
}

const _: () = assert!(core::mem::size_of::<Trb>() == 16);

impl Trb {
    /// All-zeros TRB. `const` so callers can build static ring buffers.
    pub const fn zeroed() -> Self {
        Trb { param: 0, status: 0, control: 0 }
    }

    /// Extract TRB type from control word (bits 15:10).
    pub fn trb_type(&self) -> u8 {
        ((self.control >> 10) & 0x3F) as u8
    }

    /// Extract completion code from status word (bits 31:24).
    pub fn completion_code(&self) -> u8 {
        (self.status >> 24) as u8
    }

    /// Extract slot ID from control word (bits 31:24).
    pub fn slot_id(&self) -> u8 {
        (self.control >> 24) as u8
    }

    /// Extract endpoint ID from Transfer Event control (bits 20:16).
    pub fn endpoint_id(&self) -> u8 {
        ((self.control >> 16) & 0x1F) as u8
    }

    /// Extract cycle bit (bit 0 of control).
    pub fn cycle(&self) -> bool {
        self.control & 1 != 0
    }
}

// ---------------------------------------------------------------------------
// TRB Type constants (xHCI 1.2 §6.4.6 — Table 6-91)
// ---------------------------------------------------------------------------

/// Normal TRB — bulk/interrupt transfer data buffer (type 1).
pub const TRB_NORMAL: u8 = 1;
/// Setup Stage TRB — first TRB of a control transfer (type 2).
pub const TRB_SETUP_STAGE: u8 = 2;
/// Data Stage TRB — optional data phase of a control transfer (type 3).
pub const TRB_DATA_STAGE: u8 = 3;
/// Status Stage TRB — final TRB of a control transfer (type 4).
pub const TRB_STATUS_STAGE: u8 = 4;
/// Link TRB — pointer used to chain ring segments or wrap a ring (type 6).
pub const TRB_LINK: u8 = 6;
/// No-Op Command TRB — used to verify the command ring (type 23).
pub const TRB_NO_OP_CMD: u8 = 23;
/// Enable Slot Command TRB — allocate a device slot (type 9).
pub const TRB_ENABLE_SLOT: u8 = 9;
/// Disable Slot Command TRB — release a device slot (type 10).
pub const TRB_DISABLE_SLOT: u8 = 10;
/// Address Device Command TRB — bind a slot to a USB address (type 11).
pub const TRB_ADDRESS_DEV: u8 = 11;
/// Configure Endpoint Command TRB — add/remove endpoints on a slot (type 12).
pub const TRB_CONFIGURE_EP: u8 = 12;
/// Reset Endpoint Command TRB — clear a halted endpoint (type 14).
pub const TRB_RESET_EP: u8 = 14;
/// Stop Endpoint Command TRB — pause transfers on an endpoint (type 15).
pub const TRB_STOP_EP: u8 = 15;
/// Transfer Event TRB — completion report for a transfer ring (type 32).
pub const TRB_XFER_EVENT: u8 = 32;
/// Command Completion Event TRB — result of a command ring submission (type 33).
pub const TRB_CMD_COMPLETE: u8 = 33;
/// Port Status Change Event TRB — root-hub port event (type 34).
pub const TRB_PORT_STATUS: u8 = 34;

// ---------------------------------------------------------------------------
// Completion codes
// ---------------------------------------------------------------------------

/// xHCI 1.2 §6.4.5 completion code 1 — operation completed without error.
pub const CC_SUCCESS: u8 = 1;

// ---------------------------------------------------------------------------
// Ring sizes
// ---------------------------------------------------------------------------

/// Total TRB slots in a ring (fits in one 4 KiB page: 4096/16 = 256).
pub const RING_SIZE: usize = 256;
/// Usable slots (last slot is Link TRB for command/transfer rings).
pub const RING_USABLE: usize = 255;

// ---------------------------------------------------------------------------
// Command TRB builders
// ---------------------------------------------------------------------------

/// Build a No-Op Command TRB.
pub fn cmd_no_op() -> Trb {
    Trb {
        param: 0,
        status: 0,
        control: (TRB_NO_OP_CMD as u32) << 10,
    }
}

/// Build an Enable Slot Command TRB.
pub fn cmd_enable_slot() -> Trb {
    Trb {
        param: 0,
        status: 0,
        control: (TRB_ENABLE_SLOT as u32) << 10,
    }
}

/// Build a Disable Slot Command TRB.
/// `slot_id`: slot to disable.
pub fn cmd_disable_slot(slot_id: u8) -> Trb {
    Trb {
        param: 0,
        status: 0,
        control: (TRB_DISABLE_SLOT as u32) << 10 | ((slot_id as u32) << 24),
    }
}

/// Build an Address Device Command TRB.
/// `input_ctx_phys`: physical address of the input context (16-byte aligned).
/// `slot_id`: slot to address.
/// `bsr`: Block Set Address Request — if true, skip SET_ADDRESS.
pub fn cmd_address_device(input_ctx_phys: u64, slot_id: u8, bsr: bool) -> Trb {
    let mut ctrl = (TRB_ADDRESS_DEV as u32) << 10 | ((slot_id as u32) << 24);
    if bsr {
        ctrl |= 1 << 9; // BSR bit
    }
    Trb {
        param: input_ctx_phys,
        status: 0,
        control: ctrl,
    }
}

/// Build a Configure Endpoint Command TRB.
pub fn cmd_configure_endpoint(input_ctx_phys: u64, slot_id: u8) -> Trb {
    Trb {
        param: input_ctx_phys,
        status: 0,
        control: (TRB_CONFIGURE_EP as u32) << 10 | ((slot_id as u32) << 24),
    }
}

// ---------------------------------------------------------------------------
// Transfer TRB builders (for EP0 control transfers and interrupt transfers)
// ---------------------------------------------------------------------------

/// Build a Setup Stage TRB for a control transfer.
/// `setup_packet`: 8 bytes of USB setup data packed as u64 (little-endian).
/// `trt`: Transfer Type — 0=No Data, 2=OUT Data, 3=IN Data.
pub fn trb_setup_stage(setup_packet: u64, trt: u8) -> Trb {
    Trb {
        param: setup_packet,
        status: 8, // TRB Transfer Length = 8 (setup packet size)
        // Type=SETUP_STAGE(2), IDT=1 (bit 6), TRT in bits 17:16
        control: (TRB_SETUP_STAGE as u32) << 10
            | (1 << 6)  // IDT — Immediate Data
            | ((trt as u32) << 16),
    }
}

/// Build a Data Stage TRB for a control transfer.
/// `dir_in`: true for IN (device-to-host), false for OUT.
pub fn trb_data_stage(buf_phys: u64, length: u16, dir_in: bool) -> Trb {
    let mut ctrl = (TRB_DATA_STAGE as u32) << 10;
    if dir_in {
        ctrl |= 1 << 16; // DIR = IN
    }
    Trb {
        param: buf_phys,
        status: length as u32,
        control: ctrl,
    }
}

/// Build a Status Stage TRB for a control transfer.
/// `dir_in`: true if status direction is IN (i.e., for OUT/No-Data transfers).
/// Set IOC to get a Transfer Event.
pub fn trb_status_stage(dir_in: bool) -> Trb {
    let mut ctrl = (TRB_STATUS_STAGE as u32) << 10 | (1 << 5); // IOC
    if dir_in {
        ctrl |= 1 << 16; // DIR = IN
    }
    Trb {
        param: 0,
        status: 0,
        control: ctrl,
    }
}

/// Build a Normal TRB for an interrupt IN transfer.
/// Set IOC to get a Transfer Event on completion.
pub fn trb_normal(buf_phys: u64, length: u16) -> Trb {
    Trb {
        param: buf_phys,
        status: length as u32,
        control: (TRB_NORMAL as u32) << 10 | (1 << 5), // IOC
    }
}

// ---------------------------------------------------------------------------
// TrbRing — Producer ring (for Command Ring and Transfer Rings)
// ---------------------------------------------------------------------------

/// Producer-side state for a TRB ring (command ring or transfer ring).
///
/// Owns the enqueue cursor and the Producer Cycle State bit used by
/// the controller to tell new TRBs from stale ones. The backing page
/// is caller-allocated (4 KiB, `RING_SIZE` entries) and the last slot
/// is reserved for the Link TRB that wraps back to the start.
pub struct TrbRing {
    base: *mut Trb,
    phys: u64,
    enqueue: usize,
    pcs: bool, // Producer Cycle State
}

impl TrbRing {
    /// Initialize a TRB ring at the given virtual/physical address.
    /// Zeros all entries and writes a Link TRB at the last slot.
    pub unsafe fn init(virt: *mut u8, phys: u64) -> Self {
        // Zero all entries.
        core::ptr::write_bytes(virt, 0, 4096);

        let base = virt as *mut Trb;

        // Write Link TRB at slot RING_USABLE (index 255).
        let link = base.add(RING_USABLE);
        // param = physical address of ring start (wrap target).
        core::ptr::write_volatile(&mut (*link).param as *mut u64, phys);
        // control: type=LINK, Toggle Cycle bit (bit 1).
        // Cycle bit (bit 0) will be set when we wrap — start as 0 (opposite of PCS=true).
        core::ptr::write_volatile(
            &mut (*link).control as *mut u32,
            ((TRB_LINK as u32) << 10) | (1 << 1), // TC=1, cycle=0
        );

        TrbRing { base, phys, enqueue: 0, pcs: true }
    }

    /// Enqueue a TRB. Sets the cycle bit from PCS. Returns the physical address.
    pub unsafe fn enqueue(&mut self, mut trb: Trb) -> u64 {
        // Set or clear cycle bit based on PCS.
        if self.pcs {
            trb.control |= 1; // set cycle bit
        } else {
            trb.control &= !1; // clear cycle bit
        }

        let slot_phys = self.phys + (self.enqueue as u64) * 16;
        core::ptr::write_volatile(self.base.add(self.enqueue), trb);

        self.enqueue += 1;
        if self.enqueue >= RING_USABLE {
            // We've reached the Link TRB — toggle its cycle bit and wrap.
            let link = self.base.add(RING_USABLE);
            let mut link_ctrl = core::ptr::read_volatile(&(*link).control as *const u32);
            // Clear old cycle bit, set current PCS.
            link_ctrl = (link_ctrl & !1) | (self.pcs as u32);
            core::ptr::write_volatile(&mut (*link).control as *mut u32, link_ctrl);
            self.enqueue = 0;
            self.pcs = !self.pcs; // Toggle PCS
        }

        slot_phys
    }

    /// Get the physical address of the ring base.
    pub fn phys(&self) -> u64 {
        self.phys
    }
}

// ---------------------------------------------------------------------------
// EventRing — Consumer ring (for Event Ring)
// ---------------------------------------------------------------------------

/// Consumer-side state for an Event Ring.
///
/// Tracks the dequeue cursor and the Consumer Cycle State; the
/// controller posts events with its own cycle bit and software
/// compares against `ccs` to find fresh entries.
pub struct EventRing {
    base: *const Trb,
    phys: u64,
    dequeue: usize,
    ccs: bool, // Consumer Cycle State
}

impl EventRing {
    /// Initialize an event ring at the given virtual/physical address.
    pub unsafe fn init(virt: *mut u8, phys: u64) -> Self {
        core::ptr::write_bytes(virt, 0, 4096);
        EventRing {
            base: virt as *const Trb,
            phys,
            dequeue: 0,
            ccs: true,
        }
    }

    /// Poll the next event. Returns Some(trb) if a new event is available.
    pub unsafe fn poll(&self) -> Option<Trb> {
        let trb = core::ptr::read_volatile(self.base.add(self.dequeue));
        if trb.cycle() == self.ccs {
            Some(trb)
        } else {
            None
        }
    }

    /// Advance the dequeue pointer after consuming an event.
    pub fn advance(&mut self) {
        self.dequeue += 1;
        if self.dequeue >= RING_SIZE {
            self.dequeue = 0;
            self.ccs = !self.ccs;
        }
    }

    /// Get the physical address of the current dequeue position (for ERDP writeback).
    pub fn dequeue_phys(&self) -> u64 {
        self.phys + (self.dequeue as u64) * 16
    }
}

// ---------------------------------------------------------------------------
// ERST entry (Event Ring Segment Table)
// ---------------------------------------------------------------------------

/// Event Ring Segment Table Entry (16 bytes).
///
/// The ERST lets the controller know where one or more event-ring
/// segments live in physical memory. Our driver uses a single
/// segment, so the table has exactly one entry.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct ErstEntry {
    /// Physical base address of the event ring segment (64-byte aligned).
    pub ring_segment_base: u64,
    /// Number of TRBs in the segment (16..4096 per xHCI 1.2 §6.5).
    pub ring_segment_size: u32,
    _reserved: u32,
}

const _: () = assert!(core::mem::size_of::<ErstEntry>() == 16);

impl ErstEntry {
    /// Build a single-segment ERST entry pointing at `base_phys` and
    /// advertising `size` TRB slots.
    pub fn new(base_phys: u64, size: u32) -> Self {
        ErstEntry {
            ring_segment_base: base_phys,
            ring_segment_size: size,
            _reserved: 0,
        }
    }
}
