//! sot-statusbar -- Tokyo Night layer-shell status bar for the sotOS compositor.
//!
//! Connects to the native `compositor` IPC service, walks the Wayland
//! handshake (wl_display.get_registry, bind wl_compositor/wl_shm), and then
//! attempts to bind `zwlr_layer_shell_v1`. When layer-shell lands (G7), the
//! bar anchors TOP|LEFT|RIGHT with exclusive_zone=24 and draws:
//!
//!   * TSC-derived wall clock
//!   * Free memory percentage  (sys::debug_free_frames)
//!   * Live process/thread count (sys::thread_count)
//!
//! On the current sotBSD HEAD the compositor does NOT yet advertise
//! `zwlr_layer_shell_v1`, so the bar takes the graceful fallback path
//! documented in the task description: it prints `statusbar: no layer-shell`
//! and enters an idle loop. Success path prints `=== sot-statusbar: WIRED ===`.
//!
//! Wire protocol bytes mirror services/hello-gui/src/main.rs verbatim.

#![no_std]
#![no_main]

use sotos_common::sys;
use sotos_common::{BootInfo, IpcMsg, BOOT_INFO_ADDR};

// ---------------------------------------------------------------------------
// Status bar geometry
// ---------------------------------------------------------------------------

/// Status bar height in pixels (matches exclusive_zone).
const BAR_H: u32 = 24;

/// Placeholder width -- the compositor will send a configure event with the
/// real output width. Until we handle that, use a sensible default.
const BAR_W: u32 = 1280;

/// Bytes per pixel (XRGB8888).
const BPP: u32 = 4;

/// SHM pool size.
const POOL_SIZE: u32 = BAR_W * BAR_H * BPP;

/// Virtual address where we map the SHM pool in sot-statusbar's own AS.
///
/// 0x9000000 sits in the documented gap above the interp load base
/// (0x6000000) and below the interp buf base (0xA000000) -- see the
/// address-space layout comment in services/init/src/main.rs. Avoids
/// 0x7000000, which historically aliased CHILD_BRK and caused the
/// nano-on-LUCAS GPF called out in MEMORY.md.
const CLIENT_POOL_BASE: u64 = 0x9000000;

// ---------------------------------------------------------------------------
// Tokyo Night palette (sourced from sotos-theme)
// ---------------------------------------------------------------------------

const TN_BG: u32     = sotos_theme::TOKYO_NIGHT.bg;        // storm background
const TN_FG: u32     = sotos_theme::TOKYO_NIGHT.fg;        // foreground text
const TN_ACCENT: u32 = sotos_theme::TOKYO_NIGHT.accent;    // blue accent
const TN_GREEN: u32  = sotos_theme::TOKYO_NIGHT.green_alt; // memory OK
const TN_RED: u32    = sotos_theme::TOKYO_NIGHT.red;        // memory low

// ---------------------------------------------------------------------------
// IPC tags (must match compositor::wayland::mod constants verbatim)
// ---------------------------------------------------------------------------

const WL_MSG_TAG: u64 = 0x574C;            // "WL"
const WL_CONNECT_TAG: u64 = 0x574C_434F;   // "WLCO"
const WL_SHM_POOL_TAG: u64 = 0x574C_5348;  // "WLSH"

/// Max bytes per IPC message payload (8 regs * 8 bytes).
const IPC_DATA_MAX: usize = 64;

// ---------------------------------------------------------------------------
// Wayland object IDs (client-allocated, start at 2)
// ---------------------------------------------------------------------------

const WL_DISPLAY_ID: u32      = 1;
const REGISTRY_ID: u32        = 2;
const SHM_ID: u32             = 3;
const COMPOSITOR_ID: u32      = 4;
const LAYER_SHELL_ID: u32     = 5;
const POOL_ID: u32            = 6;
const BUFFER_ID: u32          = 7;
const SURFACE_ID: u32         = 8;
const LAYER_SURFACE_ID: u32   = 9;

// zwlr_layer_shell_v1 layer constants
const ZWLR_LAYER_TOP: u32 = 2;

// zwlr_layer_surface_v1 request opcodes we use.
const LS_OP_SET_SIZE: u16 = 0;
const LS_OP_SET_ANCHOR: u16 = 1;
const LS_OP_SET_EXCLUSIVE_ZONE: u16 = 2;
const LS_OP_ACK_CONFIGURE: u16 = 6;
const LS_EVT_CONFIGURE_OPCODE: u16 = 0;

// zwlr_layer_surface_v1 anchor bitmask: top | left | right
const ANCHOR_TOP: u32 = 1;
const ANCHOR_LEFT: u32 = 4;
const ANCHOR_RIGHT: u32 = 8;
const ANCHOR_TOP_FULL: u32 = ANCHOR_TOP | ANCHOR_LEFT | ANCHOR_RIGHT;

// Interface name we probe for to detect layer-shell support.
const LAYER_SHELL_INTERFACE: &[u8] = b"zwlr_layer_shell_v1";

// ---------------------------------------------------------------------------
// Tiny stdout helpers (serial)
// ---------------------------------------------------------------------------

fn print(s: &[u8]) {
    for &b in s {
        sys::debug_print(b);
    }
}

fn print_u32(mut val: u32) {
    if val == 0 {
        sys::debug_print(b'0');
        return;
    }
    let mut buf = [0u8; 10];
    let mut i = 0;
    while val > 0 && i < buf.len() {
        buf[i] = b'0' + (val % 10) as u8;
        val /= 10;
        i += 1;
    }
    while i > 0 {
        i -= 1;
        sys::debug_print(buf[i]);
    }
}

fn print_u64(mut val: u64) {
    if val == 0 {
        sys::debug_print(b'0');
        return;
    }
    let mut buf = [0u8; 20];
    let mut i = 0;
    while val > 0 && i < buf.len() {
        buf[i] = b'0' + (val % 10) as u8;
        val /= 10;
        i += 1;
    }
    while i > 0 {
        i -= 1;
        sys::debug_print(buf[i]);
    }
}

fn print_hex(val: u64) {
    let hex = b"0123456789abcdef";
    print(b"0x");
    for i in (0..16).rev() {
        let nibble = ((val >> (i * 4)) & 0xF) as usize;
        sys::debug_print(hex[nibble]);
    }
}

// ---------------------------------------------------------------------------
// Wayland wire builder (byte-for-byte identical to services/hello-gui)
// ---------------------------------------------------------------------------

struct WireBuilder {
    buf: [u8; IPC_DATA_MAX],
    len: usize,
}

impl WireBuilder {
    fn new(object_id: u32, opcode: u16) -> Self {
        let mut b = Self {
            buf: [0u8; IPC_DATA_MAX],
            len: 8,
        };
        b.buf[0..4].copy_from_slice(&object_id.to_ne_bytes());
        let op = (opcode as u32).to_ne_bytes();
        b.buf[4..8].copy_from_slice(&op);
        b
    }

    fn put_u32(&mut self, val: u32) {
        let bytes = val.to_ne_bytes();
        self.buf[self.len..self.len + 4].copy_from_slice(&bytes);
        self.len += 4;
    }

    fn put_i32(&mut self, val: i32) {
        self.put_u32(val as u32);
    }

    fn put_string(&mut self, s: &[u8]) {
        let len_with_nul = s.len() + 1;
        self.put_u32(len_with_nul as u32);
        self.buf[self.len..self.len + s.len()].copy_from_slice(s);
        self.buf[self.len + s.len()] = 0;
        let padded = (len_with_nul + 3) & !3;
        self.len += padded;
    }

    fn finish(&mut self) -> IpcMsg {
        let size_opcode = ((self.len as u32) << 16)
            | (u32::from_ne_bytes([self.buf[4], self.buf[5], self.buf[6], self.buf[7]]) & 0xFFFF);
        self.buf[4..8].copy_from_slice(&size_opcode.to_ne_bytes());

        let mut msg = IpcMsg::empty();
        msg.tag = WL_MSG_TAG | ((self.len as u64) << 16);
        let dst = &mut msg.regs as *mut u64 as *mut u8;
        unsafe {
            core::ptr::copy_nonoverlapping(self.buf.as_ptr(), dst, self.len);
        }
        msg
    }
}

fn wl_call(ep: u64, msg: &IpcMsg) -> IpcMsg {
    match sys::call(ep, msg) {
        Ok(reply) => reply,
        Err(e) => {
            print(b"statusbar: IPC call failed ");
            print_hex(e as u64);
            print(b"\n");
            IpcMsg::empty()
        }
    }
}

/// Send wl_surface damage + commit for the full bar. Used for both the
/// initial draw and every tick of the redraw loop.
fn damage_and_commit(ep: u64) {
    let mut dmg = WireBuilder::new(SURFACE_ID, 2);
    dmg.put_i32(0);
    dmg.put_i32(0);
    dmg.put_i32(BAR_W as i32);
    dmg.put_i32(BAR_H as i32);
    let _ = wl_call(ep, &dmg.finish());

    let mut commit = WireBuilder::new(SURFACE_ID, 6);
    let _ = wl_call(ep, &commit.finish());
}

// ---------------------------------------------------------------------------
// Registry parsing: scan the reply for `zwlr_layer_shell_v1`.
//
// The compositor packs globals as wl_registry::global events:
//   header(8) + name(4) + interface_string + version(4)
// where interface_string is: len(4) + bytes(len) + padding to 4.
// We walk the reply byte stream and look for the interface name.
// ---------------------------------------------------------------------------

fn reply_bytes(msg: &IpcMsg) -> ([u8; IPC_DATA_MAX], usize) {
    let byte_count = ((msg.tag >> 16) & 0xFFFF) as usize;
    let byte_count = byte_count.min(IPC_DATA_MAX);
    let mut buf = [0u8; IPC_DATA_MAX];
    let src = &msg.regs as *const u64 as *const u8;
    unsafe {
        core::ptr::copy_nonoverlapping(src, buf.as_mut_ptr(), byte_count);
    }
    (buf, byte_count)
}

/// Walk the packed events in `buf[..len]` looking for a
/// `zwlr_layer_surface_v1::configure(serial, width, height)` event
/// targeted at `surface_object_id`. Returns Some(serial) if found.
///
/// The compositor sends this event immediately after `get_layer_surface`
/// so the client can ack it and commit its first buffer (per the
/// wlr-layer-shell-unstable-v1 spec). See
/// services/compositor/src/wayland/layer_shell.rs (send_configure).
fn find_layer_configure(buf: &[u8], len: usize, surface_object_id: u32) -> Option<u32> {
    let mut off = 0usize;
    while off + 8 <= len {
        let obj = u32::from_ne_bytes([buf[off], buf[off + 1], buf[off + 2], buf[off + 3]]);
        let size_op = u32::from_ne_bytes([buf[off + 4], buf[off + 5], buf[off + 6], buf[off + 7]]);
        let opcode = (size_op & 0xFFFF) as u16;
        let size = (size_op >> 16) as usize;

        if size < 8 || off + size > len {
            return None;
        }

        // configure payload = serial(4) + width(4) + height(4), 20B incl header.
        if obj == surface_object_id && opcode == LS_EVT_CONFIGURE_OPCODE && size >= 20 {
            let serial = u32::from_ne_bytes([
                buf[off + 8],
                buf[off + 9],
                buf[off + 10],
                buf[off + 11],
            ]);
            return Some(serial);
        }

        off += size;
    }
    None
}

/// Walk the packed events in `buf[..len]` searching for a `global` event
/// advertising `needle` as the interface name. Returns Some(global_name)
/// if found, otherwise None.
fn find_global(buf: &[u8], len: usize, needle: &[u8]) -> Option<u32> {
    // Each wl_registry::global event is:
    //   header(8) + name(4) + interface_string(4+len+pad) + version(4)
    let mut off = 0usize;
    while off + 8 <= len {
        let size_op = u32::from_ne_bytes([buf[off + 4], buf[off + 5], buf[off + 6], buf[off + 7]]);
        let opcode = (size_op & 0xFFFF) as u16;
        let size = (size_op >> 16) as usize;

        if size < 8 || off + size > len {
            return None;
        }

        if opcode == 0 && size >= 20 {
            let payload = &buf[off + 8..off + size];
            let str_len = u32::from_ne_bytes([payload[4], payload[5], payload[6], payload[7]]) as usize;
            if str_len > 0 && 8 + str_len <= payload.len() {
                let str_bytes = &payload[8..8 + str_len - 1];
                if str_bytes == needle {
                    return Some(u32::from_ne_bytes([payload[0], payload[1], payload[2], payload[3]]));
                }
            }
        }

        off += size;
    }
    None
}

// ---------------------------------------------------------------------------
// Metrics (sampled once per redraw)
// ---------------------------------------------------------------------------

#[derive(Clone, Copy)]
struct Metrics {
    clock_secs: u64,
    mem_pct: u32,     // free frames / initial * 100
    procs: u32,       // sys::thread_count()
}

/// Anchor TSC reading used to derive a monotonic "seconds since boot" clock.
/// The rate (2 GHz) matches the assumption baked into the vDSO in
/// services/init/src/vdso.rs.
const TSC_HZ: u64 = 2_000_000_000;

fn sample_metrics(baseline_free: u64) -> Metrics {
    let tsc = sys::rdtsc();
    let clock_secs = tsc / TSC_HZ;
    let free_now = sys::debug_free_frames();
    let mem_pct = if baseline_free == 0 {
        0
    } else {
        ((free_now.min(baseline_free) * 100) / baseline_free) as u32
    };
    let procs = sys::thread_count() as u32;
    Metrics { clock_secs, mem_pct, procs }
}

// ---------------------------------------------------------------------------
// Pixel rendering (only runs when layer-shell is live + self_as_cap is set)
// ---------------------------------------------------------------------------

fn clear_bar(pool: *mut u32, w: u32, h: u32) {
    let total = (w * h) as usize;
    for i in 0..total {
        unsafe { pool.add(i).write_volatile(TN_BG); }
    }
}

fn fill_rect(pool: *mut u32, stride_px: u32, x: u32, y: u32, w: u32, h: u32, color: u32) {
    for row in 0..h {
        for col in 0..w {
            let off = ((y + row) * stride_px + (x + col)) as usize;
            unsafe { pool.add(off).write_volatile(color); }
        }
    }
}

/// Draw the status bar for the given metrics into the SHM pool.
/// Layout: accent stripe on the far left, memory bar on the right,
/// and plain-color blocks in between as placeholders for glyphs (we
/// do not ship a font in this minimal implementation -- the blocks
/// visually encode the clock seconds % 60 / process count % 60).
fn draw_bar(pool: *mut u32, m: &Metrics) {
    let stride_px = BAR_W;
    clear_bar(pool, BAR_W, BAR_H);

    // Left accent strip (4 px wide).
    fill_rect(pool, stride_px, 0, 0, 4, BAR_H, TN_ACCENT);

    // Clock block: width scales with (seconds % 60).
    let clock_w = ((m.clock_secs % 60) as u32).saturating_mul(2) + 4;
    fill_rect(pool, stride_px, 12, 4, clock_w.min(120), BAR_H - 8, TN_FG);

    // Process count block: width scales with procs.
    let proc_w = (m.procs.min(40)) * 3 + 4;
    fill_rect(pool, stride_px, 150, 4, proc_w, BAR_H - 8, TN_FG);

    // Memory bar on the right -- green when >= 25% free, red otherwise.
    // The cleared background already shows through the unfilled portion,
    // so we only paint the filled section.
    let mem_bar_w = 200u32;
    let mem_fill = (mem_bar_w * m.mem_pct.min(100)) / 100;
    let mem_x = BAR_W.saturating_sub(mem_bar_w + 8);
    let mem_color = if m.mem_pct >= 25 { TN_GREEN } else { TN_RED };
    fill_rect(pool, stride_px, mem_x, 4, mem_fill, BAR_H - 8, mem_color);
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    print(b"sot-statusbar: starting\n");

    let boot_info = unsafe { &*(BOOT_INFO_ADDR as *const BootInfo) };
    let self_as_cap = if boot_info.is_valid() {
        boot_info.self_as_cap
    } else {
        0
    };

    // -- Step 1: look up compositor service --
    let comp_ep = {
        let name = b"compositor";
        let mut attempts = 0u32;
        loop {
            match sys::svc_lookup(name.as_ptr() as u64, name.len() as u64) {
                Ok(ep) if ep != 0 => break ep,
                _ => {
                    sys::yield_now();
                    attempts += 1;
                    if attempts > 10_000 {
                        print(b"sot-statusbar: compositor not available after 10k yields\n");
                        idle_forever();
                    }
                }
            }
        }
    };
    print(b"sot-statusbar: compositor ep=");
    print_hex(comp_ep);
    print(b"\n");

    // -- Step 2: send connect --
    let mut connect = IpcMsg::empty();
    connect.tag = WL_CONNECT_TAG;
    let reply = wl_call(comp_ep, &connect);
    if reply.tag != WL_CONNECT_TAG || reply.regs[0] != 1 {
        print(b"sot-statusbar: connection rejected\n");
        idle_forever();
    }
    print(b"sot-statusbar: connected\n");

    // -- Step 3: wl_display.get_registry (opcode 1) --
    let mut msg = WireBuilder::new(WL_DISPLAY_ID, 1);
    msg.put_u32(REGISTRY_ID);
    let reply = wl_call(comp_ep, &msg.finish());

    // -- Step 4: scan the advertised globals for zwlr_layer_shell_v1 --
    let (reply_buf, reply_len) = reply_bytes(&reply);
    let layer_shell_name = match find_global(&reply_buf, reply_len, LAYER_SHELL_INTERFACE) {
        Some(n) => n,
        None => {
            print(b"statusbar: no layer-shell\n");
            idle_forever();
        }
    };

    print(b"sot-statusbar: layer-shell advertised as global name=");
    print_u32(layer_shell_name);
    print(b"\n");

    // -- Step 5: bind wl_compositor, wl_shm, zwlr_layer_shell_v1 --
    {
        let mut m = WireBuilder::new(REGISTRY_ID, 0);
        m.put_u32(1);
        m.put_string(b"wl_compositor");
        m.put_u32(4);
        m.put_u32(COMPOSITOR_ID);
        let _ = wl_call(comp_ep, &m.finish());
    }
    {
        let mut m = WireBuilder::new(REGISTRY_ID, 0);
        m.put_u32(2);
        m.put_string(b"wl_shm");
        m.put_u32(1);
        m.put_u32(SHM_ID);
        let _ = wl_call(comp_ep, &m.finish());
    }
    {
        let mut m = WireBuilder::new(REGISTRY_ID, 0);
        m.put_u32(layer_shell_name);
        m.put_string(LAYER_SHELL_INTERFACE);
        m.put_u32(1);
        m.put_u32(LAYER_SHELL_ID);
        let _ = wl_call(comp_ep, &m.finish());
    }

    // -- Step 6: create wl_surface (wl_compositor::create_surface, opcode 0) --
    {
        let mut m = WireBuilder::new(COMPOSITOR_ID, 0);
        m.put_u32(SURFACE_ID);
        let _ = wl_call(comp_ep, &m.finish());
    }

    // -- Step 7: zwlr_layer_shell_v1::get_layer_surface (opcode 0) --
    //    args: id(new_id), surface(object), output(object, null=0),
    //          layer(uint), namespace(string)
    //
    // The compositor replies with the initial configure(serial, 0, 0)
    // event packed into the IPC reply (see layer_shell::send_configure
    // in services/compositor). We capture the reply, scan it for the
    // configure event, and remember the serial for step 8b.
    let initial_configure_serial: u32 = {
        let mut m = WireBuilder::new(LAYER_SHELL_ID, 0);
        m.put_u32(LAYER_SURFACE_ID);
        m.put_u32(SURFACE_ID);
        m.put_u32(0);              // output = null (default)
        m.put_u32(ZWLR_LAYER_TOP); // top layer
        m.put_string(b"sot-statusbar");
        let reply = wl_call(comp_ep, &m.finish());
        let (rbuf, rlen) = reply_bytes(&reply);
        find_layer_configure(&rbuf, rlen, LAYER_SURFACE_ID).unwrap_or(0)
    };

    // -- Step 8a: configure layer_surface (size, anchor, exclusive_zone) --
    {
        let mut m = WireBuilder::new(LAYER_SURFACE_ID, LS_OP_SET_SIZE);
        m.put_u32(BAR_W);
        m.put_u32(BAR_H);
        let _ = wl_call(comp_ep, &m.finish());
    }
    {
        let mut m = WireBuilder::new(LAYER_SURFACE_ID, LS_OP_SET_ANCHOR);
        m.put_u32(ANCHOR_TOP_FULL);
        let _ = wl_call(comp_ep, &m.finish());
    }
    {
        let mut m = WireBuilder::new(LAYER_SURFACE_ID, LS_OP_SET_EXCLUSIVE_ZONE);
        m.put_i32(BAR_H as i32);
        let _ = wl_call(comp_ep, &m.finish());
    }

    // -- Step 8b: ack_configure(serial) --
    //
    // Per wlr-layer-shell-unstable-v1 the layer surface is NOT mapped until
    // the client acks the compositor's configure event; skipping this
    // leaves the bar invisible even with a buffer attached. sotOS's
    // compositor accepts any serial as an ack, so the fallback 0 in
    // `initial_configure_serial` (when the event hadn't arrived yet) is
    // safe.
    {
        let mut m = WireBuilder::new(LAYER_SURFACE_ID, LS_OP_ACK_CONFIGURE);
        m.put_u32(initial_configure_serial);
        let _ = wl_call(comp_ep, &m.finish());
    }

    // -- Step 9: allocate SHM pool and map it --
    let draw_ready = if self_as_cap != 0 {
        match setup_shm_pool(comp_ep) {
            Ok(()) => true,
            Err(()) => {
                print(b"sot-statusbar: shm setup failed, skipping pixel draw\n");
                false
            }
        }
    } else {
        print(b"sot-statusbar: no self_as_cap, skipping pixel draw\n");
        false
    };

    // -- Step 10: initial draw + commit --
    let baseline_free = sys::debug_free_frames();
    let mut metrics = sample_metrics(baseline_free);

    if draw_ready {
        draw_bar(CLIENT_POOL_BASE as *mut u32, &metrics);

        // wl_surface::attach(buffer, 0, 0)
        let mut attach = WireBuilder::new(SURFACE_ID, 1);
        attach.put_u32(BUFFER_ID);
        attach.put_i32(0);
        attach.put_i32(0);
        let _ = wl_call(comp_ep, &attach.finish());

        damage_and_commit(comp_ep);
    } else {
        // Even without pixels, commit the surface so the compositor
        // knows the layer client is alive.
        let mut commit = WireBuilder::new(SURFACE_ID, 6);
        let _ = wl_call(comp_ep, &commit.finish());
    }

    print(b"=== sot-statusbar: WIRED ===\n");

    // -- Step 11: redraw loop (~1 Hz via TSC deadline) --
    loop {
        let deadline = sys::rdtsc().wrapping_add(TSC_HZ);
        while sys::rdtsc() < deadline {
            sys::yield_now();
        }

        metrics = sample_metrics(baseline_free);

        if draw_ready {
            draw_bar(CLIENT_POOL_BASE as *mut u32, &metrics);
            damage_and_commit(comp_ep);
        }

        // Periodic heartbeat to the serial console so the boot-smoke
        // CI grep has something to match after the WIRED banner.
        print(b"sot-statusbar: tick clock=");
        print_u64(metrics.clock_secs);
        print(b" mem=");
        print_u32(metrics.mem_pct);
        print(b"% procs=");
        print_u32(metrics.procs);
        print(b"\n");
    }
}

// ---------------------------------------------------------------------------
// SHM pool setup (only called on the happy path)
// ---------------------------------------------------------------------------

fn setup_shm_pool(comp_ep: u64) -> Result<(), ()> {
    let boot_info = unsafe { &*(BOOT_INFO_ADDR as *const BootInfo) };
    let self_as_cap = boot_info.self_as_cap;

    let pages = ((POOL_SIZE as usize) + 0xFFF) / 0x1000;
    let shm_handle = match sys::shm_create(pages as u64) {
        Ok(h) => h,
        Err(e) => {
            print(b"sot-statusbar: shm_create failed ");
            print_hex(e as u64);
            print(b"\n");
            return Err(());
        }
    };

    // wl_shm::create_pool (opcode 0): pool_id, fd, size
    let mut m = WireBuilder::new(SHM_ID, 0);
    m.put_u32(POOL_ID);
    m.put_i32(shm_handle as i32);
    m.put_u32(POOL_SIZE);
    let reply = wl_call(comp_ep, &m.finish());
    if reply.tag != WL_SHM_POOL_TAG {
        print(b"sot-statusbar: unexpected pool reply\n");
        return Err(());
    }

    // shm_map's 4th arg is a flags bitmap (bit 0 = writable), NOT a page
    // count -- the kernel pulls page_count from the ShmObject itself
    // (see kernel/src/shm.rs). All `pages` allocated above get mapped.
    const SHM_MAP_WRITABLE: u64 = 1;
    if sys::shm_map(shm_handle, self_as_cap, CLIENT_POOL_BASE, SHM_MAP_WRITABLE).is_err() {
        print(b"sot-statusbar: shm_map failed\n");
        return Err(());
    }

    // wl_shm_pool::create_buffer (opcode 0)
    let stride = BAR_W * BPP;
    let mut m = WireBuilder::new(POOL_ID, 0);
    m.put_u32(BUFFER_ID);
    m.put_i32(0);
    m.put_i32(BAR_W as i32);
    m.put_i32(BAR_H as i32);
    m.put_i32(stride as i32);
    m.put_u32(1); // XRGB8888
    let _ = wl_call(comp_ep, &m.finish());

    Ok(())
}

fn idle_forever() -> ! {
    loop {
        sys::yield_now();
    }
}

// ---------------------------------------------------------------------------
// Panic handler
// ---------------------------------------------------------------------------

#[panic_handler]
fn panic(info: &core::panic::PanicInfo) -> ! {
    print(b"sot-statusbar: PANIC");
    if let Some(loc) = info.location() {
        print(b" at ");
        for &b in loc.file().as_bytes() {
            sys::debug_print(b);
        }
        print(b":");
        print_u32(loc.line());
    }
    print(b"\n");
    idle_forever();
}
