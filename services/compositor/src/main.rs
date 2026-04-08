//! sotOS Wayland Compositor Service
//!
//! A minimal Wayland compositor that:
//! - Registers as "compositor" via service registry
//! - Accepts Wayland client connections over IPC
//! - Parses Wayland binary wire protocol messages from IPC data
//! - Dispatches to object handlers (wl_display, wl_registry,
//!   wl_compositor, wl_shm, xdg_wm_base, wl_surface, xdg_surface,
//!   xdg_toplevel, wl_seat)
//! - Renders client buffers to the framebuffer
//! - Forwards keyboard/mouse input as Wayland events

#![no_std]
#![no_main]

mod wayland;
mod render;
mod input;

use sotos_common::sys;
use sotos_common::{BootInfo, IpcMsg, BOOT_INFO_ADDR, SyncUnsafeCell};

use render::Framebuffer;
use wayland::{
    ClientObjects, WlMessage, DispatchResult,
    WL_MSG_TAG, WL_CONNECT_TAG, WL_SHM_POOL_TAG, IPC_DATA_MAX,
};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum number of connected Wayland clients.
const MAX_CLIENTS: usize = 8;

/// Maximum surfaces tracked.
const MAX_SURFACES: usize = 32;

/// Maximum toplevel windows.
const MAX_TOPLEVELS: usize = 16;

/// Maximum SHM pools.
const MAX_POOLS: usize = 16;

/// Maximum SHM buffers.
const MAX_BUFFERS: usize = 32;

/// Base virtual address for SHM pool mappings in compositor's AS.
const POOL_BASE: u64 = 0x8000000;

/// Maximum size per pool (1 MiB).
const MAX_POOL_SIZE: usize = 1024 * 1024;

/// Desktop background color (dark blue-gray).
const BG_COLOR: u32 = 0xFF2D2D3D;

/// Title bar height in pixels.
const TITLE_BAR_HEIGHT: u32 = 24;

/// IPC recv_timeout in scheduler ticks (~10ms at 100Hz = 1 tick).
const IPC_POLL_TICKS: u32 = 1;

// ---------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------

/// A connected Wayland client.
struct WlClient {
    active: bool,
    /// IPC endpoint for this client.
    endpoint_cap: u64,
    /// Per-client object ID tracking for wire protocol dispatch.
    objects: ClientObjects,
}

impl WlClient {
    const fn empty() -> Self {
        Self {
            active: false,
            endpoint_cap: 0,
            objects: ClientObjects::empty(),
        }
    }
}

/// A wl_surface.
struct Surface {
    active: bool,
    surface_id: u32,
    client_idx: usize,
    /// Currently attached buffer index (into BUFFERS).
    buffer_idx: Option<usize>,
    /// Committed (ready to display).
    committed: bool,
}

impl Surface {
    const fn empty() -> Self {
        Self {
            active: false,
            surface_id: 0,
            client_idx: 0,
            buffer_idx: None,
            committed: false,
        }
    }
}

// ---------------------------------------------------------------------------
// Global compositor state (no heap -- all fixed-size)
// ---------------------------------------------------------------------------

static FB: SyncUnsafeCell<Framebuffer> = SyncUnsafeCell::new(Framebuffer::empty());
static CLIENTS: SyncUnsafeCell<[WlClient; MAX_CLIENTS]> = SyncUnsafeCell::new([const { WlClient::empty() }; MAX_CLIENTS]);
static SURFACES: SyncUnsafeCell<[Surface; MAX_SURFACES]> = SyncUnsafeCell::new([const { Surface::empty() }; MAX_SURFACES]);
static TOPLEVELS: SyncUnsafeCell<[wayland::shell::Toplevel; MAX_TOPLEVELS]> =
    SyncUnsafeCell::new([const { wayland::shell::Toplevel::empty() }; MAX_TOPLEVELS]);
static POOLS: SyncUnsafeCell<[wayland::shm::ShmPool; MAX_POOLS]> =
    SyncUnsafeCell::new([const { wayland::shm::ShmPool::empty() }; MAX_POOLS]);
static BUFFERS: SyncUnsafeCell<[wayland::shm::ShmBuffer; MAX_BUFFERS]> =
    SyncUnsafeCell::new([const { wayland::shm::ShmBuffer::empty() }; MAX_BUFFERS]);

/// Compositor's own AS capability (for shm_map into self).
static SELF_AS_CAP: SyncUnsafeCell<u64> = SyncUnsafeCell::new(0);

/// Mouse cursor position.
static CURSOR_X: SyncUnsafeCell<i32> = SyncUnsafeCell::new(0);
static CURSOR_Y: SyncUnsafeCell<i32> = SyncUnsafeCell::new(0);

/// Configure serial counter.
static CONFIGURE_SERIAL: SyncUnsafeCell<u32> = SyncUnsafeCell::new(1);

/// Global event serial counter (for input events sent to clients).
static EVENT_SERIAL: SyncUnsafeCell<u32> = SyncUnsafeCell::new(100);

/// Per-frame input focus state.
///
/// Consolidates the keyboard / pointer focus tracked across the compositor.
/// Surface IDs are Wayland `wl_surface` object IDs (per-client). The
/// `*_idx` fields cache the matching slots in the global `CLIENTS`,
/// `TOPLEVELS` and `SURFACES` tables so the input handlers can dispatch
/// without re-walking those arrays.
struct FocusState {
    /// Wayland `wl_surface` object ID with keyboard focus, or `None`.
    keyboard_focus: Option<u32>,
    /// Latest pointer position in screen coordinates.
    pointer_x: i32,
    pointer_y: i32,
    /// Wayland `wl_surface` object ID currently under the cursor, or `None`.
    hovered_surface: Option<u32>,
    /// Cached index into `CLIENTS` for the keyboard-focused client
    /// (`MAX_CLIENTS` if none).
    focused_client_idx: usize,
    /// Cached index into `TOPLEVELS` for the focused toplevel
    /// (`MAX_TOPLEVELS` if none).
    focused_toplevel_idx: usize,
}

impl FocusState {
    const fn empty() -> Self {
        Self {
            keyboard_focus: None,
            pointer_x: 0,
            pointer_y: 0,
            hovered_surface: None,
            focused_client_idx: MAX_CLIENTS,
            focused_toplevel_idx: MAX_TOPLEVELS,
        }
    }
}

// SAFETY: the compositor runs as a single-threaded IPC loop. There are no
// AP cores polling input, no signal handlers reading FocusState, and all
// consumers (handle_keyboard, handle_mouse, compose, apply_dispatch_result)
// are called serially from the main loop. A Mutex would be cargo-cult.
static FOCUS: SyncUnsafeCell<FocusState> = SyncUnsafeCell::new(FocusState::empty());

/// Drag state: if dragging a window, (toplevel_idx, offset_x, offset_y).
static DRAG_TL: SyncUnsafeCell<usize> = SyncUnsafeCell::new(MAX_TOPLEVELS);
static DRAG_OFS_X: SyncUnsafeCell<i32> = SyncUnsafeCell::new(0);
static DRAG_OFS_Y: SyncUnsafeCell<i32> = SyncUnsafeCell::new(0);

/// TSC of last composed frame (SDF: fixed token production rate).
static LAST_FRAME_TSC: SyncUnsafeCell<u64> = SyncUnsafeCell::new(0);
/// Damage flag: set when any visual state changes.
static DAMAGE: SyncUnsafeCell<bool> = SyncUnsafeCell::new(true);

/// Frame interval in TSC ticks: ~16.67ms at 2 GHz = 60 Hz.
const FRAME_INTERVAL: u64 = 33_340_000;

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

fn print(s: &[u8]) {
    for &b in s {
        sys::debug_print(b);
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

fn print_u32_dec(mut val: u32) {
    if val == 0 {
        sys::debug_print(b'0');
        return;
    }
    let mut buf = [0u8; 10];
    let mut i = 0;
    while val > 0 && i < 10 {
        buf[i] = b'0' + (val % 10) as u8;
        val /= 10;
        i += 1;
    }
    while i > 0 {
        i -= 1;
        sys::debug_print(buf[i]);
    }
}

fn rdtsc() -> u64 {
    let lo: u32;
    let hi: u32;
    unsafe {
        core::arch::asm!("rdtsc", out("eax") lo, out("edx") hi, options(nomem, nostack));
    }
    ((hi as u64) << 32) | (lo as u64)
}

fn mark_damage() {
    unsafe { *DAMAGE.get() = true; }
}

fn next_event_serial() -> u32 {
    unsafe {
        let s = &mut *EVENT_SERIAL.get();
        let val = *s;
        *s = val.wrapping_add(1);
        val
    }
}

/// Millisecond timestamp derived from TSC (approximate, 2 GHz assumed).
fn tsc_millis() -> u32 {
    (rdtsc() / 2_000_000) as u32
}

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    print(b"compositor: starting\n");

    let boot_info = unsafe { &*(BOOT_INFO_ADDR as *const BootInfo) };
    if !boot_info.is_valid() {
        print(b"compositor: invalid BootInfo!\n");
        loop { sys::yield_now(); }
    }

    // Initialize framebuffer from BootInfo.
    unsafe {
        let fb = &mut *FB.get();
        fb.addr = boot_info.fb_addr;
        fb.width = boot_info.fb_width;
        fb.height = boot_info.fb_height;
        fb.pitch = boot_info.fb_pitch;
        fb.bpp = boot_info.fb_bpp;
    }

    print(b"compositor: fb ");
    print_hex(boot_info.fb_addr);
    print(b" ");
    print_hex(boot_info.fb_width as u64);
    print(b"x");
    print_hex(boot_info.fb_height as u64);
    print(b"\n");

    // Read self AS cap from BootInfo (cap[1]).
    let self_as_cap = boot_info.self_as_cap;
    if self_as_cap != 0 {
        unsafe { *SELF_AS_CAP.get() = self_as_cap; }
        print(b"compositor: self_as_cap=");
        print_hex(self_as_cap);
        print(b"\n");
    } else {
        print(b"compositor: WARNING: no self_as_cap, SHM sharing disabled\n");
    }

    // Register as "compositor" service.
    let ep_cap = boot_info.caps[0]; // endpoint for IPC
    let svc_name = b"compositor";
    match sys::svc_register(
        svc_name.as_ptr() as u64,
        svc_name.len() as u64,
        ep_cap,
    ) {
        Ok(()) => print(b"compositor: registered service\n"),
        Err(_) => print(b"compositor: svc_register failed\n"),
    }

    // Initialise input rings non-destructively. We probe the KB/MOUSE
    // SPSC pages (and mark them as "polled" for the WIRED smoke test)
    // BEFORE waiting for a client, so the boot-smoke marker is emitted
    // even when the compositor has no clients yet. We do NOT consume any
    // bytes here -- LUCAS still owns the hardware until a client arrives.
    if input::try_init() {
        print(b"compositor: input rings available\n");
    } else {
        print(b"compositor: WARNING: input device init failed, continuing without input\n");
    }
    if input::rings_polled() {
        print(b"=== compositor input: WIRED ===\n");
    } else {
        print(b"=== compositor input: FAIL ===\n");
    }

    print(b"compositor: waiting for clients on IPC\n");

    // Passive: block on IPC endpoint waiting for Wayland client connections.
    // Do NOT touch framebuffer or consume KB/MOUSE bytes until a client
    // connects -- the serial console and LUCAS shell own those resources
    // until then. Boot-smoke: events are silently swallowed when no
    // client is connected (this is NOT an error).
    loop {
        match sys::recv(ep_cap) {
            Ok(msg) => {
                print(b"compositor: client connected, activating\n");
                handle_new_connection(ep_cap, &msg);
                break;
            }
            Err(_) => {
                sys::yield_now();
            }
        }
    }

    // First client connected -- take over the framebuffer.
    unsafe {
        let fb = &mut *FB.get();
        fb.clear(BG_COLOR);
        *CURSOR_X.get() = (fb.width / 2) as i32;
        *CURSOR_Y.get() = (fb.height / 2) as i32;
        let focus = &mut *FOCUS.get();
        focus.pointer_x = (fb.width / 2) as i32;
        focus.pointer_y = (fb.height / 2) as i32;
    }

    // Active compositing loop with IPC polling.
    loop {
        // Poll for IPC messages (non-blocking with short timeout).
        poll_ipc(ep_cap);

        // Process input if available (may set damage flag).
        // read_kb_scancode/read_mouse_packet return None when input
        // is not available, so the compositor continues rendering.
        while let Some(scancode) = input::read_kb_scancode() {
            handle_keyboard(scancode);
        }
        while let Some(packet) = input::read_mouse_packet() {
            handle_mouse(packet);
        }

        // Frame pacing: only compose if damaged or interval elapsed.
        let now = rdtsc();
        let elapsed = unsafe { now.wrapping_sub(*LAST_FRAME_TSC.get()) };
        let damaged = unsafe { *DAMAGE.get() };

        if damaged || elapsed >= FRAME_INTERVAL {
            compose();
            unsafe {
                *LAST_FRAME_TSC.get() = now;
                *DAMAGE.get() = false;
            }
        } else {
            sys::yield_now();
        }
    }
}

// ---------------------------------------------------------------------------
// IPC message handling
// ---------------------------------------------------------------------------

/// Poll the IPC endpoint for incoming messages without blocking for long.
fn poll_ipc(ep_cap: u64) {
    // Use recv_timeout to avoid blocking the compositing loop.
    match sys::recv_timeout(ep_cap, IPC_POLL_TICKS) {
        Ok(msg) => {
            process_ipc_message(ep_cap, &msg);
        }
        Err(_) => {
            // Timeout or error -- no message pending, continue.
        }
    }
}

/// Process a single IPC message: either a new connection or a wire protocol message.
/// Note: WL_CONNECT_TAG check must come before WL_MSG_TAG because
/// WL_CONNECT_TAG's low 16 bits happen to equal WL_MSG_TAG.
fn process_ipc_message(ep_cap: u64, msg: &IpcMsg) {
    if msg.tag == WL_CONNECT_TAG {
        handle_new_connection(ep_cap, msg);
        return;
    }

    if (msg.tag & 0xFFFF) == WL_MSG_TAG {
        handle_wire_message(ep_cap, msg);
        return;
    }

    // Unknown tag -- treat as connection attempt.
    handle_new_connection(ep_cap, msg);
}

/// Register a new client connection.
fn handle_new_connection(ep_cap: u64, _msg: &IpcMsg) {
    let clients = unsafe { &mut *CLIENTS.get() };
    for i in 0..MAX_CLIENTS {
        if !clients[i].active {
            clients[i].active = true;
            clients[i].endpoint_cap = ep_cap;
            clients[i].objects = ClientObjects::empty();
            print(b"compositor: client ");
            print_u32_dec(i as u32);
            print(b" connected\n");

            // Send an acknowledgment reply so the client unblocks.
            let mut reply = IpcMsg::empty();
            reply.tag = WL_CONNECT_TAG;
            reply.regs[0] = 1; // success
            let _ = sys::send(ep_cap, &reply);
            return;
        }
    }
    // No free slots -- reject.
    print(b"compositor: no free client slots\n");
    let mut reply = IpcMsg::empty();
    reply.tag = WL_CONNECT_TAG;
    reply.regs[0] = 0; // failure
    let _ = sys::send(ep_cap, &reply);
}

/// Handle an incoming Wayland wire protocol message.
fn handle_wire_message(ep_cap: u64, msg: &IpcMsg) {
    // Extract raw bytes from IPC registers.
    let mut wire_buf = [0u8; IPC_DATA_MAX];
    let wire_len = wayland::ipc_to_wire(msg, &mut wire_buf);
    if wire_len < 8 {
        // Too short for a Wayland header -- send empty reply.
        let _ = sys::send(ep_cap, &IpcMsg::empty());
        return;
    }

    // Parse the Wayland message header.
    let mut wl_msg = WlMessage::empty();
    let consumed = match wl_msg.parse_header(&wire_buf[..wire_len]) {
        Some(n) => n,
        None => {
            print(b"compositor: malformed wayland msg\n");
            let _ = sys::send(ep_cap, &IpcMsg::empty());
            return;
        }
    };

    print(b"compositor: wl obj=");
    print_u32_dec(wl_msg.object_id);
    print(b" op=");
    print_u32_dec(wl_msg.opcode as u32);
    print(b" sz=");
    print_u32_dec(wl_msg.size as u32);
    print(b"\n");

    // Find which client this came from (first active client on this endpoint).
    let client_idx = find_client(ep_cap);
    if client_idx >= MAX_CLIENTS {
        print(b"compositor: msg from unknown client\n");
        let _ = sys::send(ep_cap, &IpcMsg::empty());
        return;
    }

    // Dispatch the message.
    let result = unsafe {
        let clients = &mut *CLIENTS.get();
        let serial = &mut *CONFIGURE_SERIAL.get();
        wayland::dispatch_message(&wl_msg, &mut clients[client_idx].objects, serial)
    };

    // Apply state changes from the dispatch result.
    apply_dispatch_result(client_idx, &result);

    // If there are remaining bytes in the buffer (multiple messages packed
    // into one IPC transfer), parse them too.
    let mut offset = consumed;
    while offset + 8 <= wire_len {
        let mut next_msg = WlMessage::empty();
        match next_msg.parse_header(&wire_buf[offset..wire_len]) {
            Some(n) => {
                let next_result = unsafe {
                    let clients = &mut *CLIENTS.get();
                    let serial = &mut *CONFIGURE_SERIAL.get();
                    wayland::dispatch_message(&next_msg, &mut clients[client_idx].objects, serial)
                };
                apply_dispatch_result(client_idx, &next_result);
                // Send events for this sub-message inline.
                send_events(ep_cap, &next_result);
                offset += n;
            }
            None => break,
        }
    }

    // Send response events for the first (or only) message.
    send_events(ep_cap, &result);
}

/// Send response events back to the client via IPC.
/// If a new SHM pool was created, sends the SHM handle so the client can map it.
fn send_events(ep_cap: u64, result: &DispatchResult) {
    // If a new SHM pool was created, send the SHM handle as the reply.
    // The client needs this to call shm_map() and map the pool into its AS.
    let (pool_id, pool_size, _) = result.new_pool;
    if pool_id != 0 && pool_size > 0 {
        // Look up the pool to get the SHM handle.
        let pools = unsafe { &*POOLS.get() };
        for pi in 0..MAX_POOLS {
            if pools[pi].active && pools[pi].pool_id == pool_id {
                let reply = wayland::shm_pool_reply(
                    pools[pi].shm_handle,
                    pools[pi].page_count,
                    pool_id,
                );
                print(b"compositor: sending SHM handle ");
                print_u32_dec(pools[pi].shm_handle as u32);
                print(b" to client for pool ");
                print_u32_dec(pool_id);
                print(b"\n");
                let _ = sys::send(ep_cap, &reply);
                return;
            }
        }
    }

    if result.event_count == 0 {
        // Always send a reply so the client unblocks (even if no events).
        let _ = sys::send(ep_cap, &IpcMsg::empty());
        return;
    }

    // Pack events into IPC reply.
    let reply = wayland::events_to_ipc(&result.events, result.event_count);
    let _ = sys::send(ep_cap, &reply);
}

/// Find the client index for the given endpoint capability.
fn find_client(ep_cap: u64) -> usize {
    let clients = unsafe { &*CLIENTS.get() };
    for i in 0..MAX_CLIENTS {
        if clients[i].active && clients[i].endpoint_cap == ep_cap {
            return i;
        }
    }
    // If no client found, use the first active client as fallback.
    // This handles the case where all clients share the same service endpoint.
    for i in 0..MAX_CLIENTS {
        if clients[i].active {
            return i;
        }
    }
    MAX_CLIENTS // sentinel: no client found
}

/// Apply state changes from a dispatch result to the global compositor state.
fn apply_dispatch_result(client_idx: usize, result: &DispatchResult) {
    // New surface created?
    if result.new_surface_id != 0 {
        let surfaces = unsafe { &mut *SURFACES.get() };
        for i in 0..MAX_SURFACES {
            if !surfaces[i].active {
                surfaces[i].active = true;
                surfaces[i].surface_id = result.new_surface_id;
                surfaces[i].client_idx = client_idx;
                surfaces[i].buffer_idx = None;
                surfaces[i].committed = false;
                print(b"compositor: new surface ");
                print_u32_dec(result.new_surface_id);
                print(b"\n");
                break;
            }
        }
    }

    // Surface attach?
    if result.attach.0 != 0 {
        let (surface_id, buffer_id) = result.attach;
        let surfaces = unsafe { &mut *SURFACES.get() };
        let buffers = unsafe { &*BUFFERS.get() };
        for i in 0..MAX_SURFACES {
            if surfaces[i].active && surfaces[i].surface_id == surface_id {
                // Find the buffer index.
                for bi in 0..MAX_BUFFERS {
                    if buffers[bi].active && buffers[bi].buffer_id == buffer_id {
                        surfaces[i].buffer_idx = Some(bi);
                        break;
                    }
                }
                break;
            }
        }
    }

    // Surface committed?
    if result.committed_surface_id != 0 {
        let surfaces = unsafe { &mut *SURFACES.get() };
        for i in 0..MAX_SURFACES {
            if surfaces[i].active && surfaces[i].surface_id == result.committed_surface_id {
                surfaces[i].committed = true;
                mark_damage();
                break;
            }
        }
    }

    // New toplevel?
    let (tl_id, xdg_id, wl_surf_id) = result.new_toplevel;
    if tl_id != 0 {
        let toplevels = unsafe { &mut *TOPLEVELS.get() };
        for i in 0..MAX_TOPLEVELS {
            if !toplevels[i].active {
                toplevels[i].active = true;
                toplevels[i].toplevel_id = tl_id;
                toplevels[i].xdg_surface_id = xdg_id;
                toplevels[i].wl_surface_id = wl_surf_id;
                toplevels[i].x = 50 + (i as i32 * 30); // cascade
                toplevels[i].y = 50 + (i as i32 * 30) + TITLE_BAR_HEIGHT as i32;
                toplevels[i].width = 640;
                toplevels[i].height = 480;
                print(b"compositor: new toplevel ");
                print_u32_dec(tl_id);
                print(b"\n");
                mark_damage();
                break;
            }
        }
    }

    // New popup? Resolve parent position and stash in the popup pool.
    if result.new_popup.popup_id != 0 {
        let birth = result.new_popup;
        let clients = unsafe { &*CLIENTS.get() };
        let objs = &clients[client_idx].objects;
        let popup_wl_surface = objs.wl_surface_for_xdg(result.new_popup_xdg_surface);
        let parent_wl_surface = objs.wl_surface_for_xdg(birth.parent_xdg_surface);
        let mut parent_origin = (0i32, 0i32);
        if parent_wl_surface != 0 {
            let toplevels = unsafe { &*TOPLEVELS.get() };
            for tl in toplevels.iter() {
                if tl.active && tl.wl_surface_id == parent_wl_surface {
                    parent_origin = (tl.x, tl.y);
                    break;
                }
            }
        }
        if wayland::shell::spawn_popup(
            birth,
            popup_wl_surface,
            parent_wl_surface,
            parent_origin,
        ).is_some() {
            print(b"compositor: new popup ");
            print_u32_dec(birth.popup_id);
            print(b"\n");
            mark_damage();
        }
    }

    if result.popup_destroyed != 0 || result.popup_repositioned != 0 {
        mark_damage();
    }

    // Title update?
    let (title_tl_id, ref title_buf, title_len) = result.title_update;
    if title_tl_id != 0 && title_len > 0 {
        let toplevels = unsafe { &mut *TOPLEVELS.get() };
        for i in 0..MAX_TOPLEVELS {
            if toplevels[i].active && toplevels[i].toplevel_id == title_tl_id {
                let copy_len = title_len.min(64);
                toplevels[i].title[..copy_len].copy_from_slice(&title_buf[..copy_len]);
                toplevels[i].title_len = copy_len;
                mark_damage();
                break;
            }
        }
    }

    // New SHM pool? Use kernel SHM for cross-process sharing.
    let (pool_id, pool_size, client_shm_hint) = result.new_pool;
    if pool_id != 0 && pool_size > 0 {
        let pools = unsafe { &mut *POOLS.get() };
        let self_as_cap = unsafe { *SELF_AS_CAP.get() };
        for pi in 0..MAX_POOLS {
            if !pools[pi].active {
                let clamped_size = (pool_size as usize).min(MAX_POOL_SIZE);
                let pages = (clamped_size + 0xFFF) / 0x1000;
                let pool_vaddr = POOL_BASE + (pi as u64) * MAX_POOL_SIZE as u64;

                // Check if client already created the SHM object (fd >= 0 is
                // the kernel SHM handle). If so, reuse it. Otherwise create one.
                let shm_handle = if client_shm_hint >= 0 {
                    // Client pre-created the SHM; just use its handle.
                    client_shm_hint as u64
                } else {
                    // Compositor creates the SHM object.
                    match sys::shm_create(pages as u64) {
                        Ok(h) => h,
                        Err(e) => {
                            print(b"compositor: shm_create failed: ");
                            print_hex(e as u64);
                            print(b"\n");
                            break;
                        }
                    }
                };

                // Map the SHM into compositor's AS.
                let map_ok = if self_as_cap != 0 {
                    // flags: bit 0 = writable
                    match sys::shm_map(shm_handle, self_as_cap, pool_vaddr, 1) {
                        Ok(()) => true,
                        Err(e) => {
                            print(b"compositor: shm_map failed: ");
                            print_hex(e as u64);
                            print(b"\n");
                            false
                        }
                    }
                } else {
                    // Fallback: allocate frames directly (no sharing).
                    let mut ok = true;
                    for p in 0..pages {
                        let vaddr = pool_vaddr + (p as u64) * 0x1000;
                        match sys::frame_alloc() {
                            Ok(frame_cap) => {
                                if sys::map(vaddr, frame_cap, 0x2).is_err() {
                                    print(b"compositor: pool map failed\n");
                                    ok = false;
                                    break;
                                }
                            }
                            Err(_) => {
                                print(b"compositor: pool frame_alloc failed\n");
                                ok = false;
                                break;
                            }
                        }
                    }
                    ok
                };

                if map_ok {
                    pools[pi].active = true;
                    pools[pi].pool_id = pool_id;
                    pools[pi].shm_handle = shm_handle;
                    pools[pi].page_count = pages as u32;
                    pools[pi].size = pool_size;
                    pools[pi].mapped_vaddr = pool_vaddr;
                    print(b"compositor: pool ");
                    print_u32_dec(pool_id);
                    print(b" shm_handle=");
                    print_u32_dec(shm_handle as u32);
                    print(b" mapped at ");
                    print_hex(pool_vaddr);
                    print(b" (");
                    print_u32_dec(pages as u32);
                    print(b" pages)\n");
                }
                break;
            }
        }
    }

    // New SHM buffer? Store in BUFFERS array with correct pool_idx.
    let (ref new_buf, pool_object_id) = result.new_buffer;
    if new_buf.buffer_id != 0 {
        let buffers = unsafe { &mut *BUFFERS.get() };
        let pools = unsafe { &*POOLS.get() };
        // Find the pool index by pool_object_id.
        let mut found_pool_idx = MAX_POOLS;
        for pi in 0..MAX_POOLS {
            if pools[pi].active && pools[pi].pool_id == pool_object_id {
                found_pool_idx = pi;
                break;
            }
        }
        if found_pool_idx < MAX_POOLS {
            for bi in 0..MAX_BUFFERS {
                if !buffers[bi].active {
                    buffers[bi].active = true;
                    buffers[bi].buffer_id = new_buf.buffer_id;
                    buffers[bi].pool_idx = found_pool_idx;
                    buffers[bi].offset = new_buf.offset;
                    buffers[bi].width = new_buf.width;
                    buffers[bi].height = new_buf.height;
                    buffers[bi].stride = new_buf.stride;
                    buffers[bi].format = new_buf.format;
                    print(b"compositor: buffer ");
                    print_u32_dec(new_buf.buffer_id);
                    print(b" (");
                    print_u32_dec(new_buf.width);
                    print(b"x");
                    print_u32_dec(new_buf.height);
                    print(b") in pool ");
                    print_u32_dec(pool_object_id);
                    print(b"\n");
                    break;
                }
            }
        } else {
            print(b"compositor: buffer references unknown pool ");
            print_u32_dec(pool_object_id);
            print(b"\n");
        }
    }

    // When a new toplevel is created, auto-focus the first one.
    if tl_id != 0 {
        unsafe {
            let focus = &mut *FOCUS.get();
            if focus.focused_toplevel_idx >= MAX_TOPLEVELS {
                // Find the toplevel we just created.
                let tls = &*TOPLEVELS.get();
                for i in 0..MAX_TOPLEVELS {
                    if tls[i].active && tls[i].toplevel_id == tl_id {
                        focus.focused_toplevel_idx = i;
                        focus.focused_client_idx = client_idx;
                        focus.keyboard_focus = Some(tls[i].wl_surface_id);
                        print(b"compositor: focused toplevel ");
                        print_u32_dec(tl_id);
                        print(b"\n");
                        break;
                    }
                }
            }
        }
    }

    // Damage reported?
    if result.damage {
        mark_damage();
    }
}

// ---------------------------------------------------------------------------
// Input handling
// ---------------------------------------------------------------------------

fn handle_keyboard(scancode: u8) {
    let is_release = scancode & 0x80 != 0;
    let code = scancode & 0x7F;
    let keycode = wayland::seat::scancode_to_linux_keycode(code);
    if keycode == 0 { return; }

    let state = if is_release { 0u32 } else { 1u32 };

    // Send wl_keyboard::key event to the focused client. With no
    // focused client we silently swallow the event (boot-smoke path).
    unsafe {
        let focus = &*FOCUS.get();
        let focused_cl = focus.focused_client_idx;
        if focused_cl >= MAX_CLIENTS { return; }
        if focus.keyboard_focus.is_none() { return; }

        let clients = &*CLIENTS.get();
        if !clients[focused_cl].active { return; }

        let keyboard_id = clients[focused_cl].objects.keyboard_id;
        if keyboard_id == 0 { return; }

        let serial = next_event_serial();
        let time = tsc_millis();

        // Build wl_keyboard::key event (opcode 3)
        // Args: serial(u32), time(u32), key(u32), state(u32)
        let mut ev = wayland::WlEvent::new();
        ev.begin(keyboard_id, 3); // wl_keyboard::key
        ev.put_u32(serial);
        ev.put_u32(time);
        ev.put_u32(keycode);
        ev.put_u32(state);
        ev.finish();

        let ipc_reply = wayland::wire_to_ipc(&ev);
        let _ = sys::send(clients[focused_cl].endpoint_cap, &ipc_reply);
    }

    mark_damage();
}

fn handle_mouse(packet: input::MousePacket) {
    let (cursor_x, cursor_y);
    unsafe {
        let fb = &*FB.get();
        let cx = &mut *CURSOR_X.get();
        let cy = &mut *CURSOR_Y.get();
        *cx = (*cx + packet.dx).max(0).min(fb.width as i32 - 1);
        *cy = (*cy + packet.dy).max(0).min(fb.height as i32 - 1);
        cursor_x = *cx;
        cursor_y = *cy;
        let focus = &mut *FOCUS.get();
        focus.pointer_x = *cx;
        focus.pointer_y = *cy;
    }

    mark_damage();

    // Hit-test: find which toplevel the cursor is over.
    let toplevels = unsafe { &*TOPLEVELS.get() };
    let mut hit_tl_idx: usize = MAX_TOPLEVELS;
    // Iterate in reverse so topmost (last-created) windows get priority.
    let mut i = MAX_TOPLEVELS;
    while i > 0 {
        i -= 1;
        let tl = &toplevels[i];
        if !tl.active { continue; }
        // Toplevel bounds: (tl.x, tl.y - TITLE_BAR_HEIGHT) to (tl.x + width, tl.y + height).
        let x0 = tl.x;
        let y0 = tl.y - TITLE_BAR_HEIGHT as i32;
        let x1 = tl.x + tl.width as i32;
        let y1 = tl.y + tl.height as i32;
        if cursor_x >= x0 && cursor_x < x1 && cursor_y >= y0 && cursor_y < y1 {
            hit_tl_idx = i;
            break;
        }
    }

    // ── Drag handling ──
    unsafe {
        let drag_tl = &mut *DRAG_TL.get();

        // If left button released, stop dragging.
        if packet.buttons & 0x01 == 0 && *drag_tl < MAX_TOPLEVELS {
            *drag_tl = MAX_TOPLEVELS;
        }

        // If currently dragging, move the toplevel.
        if *drag_tl < MAX_TOPLEVELS {
            let toplevels_mut = &mut *TOPLEVELS.get();
            let tl = &mut toplevels_mut[*drag_tl];
            tl.x = cursor_x - *DRAG_OFS_X.get();
            tl.y = cursor_y - *DRAG_OFS_Y.get();
            mark_damage();
        }
    }

    // ── Click handling: focus, z-order, drag start, close ──
    static PREV_BUTTONS: SyncUnsafeCell<u8> = SyncUnsafeCell::new(0);
    let prev_btn = unsafe { *PREV_BUTTONS.get() };
    let left_pressed = (packet.buttons & 0x01 != 0) && (prev_btn & 0x01 == 0);

    if hit_tl_idx < MAX_TOPLEVELS && left_pressed {
        let tl = &toplevels[hit_tl_idx];

        // Check if click is on the close button (top-right 16x16 of title bar).
        let close_x0 = tl.x + tl.width as i32 - 20;
        let close_y0 = tl.y - TITLE_BAR_HEIGHT as i32 + 4;
        if cursor_x >= close_x0 && cursor_x < close_x0 + 16
            && cursor_y >= close_y0 && cursor_y < close_y0 + 16
        {
            // Close the toplevel.
            //
            // The close-button is currently the ONLY surface-destruction path
            // in the compositor. When client-disconnect / xdg_toplevel.destroy
            // / wl_surface.destroy land, every one of those code paths MUST
            // also clear `hovered_surface` (and `focused_*`) for any surface
            // it tears down — otherwise input handlers will dispatch events
            // to a dead wl_surface ID.
            unsafe {
                let toplevels_mut = &mut *TOPLEVELS.get();
                let destroyed_surface_id = toplevels_mut[hit_tl_idx].wl_surface_id;
                toplevels_mut[hit_tl_idx].active = false;
                // Clear focus if this was focused.
                let focus = &mut *FOCUS.get();
                if focus.focused_toplevel_idx == hit_tl_idx {
                    focus.focused_toplevel_idx = MAX_TOPLEVELS;
                    focus.focused_client_idx = MAX_CLIENTS;
                    focus.keyboard_focus = None;
                }
                // Clear hover if it pointed at the destroyed surface, so the
                // next mouse event doesn't dispatch to a dead wl_surface ID.
                if focus.hovered_surface == Some(destroyed_surface_id) {
                    focus.hovered_surface = None;
                }
            }
            mark_damage();
            unsafe { *PREV_BUTTONS.get() = packet.buttons; }
            return;
        }

        // Check if click is on the title bar (above tl.y) → start drag.
        if cursor_y < tl.y {
            unsafe {
                *DRAG_TL.get() = hit_tl_idx;
                *DRAG_OFS_X.get() = cursor_x - tl.x;
                *DRAG_OFS_Y.get() = cursor_y - tl.y;
            }
        }

        // Z-order: bring to front by swapping with the last active slot.
        if hit_tl_idx < MAX_TOPLEVELS {
            unsafe {
                let toplevels_mut = &mut *TOPLEVELS.get();
                // Find the highest active index.
                let mut last_active = hit_tl_idx;
                for j in (hit_tl_idx + 1)..MAX_TOPLEVELS {
                    if toplevels_mut[j].active { last_active = j; }
                }
                if last_active != hit_tl_idx {
                    // Swap so clicked window is at higher index (rendered later = on top).
                    let a = core::ptr::addr_of_mut!(toplevels_mut[hit_tl_idx]);
                    let b = core::ptr::addr_of_mut!(toplevels_mut[last_active]);
                    core::ptr::swap(a, b);
                    hit_tl_idx = last_active;
                }
            }
        }

        // Click-to-focus: update focus to this window's client + surface.
        unsafe {
            let surfaces = &*SURFACES.get();
            let tl = &(*TOPLEVELS.get())[hit_tl_idx];
            let focus = &mut *FOCUS.get();
            focus.focused_toplevel_idx = hit_tl_idx;
            focus.keyboard_focus = Some(tl.wl_surface_id);
            for si in 0..MAX_SURFACES {
                if surfaces[si].active && surfaces[si].surface_id == tl.wl_surface_id {
                    focus.focused_client_idx = surfaces[si].client_idx;
                    break;
                }
            }
        }
        mark_damage();
    }

    unsafe { *PREV_BUTTONS.get() = packet.buttons; }

    unsafe {
        let focus = &mut *FOCUS.get();
        focus.hovered_surface = if hit_tl_idx < MAX_TOPLEVELS {
            Some(toplevels[hit_tl_idx].wl_surface_id)
        } else {
            None
        };
    }

    // Send pointer events to the client that owns the hit toplevel.
    // No client = silently swallow (not an error).
    if hit_tl_idx < MAX_TOPLEVELS {
        let tl = &toplevels[hit_tl_idx];
        // Find the client owning this toplevel's surface.
        let surfaces = unsafe { &*SURFACES.get() };
        let mut target_client_idx = MAX_CLIENTS;
        for si in 0..MAX_SURFACES {
            if surfaces[si].active && surfaces[si].surface_id == tl.wl_surface_id {
                target_client_idx = surfaces[si].client_idx;
                break;
            }
        }
        if target_client_idx < MAX_CLIENTS {
            let clients = unsafe { &*CLIENTS.get() };
            let cl = &clients[target_client_idx];
            if cl.active && cl.objects.pointer_id != 0 {
                let pointer_id = cl.objects.pointer_id;
                let ep = cl.endpoint_cap;
                let time = tsc_millis();

                // Compute surface-local coordinates.
                // The client content area starts at (tl.x, tl.y) -- below the title bar.
                let surface_x = cursor_x - tl.x;
                let surface_y = cursor_y - tl.y;

                // Wayland fixed-point: value * 256 (wl_fixed_t is 24.8 format).
                let fx = (surface_x * 256) as i32;
                let fy = (surface_y * 256) as i32;

                // Build wl_pointer::motion event (opcode 1)
                // Args: time(u32), surface_x(fixed), surface_y(fixed)
                let mut ev = wayland::WlEvent::new();
                ev.begin(pointer_id, 1); // wl_pointer::motion
                ev.put_u32(time);
                ev.put_i32(fx);
                ev.put_i32(fy);
                ev.finish();

                // Check for button events (PS/2: bit0=left, bit1=right, bit2=middle).
                // We track previous button state to detect press/release edges.
                let prev = prev_btn;
                let cur = packet.buttons;

                // Wayland button codes: left=0x110 (BTN_LEFT), right=0x111, middle=0x112.
                let button_map: [(u8, u32); 3] = [
                    (0x01, 0x110), // left
                    (0x02, 0x111), // right
                    (0x04, 0x112), // middle
                ];

                // We need to send motion + optional button events + frame.
                // Pack them into a contiguous buffer and send all at once.
                let mut events_buf: [wayland::WlEvent; 6] = [const { wayland::WlEvent::new() }; 6];

                // Motion event first.
                events_buf[0] = ev;
                let mut ev_count = 1usize;

                // Button events for edges.
                for &(mask, code) in &button_map {
                    let was_pressed = prev & mask != 0;
                    let is_pressed = cur & mask != 0;
                    if was_pressed != is_pressed && ev_count < 5 {
                        let serial = next_event_serial();
                        let state = if is_pressed { 1u32 } else { 0u32 };
                        let mut btn_ev = wayland::WlEvent::new();
                        btn_ev.begin(pointer_id, 2); // wl_pointer::button
                        btn_ev.put_u32(serial);
                        btn_ev.put_u32(time);
                        btn_ev.put_u32(code);
                        btn_ev.put_u32(state);
                        btn_ev.finish();
                        events_buf[ev_count] = btn_ev;
                        ev_count += 1;
                    }
                }

                // wl_pointer::frame event (opcode 5) -- no arguments.
                if ev_count < 6 {
                    let mut frame_ev = wayland::WlEvent::new();
                    frame_ev.begin(pointer_id, 5); // wl_pointer::frame
                    frame_ev.finish();
                    events_buf[ev_count] = frame_ev;
                    ev_count += 1;
                }

                // Send all pointer events packed into one IPC message.
                let mut packed_events: [wayland::WlEvent; wayland::MAX_EVENTS] =
                    [const { wayland::WlEvent::new() }; wayland::MAX_EVENTS];
                for idx in 0..ev_count.min(wayland::MAX_EVENTS) {
                    packed_events[idx].buf[..events_buf[idx].len]
                        .copy_from_slice(&events_buf[idx].buf[..events_buf[idx].len]);
                    packed_events[idx].len = events_buf[idx].len;
                }
                let ipc_reply = wayland::events_to_ipc(&packed_events, ev_count);
                let _ = sys::send(ep, &ipc_reply);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Compositing
// ---------------------------------------------------------------------------

fn compose() {
    unsafe {
        let fb = &mut *FB.get();
        let toplevels = &*TOPLEVELS.get();
        let surfaces = &*SURFACES.get();
        let buffers = &*BUFFERS.get();
        let pools = &*POOLS.get();
        let focused_tl = (*FOCUS.get()).focused_toplevel_idx;

        // Clear background (needed since we only redraw on damage).
        fb.clear(BG_COLOR);

        // Draw all active toplevels.
        for i in 0..MAX_TOPLEVELS {
            let tl = &toplevels[i];
            if !tl.active { continue; }

            // Title bar color: highlight focused toplevel.
            let bar_color = if i == focused_tl { 0xFF5577AA } else { 0xFF404040 };
            fb.fill_rect(
                tl.x, tl.y - TITLE_BAR_HEIGHT as i32,
                tl.width, TITLE_BAR_HEIGHT,
                bar_color,
            );
            // Close button (top-right corner of title bar).
            let close_x = tl.x + tl.width as i32 - 20;
            let close_y = tl.y - TITLE_BAR_HEIGHT as i32 + 4;
            fb.fill_rect(close_x, close_y, 16, 16, 0xFFFF5555);
            // "X" on close button
            fb.draw_text(close_x + 4, close_y + 4, b"x", 0xFFFFFFFF);

            // Title text in the title bar.
            let text_x = tl.x + 6;
            let text_y = tl.y - TITLE_BAR_HEIGHT as i32 + 8;
            let max_chars = ((tl.width as i32 - 30) / 8).max(0) as usize;
            let len = tl.title_len.min(max_chars);
            if len > 0 {
                fb.draw_text(text_x, text_y, &tl.title[..len], 0xFFEEEEEE);
            }

            // Find the surface and its buffer.
            let mut found_buffer = false;
            for si in 0..MAX_SURFACES {
                let surf = &surfaces[si];
                if !surf.active || surf.surface_id != tl.wl_surface_id { continue; }
                if !surf.committed { continue; }

                if let Some(buf_idx) = surf.buffer_idx {
                    let buf = &buffers[buf_idx];
                    if !buf.active { continue; }

                    // Find the pool and blit the buffer.
                    let pool_idx = buf.pool_idx;
                    if pool_idx < MAX_POOLS && pools[pool_idx].active {
                        let pool = &pools[pool_idx];
                        let src = (pool.mapped_vaddr + buf.offset as u64) as *const u32;

                        // Blit directly from the shared pool memory.
                        // With real SHM, the client writes pixels here and the
                        // compositor reads them -- no test pattern needed.
                        fb.blit(tl.x, tl.y, buf.width, buf.height, src, buf.stride);
                        found_buffer = true;
                    }
                }
                break;
            }

            // If no buffer attached yet, draw a placeholder fill.
            if !found_buffer {
                fb.fill_rect(tl.x, tl.y, tl.width, tl.height, 0xFF333355);
            }
        }

        // Draw cursor on top of everything.
        fb.draw_cursor(*CURSOR_X.get(), *CURSOR_Y.get());
    }
}

// ---------------------------------------------------------------------------
// Panic handler
// ---------------------------------------------------------------------------

#[panic_handler]
fn panic(info: &core::panic::PanicInfo) -> ! {
    print(b"compositor: PANIC: ");
    if let Some(loc) = info.location() {
        let file = loc.file().as_bytes();
        for &b in file { sys::debug_print(b); }
        print(b":");
        print_u32_dec(loc.line());
    }
    print(b"\n");
    loop { sys::yield_now(); }
}
