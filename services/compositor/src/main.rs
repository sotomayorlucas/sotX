//! sotOS Wayland Compositor Service
//!
//! A minimal Wayland compositor that:
//! - Registers as "compositor" via service registry
//! - Accepts Wayland client connections over AF_UNIX (via IPC)
//! - Implements core Wayland protocol: wl_display, wl_registry,
//!   wl_compositor, wl_shm, xdg_wm_base, wl_seat
//! - Renders client buffers to the framebuffer
//! - Forwards keyboard/mouse input as Wayland events

#![no_std]
#![no_main]

mod wayland;
mod render;
mod input;

use sotos_common::sys;
use sotos_common::{BootInfo, BOOT_INFO_ADDR, SyncUnsafeCell};

use render::Framebuffer;

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

/// Desktop background color (dark blue-gray).
const BG_COLOR: u32 = 0xFF2D2D3D;

/// Title bar height in pixels.
const TITLE_BAR_HEIGHT: u32 = 24;

// ---------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------

/// A connected Wayland client.
struct WlClient {
    active: bool,
    /// IPC endpoint for this client.
    endpoint_cap: u64,
    /// Client's wl_registry object ID.
    registry_id: u32,
    /// Bound object IDs per global.
    compositor_id: u32,
    shm_id: u32,
    xdg_wm_base_id: u32,
    seat_id: u32,
    pointer_id: u32,
    keyboard_id: u32,
}

impl WlClient {
    const fn empty() -> Self {
        Self {
            active: false,
            endpoint_cap: 0,
            registry_id: 0,
            compositor_id: 0,
            shm_id: 0,
            xdg_wm_base_id: 0,
            seat_id: 0,
            pointer_id: 0,
            keyboard_id: 0,
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
// Global compositor state (no heap — all fixed-size)
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

/// Mouse cursor position.
static CURSOR_X: SyncUnsafeCell<i32> = SyncUnsafeCell::new(0);
static CURSOR_Y: SyncUnsafeCell<i32> = SyncUnsafeCell::new(0);

/// Configure serial counter.
static CONFIGURE_SERIAL: SyncUnsafeCell<u32> = SyncUnsafeCell::new(1);

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

    print(b"compositor: waiting for clients on IPC\n");

    // Passive: block on IPC endpoint waiting for Wayland client connections.
    // Do NOT touch framebuffer or KB/MOUSE rings until a client connects —
    // the serial console and LUCAS shell own those resources until then.
    loop {
        // Block until a client sends an IPC message to our endpoint.
        match sys::recv(ep_cap) {
            Ok(_msg) => {
                print(b"compositor: client connected, activating\n");
                break;
            }
            Err(_) => {
                sys::yield_now();
            }
        }
    }

    // First client connected — take over the framebuffer.
    unsafe {
        let fb = &mut *FB.get();
        fb.clear(BG_COLOR);
        *CURSOR_X.get() = (fb.width / 2) as i32;
        *CURSOR_Y.get() = (fb.height / 2) as i32;
    }

    // Active compositing loop (SDF: 60 Hz fixed-rate production).
    loop {
        // Process input (may set damage flag).
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
// Input handling
// ---------------------------------------------------------------------------

fn handle_keyboard(scancode: u8) {
    let is_release = scancode & 0x80 != 0;
    let code = scancode & 0x7F;
    let keycode = wayland::seat::scancode_to_linux_keycode(code);
    if keycode == 0 { return; }

    let state = if is_release { 0u32 } else { 1u32 };

    // Send wl_keyboard::key to focused client's keyboard.
    // (Simplified: send to first client with a keyboard binding.)
    let _ = (keycode, state); // TODO: send via IPC once clients connect

    mark_damage();
}

fn handle_mouse(packet: input::MousePacket) {
    unsafe {
        let fb = &*FB.get();
        let cx = &mut *CURSOR_X.get();
        let cy = &mut *CURSOR_Y.get();
        *cx = (*cx + packet.dx).max(0).min(fb.width as i32 - 1);
        *cy = (*cy + packet.dy).max(0).min(fb.height as i32 - 1);
    }

    mark_damage();

    // TODO: hit-test toplevels, send wl_pointer::motion/button/frame events
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

        // Clear background (needed since we only redraw on damage).
        fb.clear(BG_COLOR);

        // Draw all active toplevels.
        for i in 0..MAX_TOPLEVELS {
            let tl = &toplevels[i];
            if !tl.active { continue; }

            // Draw title bar.
            fb.draw_title_bar(
                tl.x, tl.y - TITLE_BAR_HEIGHT as i32,
                tl.width,
                &tl.title[..tl.title_len],
            );

            // Find the surface and its buffer.
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
                        fb.blit(tl.x, tl.y, buf.width, buf.height, src, buf.stride);
                    }
                }
                break;
            }
        }

        // Draw cursor on top.
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
        // Print line number (simple decimal)
        let mut line = loc.line();
        let mut buf = [0u8; 10];
        let mut i = 0;
        if line == 0 {
            sys::debug_print(b'0');
        } else {
            while line > 0 && i < 10 {
                buf[i] = b'0' + (line % 10) as u8;
                line /= 10;
                i += 1;
            }
            while i > 0 {
                i -= 1;
                sys::debug_print(buf[i]);
            }
        }
    }
    print(b"\n");
    loop { sys::yield_now(); }
}
