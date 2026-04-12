//! sotos-term: a real Wayland terminal emulator for sotOS.
//!
//! This is a native Wayland client: it looks up the compositor via the
//! kernel service registry, walks the standard xdg_shell handshake to
//! create an 80x24 `xdg_toplevel` titled "sotOS Terminal", then streams
//! bytes from the kernel debug port through `vte::Parser` and renders the
//! resulting grid into an SHM buffer using embedded-graphics `FONT_6X10`.
//!
//! Because init's `spawn_process` does not yet forward a child AS cap,
//! this service is loaded directly by the kernel (see
//! `kernel/src/main.rs::load_sotos_term_process`) so its BootInfo page
//! contains a real `self_as_cap`, which we need for `shm_map`.
//!
//! ## Input path
//! Wayland wl_keyboard events (Linux keycodes) are converted to ASCII and
//! written to serial COM1 so LUCAS receives them. COM1 output from LUCAS
//! feeds the vte parser for display. PTY integration is left for a
//! follow-up -- this uses the serial COM1 bridge.

#![no_std]
#![no_main]

mod keyboard;
mod term;
mod wayland;

use sotos_common::{sys, BootInfo, IpcMsg, BOOT_INFO_ADDR};

use crate::term::{POOL_SIZE, WIN_H, WIN_W};
use crate::wayland::{
    wl_call, wl_call_noreply, WireBuilder, BUFFER_ID, COMPOSITOR_ID, KEYBOARD_ID, POINTER_ID,
    POOL_ID, REGISTRY_ID, SEAT_ID, SHM_ID, SURFACE_ID, WL_CONNECT_TAG, WL_DISPLAY_ID,
    WL_MSG_TAG, WL_SHM_POOL_TAG, XDG_SURFACE_ID, XDG_TOPLEVEL_ID, XDG_WM_BASE_ID,
};

/// Client-side SHM pool base (unused by any other Wayland client -- hello-gui
/// uses 0x7000000, sot-statusbar uses 0x9000000).
const CLIENT_POOL_BASE: u64 = 0xC000_0000;

// ---------------------------------------------------------------------------
// Tiny serial print helpers (debug only)
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
        let n = ((val >> (i * 4)) & 0xF) as usize;
        sys::debug_print(hex[n]);
    }
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    print(b"sotos-term: starting\n");

    let boot_info = unsafe { &*(BOOT_INFO_ADDR as *const BootInfo) };
    if !boot_info.is_valid() {
        print(b"sotos-term: no valid BootInfo, halting\n");
        loop {
            sys::yield_now();
        }
    }

    let self_as_cap = boot_info.self_as_cap;
    if self_as_cap == 0 {
        print(b"sotos-term: self_as_cap=0, cannot shm_map, halting\n");
        loop {
            sys::yield_now();
        }
    }

    // Look up the compositor via the service registry.
    let comp_ep = loop {
        let name = b"compositor";
        match sys::svc_lookup(name.as_ptr() as u64, name.len() as u64) {
            Ok(ep) if ep != 0 => break ep,
            _ => sys::yield_now(),
        }
    };
    print(b"sotos-term: compositor ep=");
    print_hex(comp_ep);
    print(b"\n");

    // Connect.
    let mut connect_msg = IpcMsg::empty();
    connect_msg.tag = WL_CONNECT_TAG;
    let reply = wl_call(comp_ep, &connect_msg);
    if reply.tag != WL_CONNECT_TAG || reply.regs[0] != 1 {
        print(b"sotos-term: compositor rejected connect\n");
        loop {
            sys::yield_now();
        }
    }

    // wl_display.get_registry (opcode 1).
    {
        let mut msg = WireBuilder::new(WL_DISPLAY_ID, 1);
        msg.put_u32(REGISTRY_ID);
        let _ = wl_call(comp_ep, &msg.finish());
    }

    // Bind the globals we care about. Global names must match
    // `services/compositor/src/wayland/registry.rs:GLOBALS`.
    bind_global(comp_ep, 1, b"wl_compositor", 4, COMPOSITOR_ID);
    bind_global(comp_ep, 2, b"wl_shm", 1, SHM_ID);
    bind_global(comp_ep, 3, b"xdg_wm_base", 2, XDG_WM_BASE_ID);
    bind_global(comp_ep, 4, b"wl_seat", 5, SEAT_ID);

    // Create the SHM object (kernel-level) -- one big shared memory region.
    let pages = ((POOL_SIZE as usize) + 0xFFF) / 0x1000;
    let shm_handle = match sys::shm_create(pages as u64) {
        Ok(h) => h,
        Err(_) => {
            print(b"sotos-term: shm_create failed\n");
            loop {
                sys::yield_now();
            }
        }
    };

    // Register the SHM as a wl_shm_pool and remember the confirmed handle.
    let confirmed_handle = {
        let mut msg = WireBuilder::new(SHM_ID, 0);
        msg.put_u32(POOL_ID);
        msg.put_i32(shm_handle as i32);
        msg.put_u32(POOL_SIZE);
        let reply = wl_call(comp_ep, &msg.finish());
        if reply.tag == WL_SHM_POOL_TAG {
            reply.regs[0]
        } else {
            shm_handle
        }
    };

    // Map SHM into our own address space so we can write pixels directly.
    if sys::shm_map(confirmed_handle, self_as_cap, CLIENT_POOL_BASE, 1).is_err() {
        print(b"sotos-term: shm_map failed\n");
        loop {
            sys::yield_now();
        }
    }
    let pool_ptr = CLIENT_POOL_BASE as *mut u32;

    // Create the wl_buffer out of the pool, the wl_surface, xdg_surface,
    // and xdg_toplevel -- standard handshake.
    {
        let stride = WIN_W * 4;
        let mut msg = WireBuilder::new(POOL_ID, 0); // create_buffer
        msg.put_u32(BUFFER_ID);
        msg.put_i32(0);
        msg.put_i32(WIN_W as i32);
        msg.put_i32(WIN_H as i32);
        msg.put_i32(stride as i32);
        msg.put_u32(1); // XRGB8888
        wl_call_noreply(comp_ep, &msg.finish());
    }
    {
        let mut msg = WireBuilder::new(COMPOSITOR_ID, 0); // create_surface
        msg.put_u32(SURFACE_ID);
        wl_call_noreply(comp_ep, &msg.finish());
    }
    {
        let mut msg = WireBuilder::new(XDG_WM_BASE_ID, 1); // get_xdg_surface
        msg.put_u32(XDG_SURFACE_ID);
        msg.put_u32(SURFACE_ID);
        wl_call_noreply(comp_ep, &msg.finish());
    }
    {
        let mut msg = WireBuilder::new(XDG_SURFACE_ID, 1); // get_toplevel
        msg.put_u32(XDG_TOPLEVEL_ID);
        wl_call_noreply(comp_ep, &msg.finish());
    }
    {
        let mut msg = WireBuilder::new(XDG_TOPLEVEL_ID, 2); // set_title
        msg.put_string(b"sotOS Terminal");
        wl_call_noreply(comp_ep, &msg.finish());
    }
    {
        // Claim keyboard + pointer so the compositor routes input events to us.
        let mut msg = WireBuilder::new(SEAT_ID, 1); // wl_seat::get_keyboard
        msg.put_u32(KEYBOARD_ID);
        wl_call_noreply(comp_ep, &msg.finish());
        let mut msg = WireBuilder::new(SEAT_ID, 0); // wl_seat::get_pointer
        msg.put_u32(POINTER_ID);
        wl_call_noreply(comp_ep, &msg.finish());
    }

    // Splash: put a visible banner into the grid so the window has
    // something to render on the first commit even before any bytes
    // arrive on COM1.
    write_banner();

    // First render -- draw the initial grid into SHM.
    term::render(pool_ptr);

    // Attach the buffer, damage the surface, commit. This is the point
    // the compositor finally composes our window.
    attach_damage_commit(comp_ep);

    print(b"sotos-term: window committed, entering main loop\n");

    // ------------------------------------------------------------------
    // Main loop -- drain serial input + compositor keyboard events.
    // ------------------------------------------------------------------
    let mut parser = vte::Parser::new();
    let mut performer = term::Performer;
    let mut idle_ticks: u32 = 0;

    loop {
        let mut got_any = false;

        // 1. Poll for incoming Wayland events (keyboard) from the compositor.
        //    The compositor pushes wl_keyboard::key events via sys::send()
        //    to our endpoint. We use recv_timeout with a very short timeout
        //    so we don't block the serial drain loop.
        poll_compositor_events(comp_ep);

        // 2. Drain up to 256 bytes of serial input per iteration so a burst
        //    of kernel logs doesn't starve the render commit.
        for _ in 0..256 {
            match sys::debug_read() {
                Some(b) => {
                    parser.advance(&mut performer, b);
                    got_any = true;
                }
                None => break,
            }
        }

        if term::TERM.get().dirty {
            term::render(pool_ptr);
            commit_frame(comp_ep);
            idle_ticks = 0;
        } else if got_any {
            idle_ticks = 0;
        } else {
            // Back off gently so we don't spin-starve the scheduler.
            idle_ticks = idle_ticks.saturating_add(1);
            if idle_ticks > 64 {
                sys::yield_now();
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Compositor event handling
// ---------------------------------------------------------------------------

/// Poll the compositor endpoint for incoming Wayland events (non-blocking).
///
/// The compositor sends wl_keyboard::key events when this window has focus.
/// We parse them, convert the Linux keycode to ASCII via the keyboard module,
/// and feed the resulting byte to serial COM1 so LUCAS receives it.
fn poll_compositor_events(comp_ep: u64) {
    // Drain up to 16 queued events per iteration so a burst of keypresses
    // doesn't lag behind the render loop.
    for _ in 0..16 {
        let msg = match sys::recv_timeout(comp_ep, 1) {
            Ok(m) => m,
            Err(_) => return,
        };

        if msg.tag & 0xFFFF != WL_MSG_TAG {
            continue;
        }

        let mut wire = [0u8; wayland::IPC_DATA_MAX];
        let wire_len = wayland::ipc_to_wire(&msg, &mut wire);
        if wire_len < 8 {
            continue;
        }

        let object_id = u32::from_ne_bytes([wire[0], wire[1], wire[2], wire[3]]);
        let size_opcode = u32::from_ne_bytes([wire[4], wire[5], wire[6], wire[7]]);
        let opcode = (size_opcode & 0xFFFF) as u16;

        // wl_keyboard::key (opcode 3): serial(u32), time(u32), key(u32), state(u32)
        if object_id == KEYBOARD_ID && opcode == 3 && wire_len >= 24 {
            let keycode = u32::from_ne_bytes([wire[16], wire[17], wire[18], wire[19]]);
            let state = u32::from_ne_bytes([wire[20], wire[21], wire[22], wire[23]]);
            if let Some(ascii) = keyboard::process_key(keycode, state) {
                keyboard::send_to_serial(ascii);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn bind_global(ep: u64, global_name: u32, interface: &[u8], version: u32, client_id: u32) {
    let mut msg = WireBuilder::new(REGISTRY_ID, 0); // wl_registry::bind
    msg.put_u32(global_name);
    msg.put_string(interface);
    msg.put_u32(version);
    msg.put_u32(client_id);
    let _ = wl_call(ep, &msg.finish());
}

fn attach_damage_commit(ep: u64) {
    {
        let mut msg = WireBuilder::new(SURFACE_ID, 1); // attach
        msg.put_u32(BUFFER_ID);
        msg.put_i32(0);
        msg.put_i32(0);
        wl_call_noreply(ep, &msg.finish());
    }
    {
        let mut msg = WireBuilder::new(SURFACE_ID, 2); // damage
        msg.put_i32(0);
        msg.put_i32(0);
        msg.put_i32(WIN_W as i32);
        msg.put_i32(WIN_H as i32);
        wl_call_noreply(ep, &msg.finish());
    }
    {
        let mut msg = WireBuilder::new(SURFACE_ID, 6); // commit
        wl_call_noreply(ep, &msg.finish());
    }
}

/// Just damage + commit. attach() only needs to run once because the buffer
/// stays attached until destroyed.
fn commit_frame(ep: u64) {
    {
        let mut msg = WireBuilder::new(SURFACE_ID, 2); // damage
        msg.put_i32(0);
        msg.put_i32(0);
        msg.put_i32(WIN_W as i32);
        msg.put_i32(WIN_H as i32);
        wl_call_noreply(ep, &msg.finish());
    }
    {
        let mut msg = WireBuilder::new(SURFACE_ID, 6); // commit
        wl_call_noreply(ep, &msg.finish());
    }
}

/// Paint a centred banner into the grid at boot.
fn write_banner() {
    let t = term::TERM.get();
    let msg: &[u8] = b"sotOS Terminal";
    let start_col = if term::COLS > msg.len() {
        (term::COLS - msg.len()) / 2
    } else {
        0
    };
    t.cur_row = 1;
    t.cur_col = start_col;
    t.fg = term::TN_CYAN;
    for &b in msg {
        t.put(b);
    }
    // Cursor home + restore default FG so vte-driven output starts fresh.
    t.cur_row = 3;
    t.cur_col = 0;
    t.fg = term::TN_FG;
    t.dirty = true;
}

// ---------------------------------------------------------------------------
// Panic handler
// ---------------------------------------------------------------------------

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    print(b"sotos-term: PANIC\n");
    loop {
        sys::yield_now();
    }
}
