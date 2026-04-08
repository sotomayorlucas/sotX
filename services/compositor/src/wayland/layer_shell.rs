//! `zwlr_layer_shell_v1` -- layer surfaces for panels, bars, notifications,
//! wallpapers and other desktop shell furniture.
//!
//! Reference: <https://wayland.app/protocols/wlr-layer-shell-unstable-v1>
//!
//! Layers are stacked bottom → top as:
//!   Background (0) → Bottom (1) → (xdg toplevels) → Top (2) → Overlay (3)
//!
//! Each layer surface can be anchored to any combination of screen edges.
//! Anchoring to an opposing pair of edges (left+right or top+bottom)
//! stretches the surface along that axis. The `exclusive_zone` property
//! lets a surface reserve screen real estate so regular toplevels don't
//! overlap it — this is how status bars and docks are implemented.
//!
//! `layout_all` / `layout_layer_surfaces` is the pure geometry routine
//! used both by the compose loop and by unit tests.

use super::{WlEvent, WlMessage};
use sotos_common::SyncUnsafeCell;

/// Maximum layer surfaces tracked compositor-wide. Budget: 2 bars (top +
/// bottom) + 1 wallpaper + 1 launcher + 1 notification area = 5 common,
/// plus slack.
pub const MAX_LAYER_SURFACES: usize = 8;

// ---------------------------------------------------------------------------
// Wayland wire constants.
//
// The unused items are kept as the complete protocol surface so future
// work (e.g. popup support, closed event, explicit destroy routing)
// doesn't have to re-derive the opcodes from the spec.
// ---------------------------------------------------------------------------

#[allow(dead_code)]
mod wire {
    // zwlr_layer_shell_v1 requests
    pub const GET_LAYER_SURFACE: u16 = 0;
    pub const DESTROY: u16 = 1;

    // zwlr_layer_surface_v1 requests
    pub const SET_SIZE: u16 = 0;
    pub const SET_ANCHOR: u16 = 1;
    pub const SET_EXCLUSIVE_ZONE: u16 = 2;
    pub const SET_MARGIN: u16 = 3;
    pub const SET_KB_INTERACTIVITY: u16 = 4;
    pub const GET_POPUP: u16 = 5;
    pub const ACK_CONFIGURE: u16 = 6;
    pub const SURFACE_DESTROY: u16 = 7;

    // zwlr_layer_surface_v1 events
    pub const EVT_CONFIGURE: u16 = 0;
    pub const EVT_CLOSED: u16 = 1;
}

pub const LAYER_SHELL_GET_LAYER_SURFACE: u16 = wire::GET_LAYER_SURFACE;
pub const LAYER_SURFACE_SET_SIZE: u16 = wire::SET_SIZE;
pub const LAYER_SURFACE_SET_ANCHOR: u16 = wire::SET_ANCHOR;
pub const LAYER_SURFACE_SET_EXCLUSIVE_ZONE: u16 = wire::SET_EXCLUSIVE_ZONE;
pub const LAYER_SURFACE_SET_MARGIN: u16 = wire::SET_MARGIN;
pub const LAYER_SURFACE_SET_KB_INTERACTIVITY: u16 = wire::SET_KB_INTERACTIVITY;
pub const LAYER_SURFACE_ACK_CONFIGURE: u16 = wire::ACK_CONFIGURE;
pub const LAYER_SURFACE_DESTROY: u16 = wire::SURFACE_DESTROY;
pub const LAYER_SURFACE_EVT_CONFIGURE: u16 = wire::EVT_CONFIGURE;

// zwlr_layer_shell_v1 layer enum (wire-protocol numeric values).
pub const LAYER_BACKGROUND: u32 = 0;
pub const LAYER_BOTTOM: u32 = 1;
pub const LAYER_OVERLAY: u32 = 3;

// zwlr_layer_surface_v1 anchor bits
pub const ANCHOR_TOP: u32 = 1;
pub const ANCHOR_BOTTOM: u32 = 2;
pub const ANCHOR_LEFT: u32 = 4;
pub const ANCHOR_RIGHT: u32 = 8;

// ---------------------------------------------------------------------------
// Layer enum
// ---------------------------------------------------------------------------

/// Wayland layer-shell z-order tier.
#[repr(u8)]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Layer {
    Background = 0,
    Bottom = 1,
    Top = 2,
    Overlay = 3,
}

impl Layer {
    /// Build a `Layer` from the wire-protocol enum value. Out-of-range
    /// values fall back to `Top` — the Wayland spec says servers MAY
    /// refuse the bind; we lenient-route instead to avoid crashing the
    /// compositor on bad clients.
    pub const fn from_u32(v: u32) -> Self {
        match v {
            LAYER_BACKGROUND => Layer::Background,
            LAYER_BOTTOM => Layer::Bottom,
            LAYER_OVERLAY => Layer::Overlay,
            _ => Layer::Top,
        }
    }

    pub const fn as_u32(self) -> u32 {
        self as u32
    }
}

// ---------------------------------------------------------------------------
// LayerSurface record
// ---------------------------------------------------------------------------

/// A `zwlr_layer_surface_v1` instance. All fields are client-driven
/// except `x`, `y`, `configured` and `active` which the compositor
/// maintains.
#[derive(Clone, Copy)]
pub struct LayerSurface {
    /// Wayland object ID of the layer_surface.
    pub object_id: u32,
    /// Attached `wl_surface` ID (0 = not yet bound).
    pub surface_id: u32,
    pub layer: Layer,
    /// OR of `ANCHOR_*` bits.
    pub anchor: u32,
    /// Negative = don't reserve space (overlay behaviour).
    pub exclusive_zone: i32,
    pub margin_top: i32,
    pub margin_right: i32,
    pub margin_bottom: i32,
    pub margin_left: i32,
    /// Client-requested size. 0 on an anchored axis means "stretch".
    pub width: u32,
    pub height: u32,
    /// Laid-out on-screen position (compositor-computed).
    pub x: i32,
    pub y: i32,
    /// Laid-out on-screen size (compositor-computed).
    pub computed_width: u32,
    pub computed_height: u32,
    /// 0 = none, 1 = on_demand, 2 = exclusive. We honour the bit in
    /// `seat.rs` focus routing but the field is stored raw.
    pub keyboard_interactivity: u32,
    /// Set once the client has ack'd the first configure.
    pub configured: bool,
    pub active: bool,
}

impl LayerSurface {
    pub const fn empty() -> Self {
        Self {
            object_id: 0,
            surface_id: 0,
            layer: Layer::Top,
            anchor: 0,
            exclusive_zone: 0,
            margin_top: 0,
            margin_right: 0,
            margin_bottom: 0,
            margin_left: 0,
            width: 0,
            height: 0,
            x: 0,
            y: 0,
            computed_width: 0,
            computed_height: 0,
            keyboard_interactivity: 0,
            configured: false,
            active: false,
        }
    }
}

// ---------------------------------------------------------------------------
// Static pool
// ---------------------------------------------------------------------------

static LAYER_SURFACES: SyncUnsafeCell<[LayerSurface; MAX_LAYER_SURFACES]> =
    SyncUnsafeCell::new([const { LayerSurface::empty() }; MAX_LAYER_SURFACES]);

/// Reserve a new slot. Returns the slot index or `None` if the pool is
/// full. The caller must populate `object_id` / `surface_id` before the
/// slot becomes useful.
pub fn allocate() -> Option<usize> {
    let pool = unsafe { &mut *LAYER_SURFACES.get() };
    for (i, slot) in pool.iter_mut().enumerate() {
        if !slot.active {
            *slot = LayerSurface::empty();
            slot.active = true;
            return Some(i);
        }
    }
    None
}

/// Free a slot by object_id. Returns true if a slot was released.
pub fn destroy_by_object(object_id: u32) -> bool {
    let pool = unsafe { &mut *LAYER_SURFACES.get() };
    for slot in pool.iter_mut() {
        if slot.active && slot.object_id == object_id {
            *slot = LayerSurface::empty();
            return true;
        }
    }
    false
}

/// Look up an active layer_surface by wire object ID.
pub fn get_mut(object_id: u32) -> Option<&'static mut LayerSurface> {
    let pool = unsafe { &mut *LAYER_SURFACES.get() };
    for slot in pool.iter_mut() {
        if slot.active && slot.object_id == object_id {
            return Some(slot);
        }
    }
    None
}

/// Look up an active layer_surface by pool slot index (used right
/// after `allocate()` returns a slot, before `object_id` is populated).
pub fn get_mut_by_slot(slot: usize) -> Option<&'static mut LayerSurface> {
    if slot >= MAX_LAYER_SURFACES {
        return None;
    }
    let pool = unsafe { &mut *LAYER_SURFACES.get() };
    let ls = &mut pool[slot];
    if ls.active { Some(ls) } else { None }
}

/// Iterator over all active layer surfaces.
pub fn iter() -> impl Iterator<Item = &'static LayerSurface> {
    let pool = unsafe { &*LAYER_SURFACES.get() };
    pool.iter().filter(|s| s.active)
}

/// Iterator over active layer surfaces restricted to a single layer.
pub fn iter_layer(layer: Layer) -> impl Iterator<Item = &'static LayerSurface> {
    iter().filter(move |s| s.layer == layer)
}

/// Cumulative exclusive-zone reservation per edge after `layout_all`.
/// Consumers (the toplevel renderer) reduce the usable area by these
/// values so regular windows don't draw under panels.
#[derive(Clone, Copy, Default, Debug, PartialEq, Eq)]
pub struct ExclusiveInsets {
    pub top: u32,
    pub bottom: u32,
    pub left: u32,
    pub right: u32,
}

impl ExclusiveInsets {
    pub const fn zero() -> Self {
        Self { top: 0, bottom: 0, left: 0, right: 0 }
    }
}

/// Layout every active layer surface in the global pool against a
/// screen of the given size. Returns the cumulative exclusive insets
/// so `compose()` can clamp toplevel draws.
pub fn layout_all(screen_w: u32, screen_h: u32) -> ExclusiveInsets {
    let pool = unsafe { &mut *LAYER_SURFACES.get() };
    layout_layer_surfaces(pool, screen_w, screen_h)
}

/// Pure helper: lay out a mutable slice of layer surfaces. Isolated
/// from the static pool so unit tests can drive it deterministically.
///
/// Layout rules (matches `wlr-layer-shell` spec):
///   * An anchored axis pair (L+R / T+B) stretches the surface along
///     that axis to `screen_dim - margin_start - margin_end`.
///   * A single-edge anchor pins the surface to that edge, honoring the
///     corresponding margin; the opposite axis uses the client width.
///   * No anchor → centred on screen.
///   * `exclusive_zone > 0` reserves space on the anchored edge; later
///     surfaces on the same edge stack on top of earlier ones.
///   * `exclusive_zone < 0` or `== 0` reserves nothing.
///
/// Layering order within the pool is the iteration order; clients that
/// want deterministic bar stacking should commit in the order they want
/// reserved. Surfaces are laid out in ascending layer order
/// (Background → Overlay) so lower-tier panels reserve space first.
pub fn layout_layer_surfaces(
    pool: &mut [LayerSurface],
    screen_w: u32,
    screen_h: u32,
) -> ExclusiveInsets {
    let mut insets = ExclusiveInsets::zero();
    if screen_w == 0 || screen_h == 0 {
        return insets;
    }

    // Iterate in ascending layer tier so Background/Bottom reserve
    // zones before Top/Overlay (whose exclusive_zone is usually <0).
    for tier in [Layer::Background, Layer::Bottom, Layer::Top, Layer::Overlay] {
        for ls in pool.iter_mut() {
            if !ls.active || ls.layer != tier {
                continue;
            }
            layout_one(ls, screen_w, screen_h, &mut insets);
        }
    }
    insets
}

fn layout_one(
    ls: &mut LayerSurface,
    screen_w: u32,
    screen_h: u32,
    insets: &mut ExclusiveInsets,
) {
    let anchor = ls.anchor;
    let has_top = anchor & ANCHOR_TOP != 0;
    let has_bottom = anchor & ANCHOR_BOTTOM != 0;
    let has_left = anchor & ANCHOR_LEFT != 0;
    let has_right = anchor & ANCHOR_RIGHT != 0;

    let sw = screen_w as i32;
    let sh = screen_h as i32;

    // Usable area = screen minus already-reserved insets.
    let avail_x0 = insets.left as i32;
    let avail_y0 = insets.top as i32;
    let avail_x1 = sw - insets.right as i32;
    let avail_y1 = sh - insets.bottom as i32;
    let avail_w = (avail_x1 - avail_x0).max(0);
    let avail_h = (avail_y1 - avail_y0).max(0);

    // ── Width ──
    let width: i32 = if has_left && has_right {
        // Stretch.
        (avail_w - ls.margin_left - ls.margin_right).max(0)
    } else if ls.width > 0 {
        ls.width as i32
    } else {
        // Spec: a 0-sized unanchored axis is an error, but we pick the
        // full available width as a safe fallback.
        avail_w
    };

    // ── Height ──
    let height: i32 = if has_top && has_bottom {
        (avail_h - ls.margin_top - ls.margin_bottom).max(0)
    } else if ls.height > 0 {
        ls.height as i32
    } else {
        avail_h
    };

    // ── X ──
    let x: i32 = if has_left && !has_right {
        avail_x0 + ls.margin_left
    } else if has_right && !has_left {
        avail_x1 - width - ls.margin_right
    } else {
        // Centred (either both or neither horizontal anchor bits set).
        avail_x0 + (avail_w - width) / 2
    };

    // ── Y ──
    let y: i32 = if has_top && !has_bottom {
        avail_y0 + ls.margin_top
    } else if has_bottom && !has_top {
        avail_y1 - height - ls.margin_bottom
    } else {
        avail_y0 + (avail_h - height) / 2
    };

    ls.x = x;
    ls.y = y;
    ls.computed_width = width.max(0) as u32;
    ls.computed_height = height.max(0) as u32;

    // ── Exclusive-zone accounting ──
    if ls.exclusive_zone > 0 {
        let zone = ls.exclusive_zone as u32;
        // Reserve on the dominant anchored edge. If anchored to a
        // single edge, that's the edge. If anchored to opposite-edge
        // pair on an axis, we use the orthogonal single-edge anchor.
        if has_top && !has_bottom {
            let reserved = zone.saturating_add(ls.margin_top.max(0) as u32);
            insets.top = insets.top.saturating_add(reserved);
        } else if has_bottom && !has_top {
            let reserved = zone.saturating_add(ls.margin_bottom.max(0) as u32);
            insets.bottom = insets.bottom.saturating_add(reserved);
        } else if has_left && !has_right {
            let reserved = zone.saturating_add(ls.margin_left.max(0) as u32);
            insets.left = insets.left.saturating_add(reserved);
        } else if has_right && !has_left {
            let reserved = zone.saturating_add(ls.margin_right.max(0) as u32);
            insets.right = insets.right.saturating_add(reserved);
        }
        // If anchored to all four sides (or none), `exclusive_zone` is
        // meaningless per spec; reserve nothing.
    }
}

// ---------------------------------------------------------------------------
// Wire-protocol handlers
// ---------------------------------------------------------------------------

/// Result of a `zwlr_layer_shell_v1::get_layer_surface` request.
pub struct GetLayerSurfaceResult {
    pub object_id: u32,
    pub surface_id: u32,
    pub layer: Layer,
}

/// Handle a request addressed to `zwlr_layer_shell_v1`.
///
/// Returns `Some` for `get_layer_surface` so the dispatcher can track
/// the new object ID.
///
/// Wire format of `get_layer_surface`:
///   new_id(id: u32)
///   wl_surface(object: u32)
///   output(object: u32)         -- we ignore, single-output server
///   layer(enum: u32)
///   namespace(string)           -- we ignore the content
pub fn handle_shell_request(msg: &WlMessage) -> Option<GetLayerSurfaceResult> {
    match msg.opcode {
        LAYER_SHELL_GET_LAYER_SURFACE => {
            let object_id = msg.arg_u32(0);
            let surface_id = msg.arg_u32(4);
            let _output = msg.arg_u32(8);
            let layer = Layer::from_u32(msg.arg_u32(12));
            Some(GetLayerSurfaceResult { object_id, surface_id, layer })
        }
        _ => None,
    }
}

/// Handle a request addressed to a `zwlr_layer_surface_v1` object.
///
/// Mutates the pool slot matching `msg.object_id`. Returns `true` if
/// the layout is now dirty (caller should re-run `layout_all`).
pub fn handle_surface_request(msg: &WlMessage) -> bool {
    let obj = msg.object_id;
    let ls = match get_mut(obj) {
        Some(s) => s,
        None => return false,
    };
    match msg.opcode {
        LAYER_SURFACE_SET_SIZE => {
            ls.width = msg.arg_u32(0);
            ls.height = msg.arg_u32(4);
            true
        }
        LAYER_SURFACE_SET_ANCHOR => {
            ls.anchor = msg.arg_u32(0);
            true
        }
        LAYER_SURFACE_SET_EXCLUSIVE_ZONE => {
            ls.exclusive_zone = msg.arg_i32(0);
            true
        }
        LAYER_SURFACE_SET_MARGIN => {
            ls.margin_top = msg.arg_i32(0);
            ls.margin_right = msg.arg_i32(4);
            ls.margin_bottom = msg.arg_i32(8);
            ls.margin_left = msg.arg_i32(12);
            true
        }
        LAYER_SURFACE_SET_KB_INTERACTIVITY => {
            ls.keyboard_interactivity = msg.arg_u32(0);
            false
        }
        LAYER_SURFACE_ACK_CONFIGURE => {
            ls.configured = true;
            false
        }
        LAYER_SURFACE_DESTROY => {
            destroy_by_object(obj);
            true
        }
        _ => false,
    }
}

/// Build a `zwlr_layer_surface_v1::configure` event.
///
/// Wire format: serial(u32), width(u32), height(u32)
pub fn send_configure(
    object_id: u32,
    serial: u32,
    width: u32,
    height: u32,
    events: &mut [WlEvent; super::MAX_EVENTS],
    event_count: &mut usize,
) {
    if *event_count >= events.len() {
        return;
    }
    let mut ev = WlEvent::new();
    ev.begin(object_id, LAYER_SURFACE_EVT_CONFIGURE);
    ev.put_u32(serial);
    ev.put_u32(width);
    ev.put_u32(height);
    ev.finish();
    events[*event_count] = ev;
    *event_count += 1;
}

// ---------------------------------------------------------------------------
// Test helpers (only compiled when the `cfg(test)` predicate is set).
//
// The compositor binary is `no_std` + `no_main` and cannot host Rust's
// default test harness, so these helpers exist for downstream test
// crates and for `cargo check --tests` once the compositor is moved
// into a workspace member that supports std.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn fresh(layer: Layer, anchor: u32, w: u32, h: u32) -> LayerSurface {
        let mut ls = LayerSurface::empty();
        ls.active = true;
        ls.layer = layer;
        ls.anchor = anchor;
        ls.width = w;
        ls.height = h;
        ls
    }

    #[test]
    fn layer_from_u32_round_trips() {
        assert_eq!(Layer::from_u32(0), Layer::Background);
        assert_eq!(Layer::from_u32(1), Layer::Bottom);
        assert_eq!(Layer::from_u32(2), Layer::Top);
        assert_eq!(Layer::from_u32(3), Layer::Overlay);
        // Out-of-range falls back to Top.
        assert_eq!(Layer::from_u32(99), Layer::Top);
    }

    #[test]
    fn top_anchored_bar_is_full_width_at_y_zero() {
        let mut pool = [fresh(
            Layer::Top,
            ANCHOR_TOP | ANCHOR_LEFT | ANCHOR_RIGHT,
            0,
            24,
        )];
        let insets = layout_layer_surfaces(&mut pool, 1920, 1080);
        assert_eq!(pool[0].x, 0);
        assert_eq!(pool[0].y, 0);
        assert_eq!(pool[0].computed_width, 1920);
        assert_eq!(pool[0].computed_height, 24);
        // No exclusive_zone set → no insets reserved.
        assert_eq!(insets, ExclusiveInsets::zero());
    }

    #[test]
    fn bottom_anchored_bar_sits_at_bottom_edge() {
        let mut pool = [fresh(
            Layer::Bottom,
            ANCHOR_BOTTOM | ANCHOR_LEFT | ANCHOR_RIGHT,
            0,
            40,
        )];
        let insets = layout_layer_surfaces(&mut pool, 800, 600);
        assert_eq!(pool[0].x, 0);
        assert_eq!(pool[0].computed_width, 800);
        assert_eq!(pool[0].computed_height, 40);
        assert_eq!(pool[0].y, 600 - 40);
        assert_eq!(insets, ExclusiveInsets::zero());
    }

    #[test]
    fn unanchored_surface_is_centred() {
        let mut pool = [fresh(Layer::Overlay, 0, 200, 100)];
        layout_layer_surfaces(&mut pool, 1000, 600);
        assert_eq!(pool[0].x, (1000 - 200) / 2);
        assert_eq!(pool[0].y, (600 - 100) / 2);
        assert_eq!(pool[0].computed_width, 200);
        assert_eq!(pool[0].computed_height, 100);
    }

    #[test]
    fn exclusive_zone_reserves_top_edge() {
        let mut pool = [fresh(
            Layer::Top,
            ANCHOR_TOP | ANCHOR_LEFT | ANCHOR_RIGHT,
            0,
            24,
        )];
        pool[0].exclusive_zone = 24;
        let insets = layout_layer_surfaces(&mut pool, 1920, 1080);
        assert_eq!(insets.top, 24);
        assert_eq!(insets.bottom, 0);
    }

    #[test]
    fn two_bars_stack_exclusive_zones() {
        let mut pool = [
            fresh(
                Layer::Bottom,
                ANCHOR_TOP | ANCHOR_LEFT | ANCHOR_RIGHT,
                0,
                20,
            ),
            fresh(
                Layer::Top,
                ANCHOR_TOP | ANCHOR_LEFT | ANCHOR_RIGHT,
                0,
                24,
            ),
        ];
        pool[0].exclusive_zone = 20;
        pool[1].exclusive_zone = 24;
        let insets = layout_layer_surfaces(&mut pool, 1920, 1080);
        assert_eq!(insets.top, 44);
        // Second bar is pushed down by the first bar's reserved zone.
        assert_eq!(pool[0].y, 0);
        assert_eq!(pool[1].y, 20);
    }

    #[test]
    fn margin_offsets_single_edge_anchor() {
        let mut pool = [fresh(Layer::Top, ANCHOR_LEFT, 100, 200)];
        pool[0].margin_left = 10;
        pool[0].margin_top = 5;
        layout_layer_surfaces(&mut pool, 800, 600);
        assert_eq!(pool[0].x, 10);
        // With only LEFT set, vertical anchor is "centred".
        assert_eq!(pool[0].y, (600 - 200) / 2);
    }

    #[test]
    fn background_layered_before_top_in_iteration() {
        // Background surface gets its exclusive zone applied before the
        // Top surface sees its available area. Here the background is
        // full-screen with no zone, but a Bottom bar reserves 30 px and
        // the Top bar (same anchor) sees that reservation.
        let mut pool = [
            fresh(
                Layer::Top,
                ANCHOR_TOP | ANCHOR_LEFT | ANCHOR_RIGHT,
                0,
                24,
            ),
            fresh(
                Layer::Bottom,
                ANCHOR_TOP | ANCHOR_LEFT | ANCHOR_RIGHT,
                0,
                30,
            ),
        ];
        // index 0 is Top tier (laid out after Bottom despite coming
        // first in the slice) -- confirm tier ordering wins.
        pool[1].exclusive_zone = 30;
        let insets = layout_layer_surfaces(&mut pool, 1000, 1000);
        assert_eq!(insets.top, 30);
        // Bottom tier went first, so pool[1] sits at y=0.
        assert_eq!(pool[1].y, 0);
        // Top tier laid out against the reduced area.
        assert_eq!(pool[0].y, 30);
    }

    #[test]
    fn zero_screen_returns_empty_insets() {
        let mut pool = [fresh(Layer::Top, ANCHOR_TOP, 100, 24)];
        let insets = layout_layer_surfaces(&mut pool, 0, 0);
        assert_eq!(insets, ExclusiveInsets::zero());
    }

    #[test]
    fn stretch_with_margins_subtracts_both_sides() {
        let mut pool = [fresh(
            Layer::Top,
            ANCHOR_TOP | ANCHOR_LEFT | ANCHOR_RIGHT,
            0,
            30,
        )];
        pool[0].margin_left = 8;
        pool[0].margin_right = 12;
        layout_layer_surfaces(&mut pool, 1000, 500);
        assert_eq!(pool[0].computed_width, 1000 - 8 - 12);
    }
}
