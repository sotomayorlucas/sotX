// Standalone test harness for layer_shell geometry.
//
// The compositor is built as a #![no_std] #![no_main] binary with
// -Zbuild-std, which makes `cargo test` unable to run unit tests
// (duplicate lang-item errors when the test harness pulls in std-
// dependent crates). This file replicates the pure geometry portion
// of `services/compositor/src/wayland/layer_shell.rs` with std on the
// host so we can exercise the layout logic deterministically.
//
// Run with:
//
//   rustc --edition 2021 services/compositor/host-tests/layer_shell_geometry.rs \
//     -o target/layer_shell_geometry && target/layer_shell_geometry
//
// The code under test is kept byte-for-byte in sync with
// `layout_layer_surfaces` in the compositor module.

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[allow(dead_code)]
pub enum Layer {
    Background = 0,
    Bottom = 1,
    Top = 2,
    Overlay = 3,
}

impl Layer {
    pub const fn from_u32(v: u32) -> Self {
        match v {
            0 => Layer::Background,
            1 => Layer::Bottom,
            3 => Layer::Overlay,
            _ => Layer::Top,
        }
    }
}

pub const ANCHOR_TOP: u32 = 1;
pub const ANCHOR_BOTTOM: u32 = 2;
pub const ANCHOR_LEFT: u32 = 4;
pub const ANCHOR_RIGHT: u32 = 8;

#[derive(Clone, Copy)]
pub struct LayerSurface {
    pub object_id: u32,
    pub surface_id: u32,
    pub layer: Layer,
    pub anchor: u32,
    pub exclusive_zone: i32,
    pub margin_top: i32,
    pub margin_right: i32,
    pub margin_bottom: i32,
    pub margin_left: i32,
    pub width: u32,
    pub height: u32,
    pub x: i32,
    pub y: i32,
    pub computed_width: u32,
    pub computed_height: u32,
    pub keyboard_interactivity: u32,
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

pub fn layout_layer_surfaces(
    pool: &mut [LayerSurface],
    screen_w: u32,
    screen_h: u32,
) -> ExclusiveInsets {
    let mut insets = ExclusiveInsets::zero();
    if screen_w == 0 || screen_h == 0 {
        return insets;
    }
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

    let avail_x0 = insets.left as i32;
    let avail_y0 = insets.top as i32;
    let avail_x1 = sw - insets.right as i32;
    let avail_y1 = sh - insets.bottom as i32;
    let avail_w = (avail_x1 - avail_x0).max(0);
    let avail_h = (avail_y1 - avail_y0).max(0);

    let width: i32 = if has_left && has_right {
        (avail_w - ls.margin_left - ls.margin_right).max(0)
    } else if ls.width > 0 {
        ls.width as i32
    } else {
        avail_w
    };

    let height: i32 = if has_top && has_bottom {
        (avail_h - ls.margin_top - ls.margin_bottom).max(0)
    } else if ls.height > 0 {
        ls.height as i32
    } else {
        avail_h
    };

    let x: i32 = if has_left && !has_right {
        avail_x0 + ls.margin_left
    } else if has_right && !has_left {
        avail_x1 - width - ls.margin_right
    } else {
        avail_x0 + (avail_w - width) / 2
    };

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

    if ls.exclusive_zone > 0 {
        let zone = ls.exclusive_zone as u32;
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
    }
}

// ---------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------

fn fresh(layer: Layer, anchor: u32, w: u32, h: u32) -> LayerSurface {
    let mut ls = LayerSurface::empty();
    ls.active = true;
    ls.layer = layer;
    ls.anchor = anchor;
    ls.width = w;
    ls.height = h;
    ls
}

fn eq<T: PartialEq + std::fmt::Debug>(name: &str, got: T, want: T) {
    if got != want {
        eprintln!("FAIL: {} -- got {:?}, want {:?}", name, got, want);
        std::process::exit(1);
    }
    println!("ok   {}", name);
}

fn main() {
    // 1. Layer enum round trip
    eq("layer_from_u32(0)", Layer::from_u32(0), Layer::Background);
    eq("layer_from_u32(1)", Layer::from_u32(1), Layer::Bottom);
    eq("layer_from_u32(2)", Layer::from_u32(2), Layer::Top);
    eq("layer_from_u32(3)", Layer::from_u32(3), Layer::Overlay);
    eq("layer_from_u32(99) falls back to Top", Layer::from_u32(99), Layer::Top);

    // 2. Top bar stretches full width at y=0
    {
        let mut pool = [fresh(Layer::Top, ANCHOR_TOP | ANCHOR_LEFT | ANCHOR_RIGHT, 0, 24)];
        let insets = layout_layer_surfaces(&mut pool, 1920, 1080);
        eq("top bar x", pool[0].x, 0);
        eq("top bar y", pool[0].y, 0);
        eq("top bar w", pool[0].computed_width, 1920);
        eq("top bar h", pool[0].computed_height, 24);
        eq("top bar insets zero (no zone)", insets, ExclusiveInsets::zero());
    }

    // 3. Bottom bar sits at bottom edge
    {
        let mut pool = [fresh(Layer::Bottom, ANCHOR_BOTTOM | ANCHOR_LEFT | ANCHOR_RIGHT, 0, 40)];
        let insets = layout_layer_surfaces(&mut pool, 800, 600);
        eq("bottom bar x", pool[0].x, 0);
        eq("bottom bar w", pool[0].computed_width, 800);
        eq("bottom bar h", pool[0].computed_height, 40);
        eq("bottom bar y", pool[0].y, 600 - 40);
        eq("bottom bar insets zero (no zone)", insets, ExclusiveInsets::zero());
    }

    // 4. Unanchored surface is centred
    {
        let mut pool = [fresh(Layer::Overlay, 0, 200, 100)];
        layout_layer_surfaces(&mut pool, 1000, 600);
        eq("centred x", pool[0].x, (1000 - 200) / 2);
        eq("centred y", pool[0].y, (600 - 100) / 2);
        eq("centred w", pool[0].computed_width, 200);
        eq("centred h", pool[0].computed_height, 100);
    }

    // 5. Exclusive zone reserves top edge
    {
        let mut pool = [fresh(Layer::Top, ANCHOR_TOP | ANCHOR_LEFT | ANCHOR_RIGHT, 0, 24)];
        pool[0].exclusive_zone = 24;
        let insets = layout_layer_surfaces(&mut pool, 1920, 1080);
        eq("reserved top=24", insets.top, 24);
        eq("reserved bottom=0", insets.bottom, 0);
    }

    // 6. Two bars stack their exclusive zones
    {
        let mut pool = [
            fresh(Layer::Bottom, ANCHOR_TOP | ANCHOR_LEFT | ANCHOR_RIGHT, 0, 20),
            fresh(Layer::Top,    ANCHOR_TOP | ANCHOR_LEFT | ANCHOR_RIGHT, 0, 24),
        ];
        pool[0].exclusive_zone = 20;
        pool[1].exclusive_zone = 24;
        let insets = layout_layer_surfaces(&mut pool, 1920, 1080);
        eq("two-bar insets top=44", insets.top, 44);
        eq("first bar y=0", pool[0].y, 0);
        eq("second bar y=20", pool[1].y, 20);
    }

    // 7. Margin offsets single-edge anchor
    {
        let mut pool = [fresh(Layer::Top, ANCHOR_LEFT, 100, 200)];
        pool[0].margin_left = 10;
        pool[0].margin_top = 5;
        layout_layer_surfaces(&mut pool, 800, 600);
        eq("left-anchored x=margin_left", pool[0].x, 10);
        eq("vertically centred y", pool[0].y, (600 - 200) / 2);
    }

    // 8. Tier ordering: Bottom layer is laid out before Top layer
    //    (ignoring slice order)
    {
        let mut pool = [
            fresh(Layer::Top,    ANCHOR_TOP | ANCHOR_LEFT | ANCHOR_RIGHT, 0, 24),
            fresh(Layer::Bottom, ANCHOR_TOP | ANCHOR_LEFT | ANCHOR_RIGHT, 0, 30),
        ];
        pool[1].exclusive_zone = 30;
        let insets = layout_layer_surfaces(&mut pool, 1000, 1000);
        eq("tier-order reserved", insets.top, 30);
        eq("bottom-tier y=0", pool[1].y, 0);
        eq("top-tier y after bottom reservation", pool[0].y, 30);
    }

    // 9. Zero-size screen returns empty insets
    {
        let mut pool = [fresh(Layer::Top, ANCHOR_TOP, 100, 24)];
        let insets = layout_layer_surfaces(&mut pool, 0, 0);
        eq("zero-screen insets", insets, ExclusiveInsets::zero());
    }

    // 10. Stretched width subtracts both margins
    {
        let mut pool = [fresh(Layer::Top, ANCHOR_TOP | ANCHOR_LEFT | ANCHOR_RIGHT, 0, 30)];
        pool[0].margin_left = 8;
        pool[0].margin_right = 12;
        layout_layer_surfaces(&mut pool, 1000, 500);
        eq("stretch minus margins", pool[0].computed_width, 1000 - 8 - 12);
    }

    println!("\nall layer_shell tests passed");
}
