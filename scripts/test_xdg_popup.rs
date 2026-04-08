//! Standalone unit test harness for wayland/xdg_popup.rs.
//!
//! The compositor crate is `#![no_std] #![no_main]` with a nailed-down
//! `.cargo/config.toml` that forces `target = x86_64-unknown-none` + a
//! custom linker script. Running `cargo test` on it isn't practical, so
//! this file re-exports the pure logic (no static pools, no unsafe) and
//! verifies the `place_popup` arithmetic against the xdg-shell spec.
//!
//! Run manually with:
//!     rustc --edition 2021 --test scripts/test_xdg_popup.rs -o target/test_xdg_popup.exe
//!     ./target/test_xdg_popup.exe

#![allow(dead_code)]

pub const ANCHOR_NONE: u32 = 0;
pub const ANCHOR_TOP: u32 = 1;
pub const ANCHOR_BOTTOM: u32 = 2;
pub const ANCHOR_LEFT: u32 = 3;
pub const ANCHOR_RIGHT: u32 = 4;
pub const ANCHOR_TOP_LEFT: u32 = 5;
pub const ANCHOR_BOTTOM_LEFT: u32 = 6;
pub const ANCHOR_TOP_RIGHT: u32 = 7;
pub const ANCHOR_BOTTOM_RIGHT: u32 = 8;

pub const GRAVITY_NONE: u32 = 0;
pub const GRAVITY_TOP: u32 = 1;
pub const GRAVITY_BOTTOM: u32 = 2;
pub const GRAVITY_LEFT: u32 = 3;
pub const GRAVITY_RIGHT: u32 = 4;
pub const GRAVITY_TOP_LEFT: u32 = 5;
pub const GRAVITY_BOTTOM_LEFT: u32 = 6;
pub const GRAVITY_TOP_RIGHT: u32 = 7;
pub const GRAVITY_BOTTOM_RIGHT: u32 = 8;

#[derive(Clone, Copy, Default)]
pub struct Positioner {
    pub size_w: i32,
    pub size_h: i32,
    pub anchor_x: i32,
    pub anchor_y: i32,
    pub anchor_w: i32,
    pub anchor_h: i32,
    pub anchor: u32,
    pub gravity: u32,
    pub offset_x: i32,
    pub offset_y: i32,
}

#[derive(Clone, Copy, Default)]
pub struct Popup {
    pub x: i32,
    pub y: i32,
    pub width: u32,
    pub height: u32,
}

fn anchor_point(anchor: u32, rx: i32, ry: i32, rw: i32, rh: i32) -> (i32, i32) {
    let cx = rx + rw / 2;
    let cy = ry + rh / 2;
    let left = rx;
    let right = rx + rw;
    let top = ry;
    let bottom = ry + rh;
    match anchor {
        ANCHOR_TOP => (cx, top),
        ANCHOR_BOTTOM => (cx, bottom),
        ANCHOR_LEFT => (left, cy),
        ANCHOR_RIGHT => (right, cy),
        ANCHOR_TOP_LEFT => (left, top),
        ANCHOR_BOTTOM_LEFT => (left, bottom),
        ANCHOR_TOP_RIGHT => (right, top),
        ANCHOR_BOTTOM_RIGHT => (right, bottom),
        _ => (cx, cy),
    }
}

fn gravity_offset(gravity: u32, w: i32, h: i32) -> (i32, i32) {
    match gravity {
        GRAVITY_TOP => (-w / 2, -h),
        GRAVITY_BOTTOM => (-w / 2, 0),
        GRAVITY_LEFT => (-w, -h / 2),
        GRAVITY_RIGHT => (0, -h / 2),
        GRAVITY_TOP_LEFT => (-w, -h),
        GRAVITY_BOTTOM_LEFT => (-w, 0),
        GRAVITY_TOP_RIGHT => (0, -h),
        GRAVITY_BOTTOM_RIGHT => (0, 0),
        _ => (-w / 2, -h / 2),
    }
}

pub fn place_popup(popup: &mut Popup, positioner: &Positioner, parent_x: i32, parent_y: i32) {
    let (ax, ay) = anchor_point(
        positioner.anchor,
        positioner.anchor_x,
        positioner.anchor_y,
        positioner.anchor_w,
        positioner.anchor_h,
    );
    let screen_ax = parent_x + ax;
    let screen_ay = parent_y + ay;
    let w = positioner.size_w.max(0);
    let h = positioner.size_h.max(0);
    let (gdx, gdy) = gravity_offset(positioner.gravity, w, h);
    popup.x = screen_ax + gdx + positioner.offset_x;
    popup.y = screen_ay + gdy + positioner.offset_y;
    popup.width = w as u32;
    popup.height = h as u32;
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pos(anchor: u32, gravity: u32, w: i32, h: i32) -> Positioner {
        Positioner {
            size_w: w,
            size_h: h,
            anchor_x: 50,
            anchor_y: 40,
            anchor_w: 100,
            anchor_h: 20,
            anchor,
            gravity,
            ..Default::default()
        }
    }

    #[test]
    fn anchor_none_centers_in_rect() {
        let p = pos(ANCHOR_NONE, GRAVITY_NONE, 40, 10);
        let mut pu = Popup::default();
        place_popup(&mut pu, &p, 0, 0);
        assert_eq!(pu.x, 80);
        assert_eq!(pu.y, 45);
        assert_eq!(pu.width, 40);
        assert_eq!(pu.height, 10);
    }

    #[test]
    fn anchor_bottom_gravity_bottom_menu() {
        let p = pos(ANCHOR_BOTTOM, GRAVITY_BOTTOM, 80, 200);
        let mut pu = Popup::default();
        place_popup(&mut pu, &p, 10, 10);
        assert_eq!(pu.x, 70);
        assert_eq!(pu.y, 70);
        assert_eq!(pu.width, 80);
        assert_eq!(pu.height, 200);
    }

    #[test]
    fn anchor_top_right_gravity_top_right_tooltip() {
        let p = pos(ANCHOR_TOP_RIGHT, GRAVITY_TOP_RIGHT, 60, 30);
        let mut pu = Popup::default();
        place_popup(&mut pu, &p, 200, 100);
        assert_eq!(pu.x, 350);
        assert_eq!(pu.y, 110);
    }

    #[test]
    fn offset_is_applied_last() {
        let mut p = pos(ANCHOR_BOTTOM, GRAVITY_BOTTOM, 50, 50);
        p.offset_x = 7;
        p.offset_y = -3;
        let mut pu = Popup::default();
        place_popup(&mut pu, &p, 0, 0);
        assert_eq!(pu.x, 82);
        assert_eq!(pu.y, 57);
    }

    #[test]
    fn anchor_left_gravity_left_submenu() {
        let p = pos(ANCHOR_LEFT, GRAVITY_LEFT, 100, 60);
        let mut pu = Popup::default();
        place_popup(&mut pu, &p, 500, 200);
        assert_eq!(pu.x, 450);
        assert_eq!(pu.y, 220);
    }

    #[test]
    fn gravity_right_grows_rightward() {
        let p = pos(ANCHOR_RIGHT, GRAVITY_RIGHT, 40, 20);
        let mut pu = Popup::default();
        place_popup(&mut pu, &p, 0, 0);
        assert_eq!(pu.x, 150);
        assert_eq!(pu.y, 40);
    }
}

fn main() {
    // Empty main so `rustc` (non-test build) still links.
}
