//! Mouse event structure — the unified output format for all mouse input.

// Mouse button bitmask constants.
/// Left mouse button — bit 0 of `MouseEvent::buttons`.
pub const BUTTON_LEFT: u8 = 1 << 0;
/// Right mouse button — bit 1.
pub const BUTTON_RIGHT: u8 = 1 << 1;
/// Middle (wheel) mouse button — bit 2.
pub const BUTTON_MIDDLE: u8 = 1 << 2;
/// Side button 4 (browser "back") — bit 3.
pub const BUTTON_4: u8 = 1 << 3;
/// Side button 5 (browser "forward") — bit 4.
pub const BUTTON_5: u8 = 1 << 4;

/// A mouse event representing a state change.
///
/// Produced by both PS/2 and USB HID mouse drivers.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct MouseEvent {
    /// Button state bitmask: bit 0 = left, bit 1 = right, bit 2 = middle.
    pub buttons: u8,
    /// X movement delta (positive = right).
    pub dx: i16,
    /// Y movement delta (positive = down, consistent with screen coordinates).
    pub dy: i16,
    /// Scroll wheel delta (positive = scroll up).
    pub dz: i8,
}

const _: () = assert!(core::mem::size_of::<MouseEvent>() == 8);

impl MouseEvent {
    /// Create a zeroed (no-movement, no-button) event.
    pub const fn zeroed() -> Self {
        Self { buttons: 0, dx: 0, dy: 0, dz: 0 }
    }

    /// Check if the left button is pressed.
    pub const fn left_pressed(&self) -> bool {
        self.buttons & BUTTON_LEFT != 0
    }

    /// Check if the right button is pressed.
    pub const fn right_pressed(&self) -> bool {
        self.buttons & BUTTON_RIGHT != 0
    }

    /// Check if the middle button is pressed.
    pub const fn middle_pressed(&self) -> bool {
        self.buttons & BUTTON_MIDDLE != 0
    }

    /// Check if any button is pressed.
    pub const fn any_button(&self) -> bool {
        self.buttons != 0
    }

    /// Check if there is any movement (including scroll).
    pub const fn has_movement(&self) -> bool {
        self.dx != 0 || self.dy != 0 || self.dz != 0
    }
}

/// Accumulated mouse state — tracks absolute position and button state.
pub struct MouseState {
    /// Accumulated X position.
    pub x: i32,
    /// Accumulated Y position.
    pub y: i32,
    /// Current button state.
    pub buttons: u8,
    /// Minimum X bound.
    pub x_min: i32,
    /// Maximum X bound.
    pub x_max: i32,
    /// Minimum Y bound.
    pub y_min: i32,
    /// Maximum Y bound.
    pub y_max: i32,
}

impl MouseState {
    /// Create a new mouse state with the given bounds.
    pub const fn new(x_max: i32, y_max: i32) -> Self {
        Self {
            x: 0,
            y: 0,
            buttons: 0,
            x_min: 0,
            x_max,
            y_min: 0,
            y_max,
        }
    }

    /// Apply a mouse event to the accumulated state.
    /// Clamps position to the configured bounds.
    pub fn apply(&mut self, event: &MouseEvent) {
        self.buttons = event.buttons;

        self.x += event.dx as i32;
        self.y += event.dy as i32;

        // Clamp to bounds.
        if self.x < self.x_min { self.x = self.x_min; }
        if self.x > self.x_max { self.x = self.x_max; }
        if self.y < self.y_min { self.y = self.y_min; }
        if self.y > self.y_max { self.y = self.y_max; }
    }

    /// Set the bounds (e.g., when screen resolution changes).
    pub fn set_bounds(&mut self, x_max: i32, y_max: i32) {
        self.x_max = x_max;
        self.y_max = y_max;
    }
}
