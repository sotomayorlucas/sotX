//! sotOS GUI — Window compositor and drawing primitives.
//!
//! Provides a minimal window management system for the sotOS framebuffer:
//! - Window creation, destruction, z-ordering, and focus management
//! - Compositor: renders windows to framebuffer with overlap handling
//! - Window decorations: title bar, close button, minimize button
//! - Mouse cursor rendering (16x16 sprite)
//! - Event system: mouse click hit-testing and event delivery
//! - Basic drawing primitives: fill_rect, draw_line, draw_char, blit
//! - Modern desktop renderer via embedded-graphics (rounded windows, traffic-light buttons)
//!
//! All rendering operates on raw pixel buffers (32-bit BGRA format).
//! No heap allocation — all state is fixed-size arrays.

#![no_std]

pub mod display;
pub mod desktop;

pub use display::FramebufferDisplay;
pub use desktop::{draw_modern_desktop, DesktopLayout};
pub use tinybmp;

/// Maximum number of windows managed by the compositor.
pub const MAX_WINDOWS: usize = 16;
/// Title bar height in pixels.
pub const TITLE_BAR_HEIGHT: u32 = 24;
/// Close button width in pixels.
pub const CLOSE_BTN_WIDTH: u32 = 24;
/// Minimize button width in pixels.
pub const MINIMIZE_BTN_WIDTH: u32 = 24;
/// Maximum title length in bytes.
pub const MAX_TITLE_LEN: usize = 64;
/// Mouse cursor dimensions.
pub const CURSOR_SIZE: usize = 16;

// ---------------------------------------------------------------------------
// Color constants (BGRA format)
// ---------------------------------------------------------------------------

/// BGRA color: pack bytes into u32 [B, G, R, A].
pub const fn bgra(r: u8, g: u8, b: u8, a: u8) -> u32 {
    (a as u32) << 24 | (r as u32) << 16 | (g as u32) << 8 | (b as u32)
}

pub const COLOR_WHITE: u32 = bgra(255, 255, 255, 255);
pub const COLOR_BLACK: u32 = bgra(0, 0, 0, 255);
pub const COLOR_GRAY: u32 = bgra(128, 128, 128, 255);
pub const COLOR_DARK_GRAY: u32 = bgra(64, 64, 64, 255);
pub const COLOR_LIGHT_GRAY: u32 = bgra(192, 192, 192, 255);
pub const COLOR_BLUE: u32 = bgra(50, 100, 200, 255);
pub const COLOR_RED: u32 = bgra(220, 60, 60, 255);
pub const COLOR_YELLOW: u32 = bgra(220, 200, 60, 255);
pub const COLOR_DESKTOP: u32 = bgra(40, 80, 120, 255);
pub const COLOR_TITLE_ACTIVE: u32 = bgra(50, 100, 200, 255);
pub const COLOR_TITLE_INACTIVE: u32 = bgra(100, 100, 100, 255);
pub const COLOR_WINDOW_BG: u32 = bgra(240, 240, 240, 255);

// ---------------------------------------------------------------------------
// 8x8 bitmap font (ASCII 32-127)
// ---------------------------------------------------------------------------

/// Simple 8x8 font glyph data. Each glyph is 8 bytes (1 byte per row).
/// We store a basic set covering ASCII 32-127.
pub const FONT_WIDTH: u32 = 8;
pub const FONT_HEIGHT: u32 = 8;

/// Complete 8x8 bitmap font for ASCII 32-127 (96 glyphs, 8 bytes each = 768 bytes).
/// Standard IBM/CP437 8x8 font. Each byte is one row, MSB = leftmost pixel.
static FONT_8X8: [[u8; 8]; 96] = [
    // 32 ' ' (space)
    [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
    // 33 '!'
    [0x18, 0x18, 0x18, 0x18, 0x18, 0x00, 0x18, 0x00],
    // 34 '"'
    [0x6C, 0x6C, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
    // 35 '#'
    [0x6C, 0x6C, 0xFE, 0x6C, 0xFE, 0x6C, 0x6C, 0x00],
    // 36 '$'
    [0x18, 0x3E, 0x60, 0x3C, 0x06, 0x7C, 0x18, 0x00],
    // 37 '%'
    [0x00, 0xC6, 0xCC, 0x18, 0x30, 0x66, 0xC6, 0x00],
    // 38 '&'
    [0x38, 0x6C, 0x38, 0x76, 0xDC, 0xCC, 0x76, 0x00],
    // 39 '''
    [0x18, 0x18, 0x30, 0x00, 0x00, 0x00, 0x00, 0x00],
    // 40 '('
    [0x0C, 0x18, 0x30, 0x30, 0x30, 0x18, 0x0C, 0x00],
    // 41 ')'
    [0x30, 0x18, 0x0C, 0x0C, 0x0C, 0x18, 0x30, 0x00],
    // 42 '*'
    [0x00, 0x66, 0x3C, 0xFF, 0x3C, 0x66, 0x00, 0x00],
    // 43 '+'
    [0x00, 0x18, 0x18, 0x7E, 0x18, 0x18, 0x00, 0x00],
    // 44 ','
    [0x00, 0x00, 0x00, 0x00, 0x00, 0x18, 0x18, 0x30],
    // 45 '-'
    [0x00, 0x00, 0x00, 0x7E, 0x00, 0x00, 0x00, 0x00],
    // 46 '.'
    [0x00, 0x00, 0x00, 0x00, 0x00, 0x18, 0x18, 0x00],
    // 47 '/'
    [0x06, 0x0C, 0x18, 0x30, 0x60, 0xC0, 0x00, 0x00],
    // 48 '0'
    [0x3C, 0x66, 0x6E, 0x7E, 0x76, 0x66, 0x3C, 0x00],
    // 49 '1'
    [0x18, 0x38, 0x18, 0x18, 0x18, 0x18, 0x7E, 0x00],
    // 50 '2'
    [0x3C, 0x66, 0x06, 0x0C, 0x18, 0x30, 0x7E, 0x00],
    // 51 '3'
    [0x3C, 0x66, 0x06, 0x1C, 0x06, 0x66, 0x3C, 0x00],
    // 52 '4'
    [0x0C, 0x1C, 0x3C, 0x6C, 0xCC, 0xFE, 0x0C, 0x00],
    // 53 '5'
    [0x7E, 0x60, 0x7C, 0x06, 0x06, 0x66, 0x3C, 0x00],
    // 54 '6'
    [0x1C, 0x30, 0x60, 0x7C, 0x66, 0x66, 0x3C, 0x00],
    // 55 '7'
    [0x7E, 0x06, 0x0C, 0x18, 0x30, 0x30, 0x30, 0x00],
    // 56 '8'
    [0x3C, 0x66, 0x66, 0x3C, 0x66, 0x66, 0x3C, 0x00],
    // 57 '9'
    [0x3C, 0x66, 0x66, 0x3E, 0x06, 0x0C, 0x38, 0x00],
    // 58 ':'
    [0x00, 0x18, 0x18, 0x00, 0x18, 0x18, 0x00, 0x00],
    // 59 ';'
    [0x00, 0x18, 0x18, 0x00, 0x18, 0x18, 0x30, 0x00],
    // 60 '<'
    [0x0C, 0x18, 0x30, 0x60, 0x30, 0x18, 0x0C, 0x00],
    // 61 '='
    [0x00, 0x00, 0x7E, 0x00, 0x7E, 0x00, 0x00, 0x00],
    // 62 '>'
    [0x30, 0x18, 0x0C, 0x06, 0x0C, 0x18, 0x30, 0x00],
    // 63 '?'
    [0x3C, 0x66, 0x06, 0x0C, 0x18, 0x00, 0x18, 0x00],
    // 64 '@'
    [0x3C, 0x66, 0x6E, 0x6A, 0x6E, 0x60, 0x3C, 0x00],
    // 65 'A'
    [0x18, 0x3C, 0x66, 0x66, 0x7E, 0x66, 0x66, 0x00],
    // 66 'B'
    [0x7C, 0x66, 0x66, 0x7C, 0x66, 0x66, 0x7C, 0x00],
    // 67 'C'
    [0x3C, 0x66, 0x60, 0x60, 0x60, 0x66, 0x3C, 0x00],
    // 68 'D'
    [0x78, 0x6C, 0x66, 0x66, 0x66, 0x6C, 0x78, 0x00],
    // 69 'E'
    [0x7E, 0x60, 0x60, 0x7C, 0x60, 0x60, 0x7E, 0x00],
    // 70 'F'
    [0x7E, 0x60, 0x60, 0x7C, 0x60, 0x60, 0x60, 0x00],
    // 71 'G'
    [0x3C, 0x66, 0x60, 0x6E, 0x66, 0x66, 0x3E, 0x00],
    // 72 'H'
    [0x66, 0x66, 0x66, 0x7E, 0x66, 0x66, 0x66, 0x00],
    // 73 'I'
    [0x7E, 0x18, 0x18, 0x18, 0x18, 0x18, 0x7E, 0x00],
    // 74 'J'
    [0x06, 0x06, 0x06, 0x06, 0x66, 0x66, 0x3C, 0x00],
    // 75 'K'
    [0x66, 0x6C, 0x78, 0x70, 0x78, 0x6C, 0x66, 0x00],
    // 76 'L'
    [0x60, 0x60, 0x60, 0x60, 0x60, 0x60, 0x7E, 0x00],
    // 77 'M'
    [0xC6, 0xEE, 0xFE, 0xD6, 0xC6, 0xC6, 0xC6, 0x00],
    // 78 'N'
    [0x66, 0x76, 0x7E, 0x7E, 0x6E, 0x66, 0x66, 0x00],
    // 79 'O'
    [0x3C, 0x66, 0x66, 0x66, 0x66, 0x66, 0x3C, 0x00],
    // 80 'P'
    [0x7C, 0x66, 0x66, 0x7C, 0x60, 0x60, 0x60, 0x00],
    // 81 'Q'
    [0x3C, 0x66, 0x66, 0x66, 0x6A, 0x6C, 0x36, 0x00],
    // 82 'R'
    [0x7C, 0x66, 0x66, 0x7C, 0x6C, 0x66, 0x66, 0x00],
    // 83 'S'
    [0x3C, 0x66, 0x60, 0x3C, 0x06, 0x66, 0x3C, 0x00],
    // 84 'T'
    [0x7E, 0x18, 0x18, 0x18, 0x18, 0x18, 0x18, 0x00],
    // 85 'U'
    [0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x3C, 0x00],
    // 86 'V'
    [0x66, 0x66, 0x66, 0x66, 0x3C, 0x3C, 0x18, 0x00],
    // 87 'W'
    [0xC6, 0xC6, 0xC6, 0xD6, 0xFE, 0xEE, 0xC6, 0x00],
    // 88 'X'
    [0x66, 0x66, 0x3C, 0x18, 0x3C, 0x66, 0x66, 0x00],
    // 89 'Y'
    [0x66, 0x66, 0x3C, 0x18, 0x18, 0x18, 0x18, 0x00],
    // 90 'Z'
    [0x7E, 0x06, 0x0C, 0x18, 0x30, 0x60, 0x7E, 0x00],
    // 91 '['
    [0x3C, 0x30, 0x30, 0x30, 0x30, 0x30, 0x3C, 0x00],
    // 92 '\'
    [0xC0, 0x60, 0x30, 0x18, 0x0C, 0x06, 0x00, 0x00],
    // 93 ']'
    [0x3C, 0x0C, 0x0C, 0x0C, 0x0C, 0x0C, 0x3C, 0x00],
    // 94 '^'
    [0x18, 0x3C, 0x66, 0x00, 0x00, 0x00, 0x00, 0x00],
    // 95 '_'
    [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFE, 0x00],
    // 96 '`'
    [0x18, 0x18, 0x0C, 0x00, 0x00, 0x00, 0x00, 0x00],
    // 97 'a'
    [0x00, 0x00, 0x3C, 0x06, 0x3E, 0x66, 0x3E, 0x00],
    // 98 'b'
    [0x60, 0x60, 0x7C, 0x66, 0x66, 0x66, 0x7C, 0x00],
    // 99 'c'
    [0x00, 0x00, 0x3C, 0x66, 0x60, 0x66, 0x3C, 0x00],
    // 100 'd'
    [0x06, 0x06, 0x3E, 0x66, 0x66, 0x66, 0x3E, 0x00],
    // 101 'e'
    [0x00, 0x00, 0x3C, 0x66, 0x7E, 0x60, 0x3C, 0x00],
    // 102 'f'
    [0x1C, 0x30, 0x30, 0x7C, 0x30, 0x30, 0x30, 0x00],
    // 103 'g'
    [0x00, 0x00, 0x3E, 0x66, 0x66, 0x3E, 0x06, 0x3C],
    // 104 'h'
    [0x60, 0x60, 0x7C, 0x66, 0x66, 0x66, 0x66, 0x00],
    // 105 'i'
    [0x18, 0x00, 0x38, 0x18, 0x18, 0x18, 0x3C, 0x00],
    // 106 'j'
    [0x06, 0x00, 0x0E, 0x06, 0x06, 0x66, 0x3C, 0x00],
    // 107 'k'
    [0x60, 0x60, 0x66, 0x6C, 0x78, 0x6C, 0x66, 0x00],
    // 108 'l'
    [0x38, 0x18, 0x18, 0x18, 0x18, 0x18, 0x3C, 0x00],
    // 109 'm'
    [0x00, 0x00, 0xEC, 0xFE, 0xD6, 0xC6, 0xC6, 0x00],
    // 110 'n'
    [0x00, 0x00, 0x7C, 0x66, 0x66, 0x66, 0x66, 0x00],
    // 111 'o'
    [0x00, 0x00, 0x3C, 0x66, 0x66, 0x66, 0x3C, 0x00],
    // 112 'p'
    [0x00, 0x00, 0x7C, 0x66, 0x66, 0x7C, 0x60, 0x60],
    // 113 'q'
    [0x00, 0x00, 0x3E, 0x66, 0x66, 0x3E, 0x06, 0x06],
    // 114 'r'
    [0x00, 0x00, 0x7C, 0x66, 0x60, 0x60, 0x60, 0x00],
    // 115 's'
    [0x00, 0x00, 0x3E, 0x60, 0x3C, 0x06, 0x7C, 0x00],
    // 116 't'
    [0x30, 0x30, 0x7C, 0x30, 0x30, 0x30, 0x1C, 0x00],
    // 117 'u'
    [0x00, 0x00, 0x66, 0x66, 0x66, 0x66, 0x3E, 0x00],
    // 118 'v'
    [0x00, 0x00, 0x66, 0x66, 0x66, 0x3C, 0x18, 0x00],
    // 119 'w'
    [0x00, 0x00, 0xC6, 0xC6, 0xD6, 0xFE, 0x6C, 0x00],
    // 120 'x'
    [0x00, 0x00, 0x66, 0x3C, 0x18, 0x3C, 0x66, 0x00],
    // 121 'y'
    [0x00, 0x00, 0x66, 0x66, 0x66, 0x3E, 0x06, 0x3C],
    // 122 'z'
    [0x00, 0x00, 0x7E, 0x0C, 0x18, 0x30, 0x7E, 0x00],
    // 123 '{'
    [0x0E, 0x18, 0x18, 0x70, 0x18, 0x18, 0x0E, 0x00],
    // 124 '|'
    [0x18, 0x18, 0x18, 0x18, 0x18, 0x18, 0x18, 0x00],
    // 125 '}'
    [0x70, 0x18, 0x18, 0x0E, 0x18, 0x18, 0x70, 0x00],
    // 126 '~'
    [0x76, 0xDC, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
    // 127 DEL
    [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
];

/// Get the 8-byte glyph for an ASCII character.
/// Returns a zero glyph for control characters and values > 127.
fn font_glyph(c: u8) -> [u8; 8] {
    if c < 32 || c > 127 {
        return [0; 8];
    }
    FONT_8X8[(c - 32) as usize]
}

// ---------------------------------------------------------------------------
// Mouse cursor sprite (16x16, 1-bit with transparency)
// ---------------------------------------------------------------------------

/// 16x16 arrow cursor bitmap (1 = white, MSB-first; 0 = transparent).
/// A separate mask indicates which pixels are drawn.
const CURSOR_BITMAP: [u16; CURSOR_SIZE] = [
    0b1000_0000_0000_0000,
    0b1100_0000_0000_0000,
    0b1110_0000_0000_0000,
    0b1111_0000_0000_0000,
    0b1111_1000_0000_0000,
    0b1111_1100_0000_0000,
    0b1111_1110_0000_0000,
    0b1111_1111_0000_0000,
    0b1111_1111_1000_0000,
    0b1111_1100_0000_0000,
    0b1111_1100_0000_0000,
    0b1100_1100_0000_0000,
    0b1000_0110_0000_0000,
    0b0000_0110_0000_0000,
    0b0000_0011_0000_0000,
    0b0000_0011_0000_0000,
];

/// Cursor mask: outline in black for visibility.
const CURSOR_MASK: [u16; CURSOR_SIZE] = [
    0b1100_0000_0000_0000,
    0b1110_0000_0000_0000,
    0b1111_0000_0000_0000,
    0b1111_1000_0000_0000,
    0b1111_1100_0000_0000,
    0b1111_1110_0000_0000,
    0b1111_1111_0000_0000,
    0b1111_1111_1000_0000,
    0b1111_1111_1100_0000,
    0b1111_1111_1100_0000,
    0b1111_1110_0000_0000,
    0b1110_1111_0000_0000,
    0b1100_0111_0000_0000,
    0b0000_0111_1000_0000,
    0b0000_0011_1000_0000,
    0b0000_0011_1000_0000,
];

// ---------------------------------------------------------------------------
// Event system
// ---------------------------------------------------------------------------

/// GUI event types delivered to windows.
#[derive(Clone, Copy, Debug)]
pub enum GuiEvent {
    /// Mouse button pressed at (x, y) relative to window client area.
    MouseDown { x: i32, y: i32, button: u8 },
    /// Mouse button released.
    MouseUp { x: i32, y: i32, button: u8 },
    /// Mouse moved to (x, y) relative to window client area.
    MouseMove { x: i32, y: i32 },
    /// Key pressed (scancode).
    KeyDown { scancode: u8 },
    /// Key released.
    KeyUp { scancode: u8 },
    /// Window close requested (close button clicked).
    CloseRequest,
    /// Window gained focus.
    FocusIn,
    /// Window lost focus.
    FocusOut,
}

/// Event queue for a single window.
pub const MAX_EVENTS: usize = 32;

#[derive(Clone, Copy)]
struct EventQueue {
    events: [GuiEvent; MAX_EVENTS],
    head: usize,
    tail: usize,
    count: usize,
}

impl EventQueue {
    const fn new() -> Self {
        Self {
            events: [GuiEvent::FocusOut; MAX_EVENTS],
            head: 0,
            tail: 0,
            count: 0,
        }
    }

    fn push(&mut self, event: GuiEvent) -> bool {
        if self.count >= MAX_EVENTS {
            return false;
        }
        self.events[self.tail] = event;
        self.tail = (self.tail + 1) % MAX_EVENTS;
        self.count += 1;
        true
    }

    fn pop(&mut self) -> Option<GuiEvent> {
        if self.count == 0 {
            return None;
        }
        let event = self.events[self.head];
        self.head = (self.head + 1) % MAX_EVENTS;
        self.count -= 1;
        Some(event)
    }
}

// ---------------------------------------------------------------------------
// Window
// ---------------------------------------------------------------------------

/// A managed window in the compositor.
#[derive(Clone, Copy)]
pub struct Window {
    /// Unique window identifier.
    pub id: u32,
    /// Window position (top-left of title bar).
    pub x: i32,
    pub y: i32,
    /// Client area dimensions (excluding decorations).
    pub width: u32,
    pub height: u32,
    /// Z-order (higher = closer to front).
    pub z_order: u32,
    /// Whether the window is visible.
    pub visible: bool,
    /// Whether the window is minimized.
    pub minimized: bool,
    /// Title text (null-terminated).
    pub title: [u8; MAX_TITLE_LEN],
    pub title_len: usize,
    /// Pointer to the window's client area framebuffer.
    /// Each pixel is 4 bytes (BGRA). Size = width * height * 4.
    pub framebuffer: *mut u32,
    /// Whether this window has focus.
    pub focused: bool,
    /// Event queue.
    events: EventQueue,
}

impl Window {
    const fn empty() -> Self {
        Self {
            id: 0,
            x: 0,
            y: 0,
            width: 0,
            height: 0,
            z_order: 0,
            visible: false,
            minimized: false,
            title: [0; MAX_TITLE_LEN],
            title_len: 0,
            framebuffer: core::ptr::null_mut(),
            focused: false,
            events: EventQueue::new(),
        }
    }

    /// Total height including title bar.
    pub fn total_height(&self) -> u32 {
        self.height + TITLE_BAR_HEIGHT
    }

    /// Check if a screen-space point is inside this window (including title bar).
    pub fn contains(&self, sx: i32, sy: i32) -> bool {
        sx >= self.x
            && sx < self.x + self.width as i32
            && sy >= self.y
            && sy < self.y + self.total_height() as i32
    }

    /// Check if a screen-space point is in the title bar.
    pub fn in_title_bar(&self, sx: i32, sy: i32) -> bool {
        sx >= self.x
            && sx < self.x + self.width as i32
            && sy >= self.y
            && sy < self.y + TITLE_BAR_HEIGHT as i32
    }

    /// Check if a screen-space point is on the close button.
    pub fn in_close_button(&self, sx: i32, sy: i32) -> bool {
        let btn_x = self.x + self.width as i32 - CLOSE_BTN_WIDTH as i32;
        sx >= btn_x
            && sx < btn_x + CLOSE_BTN_WIDTH as i32
            && sy >= self.y
            && sy < self.y + TITLE_BAR_HEIGHT as i32
    }

    /// Check if a screen-space point is on the minimize button.
    pub fn in_minimize_button(&self, sx: i32, sy: i32) -> bool {
        let btn_x = self.x + self.width as i32 - CLOSE_BTN_WIDTH as i32 - MINIMIZE_BTN_WIDTH as i32;
        sx >= btn_x
            && sx < btn_x + MINIMIZE_BTN_WIDTH as i32
            && sy >= self.y
            && sy < self.y + TITLE_BAR_HEIGHT as i32
    }

    /// Push an event to this window's queue.
    pub fn push_event(&mut self, event: GuiEvent) -> bool {
        self.events.push(event)
    }

    /// Pop an event from this window's queue.
    pub fn pop_event(&mut self) -> Option<GuiEvent> {
        self.events.pop()
    }
}

// ---------------------------------------------------------------------------
// Window Manager / Compositor
// ---------------------------------------------------------------------------

/// The window manager and compositor.
///
/// Manages up to `MAX_WINDOWS` windows with z-ordering and focus tracking.
/// The compositor renders all visible windows to the screen framebuffer.
pub struct WindowManager {
    /// Window slots.
    pub windows: [Window; MAX_WINDOWS],
    /// Number of active windows.
    pub window_count: usize,
    /// Next window ID to assign.
    next_id: u32,
    /// Index of the currently focused window (or usize::MAX if none).
    pub focused_idx: usize,
    /// Screen framebuffer pointer.
    pub screen_fb: *mut u32,
    /// Screen width in pixels.
    pub screen_width: u32,
    /// Screen height in pixels.
    pub screen_height: u32,
    /// Screen stride in pixels (may differ from width due to padding).
    pub screen_stride: u32,
    /// Mouse cursor position.
    pub cursor_x: i32,
    pub cursor_y: i32,
    /// Whether cursor is visible.
    pub cursor_visible: bool,
    /// Index of the window being dragged (usize::MAX = none).
    pub drag_idx: usize,
    /// Cursor offset from the dragged window's top-left corner.
    pub drag_off_x: i32,
    pub drag_off_y: i32,
    /// Previous mouse button state (for edge detection).
    pub prev_buttons: u8,
    /// Whether the compositor needs to re-render.
    pub dirty: bool,
}

impl WindowManager {
    /// Create a new window manager.
    ///
    /// `fb` is the screen framebuffer (BGRA pixels), `w`/`h` are dimensions,
    /// `stride` is the row stride in pixels.
    pub fn new(fb: *mut u32, w: u32, h: u32, stride: u32) -> Self {
        Self {
            windows: [Window::empty(); MAX_WINDOWS],
            window_count: 0,
            next_id: 1,
            focused_idx: usize::MAX,
            screen_fb: fb,
            screen_width: w,
            screen_height: h,
            screen_stride: stride,
            cursor_x: (w / 2) as i32,
            cursor_y: (h / 2) as i32,
            cursor_visible: true,
            drag_idx: usize::MAX,
            drag_off_x: 0,
            drag_off_y: 0,
            prev_buttons: 0,
            dirty: true,
        }
    }

    /// Create a new window. Returns the window ID, or None if full.
    pub fn create_window(
        &mut self,
        x: i32,
        y: i32,
        width: u32,
        height: u32,
        title: &[u8],
        framebuffer: *mut u32,
    ) -> Option<u32> {
        if self.window_count >= MAX_WINDOWS {
            return None;
        }

        let id = self.next_id;
        self.next_id += 1;

        let idx = self.window_count;
        let w = &mut self.windows[idx];
        w.id = id;
        w.x = x;
        w.y = y;
        w.width = width;
        w.height = height;
        w.z_order = idx as u32;
        w.visible = true;
        w.minimized = false;
        w.framebuffer = framebuffer;
        w.focused = false;

        let copy_len = title.len().min(MAX_TITLE_LEN - 1);
        w.title[..copy_len].copy_from_slice(&title[..copy_len]);
        w.title_len = copy_len;

        self.window_count += 1;

        // Focus the new window.
        self.focus_window(idx);

        Some(id)
    }

    /// Destroy a window by ID.
    pub fn destroy_window(&mut self, id: u32) -> bool {
        let mut found = usize::MAX;
        for i in 0..self.window_count {
            if self.windows[i].id == id {
                found = i;
                break;
            }
        }
        if found == usize::MAX {
            return false;
        }

        // Shift remaining windows down.
        for i in found..self.window_count - 1 {
            self.windows[i] = self.windows[i + 1];
        }
        self.windows[self.window_count - 1] = Window::empty();
        self.window_count -= 1;

        // Fix focus.
        if self.focused_idx == found {
            self.focused_idx = usize::MAX;
            if self.window_count > 0 {
                self.focus_window(self.window_count - 1);
            }
        } else if self.focused_idx > found && self.focused_idx != usize::MAX {
            self.focused_idx -= 1;
        }

        true
    }

    /// Find window index by ID.
    pub fn find_window(&self, id: u32) -> Option<usize> {
        for i in 0..self.window_count {
            if self.windows[i].id == id {
                return Some(i);
            }
        }
        None
    }

    /// Set focus to a window by index.
    pub fn focus_window(&mut self, idx: usize) {
        if idx >= self.window_count {
            return;
        }

        // Unfocus old window.
        if self.focused_idx < self.window_count {
            self.windows[self.focused_idx].focused = false;
            self.windows[self.focused_idx].push_event(GuiEvent::FocusOut);
        }

        // Focus new window and bring to front.
        self.windows[idx].focused = true;
        self.windows[idx].push_event(GuiEvent::FocusIn);
        self.focused_idx = idx;

        // Update z-order: focused window gets highest z.
        let max_z = self.window_count as u32;
        self.windows[idx].z_order = max_z;
        // Push others down.
        for i in 0..self.window_count {
            if i != idx && self.windows[i].z_order >= max_z {
                self.windows[i].z_order = self.windows[i].z_order.saturating_sub(1);
            }
        }
    }

    /// Handle a mouse click at screen coordinates. Returns the window ID hit.
    pub fn handle_mouse_click(&mut self, sx: i32, sy: i32, button: u8) -> Option<u32> {
        // Find the topmost window that contains the click (highest z_order).
        let mut best_idx = usize::MAX;
        let mut best_z = 0u32;

        for i in 0..self.window_count {
            let w = &self.windows[i];
            if w.visible && !w.minimized && w.contains(sx, sy) {
                if best_idx == usize::MAX || w.z_order > best_z {
                    best_idx = i;
                    best_z = w.z_order;
                }
            }
        }

        if best_idx == usize::MAX {
            return None;
        }

        let win_id = self.windows[best_idx].id;

        // Focus this window.
        self.focus_window(best_idx);

        // Check if close button was clicked.
        if self.windows[best_idx].in_close_button(sx, sy) {
            self.windows[best_idx].push_event(GuiEvent::CloseRequest);
            return Some(win_id);
        }

        // Check if minimize button was clicked.
        if self.windows[best_idx].in_minimize_button(sx, sy) {
            self.windows[best_idx].minimized = true;
            return Some(win_id);
        }

        // Deliver mouse event relative to client area.
        let client_x = sx - self.windows[best_idx].x;
        let client_y = sy - self.windows[best_idx].y - TITLE_BAR_HEIGHT as i32;

        if client_y >= 0 {
            self.windows[best_idx].push_event(GuiEvent::MouseDown {
                x: client_x,
                y: client_y,
                button,
            });
        }

        Some(win_id)
    }

    /// Update mouse cursor position.
    pub fn move_cursor(&mut self, x: i32, y: i32) {
        self.cursor_x = x.max(0).min(self.screen_width as i32 - 1);
        self.cursor_y = y.max(0).min(self.screen_height as i32 - 1);
    }

    /// Process mouse input: cursor movement, drag start/stop, button presses.
    /// `dx`/`dy` are relative motion deltas, `buttons` is the button bitmask
    /// (bit 0 = left, bit 1 = right, bit 2 = middle).
    pub fn on_mouse_input(&mut self, dx: i32, dy: i32, buttons: u8) {
        // Update cursor position.
        self.cursor_x = (self.cursor_x + dx).max(0).min(self.screen_width as i32 - 1);
        self.cursor_y = (self.cursor_y + dy).max(0).min(self.screen_height as i32 - 1);

        let left_now = buttons & 1 != 0;
        let left_prev = self.prev_buttons & 1 != 0;

        if left_now && !left_prev {
            // Left button just pressed — find topmost window under cursor.
            let mut best_idx = usize::MAX;
            let mut best_z = 0u32;
            for i in 0..self.window_count {
                let w = &self.windows[i];
                if w.visible && !w.minimized && w.contains(self.cursor_x, self.cursor_y) {
                    if best_idx == usize::MAX || w.z_order > best_z {
                        best_idx = i;
                        best_z = w.z_order;
                    }
                }
            }

            if best_idx != usize::MAX {
                // Focus clicked window.
                self.focus_window(best_idx);

                // Check if in title bar → start drag.
                if self.windows[best_idx].in_title_bar(self.cursor_x, self.cursor_y)
                    && !self.windows[best_idx].in_close_button(self.cursor_x, self.cursor_y)
                    && !self.windows[best_idx].in_minimize_button(self.cursor_x, self.cursor_y)
                {
                    self.drag_idx = best_idx;
                    self.drag_off_x = self.cursor_x - self.windows[best_idx].x;
                    self.drag_off_y = self.cursor_y - self.windows[best_idx].y;
                }
            }
        } else if !left_now && left_prev {
            // Left button released — stop drag.
            self.drag_idx = usize::MAX;
        }

        // If dragging, update window position.
        if left_now && self.drag_idx != usize::MAX && self.drag_idx < self.window_count {
            self.windows[self.drag_idx].x = self.cursor_x - self.drag_off_x;
            self.windows[self.drag_idx].y = self.cursor_y - self.drag_off_y;
        }

        self.prev_buttons = buttons;
        self.dirty = true;
    }

    /// Composite all visible windows to the screen framebuffer (or back buffer).
    pub fn composite(&mut self) {
        if self.screen_fb.is_null() {
            return;
        }

        let fb = self.screen_fb;
        let st = self.screen_stride;
        let sw = self.screen_width;
        let sh = self.screen_height;

        // Desktop background: subtle vertical gradient (Tokyo Night).
        gradient_fill_fb(fb, st, 0, 0, sw, sh, 26, 27, 38, 20, 18, 32);

        // Build z-order sorted index list (ascending = back to front).
        let mut sorted: [usize; MAX_WINDOWS] = [0; MAX_WINDOWS];
        for i in 0..self.window_count {
            sorted[i] = i;
        }
        let n = self.window_count;
        if n > 1 {
            for i in 1..n {
                let mut j = i;
                while j > 0 && self.windows[sorted[j]].z_order < self.windows[sorted[j - 1]].z_order {
                    sorted.swap(j, j - 1);
                    j -= 1;
                }
            }
        }

        // Render windows back-to-front.
        for si in 0..n {
            let idx = sorted[si];
            let w = &self.windows[idx];
            if !w.visible || w.minimized { continue; }

            // Drop shadow (subtle, 4px offset, clamped to screen).
            let sx = (w.x + 4).max(0) as u32;
            let sy = (w.y + 4).max(0) as u32;
            let swidth = (w.width + 2).min(sw.saturating_sub(sx));
            let sheight = (w.total_height() + 2).min(sh.saturating_sub(sy));
            alpha_fill_rect_fb(fb, st, sx, sy, swidth, sheight,
                bgra(0, 0, 0, 255), 80);

            // Title bar gradient.
            let (tr1, tg1, tb1, tr2, tg2, tb2) = if w.focused {
                (55u8, 90, 170, 35, 65, 130)
            } else {
                (50, 50, 60, 40, 40, 50)
            };
            gradient_fill_fb(fb, st,
                w.x as u32, w.y as u32, w.width, TITLE_BAR_HEIGHT,
                tr1, tg1, tb1, tr2, tg2, tb2);

            // Title bar bottom accent (focused only).
            if w.focused {
                fill_rect_fb(fb, st, w.x as u32,
                    (w.y + TITLE_BAR_HEIGHT as i32 - 1) as u32,
                    w.width, 1, bgra(100, 160, 240, 255));
            }

            // Traffic-light buttons with highlight glint.
            let btn_cy = w.y + TITLE_BAR_HEIGHT as i32 / 2;
            let btn_colors: [u32; 3] = [
                bgra(237, 106, 94, 255),
                bgra(245, 191, 79, 255),
                bgra(98, 197, 84, 255),
            ];
            for (bi, &color) in btn_colors.iter().enumerate() {
                let cx = w.x + 16 + bi as i32 * 20;
                draw_filled_circle_fb(fb, st, sw, sh, cx, btn_cy, 5, color);
                draw_filled_circle_fb(fb, st, sw, sh, cx - 1, btn_cy - 1, 2,
                    bgra(255, 255, 255, 255));
            }

            // Title text centered after buttons.
            let text = &w.title[..w.title_len];
            let text_w = w.title_len as i32 * FONT_WIDTH as i32;
            let text_x = w.x + 76 + (w.width as i32 - 76 - text_w) / 2;
            draw_string_fb(fb, st, sw, sh,
                text_x, w.y + (TITLE_BAR_HEIGHT as i32 - FONT_HEIGHT as i32) / 2,
                text, bgra(210, 215, 230, 255));

            // Client area background + content blit.
            let client_y = w.y + TITLE_BAR_HEIGHT as i32;
            fill_rect_fb(fb, st, w.x as u32, client_y as u32, w.width, w.height,
                COLOR_WINDOW_BG);
            if !w.framebuffer.is_null() {
                blit_fb(fb, st, sw, sh, w.framebuffer, w.width,
                    w.x, client_y, w.width, w.height);
            }

            // Window border.
            let border_color = if w.focused {
                bgra(70, 100, 160, 255)
            } else {
                bgra(50, 50, 65, 255)
            };
            draw_rect_border(fb, st, sw, sh, w.x, w.y,
                w.width, w.total_height(), border_color);
        }

        // --- Taskbar (glass panel) ---
        let tb_h = 36u32;
        let tb_y = sh.saturating_sub(tb_h);
        alpha_fill_rect_fb(fb, st, 0, tb_y, sw, tb_h, bgra(15, 15, 25, 255), 210);
        fill_rect_fb(fb, st, 0, tb_y, sw, 1, bgra(80, 120, 200, 255));
        draw_string_fb(fb, st, sw, sh, 12, tb_y as i32 + 13,
            b"sotOS", bgra(130, 170, 255, 255));
        fill_rect_fb(fb, st, 60, tb_y + 6, 1, tb_h - 12, bgra(60, 60, 80, 255));

        // Window pills in taskbar.
        let mut pill_x = 72u32;
        for wi in 0..n {
            let w = &self.windows[wi];
            if !w.visible { continue; }
            let name = &w.title[..w.title_len.min(8)];
            let pill_w = (name.len() as u32 * FONT_WIDTH + 16).max(48);
            if w.focused {
                fill_rect_fb(fb, st, pill_x, tb_y + 6, pill_w, tb_h - 12,
                    bgra(45, 65, 110, 255));
                fill_rect_fb(fb, st, pill_x, tb_y + tb_h - 3, pill_w, 2,
                    bgra(115, 180, 255, 255));
            } else {
                fill_rect_fb(fb, st, pill_x, tb_y + 6, pill_w, tb_h - 12,
                    bgra(30, 30, 45, 255));
            }
            let tc = if w.focused { bgra(210, 220, 240, 255) }
                     else { bgra(120, 125, 150, 255) };
            draw_string_fb(fb, st, sw, sh, pill_x as i32 + 8, tb_y as i32 + 13, name, tc);
            pill_x += pill_w + 4;
        }

        // Mouse cursor on top.
        if self.cursor_visible {
            draw_cursor(fb, st, sw, sh, self.cursor_x, self.cursor_y);
        }

        self.dirty = false;
    }
}

// ---------------------------------------------------------------------------
// Drawing primitives (operate on a raw u32 framebuffer)
// ---------------------------------------------------------------------------

/// Fill a rectangle with a vertical gradient (top color → bottom color).
pub fn gradient_fill_fb(
    fb: *mut u32, stride: u32, x: u32, y: u32, w: u32, h: u32,
    r1: u8, g1: u8, b1: u8, r2: u8, g2: u8, b2: u8,
) {
    if w == 0 || h == 0 { return; }
    let hi = h as i32;
    for row in 0..h {
        let yi = row as i32;
        let r = (r1 as i32 + (r2 as i32 - r1 as i32) * yi / hi) as u8;
        let g = (g1 as i32 + (g2 as i32 - g1 as i32) * yi / hi) as u8;
        let b = (b1 as i32 + (b2 as i32 - b1 as i32) * yi / hi) as u8;
        let pixel = bgra(r, g, b, 255);
        let offset = ((y + row) * stride + x) as usize;
        unsafe {
            let row_ptr = fb.add(offset);
            for col in 0..w as usize {
                *row_ptr.add(col) = pixel;
            }
        }
    }
}

/// Fill a contiguous pixel buffer (stride = width) with a vertical gradient.
pub fn draw_gradient_into(
    buf: *mut u32, width: u32, height: u32,
    r1: u8, g1: u8, b1: u8, r2: u8, g2: u8, b2: u8,
) {
    gradient_fill_fb(buf, width, 0, 0, width, height, r1, g1, b1, r2, g2, b2);
}

/// Fill a rectangle with a solid color (scanline-optimized).
pub fn fill_rect_fb(fb: *mut u32, stride: u32, x: u32, y: u32, w: u32, h: u32, color: u32) {
    if w == 0 || h == 0 { return; }
    for row in 0..h {
        let offset = ((y + row) * stride + x) as usize;
        unsafe {
            let row_ptr = fb.add(offset);
            for col in 0..w as usize {
                *row_ptr.add(col) = color;
            }
        }
    }
}

/// Fill a rectangle with semi-transparent blending.
/// `alpha` is 0-255 (0 = fully transparent, 255 = fully opaque).
pub fn alpha_fill_rect_fb(fb: *mut u32, stride: u32, x: u32, y: u32, w: u32, h: u32, color: u32, alpha: u8) {
    if w == 0 || h == 0 || alpha == 0 { return; }
    let sr = ((color >> 16) & 0xFF) as u32;
    let sg = ((color >> 8) & 0xFF) as u32;
    let sb = (color & 0xFF) as u32;
    let a = alpha as u32;
    let inv_a = 255 - a;
    for row in 0..h {
        let offset = ((y + row) * stride + x) as usize;
        unsafe {
            let row_ptr = fb.add(offset);
            for col in 0..w as usize {
                let dst = *row_ptr.add(col);
                let dr = ((dst >> 16) & 0xFF) as u32;
                let dg = ((dst >> 8) & 0xFF) as u32;
                let db = (dst & 0xFF) as u32;
                let r = (sr * a + dr * inv_a) / 255;
                let g = (sg * a + dg * inv_a) / 255;
                let b = (sb * a + db * inv_a) / 255;
                *row_ptr.add(col) = 0xFF000000 | (r << 16) | (g << 8) | b;
            }
        }
    }
}

/// Draw a horizontal line.
pub fn draw_hline_fb(fb: *mut u32, stride: u32, x: i32, y: i32, len: u32, color: u32) {
    if y < 0 {
        return;
    }
    for i in 0..len {
        let px = x + i as i32;
        if px >= 0 {
            let offset = (y as u32 * stride + px as u32) as usize;
            unsafe {
                *fb.add(offset) = color;
            }
        }
    }
}

/// Draw a vertical line.
pub fn draw_vline_fb(fb: *mut u32, stride: u32, x: i32, y: i32, len: u32, color: u32) {
    if x < 0 {
        return;
    }
    for i in 0..len {
        let py = y + i as i32;
        if py >= 0 {
            let offset = (py as u32 * stride + x as u32) as usize;
            unsafe {
                *fb.add(offset) = color;
            }
        }
    }
}

/// Draw a line between two points (Bresenham's algorithm).
pub fn draw_line_fb(
    fb: *mut u32,
    stride: u32,
    screen_w: u32,
    screen_h: u32,
    x0: i32,
    y0: i32,
    x1: i32,
    y1: i32,
    color: u32,
) {
    let mut x = x0;
    let mut y = y0;
    let dx = (x1 - x0).abs();
    let dy = -(y1 - y0).abs();
    let sx = if x0 < x1 { 1 } else { -1 };
    let sy = if y0 < y1 { 1 } else { -1 };
    let mut err = dx + dy;

    loop {
        if x >= 0 && y >= 0 && (x as u32) < screen_w && (y as u32) < screen_h {
            let offset = (y as u32 * stride + x as u32) as usize;
            unsafe {
                *fb.add(offset) = color;
            }
        }
        if x == x1 && y == y1 {
            break;
        }
        let e2 = 2 * err;
        if e2 >= dy {
            err += dy;
            x += sx;
        }
        if e2 <= dx {
            err += dx;
            y += sy;
        }
    }
}

/// Draw a single character at (x, y) using the built-in 8x8 font.
pub fn draw_char_fb(
    fb: *mut u32,
    stride: u32,
    screen_w: u32,
    screen_h: u32,
    x: i32,
    y: i32,
    ch: u8,
    color: u32,
) {
    let glyph = font_glyph(ch);
    for row in 0..FONT_HEIGHT {
        let bits = glyph[row as usize];
        for col in 0..FONT_WIDTH {
            if bits & (0x80 >> col) != 0 {
                let px = x + col as i32;
                let py = y + row as i32;
                if px >= 0 && py >= 0 && (px as u32) < screen_w && (py as u32) < screen_h {
                    let offset = (py as u32 * stride + px as u32) as usize;
                    unsafe {
                        *fb.add(offset) = color;
                    }
                }
            }
        }
    }
}

/// Draw a string at (x, y).
pub fn draw_string_fb(
    fb: *mut u32,
    stride: u32,
    screen_w: u32,
    screen_h: u32,
    x: i32,
    y: i32,
    text: &[u8],
    color: u32,
) {
    for (i, &ch) in text.iter().enumerate() {
        draw_char_fb(fb, stride, screen_w, screen_h, x + (i as i32 * FONT_WIDTH as i32), y, ch, color);
    }
}

/// Draw a filled circle using the midpoint algorithm.
pub fn draw_filled_circle_fb(
    fb: *mut u32, stride: u32, screen_w: u32, screen_h: u32,
    cx: i32, cy: i32, radius: i32, color: u32,
) {
    for dy in -radius..=radius {
        let py = cy + dy;
        if py < 0 || py as u32 >= screen_h { continue; }
        // Half-width at this row: sqrt(r^2 - dy^2) using integer approximation.
        let dx_max = {
            let r2 = radius * radius;
            let d2 = dy * dy;
            if d2 > r2 { 0 } else {
                // Integer sqrt approximation.
                let mut x = radius;
                while x * x > r2 - d2 { x -= 1; }
                x
            }
        };
        for dx in -dx_max..=dx_max {
            let px = cx + dx;
            if px >= 0 && (px as u32) < screen_w {
                unsafe { *fb.add((py as u32 * stride + px as u32) as usize) = color; }
            }
        }
    }
}

/// Draw a rectangle border (1px).
fn draw_rect_border(
    fb: *mut u32,
    stride: u32,
    screen_w: u32,
    screen_h: u32,
    x: i32,
    y: i32,
    w: u32,
    h: u32,
    color: u32,
) {
    draw_hline_fb(fb, stride, x, y, w, color);
    draw_hline_fb(fb, stride, x, y + h as i32 - 1, w, color);
    draw_vline_fb(fb, stride, x, y, h, color);
    draw_vline_fb(fb, stride, x + w as i32 - 1, y, h, color);
    let _ = (screen_w, screen_h); // used for clipping in callers
}

/// Blit a source framebuffer onto the destination framebuffer (clipped once at entry).
pub fn blit_fb(
    dst: *mut u32,
    dst_stride: u32,
    dst_w: u32,
    dst_h: u32,
    src: *const u32,
    src_stride: u32,
    dst_x: i32,
    dst_y: i32,
    w: u32,
    h: u32,
) {
    // Clip source region to destination bounds once.
    let src_x0 = if dst_x < 0 { (-dst_x) as u32 } else { 0 };
    let src_y0 = if dst_y < 0 { (-dst_y) as u32 } else { 0 };
    let dx0 = (dst_x.max(0)) as u32;
    let dy0 = (dst_y.max(0)) as u32;
    let visible_w = w.saturating_sub(src_x0).min(dst_w.saturating_sub(dx0));
    let visible_h = h.saturating_sub(src_y0).min(dst_h.saturating_sub(dy0));
    if visible_w == 0 || visible_h == 0 { return; }

    for row in 0..visible_h {
        let sy = src_y0 + row;
        let dy = dy0 + row;
        let src_row = (sy * src_stride + src_x0) as usize;
        let dst_row = (dy * dst_stride + dx0) as usize;
        unsafe {
            let sp = src.add(src_row);
            let dp = dst.add(dst_row);
            for col in 0..visible_w as usize {
                let pixel = *sp.add(col);
                if pixel & 0xFF00_0000 != 0 {
                    *dp.add(col) = pixel;
                }
            }
        }
    }
}

/// Draw the mouse cursor at the given screen position.
fn draw_cursor(
    fb: *mut u32,
    stride: u32,
    screen_w: u32,
    screen_h: u32,
    cx: i32,
    cy: i32,
) {
    for row in 0..CURSOR_SIZE {
        for col in 0..CURSOR_SIZE {
            let px = cx + col as i32;
            let py = cy + row as i32;
            if px >= 0 && py >= 0 && (px as u32) < screen_w && (py as u32) < screen_h {
                let bit = 1u16 << (15 - col);
                let offset = (py as u32 * stride + px as u32) as usize;
                if CURSOR_BITMAP[row] & bit != 0 {
                    unsafe { *fb.add(offset) = COLOR_WHITE; }
                } else if CURSOR_MASK[row] & bit != 0 {
                    unsafe { *fb.add(offset) = COLOR_BLACK; }
                }
            }
        }
    }
}
