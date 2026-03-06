//! sotOS GUI — Window compositor and drawing primitives.
//!
//! Provides a minimal window management system for the sotOS framebuffer:
//! - Window creation, destruction, z-ordering, and focus management
//! - Compositor: renders windows to framebuffer with overlap handling
//! - Window decorations: title bar, close button, minimize button
//! - Mouse cursor rendering (16x16 sprite)
//! - Event system: mouse click hit-testing and event delivery
//! - Basic drawing primitives: fill_rect, draw_line, draw_char, blit
//!
//! All rendering operates on raw pixel buffers (32-bit BGRA format).
//! No heap allocation — all state is fixed-size arrays.

#![no_std]

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

/// Get the 8-byte glyph for an ASCII character.
/// Returns a zero glyph for unsupported characters.
fn font_glyph(c: u8) -> [u8; 8] {
    if c < 32 || c > 127 {
        return [0; 8];
    }
    // Minimal built-in glyphs for a few essential characters.
    // For a real system this would be a full 96-glyph table.
    match c {
        b' ' => [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
        b'A' => [0x18, 0x24, 0x42, 0x42, 0x7E, 0x42, 0x42, 0x00],
        b'B' => [0x7C, 0x42, 0x42, 0x7C, 0x42, 0x42, 0x7C, 0x00],
        b'C' => [0x3C, 0x42, 0x40, 0x40, 0x40, 0x42, 0x3C, 0x00],
        b'D' => [0x78, 0x44, 0x42, 0x42, 0x42, 0x44, 0x78, 0x00],
        b'E' => [0x7E, 0x40, 0x40, 0x7C, 0x40, 0x40, 0x7E, 0x00],
        b'F' => [0x7E, 0x40, 0x40, 0x7C, 0x40, 0x40, 0x40, 0x00],
        b'H' => [0x42, 0x42, 0x42, 0x7E, 0x42, 0x42, 0x42, 0x00],
        b'I' => [0x3E, 0x08, 0x08, 0x08, 0x08, 0x08, 0x3E, 0x00],
        b'L' => [0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x7E, 0x00],
        b'M' => [0x42, 0x66, 0x5A, 0x42, 0x42, 0x42, 0x42, 0x00],
        b'N' => [0x42, 0x62, 0x52, 0x4A, 0x46, 0x42, 0x42, 0x00],
        b'O' => [0x3C, 0x42, 0x42, 0x42, 0x42, 0x42, 0x3C, 0x00],
        b'S' => [0x3C, 0x42, 0x40, 0x3C, 0x02, 0x42, 0x3C, 0x00],
        b'T' => [0x7F, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x00],
        b'W' => [0x42, 0x42, 0x42, 0x42, 0x5A, 0x66, 0x42, 0x00],
        b'X' => [0x42, 0x24, 0x18, 0x18, 0x24, 0x42, 0x42, 0x00],
        b'a' => [0x00, 0x00, 0x3C, 0x02, 0x3E, 0x42, 0x3E, 0x00],
        b'b' => [0x40, 0x40, 0x5C, 0x62, 0x42, 0x42, 0x7C, 0x00],
        b'c' => [0x00, 0x00, 0x3C, 0x42, 0x40, 0x42, 0x3C, 0x00],
        b'd' => [0x02, 0x02, 0x3A, 0x46, 0x42, 0x42, 0x3E, 0x00],
        b'e' => [0x00, 0x00, 0x3C, 0x42, 0x7E, 0x40, 0x3C, 0x00],
        b'h' => [0x40, 0x40, 0x5C, 0x62, 0x42, 0x42, 0x42, 0x00],
        b'i' => [0x08, 0x00, 0x18, 0x08, 0x08, 0x08, 0x1C, 0x00],
        b'l' => [0x18, 0x08, 0x08, 0x08, 0x08, 0x08, 0x1C, 0x00],
        b'n' => [0x00, 0x00, 0x5C, 0x62, 0x42, 0x42, 0x42, 0x00],
        b'o' => [0x00, 0x00, 0x3C, 0x42, 0x42, 0x42, 0x3C, 0x00],
        b'r' => [0x00, 0x00, 0x5C, 0x62, 0x40, 0x40, 0x40, 0x00],
        b's' => [0x00, 0x00, 0x3E, 0x40, 0x3C, 0x02, 0x7C, 0x00],
        b't' => [0x08, 0x08, 0x3E, 0x08, 0x08, 0x0A, 0x04, 0x00],
        b'0' => [0x3C, 0x42, 0x46, 0x4A, 0x52, 0x62, 0x3C, 0x00],
        b'1' => [0x08, 0x18, 0x08, 0x08, 0x08, 0x08, 0x3E, 0x00],
        b'2' => [0x3C, 0x42, 0x02, 0x0C, 0x30, 0x40, 0x7E, 0x00],
        b'3' => [0x3C, 0x42, 0x02, 0x1C, 0x02, 0x42, 0x3C, 0x00],
        b'-' => [0x00, 0x00, 0x00, 0x7E, 0x00, 0x00, 0x00, 0x00],
        b'.' => [0x00, 0x00, 0x00, 0x00, 0x00, 0x18, 0x18, 0x00],
        b':' => [0x00, 0x18, 0x18, 0x00, 0x18, 0x18, 0x00, 0x00],
        b'/' => [0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x00, 0x00],
        b'x' | b'X' => [0x00, 0x00, 0x42, 0x24, 0x18, 0x24, 0x42, 0x00],
        _ => {
            // Fallback glyph (box) for characters without a defined bitmap.
            [0x00, 0x7E, 0x42, 0x42, 0x42, 0x7E, 0x00, 0x00]
        }
    }
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

    /// Composite all visible windows to the screen framebuffer.
    pub fn composite(&mut self) {
        if self.screen_fb.is_null() {
            return;
        }

        // Fill desktop background.
        fill_rect_fb(
            self.screen_fb,
            self.screen_stride,
            0,
            0,
            self.screen_width,
            self.screen_height,
            COLOR_DESKTOP,
        );

        // Build z-order sorted index list (ascending = back to front).
        let mut sorted: [usize; MAX_WINDOWS] = [0; MAX_WINDOWS];
        for i in 0..self.window_count {
            sorted[i] = i;
        }
        // Simple insertion sort by z_order.
        for i in 1..self.window_count {
            let mut j = i;
            while j > 0 && self.windows[sorted[j]].z_order < self.windows[sorted[j - 1]].z_order {
                sorted.swap(j, j - 1);
                j -= 1;
            }
        }

        // Render windows back-to-front.
        for si in 0..self.window_count {
            let idx = sorted[si];
            let w = &self.windows[idx];
            if !w.visible || w.minimized {
                continue;
            }

            // Draw title bar.
            let title_color = if w.focused {
                COLOR_TITLE_ACTIVE
            } else {
                COLOR_TITLE_INACTIVE
            };
            fill_rect_fb(
                self.screen_fb,
                self.screen_stride,
                w.x as u32,
                w.y as u32,
                w.width,
                TITLE_BAR_HEIGHT,
                title_color,
            );

            // Draw title text.
            let text = &w.title[..w.title_len];
            draw_string_fb(
                self.screen_fb,
                self.screen_stride,
                self.screen_width,
                self.screen_height,
                w.x + 4,
                w.y + 4,
                text,
                COLOR_WHITE,
            );

            // Draw close button [X].
            let close_x = w.x + w.width as i32 - CLOSE_BTN_WIDTH as i32;
            fill_rect_fb(
                self.screen_fb,
                self.screen_stride,
                close_x as u32,
                w.y as u32,
                CLOSE_BTN_WIDTH,
                TITLE_BAR_HEIGHT,
                COLOR_RED,
            );
            draw_char_fb(
                self.screen_fb,
                self.screen_stride,
                self.screen_width,
                self.screen_height,
                close_x + 8,
                w.y + 8,
                b'X',
                COLOR_WHITE,
            );

            // Draw minimize button [-].
            let min_x = close_x - MINIMIZE_BTN_WIDTH as i32;
            fill_rect_fb(
                self.screen_fb,
                self.screen_stride,
                min_x as u32,
                w.y as u32,
                MINIMIZE_BTN_WIDTH,
                TITLE_BAR_HEIGHT,
                COLOR_YELLOW,
            );
            draw_char_fb(
                self.screen_fb,
                self.screen_stride,
                self.screen_width,
                self.screen_height,
                min_x + 8,
                w.y + 8,
                b'-',
                COLOR_BLACK,
            );

            // Draw client area background.
            let client_y = w.y + TITLE_BAR_HEIGHT as i32;
            fill_rect_fb(
                self.screen_fb,
                self.screen_stride,
                w.x as u32,
                client_y as u32,
                w.width,
                w.height,
                COLOR_WINDOW_BG,
            );

            // Blit window framebuffer content into client area.
            if !w.framebuffer.is_null() {
                blit_fb(
                    self.screen_fb,
                    self.screen_stride,
                    self.screen_width,
                    self.screen_height,
                    w.framebuffer,
                    w.width,
                    w.x,
                    client_y,
                    w.width,
                    w.height,
                );
            }

            // Draw window border.
            draw_rect_border(
                self.screen_fb,
                self.screen_stride,
                self.screen_width,
                self.screen_height,
                w.x,
                w.y,
                w.width,
                w.total_height(),
                COLOR_DARK_GRAY,
            );
        }

        // Draw mouse cursor on top.
        if self.cursor_visible {
            draw_cursor(
                self.screen_fb,
                self.screen_stride,
                self.screen_width,
                self.screen_height,
                self.cursor_x,
                self.cursor_y,
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Drawing primitives (operate on a raw u32 framebuffer)
// ---------------------------------------------------------------------------

/// Fill a rectangle with a solid color.
pub fn fill_rect_fb(fb: *mut u32, stride: u32, x: u32, y: u32, w: u32, h: u32, color: u32) {
    for row in 0..h {
        for col in 0..w {
            let px = x + col;
            let py = y + row;
            let offset = (py * stride + px) as usize;
            unsafe {
                *fb.add(offset) = color;
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

/// Blit a source framebuffer onto the destination framebuffer.
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
    for row in 0..h {
        for col in 0..w {
            let px = dst_x + col as i32;
            let py = dst_y + row as i32;
            if px >= 0 && py >= 0 && (px as u32) < dst_w && (py as u32) < dst_h {
                let src_offset = (row * src_stride + col) as usize;
                let dst_offset = (py as u32 * dst_stride + px as u32) as usize;
                unsafe {
                    let pixel = *src.add(src_offset);
                    // Simple alpha check: if alpha is non-zero, draw it.
                    if pixel & 0xFF00_0000 != 0 {
                        *dst.add(dst_offset) = pixel;
                    }
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
