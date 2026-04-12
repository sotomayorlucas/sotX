//! Terminal grid state + vte `Perform` implementation.
//!
//! The grid is a fixed `ROWS x COLS` array of `Cell`s. vte drives `Performer`
//! (print/execute/csi_dispatch), which mutates the grid. `render()` walks the
//! grid and rasterizes each cell into the SHM pixel buffer with
//! embedded-graphics' `FONT_6X10`.

use core::cell::UnsafeCell;

use embedded_graphics::{
    mono_font::{ascii::FONT_6X10, MonoTextStyleBuilder},
    pixelcolor::Rgb888,
    prelude::*,
    primitives::{PrimitiveStyle, Rectangle},
    text::{Baseline, Text},
};

// ---------------------------------------------------------------------------
// Terminal dimensions
// ---------------------------------------------------------------------------

/// Number of text columns. 80 is the traditional terminal width.
pub const COLS: usize = 80;
/// Number of text rows. 24 is the traditional terminal height.
pub const ROWS: usize = 24;

/// Glyph advance in pixels -- `FONT_6X10` is 6 wide, 10 tall.
pub const CELL_W: u32 = 6;
pub const CELL_H: u32 = 10;

/// SHM pixel window dimensions.
///
/// The text area is `COLS * CELL_W = 480` wide and `ROWS * CELL_H = 240`
/// tall. We add a few extra rows of padding for the cursor and edge glyphs.
pub const WIN_W: u32 = COLS as u32 * CELL_W; // 480
pub const WIN_H: u32 = ROWS as u32 * CELL_H + 16; // 256
pub const BPP: u32 = 4;
pub const POOL_SIZE: u32 = WIN_W * WIN_H * BPP;

// ---------------------------------------------------------------------------
// Tokyo Night colour palette
// ---------------------------------------------------------------------------
//
// Values copied from `services/compositor/src/decorations.rs:68`.
pub const TN_BG: u32 = 0xFF_1A_1B_26;
pub const TN_FG: u32 = 0xFF_C0_CA_F5;
pub const TN_BLUE: u32 = 0xFF_7A_A2_F7;
pub const TN_CYAN: u32 = 0xFF_73_DA_CA;
pub const TN_GREEN: u32 = 0xFF_9E_CE_6A;
pub const TN_YELLOW: u32 = 0xFF_E0_AF_68;
pub const TN_RED: u32 = 0xFF_F7_76_8E;
pub const TN_MAGENTA: u32 = 0xFF_BB_9A_F7;
pub const TN_WHITE: u32 = 0xFF_C0_CA_F5;
pub const TN_BLACK: u32 = 0xFF_1A_1B_26;

// ---------------------------------------------------------------------------
// Grid cell
// ---------------------------------------------------------------------------

#[derive(Copy, Clone)]
pub struct Cell {
    pub ch: u8,
    pub fg: u32,
    pub bg: u32,
}

impl Cell {
    pub const BLANK: Self = Self {
        ch: b' ',
        fg: TN_FG,
        bg: TN_BG,
    };
}

// ---------------------------------------------------------------------------
// Shared terminal state
// ---------------------------------------------------------------------------

pub struct Terminal {
    pub grid: [[Cell; COLS]; ROWS],
    pub cur_col: usize,
    pub cur_row: usize,
    pub fg: u32,
    pub bg: u32,
    pub dirty: bool,
    /// Saved cursor position for ESC 7 / ESC 8 (DECSC/DECRC).
    saved_col: usize,
    saved_row: usize,
}

impl Terminal {
    pub const fn new() -> Self {
        Self {
            grid: [[Cell::BLANK; COLS]; ROWS],
            cur_col: 0,
            cur_row: 0,
            fg: TN_FG,
            bg: TN_BG,
            dirty: true,
            saved_col: 0,
            saved_row: 0,
        }
    }

    /// Put one printable byte into the grid at the cursor.
    pub fn put(&mut self, ch: u8) {
        if self.cur_row >= ROWS {
            self.cur_row = ROWS - 1;
            self.scroll_up();
        }
        if self.cur_col >= COLS {
            self.cur_col = 0;
            self.cur_row += 1;
            if self.cur_row >= ROWS {
                self.cur_row = ROWS - 1;
                self.scroll_up();
            }
        }
        self.grid[self.cur_row][self.cur_col] = Cell {
            ch,
            fg: self.fg,
            bg: self.bg,
        };
        self.cur_col += 1;
        self.dirty = true;
    }

    /// Advance to the next line (\n).
    pub fn newline(&mut self) {
        self.cur_col = 0;
        self.cur_row += 1;
        if self.cur_row >= ROWS {
            self.cur_row = ROWS - 1;
            self.scroll_up();
        }
        self.dirty = true;
    }

    /// Carriage return (\r): jump to column 0.
    pub fn cr(&mut self) {
        self.cur_col = 0;
        self.dirty = true;
    }

    /// Backspace: move cursor left one cell, if possible.
    pub fn backspace(&mut self) {
        if self.cur_col > 0 {
            self.cur_col -= 1;
            self.grid[self.cur_row][self.cur_col] = Cell::BLANK;
            self.dirty = true;
        }
    }

    /// Scroll the grid up by one row, evicting the top row and blanking the
    /// bottom row.
    pub fn scroll_up(&mut self) {
        for r in 0..(ROWS - 1) {
            self.grid[r] = self.grid[r + 1];
        }
        for c in 0..COLS {
            self.grid[ROWS - 1][c] = Cell::BLANK;
        }
        self.dirty = true;
    }

    /// Erase in display -- action 'J'.
    pub fn erase_display(&mut self, mode: u32) {
        match mode {
            0 => {
                // Erase from cursor to end of screen.
                for c in self.cur_col..COLS {
                    self.grid[self.cur_row][c] = Cell::BLANK;
                }
                for r in (self.cur_row + 1)..ROWS {
                    for c in 0..COLS {
                        self.grid[r][c] = Cell::BLANK;
                    }
                }
            }
            1 => {
                // Erase from start of screen to cursor.
                for r in 0..self.cur_row {
                    for c in 0..COLS {
                        self.grid[r][c] = Cell::BLANK;
                    }
                }
                for c in 0..=self.cur_col.min(COLS - 1) {
                    self.grid[self.cur_row][c] = Cell::BLANK;
                }
            }
            _ => {
                // 2 or 3: erase entire screen.
                for r in 0..ROWS {
                    for c in 0..COLS {
                        self.grid[r][c] = Cell::BLANK;
                    }
                }
            }
        }
        self.dirty = true;
    }

    /// Erase in line -- action 'K'.
    pub fn erase_line(&mut self, mode: u32) {
        if self.cur_row >= ROWS {
            return;
        }
        match mode {
            0 => {
                // Erase from cursor to end of line.
                for c in self.cur_col..COLS {
                    self.grid[self.cur_row][c] = Cell::BLANK;
                }
            }
            1 => {
                // Erase from start of line to cursor.
                for c in 0..=self.cur_col.min(COLS - 1) {
                    self.grid[self.cur_row][c] = Cell::BLANK;
                }
            }
            _ => {
                // 2: erase entire line.
                for c in 0..COLS {
                    self.grid[self.cur_row][c] = Cell::BLANK;
                }
            }
        }
        self.dirty = true;
    }

    /// Apply an SGR parameter. Supports: reset (0), bold (1), reverse (7),
    /// standard fg (30..37), standard bg (40..47), bright fg (90..97),
    /// bright bg (100..107).
    pub fn sgr(&mut self, param: u32) {
        match param {
            0 => {
                self.fg = TN_FG;
                self.bg = TN_BG;
            }
            1 => {
                // Bold -- brighten the current fg (approximate with white).
                self.fg = TN_WHITE;
            }
            7 => {
                // Reverse video -- swap fg and bg.
                let tmp = self.fg;
                self.fg = self.bg;
                self.bg = tmp;
            }
            27 => {
                // Reverse off -- restore defaults if reversed.
                self.fg = TN_FG;
                self.bg = TN_BG;
            }
            30 => self.fg = TN_BLACK,
            31 => self.fg = TN_RED,
            32 => self.fg = TN_GREEN,
            33 => self.fg = TN_YELLOW,
            34 => self.fg = TN_BLUE,
            35 => self.fg = TN_MAGENTA,
            36 => self.fg = TN_CYAN,
            37 => self.fg = TN_WHITE,
            39 => self.fg = TN_FG, // default fg
            40 => self.bg = TN_BLACK,
            41 => self.bg = TN_RED,
            42 => self.bg = TN_GREEN,
            43 => self.bg = TN_YELLOW,
            44 => self.bg = TN_BLUE,
            45 => self.bg = TN_MAGENTA,
            46 => self.bg = TN_CYAN,
            47 => self.bg = TN_WHITE,
            49 => self.bg = TN_BG, // default bg
            90..=97 => {
                self.fg = match param {
                    90 => 0xFF_41_48_68, // TN comment (dark gray)
                    91 => TN_RED,
                    92 => TN_GREEN,
                    93 => TN_YELLOW,
                    94 => TN_BLUE,
                    95 => TN_MAGENTA,
                    96 => TN_CYAN,
                    _ => TN_WHITE,
                };
            }
            100..=107 => {
                self.bg = match param {
                    100 => 0xFF_41_48_68, // bright black bg
                    101 => TN_RED,
                    102 => TN_GREEN,
                    103 => TN_YELLOW,
                    104 => TN_BLUE,
                    105 => TN_MAGENTA,
                    106 => TN_CYAN,
                    _ => TN_WHITE,
                };
            }
            _ => {}
        }
    }

    /// Save cursor position (DECSC / ESC 7).
    pub fn save_cursor(&mut self) {
        self.saved_col = self.cur_col;
        self.saved_row = self.cur_row;
    }

    /// Restore cursor position (DECRC / ESC 8).
    pub fn restore_cursor(&mut self) {
        self.cur_col = self.saved_col;
        self.cur_row = self.saved_row;
        self.dirty = true;
    }
}

// ---------------------------------------------------------------------------
// Shared mutable singleton
// ---------------------------------------------------------------------------

/// `no_std` single-threaded container for the terminal. sotos-term runs
/// single-threaded, so interior mutability through a raw `UnsafeCell` is
/// safe without a mutex.
pub struct StaticTerminal(UnsafeCell<Terminal>);

unsafe impl Sync for StaticTerminal {}

impl StaticTerminal {
    pub const fn new() -> Self {
        Self(UnsafeCell::new(Terminal::new()))
    }

    #[allow(clippy::mut_from_ref)]
    pub fn get(&self) -> &mut Terminal {
        unsafe { &mut *self.0.get() }
    }
}

pub static TERM: StaticTerminal = StaticTerminal::new();

// ---------------------------------------------------------------------------
// vte::Perform bridge
// ---------------------------------------------------------------------------

pub struct Performer;

impl vte::Perform for Performer {
    fn print(&mut self, c: char) {
        let byte = if (c as u32) <= 0x7E { c as u8 } else { b'?' };
        TERM.get().put(byte);
    }

    fn execute(&mut self, byte: u8) {
        let t = TERM.get();
        match byte {
            b'\n' => t.newline(),
            b'\r' => t.cr(),
            0x08 => t.backspace(),
            b'\t' => {
                let next = (t.cur_col + 8) & !7;
                if next < COLS {
                    t.cur_col = next;
                } else {
                    t.cur_col = COLS - 1;
                }
                t.dirty = true;
            }
            0x07 => {} // BEL -- ignore
            _ => {}
        }
    }

    fn esc_dispatch(&mut self, _intermediates: &[u8], _ignore: bool, byte: u8) {
        let t = TERM.get();
        match byte {
            b'7' => t.save_cursor(),
            b'8' => t.restore_cursor(),
            _ => {}
        }
    }

    fn csi_dispatch(
        &mut self,
        params: &vte::Params,
        intermediates: &[u8],
        _ignore: bool,
        action: char,
    ) {
        let t = TERM.get();
        let mut iter = params.iter();
        let p0 = iter.next().map(|s| s[0] as u32).unwrap_or(0);
        let p1 = iter.next().map(|s| s[0] as u32).unwrap_or(0);

        match action as u8 {
            b'A' => {
                // CUU -- cursor up.
                let n = p0.max(1) as usize;
                t.cur_row = t.cur_row.saturating_sub(n);
                t.dirty = true;
            }
            b'B' => {
                // CUD -- cursor down.
                let n = p0.max(1) as usize;
                t.cur_row = (t.cur_row + n).min(ROWS - 1);
                t.dirty = true;
            }
            b'C' => {
                // CUF -- cursor forward.
                let n = p0.max(1) as usize;
                t.cur_col = (t.cur_col + n).min(COLS - 1);
                t.dirty = true;
            }
            b'D' => {
                // CUB -- cursor backward.
                let n = p0.max(1) as usize;
                t.cur_col = t.cur_col.saturating_sub(n);
                t.dirty = true;
            }
            b'G' => {
                // CHA -- cursor horizontal absolute.
                let col = p0.max(1) as usize;
                t.cur_col = (col - 1).min(COLS - 1);
                t.dirty = true;
            }
            b'H' | b'f' => {
                // CUP -- cursor position.
                let row = p0.max(1) as usize;
                let col = p1.max(1) as usize;
                t.cur_row = (row - 1).min(ROWS - 1);
                t.cur_col = (col - 1).min(COLS - 1);
                t.dirty = true;
            }
            b'J' => t.erase_display(p0),
            b'K' => t.erase_line(p0),
            b'd' => {
                // VPA -- vertical position absolute.
                let row = p0.max(1) as usize;
                t.cur_row = (row - 1).min(ROWS - 1);
                t.dirty = true;
            }
            b'm' => {
                // SGR: iterate all parameters and apply each.
                t.sgr(p0);
                for sub in params.iter().skip(1) {
                    t.sgr(sub[0] as u32);
                }
            }
            b'h' | b'l' => {
                // DEC private modes -- currently just acknowledge them
                // to prevent warnings. DECTCEM (cursor show/hide) and
                // DECAWM (auto-wrap) are the main ones.
                let _ = intermediates; // '?' prefix for private modes
            }
            b's' => t.save_cursor(),
            b'u' => t.restore_cursor(),
            b'r' => {
                // DECSTBM -- set scrolling region. We ignore the region
                // and just reset the cursor to home.
                t.cur_row = 0;
                t.cur_col = 0;
                t.dirty = true;
            }
            _ => {}
        }
    }
}

// ---------------------------------------------------------------------------
// Rendering adapter -- draws the grid into the SHM pool
// ---------------------------------------------------------------------------

pub struct ShmTarget {
    pub base: *mut u32,
    pub stride_pixels: u32,
    pub width: u32,
    pub height: u32,
}

impl ShmTarget {
    fn bgra_to_rgb(c: u32) -> Rgb888 {
        Rgb888::new(
            ((c >> 16) & 0xFF) as u8,
            ((c >> 8) & 0xFF) as u8,
            (c & 0xFF) as u8,
        )
    }
}

impl OriginDimensions for ShmTarget {
    fn size(&self) -> Size {
        Size::new(self.width, self.height)
    }
}

impl DrawTarget for ShmTarget {
    type Color = Rgb888;
    type Error = core::convert::Infallible;

    fn draw_iter<I>(&mut self, pixels: I) -> Result<(), Self::Error>
    where
        I: IntoIterator<Item = Pixel<Rgb888>>,
    {
        let w = self.width as i32;
        let h = self.height as i32;
        let stride = self.stride_pixels as i32;
        for Pixel(p, color) in pixels {
            if p.x < 0 || p.y < 0 || p.x >= w || p.y >= h {
                continue;
            }
            let packed = 0xFF00_0000
                | ((color.r() as u32) << 16)
                | ((color.g() as u32) << 8)
                | (color.b() as u32);
            unsafe {
                self.base
                    .offset((p.y * stride + p.x) as isize)
                    .write_volatile(packed);
            }
        }
        Ok(())
    }
}

/// Clear the SHM pool to the terminal background color.
pub fn clear_shm(base: *mut u32) {
    for y in 0..WIN_H {
        for x in 0..WIN_W {
            let off = (y * WIN_W + x) as isize;
            unsafe {
                base.offset(off).write_volatile(TN_BG);
            }
        }
    }
}

/// Render the full terminal grid into the SHM pool. Not incremental -- on a
/// 80x24 grid this is ~2K glyphs which is plenty fast for our needs.
pub fn render(target_base: *mut u32) {
    let t = TERM.get();

    // Fill background first so previously-drawn foreground pixels are
    // overwritten even when the grid shrinks after a clear.
    clear_shm(target_base);

    let mut target = ShmTarget {
        base: target_base,
        stride_pixels: WIN_W,
        width: WIN_W,
        height: WIN_H,
    };

    // Row-major: paint backgrounds first so SGR bg changes are visible.
    for r in 0..ROWS {
        for c in 0..COLS {
            let cell = t.grid[r][c];
            if cell.bg != TN_BG {
                let x = (c as u32 * CELL_W) as i32;
                let y = (r as u32 * CELL_H) as i32;
                let rect = Rectangle::new(
                    Point::new(x, y),
                    Size::new(CELL_W, CELL_H),
                );
                let style =
                    PrimitiveStyle::with_fill(ShmTarget::bgra_to_rgb(cell.bg));
                let _ = rect.into_styled(style).draw(&mut target);
            }
        }
    }

    // Glyph pass -- one FONT_6X10 character per cell.
    for r in 0..ROWS {
        for c in 0..COLS {
            let cell = t.grid[r][c];
            if cell.ch == b' ' {
                continue;
            }
            let ch = [cell.ch];
            let s = core::str::from_utf8(&ch).unwrap_or(" ");
            let style = MonoTextStyleBuilder::new()
                .font(&FONT_6X10)
                .text_color(ShmTarget::bgra_to_rgb(cell.fg))
                .build();
            let x = (c as u32 * CELL_W) as i32;
            let y = (r as u32 * CELL_H) as i32;
            let _ = Text::with_baseline(
                s,
                Point::new(x, y),
                style,
                Baseline::Top,
            )
            .draw(&mut target);
        }
    }

    // Cursor block -- solid TN_BLUE rectangle at (cur_row, cur_col).
    if t.cur_row < ROWS && t.cur_col < COLS {
        let x = (t.cur_col as u32 * CELL_W) as i32;
        let y = (t.cur_row as u32 * CELL_H) as i32;
        let rect = Rectangle::new(Point::new(x, y), Size::new(CELL_W, CELL_H));
        let style = PrimitiveStyle::with_fill(ShmTarget::bgra_to_rgb(TN_BLUE));
        let _ = rect.into_styled(style).draw(&mut target);

        // Re-draw the glyph on top in bg color so it's legible.
        let cell = t.grid[t.cur_row][t.cur_col];
        if cell.ch != b' ' {
            let ch = [cell.ch];
            let s = core::str::from_utf8(&ch).unwrap_or(" ");
            let style = MonoTextStyleBuilder::new()
                .font(&FONT_6X10)
                .text_color(ShmTarget::bgra_to_rgb(TN_BG))
                .build();
            let _ = Text::with_baseline(
                s,
                Point::new(x, y),
                style,
                Baseline::Top,
            )
            .draw(&mut target);
        }
    }

    t.dirty = false;
}
