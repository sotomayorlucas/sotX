//! Compositor wallpaper / desktop background.
//!
//! Supports loading a BMP wallpaper from the initrd at boot. If the BMP
//! load fails (missing file, bad format, etc.), falls back to a vertical
//! Tokyo Night gradient computed at init time.
//!
//! Wallpaper selection: reads `SOTOS_WALLPAPER` env var if available,
//! defaults to `tokyo-night`. The initrd path is
//! `/usr/share/sotos/wallpapers/<name>.bmp` (packed as
//! `usr/share/sotos/wallpapers/<name>.bmp` in the CPIO archive).

use crate::render::Framebuffer;
use sotos_common::SyncUnsafeCell;

/// Tokyo Night background top color (BGRA: 26, 27, 38).
pub const BG_TOP: u32 = 0xFF1A1B26;

/// Tokyo Night background bottom color (BGRA: 16, 16, 28).
pub const BG_BOT: u32 = 0xFF10101C;

/// Maximum supported framebuffer height (4K headroom).
pub const MAX_GRADIENT_HEIGHT: usize = 2160;

/// 1024 * 768 = 786432 pixels. Static buffer for a decoded BMP wallpaper.
const IMG_W: usize = 1024;
const IMG_H: usize = 768;
const IMG_PIXELS: usize = IMG_W * IMG_H;

/// Static pixel cache for the decoded BMP image (BGRA u32).
static IMAGE_CACHE: SyncUnsafeCell<[u32; IMG_PIXELS]> =
    SyncUnsafeCell::new([0u32; IMG_PIXELS]);

/// Whether `IMAGE_CACHE` holds a valid decoded image.
static IMAGE_VALID: SyncUnsafeCell<bool> = SyncUnsafeCell::new(false);

/// Raw BMP file buffer. Max ~2.4 MiB for 1024x768x24bpp + header.
/// This is only used during init; after decoding we only read IMAGE_CACHE.
const BMP_BUF_SIZE: usize = 1024 * 768 * 3 + 256; // pixel data + header room
static BMP_BUF: SyncUnsafeCell<[u8; BMP_BUF_SIZE]> =
    SyncUnsafeCell::new([0u8; BMP_BUF_SIZE]);

/// Wallpaper state: gradient cache + image flag.
pub struct Wallpaper {
    /// One BGRA color per row (gradient fallback).
    gradient_cache: [u32; MAX_GRADIENT_HEIGHT],
    /// Number of valid rows in `gradient_cache`.
    gradient_height: usize,
    /// If true, use IMAGE_CACHE instead of gradient.
    has_image: bool,
}

impl Wallpaper {
    pub const fn empty() -> Self {
        Self {
            gradient_cache: [0u32; MAX_GRADIENT_HEIGHT],
            gradient_height: 0,
            has_image: false,
        }
    }
}

/// Global wallpaper instance.
static WALLPAPER: SyncUnsafeCell<Wallpaper> = SyncUnsafeCell::new(Wallpaper::empty());

/// Extract the (a, r, g, b) channels from a BGRA u32.
/// Layout: bits 24..31 = A, 16..23 = R, 8..15 = G, 0..7 = B.
#[inline]
fn channels(c: u32) -> (u32, u32, u32, u32) {
    (
        (c >> 24) & 0xFF,
        (c >> 16) & 0xFF,
        (c >> 8) & 0xFF,
        c & 0xFF,
    )
}

/// Pack (a, r, g, b) channels into a BGRA u32.
#[inline]
fn pack(a: u32, r: u32, g: u32, b: u32) -> u32 {
    ((a & 0xFF) << 24) | ((r & 0xFF) << 16) | ((g & 0xFF) << 8) | (b & 0xFF)
}

/// Linearly blend `top` and `bot` channel-wise. `num/den` is the
/// fractional position from top (0/den = top, den/den = bot).
#[inline]
fn blend(top: u32, bot: u32, num: u32, den: u32) -> u32 {
    let (_, tr, tg, tb) = channels(top);
    let (_, br, bg, bb) = channels(bot);
    let inv = den - num;
    let r = (tr * inv + br * num) / den;
    let g = (tg * inv + bg * num) / den;
    let b = (tb * inv + bb * num) / den;
    pack(0xFF, r, g, b)
}

/// Read a little-endian u16 from a byte slice at `off`.
#[inline]
fn read_u16(buf: &[u8], off: usize) -> u16 {
    if off + 2 > buf.len() {
        return 0;
    }
    (buf[off] as u16) | ((buf[off + 1] as u16) << 8)
}

/// Read a little-endian u32 from a byte slice at `off`.
#[inline]
fn read_u32(buf: &[u8], off: usize) -> u32 {
    if off + 4 > buf.len() {
        return 0;
    }
    (buf[off] as u32)
        | ((buf[off + 1] as u32) << 8)
        | ((buf[off + 2] as u32) << 16)
        | ((buf[off + 3] as u32) << 24)
}

/// Read a little-endian i32 from a byte slice at `off`.
#[inline]
fn read_i32(buf: &[u8], off: usize) -> i32 {
    read_u32(buf, off) as i32
}

/// Try to parse an uncompressed 24-bit BMP from `raw` into `IMAGE_CACHE`.
/// Returns true on success.
fn parse_bmp(raw: &[u8], file_size: usize) -> bool {
    if file_size < 54 {
        return false;
    }
    // Check BMP magic
    if raw[0] != b'B' || raw[1] != b'M' {
        return false;
    }

    let data_offset = read_u32(raw, 10) as usize;
    let _dib_size = read_u32(raw, 14);
    let width = read_i32(raw, 18);
    let height = read_i32(raw, 22);
    let bpp = read_u16(raw, 28);
    let compression = read_u32(raw, 30);

    // Only support uncompressed 24-bit BMPs
    if compression != 0 || bpp != 24 {
        return false;
    }
    if width <= 0 || width > IMG_W as i32 {
        return false;
    }

    // height > 0 means bottom-up; height < 0 means top-down
    let bottom_up = height > 0;
    let abs_h = if bottom_up { height } else { -height };
    if abs_h <= 0 || abs_h > IMG_H as i32 {
        return false;
    }

    let w = width as usize;
    let h = abs_h as usize;

    // Row stride in the BMP file: each row is padded to 4-byte boundary
    let row_bytes = (w * 3 + 3) & !3;

    let needed = data_offset + row_bytes * h;
    if needed > file_size {
        return false;
    }

    let cache = unsafe { &mut *IMAGE_CACHE.get() };

    // Decode pixels. BMP stores BGR, we want ARGB (0xFFRRGGBB in our BGRA layout).
    for src_y in 0..h {
        // Map source row to destination row
        let dst_y = if bottom_up { h - 1 - src_y } else { src_y };
        let row_off = data_offset + src_y * row_bytes;

        for x in 0..w {
            let pix_off = row_off + x * 3;
            if pix_off + 3 > file_size {
                return false;
            }
            let b_val = raw[pix_off] as u32;
            let g_val = raw[pix_off + 1] as u32;
            let r_val = raw[pix_off + 2] as u32;
            let dst_idx = dst_y * IMG_W + x;
            cache[dst_idx] = 0xFF000000 | (r_val << 16) | (g_val << 8) | b_val;
        }

        // Fill remaining columns with black if image is narrower than IMG_W
        for x in w..IMG_W {
            let dst_idx = dst_y * IMG_W + x;
            cache[dst_idx] = 0xFF000000;
        }
    }

    // Fill remaining rows with black if image is shorter than IMG_H
    for y in h..IMG_H {
        for x in 0..IMG_W {
            cache[y * IMG_W + x] = 0xFF000000;
        }
    }

    true
}

/// Try to load a BMP wallpaper from the initrd.
/// `name` is the wallpaper name (e.g. "tokyo-night").
/// Returns true if the wallpaper was successfully loaded.
fn try_load_bmp(name: &[u8]) -> bool {
    // Build the initrd path: "usr/share/sotos/wallpapers/<name>.bmp"
    // (CPIO entries don't have a leading slash)
    const PREFIX: &[u8] = b"usr/share/sotos/wallpapers/";
    const SUFFIX: &[u8] = b".bmp";
    const MAX_PATH: usize = 128;

    let total_len = PREFIX.len() + name.len() + SUFFIX.len();
    if total_len >= MAX_PATH {
        return false;
    }

    let mut path_buf = [0u8; MAX_PATH];
    let mut pos = 0;
    let mut i = 0;
    while i < PREFIX.len() {
        path_buf[pos] = PREFIX[i];
        pos += 1;
        i += 1;
    }
    i = 0;
    while i < name.len() {
        path_buf[pos] = name[i];
        pos += 1;
        i += 1;
    }
    i = 0;
    while i < SUFFIX.len() {
        path_buf[pos] = SUFFIX[i];
        pos += 1;
        i += 1;
    }
    let path = &path_buf[..pos];

    // Read the BMP file from the initrd into our static buffer
    let buf = unsafe { &mut *BMP_BUF.get() };
    let file_size = match sotos_common::sys::initrd_read(
        path.as_ptr() as u64,
        path.len() as u64,
        buf.as_ptr() as u64,
        BMP_BUF_SIZE as u64,
    ) {
        Ok(sz) => sz as usize,
        Err(_) => return false,
    };

    if file_size == 0 {
        return false;
    }

    parse_bmp(buf, file_size)
}

/// Get the wallpaper name from the environment or use the default.
/// Returns a static byte slice with the name.
fn wallpaper_name() -> &'static [u8] {
    // For now, default to "tokyo-night". A future integration with
    // env var reading can override this.
    b"tokyo-night"
}

/// Initialize the wallpaper: try to load a BMP from the initrd, fall
/// back to the gradient if that fails.
pub fn init(height: usize) {
    let h = height.min(MAX_GRADIENT_HEIGHT);
    let wp = unsafe { &mut *WALLPAPER.get() };
    wp.gradient_height = h;
    wp.has_image = false;

    // Always compute the gradient as a fallback
    if h == 0 {
        return;
    }
    if h == 1 {
        wp.gradient_cache[0] = BG_TOP;
    } else {
        let den = (h - 1) as u32;
        for i in 0..h {
            wp.gradient_cache[i] = blend(BG_TOP, BG_BOT, i as u32, den);
        }
    }

    // Try to load a BMP wallpaper
    let name = wallpaper_name();
    if try_load_bmp(name) {
        unsafe { *IMAGE_VALID.get() = true };
        wp.has_image = true;
        debug_print(b"wallpaper: loaded BMP from initrd\n");
    } else {
        debug_print(b"wallpaper: BMP not found, using gradient fallback\n");
    }
}

/// Print a debug message to serial via the kernel debug_print syscall.
fn debug_print(msg: &[u8]) {
    for &b in msg {
        sotos_common::sys::debug_print(b);
    }
}

/// Draw the wallpaper to the framebuffer over the rect (x, y, w, h).
/// Compatible with the damage-rectangle workflow: only the requested
/// region is drawn.
pub fn draw(fb: &mut Framebuffer, x: i32, y: i32, w: i32, h: i32) {
    if fb.addr == 0 || w <= 0 || h <= 0 {
        return;
    }
    let wp = unsafe { &*WALLPAPER.get() };
    let has_image = wp.has_image && unsafe { *IMAGE_VALID.get() };
    let cache_h = wp.gradient_height;

    let fb_w = fb.width as i32;
    let fb_h = fb.height as i32;
    let x0 = x.max(0);
    let y0 = y.max(0);
    let x1 = (x + w).min(fb_w);
    let y1 = (y + h).min(fb_h);
    if x0 >= x1 || y0 >= y1 {
        return;
    }

    let pixels_per_row = (fb.pitch / 4) as usize;
    let fb_base = fb.addr as *mut u32;
    let iw = IMG_W as i32;
    let ih = IMG_H as i32;

    // Center the BMP image on the framebuffer. Anything outside that
    // region gets the Tokyo Night gradient so resolutions larger than
    // 1024x768 (Pavilion defaults to 1366x768 / 1920x1080) don't leave
    // naked black strips showing the kernel clear color underneath.
    let img_x = (fb_w - iw) / 2;
    let img_y = (fb_h - ih) / 2;

    let image_cache = if has_image {
        Some(unsafe { &*IMAGE_CACHE.get() })
    } else {
        None
    };

    for py in y0..y1 {
        let dst_row = unsafe { fb_base.add((py as usize) * pixels_per_row) };

        // Which image row (if any) maps to this framebuffer row.
        let in_img_y = image_cache.is_some()
            && py >= img_y
            && py < img_y + ih;
        let img_src_row = if in_img_y {
            Some(((py - img_y) as usize) * IMG_W)
        } else {
            None
        };

        // Gradient color for this row — same for the whole horizontal span.
        let grad_color = if cache_h > 0 {
            wp.gradient_cache[(py as usize).min(cache_h - 1)]
        } else {
            BG_BOT
        };

        for px in x0..x1 {
            let pixel = if let Some(src_row) = img_src_row {
                if px >= img_x && px < img_x + iw {
                    // Inside image: blit from cache.
                    image_cache.unwrap()[src_row + (px - img_x) as usize]
                } else {
                    grad_color
                }
            } else {
                grad_color
            };
            unsafe {
                dst_row.add(px as usize).write_volatile(pixel);
            }
        }
    }
}
