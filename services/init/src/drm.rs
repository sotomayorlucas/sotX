// ---------------------------------------------------------------------------
// drm.rs -- Minimal DRM/KMS device emulation for /dev/dri/card0.
//
// Provides the ioctls Weston needs to discover a single CRTC+connector with
// the current framebuffer mode and to create/map/flip dumb buffers through
// the pixman software renderer path.
//
// FD kind = 30 for DRM device file descriptors.
// ---------------------------------------------------------------------------

use sotos_common::sys;
use sotos_common::{BootInfo, BOOT_INFO_ADDR, SyncUnsafeCell};
use crate::framebuffer::{print, print_u64, print_hex64};
use crate::syscalls::context::SyscallContext;

// ---------------------------------------------------------------------------
// DRM ioctl command numbers (nr field, bits 0-7 of the encoded ioctl)
// ---------------------------------------------------------------------------
const DRM_IOCTL_VERSION: u8       = 0x00;
const DRM_IOCTL_GET_CAP: u8       = 0x0C;
const DRM_IOCTL_SET_MASTER: u8    = 0x1E;
const DRM_IOCTL_DROP_MASTER: u8   = 0x1F;
const DRM_IOCTL_MODE_GETRESOURCES: u8 = 0xA0;
const DRM_IOCTL_MODE_GETCRTC: u8      = 0xA1;
const DRM_IOCTL_MODE_SETCRTC: u8      = 0xA2;
const DRM_IOCTL_MODE_GETENCODER: u8   = 0xA6;
const DRM_IOCTL_MODE_GETCONNECTOR: u8 = 0xA7;
const DRM_IOCTL_MODE_ADDFB: u8        = 0xAE;
const DRM_IOCTL_MODE_RMFB: u8         = 0xAF;
const DRM_IOCTL_MODE_PAGE_FLIP: u8    = 0xB0;
const DRM_IOCTL_MODE_CREATE_DUMB: u8  = 0xB2;
const DRM_IOCTL_MODE_MAP_DUMB: u8     = 0xB3;
const DRM_IOCTL_MODE_DESTROY_DUMB: u8 = 0xB4;
const DRM_IOCTL_MODE_ADDFB2: u8       = 0xB8;
const DRM_IOCTL_SET_CLIENT_CAP: u8    = 0x0D;
const DRM_IOCTL_MODE_CURSOR: u8       = 0xA3;
const DRM_IOCTL_MODE_CURSOR2: u8      = 0xBB;
const DRM_IOCTL_MODE_GETPROPERTY: u8  = 0xAA;
const DRM_IOCTL_MODE_GETPLANERESOURCES: u8 = 0xB5;
const DRM_IOCTL_MODE_GETPLANE: u8     = 0xB6;
const DRM_IOCTL_MODE_OBJ_GETPROPERTIES: u8 = 0xB9;
const DRM_IOCTL_GEM_CLOSE: u8        = 0x09;
const DRM_IOCTL_MODE_GETFB: u8       = 0xAD;

/// DRM ioctl type byte ('d' = 0x64).
const DRM_IOCTL_TYPE: u8 = 0x64;

/// DRM capability IDs.
const DRM_CAP_DUMB_BUFFER: u64         = 0x01;
const DRM_CAP_PRIME: u64               = 0x05;
const DRM_CAP_TIMESTAMP_MONOTONIC: u64 = 0x06;
const DRM_CAP_CURSOR_WIDTH: u64        = 0x08;
const DRM_CAP_CURSOR_HEIGHT: u64       = 0x09;
const DRM_CAP_ADDFB2_MODIFIERS: u64    = 0x10;
const DRM_CAP_CRTC_IN_VBLANK_EVENT: u64 = 0x12;

/// DRM client capability IDs.
const DRM_CLIENT_CAP_UNIVERSAL_PLANES: u64 = 2;
const DRM_CLIENT_CAP_ATOMIC: u64           = 3;

/// DRM object type IDs.
const DRM_MODE_OBJECT_CRTC: u32      = 0xcccccccc;
const DRM_MODE_OBJECT_CONNECTOR: u32 = 0xc0c0c0c0;
const DRM_MODE_OBJECT_PLANE: u32     = 0xeeeeeeee;

/// Plane/property IDs (stable synthetic values).
const PLANE_ID_PRIMARY: u32 = 100;
const PROP_ID_TYPE: u32      = 1;
const PROP_ID_CRTC_ID: u32   = 2;
const PROP_ID_FB_ID: u32     = 3;
const PROP_ID_ACTIVE: u32    = 10;
const PROP_ID_MODE_ID: u32   = 11;
const PROP_ID_DPMS: u32      = 20;
const PROP_ID_CONN_CRTC: u32 = 21;

/// FD kind value for DRM device files (used by openat/ioctl/mmap dispatch).
#[allow(dead_code)]
pub(crate) const FD_KIND_DRM: u8 = 30;

/// Framebuffer base in init's address space.
const FB_USER_BASE: u64 = 0x4000000;

// ---------------------------------------------------------------------------
// Dumb buffer + framebuffer object state
// ---------------------------------------------------------------------------

const MAX_DRM_DUMB: usize = 8;
const MAX_DUMB_FRAMES: usize = 768; // 1024*768*4 / 4096 = 768 frames for full-resolution FB

#[allow(dead_code)]
struct DrmDumbBuffer {
    active: bool,
    handle: u32,
    width: u32,
    height: u32,
    bpp: u32,
    pitch: u32,
    size: u64,
    /// Physical frame capability IDs backing this buffer.
    frames: [u64; MAX_DUMB_FRAMES],
    frame_count: usize,
    /// Fake mmap offset returned by MAP_DUMB.
    mmap_offset: u64,
    /// Virtual address where the buffer was mapped into the child (0 = not yet).
    mmap_vaddr: u64,
}

impl DrmDumbBuffer {
    const fn zeroed() -> Self {
        Self {
            active: false,
            handle: 0,
            width: 0,
            height: 0,
            bpp: 0,
            pitch: 0,
            size: 0,
            frames: [0u64; MAX_DUMB_FRAMES],
            frame_count: 0,
            mmap_offset: 0,
            mmap_vaddr: 0,
        }
    }
}

const MAX_DRM_FB: usize = 4;

#[allow(dead_code)]
struct DrmFbObject {
    active: bool,
    fb_id: u32,
    dumb_handle: u32,
    width: u32,
    height: u32,
}

impl DrmFbObject {
    const fn zeroed() -> Self {
        Self { active: false, fb_id: 0, dumb_handle: 0, width: 0, height: 0 }
    }
}

// Global DRM state (single virtual GPU, single init process).
static DRM_DUMBS: SyncUnsafeCell<[DrmDumbBuffer; MAX_DRM_DUMB]> =
    SyncUnsafeCell::new([const { DrmDumbBuffer::zeroed() }; MAX_DRM_DUMB]);
static DRM_FBS: SyncUnsafeCell<[DrmFbObject; MAX_DRM_FB]> =
    SyncUnsafeCell::new([const { DrmFbObject::zeroed() }; MAX_DRM_FB]);
static DRM_NEXT_HANDLE: SyncUnsafeCell<u32> = SyncUnsafeCell::new(1);
static DRM_NEXT_FB_ID: SyncUnsafeCell<u32>  = SyncUnsafeCell::new(1);

// Page flip event delivery state.
// When PAGE_FLIP is called with DRM_MODE_PAGE_FLIP_EVENT flag, we queue
// a drm_event_vblank response for the next read() on the DRM fd.
static DRM_FLIP_PENDING: SyncUnsafeCell<bool> = SyncUnsafeCell::new(false);
static DRM_FLIP_USER_DATA: SyncUnsafeCell<u64> = SyncUnsafeCell::new(0);
static DRM_FLIP_SEQUENCE: SyncUnsafeCell<u32> = SyncUnsafeCell::new(0);

// Currently active FB on the CRTC (updated by SETCRTC and PAGE_FLIP).
static DRM_CRTC_FB_ID: SyncUnsafeCell<u32> = SyncUnsafeCell::new(0);

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Read framebuffer info from BootInfo.
fn fb_info() -> (u32, u32, u32, u32) {
    let bi = unsafe { &*(BOOT_INFO_ADDR as *const BootInfo) };
    (bi.fb_width, bi.fb_height, bi.fb_pitch, bi.fb_bpp)
}

/// Align `v` up to the next multiple of `align` (must be power-of-two).
fn align_up(v: u32, align: u32) -> u32 {
    (v + align - 1) & !(align - 1)
}

/// Find the dumb buffer slot index backing a given fb_id.
/// Returns None if fb_id is not found or has no matching dumb buffer.
fn find_dumb_for_fb(fb_id: u32) -> Option<usize> {
    let fbs = unsafe { &*DRM_FBS.get() };
    let dumbs = unsafe { &*DRM_DUMBS.get() };
    for fb in fbs.iter() {
        if fb.active && fb.fb_id == fb_id {
            for (i, d) in dumbs.iter().enumerate() {
                if d.active && d.handle == fb.dumb_handle {
                    return Some(i);
                }
            }
            return None;
        }
    }
    None
}

/// Fill a 68-byte drm_mode_modeinfo struct for the current framebuffer mode.
fn fill_current_mode(buf: &mut [u8; 68]) {
    let (w, h, _pitch, _bpp) = fb_info();
    *buf = [0u8; 68];

    // clock: pixel clock in kHz. 60 Hz => w*h*60/1000 (rough estimate).
    let clock = (w as u32).wrapping_mul(h as u32).wrapping_mul(60) / 1000;
    buf[0..4].copy_from_slice(&clock.to_le_bytes());

    // hdisplay, hsync_start, hsync_end, htotal (u16 each)
    let hw = w as u16;
    buf[4..6].copy_from_slice(&hw.to_le_bytes());
    buf[6..8].copy_from_slice(&(hw + 24).to_le_bytes());   // hsync_start
    buf[8..10].copy_from_slice(&(hw + 80).to_le_bytes());   // hsync_end
    buf[10..12].copy_from_slice(&(hw + 160).to_le_bytes()); // htotal
    // hskew = 0 (bytes 12..14 already zeroed)

    // vdisplay, vsync_start, vsync_end, vtotal, vscan (u16 each)
    let vh = h as u16;
    buf[14..16].copy_from_slice(&vh.to_le_bytes());
    buf[16..18].copy_from_slice(&(vh + 3).to_le_bytes());   // vsync_start
    buf[18..20].copy_from_slice(&(vh + 6).to_le_bytes());   // vsync_end
    buf[20..22].copy_from_slice(&(vh + 25).to_le_bytes());  // vtotal
    // vscan = 0 (bytes 22..24 already zeroed)

    // vrefresh (u32)
    let vrefresh: u32 = 60;
    buf[24..28].copy_from_slice(&vrefresh.to_le_bytes());

    // flags (u32) = DRM_MODE_FLAG_NHSYNC | DRM_MODE_FLAG_NVSYNC
    let flags: u32 = 0x02 | 0x08;
    buf[28..32].copy_from_slice(&flags.to_le_bytes());

    // type (u32) = DRM_MODE_TYPE_PREFERRED | DRM_MODE_TYPE_DRIVER
    let mtype: u32 = 0x08 | 0x40;
    buf[32..36].copy_from_slice(&mtype.to_le_bytes());

    // name: e.g. "1024x768" (32 bytes, NUL-padded)
    let mut name = [0u8; 32];
    let mut pos = 0usize;
    let mut tmp = [0u8; 10];
    let mut n = 0;
    let mut v = w;
    if v == 0 { tmp[0] = b'0'; n = 1; }
    else { while v > 0 { tmp[n] = b'0' + (v % 10) as u8; n += 1; v /= 10; } }
    for j in (0..n).rev() { if pos < 31 { name[pos] = tmp[j]; pos += 1; } }
    if pos < 31 { name[pos] = b'x'; pos += 1; }
    n = 0;
    v = h;
    if v == 0 { tmp[0] = b'0'; n = 1; }
    else { while v > 0 { tmp[n] = b'0' + (v % 10) as u8; n += 1; v /= 10; } }
    for j in (0..n).rev() { if pos < 31 { name[pos] = tmp[j]; pos += 1; } }
    buf[36..68].copy_from_slice(&name);
}

/// Write a NUL-terminated string to guest memory at `ptr`, up to `max` bytes.
/// Returns the number of bytes actually written (excluding NUL).
fn guest_write_str(ctx: &SyscallContext, ptr: u64, max: usize, s: &[u8]) -> usize {
    if ptr == 0 || max == 0 { return 0; }
    let n = s.len().min(max);
    ctx.guest_write(ptr, &s[..n]);
    // NUL terminator (if room)
    if n < max {
        ctx.guest_write(ptr + n as u64, &[0u8]);
    }
    n
}

/// Blit a dumb buffer to the real framebuffer.
/// The dumb buffer frames are mapped into the child's address space; we read
/// through guest_read which handles both same-AS and separate-AS cases.
fn blit_dumb_to_fb(ctx: &SyscallContext, dumb: &DrmDumbBuffer) {
    if dumb.mmap_vaddr == 0 { return; }
    let (fb_w, fb_h, fb_pitch, _) = fb_info();
    let copy_h = (dumb.height).min(fb_h) as usize;
    let copy_row_bytes = ((dumb.width).min(fb_w) as usize) * 4; // 32 bpp
    // 8192 bytes supports up to 2048 pixels wide at 32bpp.
    let mut row_buf = [0u8; 8192];
    for y in 0..copy_h {
        let src = dumb.mmap_vaddr + (y as u64) * (dumb.pitch as u64);
        let dst = FB_USER_BASE + (y as u64) * (fb_pitch as u64);
        let n = copy_row_bytes.min(row_buf.len());
        ctx.guest_read(src, &mut row_buf[..n]);
        // Write to real framebuffer (always in init's AS)
        unsafe {
            core::ptr::copy_nonoverlapping(row_buf.as_ptr(), dst as *mut u8, n);
        }
    }
}

// ---------------------------------------------------------------------------
// Main DRM ioctl dispatcher
// ---------------------------------------------------------------------------

/// Handle a DRM ioctl on an fd with kind=30.
/// `cmd` is the raw ioctl number from SYS_IOCTL regs[1].
/// `arg` is the user-space pointer to the ioctl argument struct (regs[2]).
/// Returns: 0 on success, negative errno on error.
pub(crate) fn drm_ioctl(ctx: &mut SyscallContext, cmd: u64, arg: u64) -> i64 {
    // Extract nr (bits 0..7) and type (bits 8..15).
    let nr = (cmd & 0xFF) as u8;
    let ioc_type = ((cmd >> 8) & 0xFF) as u8;

    if ioc_type != DRM_IOCTL_TYPE {
        // Not a DRM ioctl -- return -ENOTTY
        return -25; // ENOTTY
    }

    print(b"DRM-IOCTL nr=0x");
    print_hex64(nr as u64);
    print(b" arg=0x");
    print_hex64(arg);
    print(b"\n");

    match nr {
        DRM_IOCTL_VERSION       => ioctl_version(ctx, arg),
        DRM_IOCTL_GET_CAP       => ioctl_get_cap(ctx, arg),
        DRM_IOCTL_SET_CLIENT_CAP => ioctl_set_client_cap(ctx, arg),
        DRM_IOCTL_SET_MASTER    => 0,
        DRM_IOCTL_DROP_MASTER   => 0,
        DRM_IOCTL_MODE_GETRESOURCES => ioctl_get_resources(ctx, arg),
        DRM_IOCTL_MODE_GETCRTC      => ioctl_get_crtc(ctx, arg),
        DRM_IOCTL_MODE_SETCRTC      => ioctl_set_crtc(ctx, arg),
        DRM_IOCTL_MODE_CURSOR | DRM_IOCTL_MODE_CURSOR2 => 0, // cursor: stub success
        DRM_IOCTL_MODE_GETENCODER   => ioctl_get_encoder(ctx, arg),
        DRM_IOCTL_MODE_GETCONNECTOR => ioctl_get_connector(ctx, arg),
        DRM_IOCTL_MODE_GETPROPERTY  => ioctl_get_property(ctx, arg),
        DRM_IOCTL_MODE_ADDFB        => ioctl_add_fb(ctx, arg),
        DRM_IOCTL_MODE_ADDFB2       => ioctl_add_fb2(ctx, arg),
        DRM_IOCTL_MODE_RMFB         => ioctl_rm_fb(ctx, arg),
        DRM_IOCTL_MODE_PAGE_FLIP    => ioctl_page_flip(ctx, arg),
        DRM_IOCTL_MODE_CREATE_DUMB  => ioctl_create_dumb(ctx, arg),
        DRM_IOCTL_MODE_MAP_DUMB     => ioctl_map_dumb(ctx, arg),
        DRM_IOCTL_MODE_DESTROY_DUMB => ioctl_destroy_dumb(ctx, arg),
        DRM_IOCTL_MODE_GETPLANERESOURCES => ioctl_get_plane_resources(ctx, arg),
        DRM_IOCTL_MODE_GETPLANE     => ioctl_get_plane(ctx, arg),
        DRM_IOCTL_MODE_OBJ_GETPROPERTIES => ioctl_obj_get_properties(ctx, arg),
        DRM_IOCTL_GEM_CLOSE         => 0, // gem close: no-op for dumb buffers
        DRM_IOCTL_MODE_GETFB        => ioctl_get_fb(ctx, arg),
        _ => {
            print(b"DRM-IOCTL unknown nr=0x");
            print_hex64(nr as u64);
            print(b"\n");
            0 // return success for unknown ioctls (stub)
        }
    }
}

// ---------------------------------------------------------------------------
// Individual ioctl handlers
// ---------------------------------------------------------------------------

/// DRM_IOCTL_VERSION (0x00)
///
/// struct drm_version {
///     int version_major;       // 0
///     int version_minor;       // 4
///     int version_patchlevel;  // 8
///     __u32 pad;               // 12 (alignment)
///     size_t name_len;         // 16
///     char *name;              // 24
///     size_t date_len;         // 32
///     char *date;              // 40
///     size_t desc_len;         // 48
///     char *desc;              // 56
/// };
/// Total: 64 bytes on x86_64 (with natural alignment padding).
fn ioctl_version(ctx: &mut SyscallContext, arg: u64) -> i64 {
    let mut buf = [0u8; 64];
    ctx.guest_read(arg, &mut buf);

    // version_major = 1
    buf[0..4].copy_from_slice(&1i32.to_le_bytes());
    // version_minor = 0
    buf[4..8].copy_from_slice(&0i32.to_le_bytes());
    // version_patchlevel = 0
    buf[8..12].copy_from_slice(&0i32.to_le_bytes());

    // name_len at offset 16 (size_t = u64)
    let name_len = u64::from_le_bytes(buf[16..24].try_into().unwrap()) as usize;
    let name_ptr = u64::from_le_bytes(buf[24..32].try_into().unwrap());
    let drv_name = b"sotX-drm";
    if name_ptr != 0 && name_len > 0 {
        guest_write_str(ctx, name_ptr, name_len, drv_name);
    }
    buf[16..24].copy_from_slice(&(drv_name.len() as u64).to_le_bytes());

    // date_len at offset 32
    let date_len = u64::from_le_bytes(buf[32..40].try_into().unwrap()) as usize;
    let date_ptr = u64::from_le_bytes(buf[40..48].try_into().unwrap());
    let drv_date = b"20260318";
    if date_ptr != 0 && date_len > 0 {
        guest_write_str(ctx, date_ptr, date_len, drv_date);
    }
    buf[32..40].copy_from_slice(&(drv_date.len() as u64).to_le_bytes());

    // desc_len at offset 48
    let desc_len = u64::from_le_bytes(buf[48..56].try_into().unwrap()) as usize;
    let desc_ptr = u64::from_le_bytes(buf[56..64].try_into().unwrap());
    let drv_desc = b"sotX virtual DRM";
    if desc_ptr != 0 && desc_len > 0 {
        guest_write_str(ctx, desc_ptr, desc_len, drv_desc);
    }
    buf[48..56].copy_from_slice(&(drv_desc.len() as u64).to_le_bytes());

    ctx.guest_write(arg, &buf);
    0
}

/// DRM_IOCTL_GET_CAP (0x0C)
///
/// struct drm_get_cap {
///     __u64 capability;  // 0
///     __u64 value;       // 8
/// };
fn ioctl_get_cap(ctx: &mut SyscallContext, arg: u64) -> i64 {
    let mut buf = [0u8; 16];
    ctx.guest_read(arg, &mut buf);
    let cap_id = u64::from_le_bytes(buf[0..8].try_into().unwrap());
    let value: u64 = match cap_id {
        DRM_CAP_DUMB_BUFFER          => 1,
        DRM_CAP_TIMESTAMP_MONOTONIC  => 1,
        DRM_CAP_PRIME                => 0,
        DRM_CAP_CURSOR_WIDTH         => 64,
        DRM_CAP_CURSOR_HEIGHT        => 64,
        DRM_CAP_ADDFB2_MODIFIERS     => 0,
        DRM_CAP_CRTC_IN_VBLANK_EVENT => 1,
        _ => 0,
    };
    buf[8..16].copy_from_slice(&value.to_le_bytes());
    ctx.guest_write(arg, &buf);
    0
}

/// DRM_IOCTL_MODE_GETRESOURCES (0xA0)
///
/// struct drm_mode_card_res {
///     __u64 fb_id_ptr;          // 0
///     __u64 crtc_id_ptr;        // 8
///     __u64 connector_id_ptr;   // 16
///     __u64 encoder_id_ptr;     // 24
///     __u32 count_fbs;          // 32
///     __u32 count_crtcs;        // 36
///     __u32 count_connectors;   // 40
///     __u32 count_encoders;     // 44
///     __u32 min_width;          // 48
///     __u32 max_width;          // 52
///     __u32 min_height;         // 56
///     __u32 max_height;         // 60
/// };
/// Total: 64 bytes.
fn ioctl_get_resources(ctx: &mut SyscallContext, arg: u64) -> i64 {
    let mut buf = [0u8; 64];
    ctx.guest_read(arg, &mut buf);

    let fb_id_ptr       = u64::from_le_bytes(buf[0..8].try_into().unwrap());
    let crtc_id_ptr     = u64::from_le_bytes(buf[8..16].try_into().unwrap());
    let connector_id_ptr= u64::from_le_bytes(buf[16..24].try_into().unwrap());
    let encoder_id_ptr  = u64::from_le_bytes(buf[24..32].try_into().unwrap());
    let count_fbs       = u32::from_le_bytes(buf[32..36].try_into().unwrap());
    let count_crtcs     = u32::from_le_bytes(buf[36..40].try_into().unwrap());
    let count_connectors= u32::from_le_bytes(buf[40..44].try_into().unwrap());
    let count_encoders  = u32::from_le_bytes(buf[44..48].try_into().unwrap());

    // Second pass: if count > 0, write IDs into the provided pointer arrays.
    if count_crtcs >= 1 && crtc_id_ptr != 0 {
        ctx.guest_write(crtc_id_ptr, &1u32.to_le_bytes());
    }
    if count_connectors >= 1 && connector_id_ptr != 0 {
        ctx.guest_write(connector_id_ptr, &1u32.to_le_bytes());
    }
    if count_encoders >= 1 && encoder_id_ptr != 0 {
        ctx.guest_write(encoder_id_ptr, &1u32.to_le_bytes());
    }

    // Count active FBs
    let fbs = unsafe { &*DRM_FBS.get() };
    let mut active_fb_count = 0u32;
    for fb in fbs.iter() {
        if fb.active { active_fb_count += 1; }
    }
    if count_fbs >= active_fb_count && fb_id_ptr != 0 {
        let mut idx = 0u32;
        for fb in fbs.iter() {
            if fb.active {
                ctx.guest_write(fb_id_ptr + (idx as u64) * 4, &fb.fb_id.to_le_bytes());
                idx += 1;
            }
        }
    }

    // Write counts
    buf[32..36].copy_from_slice(&active_fb_count.to_le_bytes());
    buf[36..40].copy_from_slice(&1u32.to_le_bytes()); // 1 CRTC
    buf[40..44].copy_from_slice(&1u32.to_le_bytes()); // 1 connector
    buf[44..48].copy_from_slice(&1u32.to_le_bytes()); // 1 encoder

    // Width/height bounds
    buf[48..52].copy_from_slice(&1u32.to_le_bytes());      // min_width
    buf[52..56].copy_from_slice(&8192u32.to_le_bytes());   // max_width
    buf[56..60].copy_from_slice(&1u32.to_le_bytes());      // min_height
    buf[60..64].copy_from_slice(&8192u32.to_le_bytes());   // max_height

    ctx.guest_write(arg, &buf);
    0
}

/// DRM_IOCTL_MODE_GETCRTC (0xA1)
///
/// struct drm_mode_crtc {
///     __u64 set_connectors_ptr;  // 0
///     __u32 count_connectors;    // 8
///     __u32 crtc_id;             // 12
///     __u32 fb_id;               // 16
///     __u32 x;                   // 20
///     __u32 y;                   // 24
///     __u32 gamma_size;          // 28
///     __u32 mode_valid;          // 32
///     struct drm_mode_modeinfo mode; // 36..104 (68 bytes)
/// };
/// Total: 104 bytes.
fn ioctl_get_crtc(ctx: &mut SyscallContext, arg: u64) -> i64 {
    let mut buf = [0u8; 104];
    ctx.guest_read(arg, &mut buf);

    let active_fb = unsafe { *DRM_CRTC_FB_ID.get() };
    buf[12..16].copy_from_slice(&1u32.to_le_bytes()); // crtc_id = 1
    buf[16..20].copy_from_slice(&active_fb.to_le_bytes()); // fb_id = currently active FB
    buf[20..24].copy_from_slice(&0u32.to_le_bytes()); // x = 0
    buf[24..28].copy_from_slice(&0u32.to_le_bytes()); // y = 0
    buf[28..32].copy_from_slice(&256u32.to_le_bytes()); // gamma_size = 256
    buf[32..36].copy_from_slice(&1u32.to_le_bytes()); // mode_valid = 1

    // Fill mode at offset 36
    let mut mode = [0u8; 68];
    fill_current_mode(&mut mode);
    buf[36..104].copy_from_slice(&mode);

    ctx.guest_write(arg, &buf);
    0
}

/// DRM_IOCTL_MODE_SETCRTC (0xA2)
///
/// Same struct as GETCRTC. We read fb_id, find the dumb buffer, and blit.
fn ioctl_set_crtc(ctx: &mut SyscallContext, arg: u64) -> i64 {
    let mut buf = [0u8; 104];
    ctx.guest_read(arg, &mut buf);
    let fb_id = u32::from_le_bytes(buf[16..20].try_into().unwrap());
    print(b"DRM-SETCRTC fb_id=");
    print_u64(fb_id as u64);
    print(b"\n");

    if fb_id != 0 {
        unsafe { *DRM_CRTC_FB_ID.get() = fb_id; }
        if let Some(idx) = find_dumb_for_fb(fb_id) {
            let dumbs = unsafe { &*DRM_DUMBS.get() };
            blit_dumb_to_fb(ctx, &dumbs[idx]);
        }
    }
    0
}

/// DRM_IOCTL_MODE_GETCONNECTOR (0xA7)
///
/// struct drm_mode_get_connector {
///     __u64 encoders_ptr;       // 0
///     __u64 modes_ptr;          // 8
///     __u64 props_ptr;          // 16
///     __u64 prop_values_ptr;    // 24
///     __u32 count_modes;        // 32
///     __u32 count_props;        // 36
///     __u32 count_encoders;     // 40
///     __u32 encoder_id;         // 44
///     __u32 connector_id;       // 48
///     __u32 connector_type;     // 52
///     __u32 connector_type_id;  // 56
///     __u32 connection;         // 60
///     __u32 mm_width;           // 64
///     __u32 mm_height;          // 68
///     __u32 subpixel;           // 72
///     __u32 pad;                // 76
/// };
/// Total: 80 bytes.
fn ioctl_get_connector(ctx: &mut SyscallContext, arg: u64) -> i64 {
    let mut buf = [0u8; 80];
    ctx.guest_read(arg, &mut buf);

    let encoders_ptr    = u64::from_le_bytes(buf[0..8].try_into().unwrap());
    let modes_ptr       = u64::from_le_bytes(buf[8..16].try_into().unwrap());
    let props_ptr       = u64::from_le_bytes(buf[16..24].try_into().unwrap());
    let pvals_ptr       = u64::from_le_bytes(buf[24..32].try_into().unwrap());
    let count_modes     = u32::from_le_bytes(buf[32..36].try_into().unwrap());
    let count_props     = u32::from_le_bytes(buf[36..40].try_into().unwrap());
    let count_encoders  = u32::from_le_bytes(buf[40..44].try_into().unwrap());

    // If caller provided buffer for modes (second pass), write the mode
    if count_modes >= 1 && modes_ptr != 0 {
        let mut mode = [0u8; 68];
        fill_current_mode(&mut mode);
        ctx.guest_write(modes_ptr, &mode);
    }

    // If caller provided buffer for encoders (second pass)
    if count_encoders >= 1 && encoders_ptr != 0 {
        ctx.guest_write(encoders_ptr, &1u32.to_le_bytes()); // encoder_id=1
    }

    // Connector properties: CRTC_ID(21), DPMS(20)
    if count_props >= 2 && props_ptr != 0 {
        ctx.guest_write(props_ptr, &PROP_ID_CONN_CRTC.to_le_bytes());
        ctx.guest_write(props_ptr + 4, &PROP_ID_DPMS.to_le_bytes());
        if pvals_ptr != 0 {
            ctx.guest_write(pvals_ptr, &1u64.to_le_bytes()); // CRTC_ID=1
            ctx.guest_write(pvals_ptr + 8, &0u64.to_le_bytes()); // DPMS=ON(0)
        }
    }

    // Fill counts and fields
    buf[32..36].copy_from_slice(&1u32.to_le_bytes());  // count_modes = 1
    buf[36..40].copy_from_slice(&2u32.to_le_bytes());  // count_props = 2
    buf[40..44].copy_from_slice(&1u32.to_le_bytes());  // count_encoders = 1
    buf[44..48].copy_from_slice(&1u32.to_le_bytes());  // encoder_id = 1
    buf[48..52].copy_from_slice(&1u32.to_le_bytes());  // connector_id = 1
    buf[52..56].copy_from_slice(&15u32.to_le_bytes()); // DRM_MODE_CONNECTOR_Virtual = 15
    buf[56..60].copy_from_slice(&1u32.to_le_bytes());  // connector_type_id = 1
    buf[60..64].copy_from_slice(&1u32.to_le_bytes());  // connection = connected (1)

    // Physical size: approximate 96 DPI
    let (w, h, _, _) = fb_info();
    let mm_w = (w as u32) * 254 / 960; // pixels * 25.4 / 96
    let mm_h = (h as u32) * 254 / 960;
    buf[64..68].copy_from_slice(&mm_w.to_le_bytes());
    buf[68..72].copy_from_slice(&mm_h.to_le_bytes());

    buf[72..76].copy_from_slice(&1u32.to_le_bytes());  // subpixel = DRM_MODE_SUBPIXEL_UNKNOWN (1)
    buf[76..80].copy_from_slice(&0u32.to_le_bytes());  // pad

    ctx.guest_write(arg, &buf);
    0
}

/// DRM_IOCTL_MODE_GETENCODER (0xA6)
///
/// struct drm_mode_get_encoder {
///     __u32 encoder_id;      // 0
///     __u32 encoder_type;    // 4
///     __u32 crtc_id;         // 8
///     __u32 possible_crtcs;  // 12
///     __u32 possible_clones; // 16
/// };
/// Total: 20 bytes.
fn ioctl_get_encoder(ctx: &mut SyscallContext, arg: u64) -> i64 {
    let mut buf = [0u8; 20];
    ctx.guest_read(arg, &mut buf);

    buf[0..4].copy_from_slice(&1u32.to_le_bytes());   // encoder_id = 1
    buf[4..8].copy_from_slice(&7u32.to_le_bytes());   // DRM_MODE_ENCODER_VIRTUAL = 7
    buf[8..12].copy_from_slice(&1u32.to_le_bytes());   // crtc_id = 1
    buf[12..16].copy_from_slice(&1u32.to_le_bytes());  // possible_crtcs = bitmask(1)
    buf[16..20].copy_from_slice(&0u32.to_le_bytes());  // possible_clones = 0

    ctx.guest_write(arg, &buf);
    0
}

/// DRM_IOCTL_MODE_CREATE_DUMB (0xB2)
///
/// struct drm_mode_create_dumb {
///     __u32 height;   // 0
///     __u32 width;    // 4
///     __u32 bpp;      // 8
///     __u32 flags;    // 12
///     __u32 handle;   // 16 (out)
///     __u32 pitch;    // 20 (out)
///     __u64 size;     // 24 (out)
/// };
/// Total: 32 bytes.
fn ioctl_create_dumb(ctx: &mut SyscallContext, arg: u64) -> i64 {
    let mut buf = [0u8; 32];
    ctx.guest_read(arg, &mut buf);

    let height = u32::from_le_bytes(buf[0..4].try_into().unwrap());
    let width  = u32::from_le_bytes(buf[4..8].try_into().unwrap());
    let bpp    = u32::from_le_bytes(buf[8..12].try_into().unwrap());

    // Pitch = width * bpp/8, aligned to 64 bytes
    let pitch = align_up(width * (bpp / 8), 64);
    let size  = (pitch as u64) * (height as u64);
    let pages = ((size + 0xFFF) & !0xFFF) / 0x1000;

    print(b"DRM-CREATE-DUMB ");
    print_u64(width as u64);
    print(b"x");
    print_u64(height as u64);
    print(b"x");
    print_u64(bpp as u64);
    print(b" pitch=");
    print_u64(pitch as u64);
    print(b" pages=");
    print_u64(pages);
    print(b"\n");

    if pages as usize > MAX_DUMB_FRAMES {
        print(b"DRM-CREATE-DUMB too large\n");
        return -12; // ENOMEM
    }

    // Find free slot
    let dumbs = unsafe { &mut *DRM_DUMBS.get() };
    let slot = match dumbs.iter().position(|d| !d.active) {
        Some(s) => s,
        None => { return -12; } // ENOMEM
    };

    // Allocate physical frames
    let mut frames = [0u64; MAX_DUMB_FRAMES];
    for p in 0..pages as usize {
        match sys::frame_alloc() {
            Ok(f) => frames[p] = f,
            Err(_) => {
                print(b"DRM-CREATE-DUMB frame_alloc fail\n");
                return -12; // ENOMEM
            }
        }
    }

    let handle = unsafe {
        let h = *DRM_NEXT_HANDLE.get();
        *DRM_NEXT_HANDLE.get() = h + 1;
        h
    };

    dumbs[slot] = DrmDumbBuffer {
        active: true,
        handle,
        width,
        height,
        bpp,
        pitch,
        size,
        frames,
        frame_count: pages as usize,
        mmap_offset: (handle as u64) * 0x10000000, // unique offset per handle
        mmap_vaddr: 0,
    };

    // Write output fields
    buf[16..20].copy_from_slice(&handle.to_le_bytes());
    buf[20..24].copy_from_slice(&pitch.to_le_bytes());
    buf[24..32].copy_from_slice(&size.to_le_bytes());
    ctx.guest_write(arg, &buf);

    print(b"DRM-CREATE-DUMB handle=");
    print_u64(handle as u64);
    print(b"\n");
    0
}

/// DRM_IOCTL_MODE_MAP_DUMB (0xB3)
///
/// struct drm_mode_map_dumb {
///     __u32 handle;   // 0
///     __u32 pad;      // 4
///     __u64 offset;   // 8 (out)
/// };
/// Total: 16 bytes.
fn ioctl_map_dumb(ctx: &mut SyscallContext, arg: u64) -> i64 {
    let mut buf = [0u8; 16];
    ctx.guest_read(arg, &mut buf);

    let handle = u32::from_le_bytes(buf[0..4].try_into().unwrap());
    let dumbs = unsafe { &*DRM_DUMBS.get() };
    for d in dumbs.iter() {
        if d.active && d.handle == handle {
            buf[8..16].copy_from_slice(&d.mmap_offset.to_le_bytes());
            ctx.guest_write(arg, &buf);
            print(b"DRM-MAP-DUMB handle=");
            print_u64(handle as u64);
            print(b" offset=0x");
            print_hex64(d.mmap_offset);
            print(b"\n");
            return 0;
        }
    }
    -22 // EINVAL
}

/// DRM_IOCTL_MODE_ADDFB (0xAE)
///
/// struct drm_mode_fb_cmd {
///     __u32 fb_id;    // 0  (out)
///     __u32 width;    // 4
///     __u32 height;   // 8
///     __u32 pitch;    // 12
///     __u32 bpp;      // 16
///     __u32 depth;    // 20
///     __u32 handle;   // 24
/// };
/// Total: 28 bytes.
fn ioctl_add_fb(ctx: &mut SyscallContext, arg: u64) -> i64 {
    let mut buf = [0u8; 28];
    ctx.guest_read(arg, &mut buf);

    let width  = u32::from_le_bytes(buf[4..8].try_into().unwrap());
    let height = u32::from_le_bytes(buf[8..12].try_into().unwrap());
    let handle = u32::from_le_bytes(buf[24..28].try_into().unwrap());

    let fbs = unsafe { &mut *DRM_FBS.get() };
    let slot = match fbs.iter().position(|f| !f.active) {
        Some(s) => s,
        None => { return -12; } // ENOMEM
    };

    let fb_id = unsafe {
        let id = *DRM_NEXT_FB_ID.get();
        *DRM_NEXT_FB_ID.get() = id + 1;
        id
    };

    fbs[slot] = DrmFbObject {
        active: true,
        fb_id,
        dumb_handle: handle,
        width,
        height,
    };

    buf[0..4].copy_from_slice(&fb_id.to_le_bytes());
    ctx.guest_write(arg, &buf);
    print(b"DRM-ADDFB id=");
    print_u64(fb_id as u64);
    print(b" handle=");
    print_u64(handle as u64);
    print(b"\n");
    0
}

/// DRM_IOCTL_MODE_ADDFB2 (0xB8)
///
/// struct drm_mode_fb_cmd2 {
///     __u32 fb_id;            // 0  (out)
///     __u32 width;            // 4
///     __u32 height;           // 8
///     __u32 pixel_format;     // 12
///     __u32 flags;            // 16
///     __u32 handles[4];       // 20, 24, 28, 32
///     __u32 pitches[4];       // 36, 40, 44, 48
///     __u32 offsets[4];       // 52, 56, 60, 64
///     __u64 modifier[4];      // 68..100
/// };
/// Total: 100 bytes (at least; may be larger with modifiers).
fn ioctl_add_fb2(ctx: &mut SyscallContext, arg: u64) -> i64 {
    let mut buf = [0u8; 100];
    ctx.guest_read(arg, &mut buf);

    let width  = u32::from_le_bytes(buf[4..8].try_into().unwrap());
    let height = u32::from_le_bytes(buf[8..12].try_into().unwrap());
    let handle = u32::from_le_bytes(buf[20..24].try_into().unwrap()); // handles[0]

    let fbs = unsafe { &mut *DRM_FBS.get() };
    let slot = match fbs.iter().position(|f| !f.active) {
        Some(s) => s,
        None => { return -12; }
    };

    let fb_id = unsafe {
        let id = *DRM_NEXT_FB_ID.get();
        *DRM_NEXT_FB_ID.get() = id + 1;
        id
    };

    fbs[slot] = DrmFbObject {
        active: true,
        fb_id,
        dumb_handle: handle,
        width,
        height,
    };

    buf[0..4].copy_from_slice(&fb_id.to_le_bytes());
    ctx.guest_write(arg, &buf);
    print(b"DRM-ADDFB2 id=");
    print_u64(fb_id as u64);
    print(b" handle=");
    print_u64(handle as u64);
    print(b"\n");
    0
}

/// DRM_IOCTL_MODE_GETFB (0xAD)
///
/// struct drm_mode_fb_cmd {
///     __u32 fb_id;    // 0 (in)
///     __u32 width;    // 4 (out)
///     __u32 height;   // 8 (out)
///     __u32 pitch;    // 12 (out)
///     __u32 bpp;      // 16 (out)
///     __u32 depth;    // 20 (out)
///     __u32 handle;   // 24 (out)
/// };
fn ioctl_get_fb(ctx: &mut SyscallContext, arg: u64) -> i64 {
    let mut buf = [0u8; 28];
    ctx.guest_read(arg, &mut buf);
    let fb_id = u32::from_le_bytes(buf[0..4].try_into().unwrap());

    let fbs = unsafe { &*DRM_FBS.get() };
    for fb in fbs.iter() {
        if fb.active && fb.fb_id == fb_id {
            buf[4..8].copy_from_slice(&fb.width.to_le_bytes());
            buf[8..12].copy_from_slice(&fb.height.to_le_bytes());
            if let Some(idx) = find_dumb_for_fb(fb_id) {
                let d = &unsafe { &*DRM_DUMBS.get() }[idx];
                buf[12..16].copy_from_slice(&d.pitch.to_le_bytes());
                buf[16..20].copy_from_slice(&d.bpp.to_le_bytes());
                // XRGB8888 has 32bpp but only 24 color depth bits
                let depth: u32 = if d.bpp == 32 { 24 } else { d.bpp };
                buf[20..24].copy_from_slice(&depth.to_le_bytes());
                buf[24..28].copy_from_slice(&d.handle.to_le_bytes());
            }
            ctx.guest_write(arg, &buf);
            return 0;
        }
    }
    -22 // EINVAL
}

/// DRM_IOCTL_MODE_RMFB (0xAF)
/// Argument is a pointer to __u32 fb_id.
fn ioctl_rm_fb(ctx: &mut SyscallContext, arg: u64) -> i64 {
    let mut buf = [0u8; 4];
    ctx.guest_read(arg, &mut buf);
    let fb_id = u32::from_le_bytes(buf);

    let fbs = unsafe { &mut *DRM_FBS.get() };
    for fb in fbs.iter_mut() {
        if fb.active && fb.fb_id == fb_id {
            fb.active = false;
            print(b"DRM-RMFB id=");
            print_u64(fb_id as u64);
            print(b"\n");
            return 0;
        }
    }
    -22 // EINVAL
}

/// DRM_IOCTL_MODE_PAGE_FLIP (0xB0)
///
/// struct drm_mode_crtc_page_flip {
///     __u32 crtc_id;     // 0
///     __u32 fb_id;       // 4
///     __u32 flags;       // 8
///     __u32 reserved;    // 12
///     __u64 user_data;   // 16
/// };
/// Total: 24 bytes.
fn ioctl_page_flip(ctx: &mut SyscallContext, arg: u64) -> i64 {
    let mut buf = [0u8; 24];
    ctx.guest_read(arg, &mut buf);

    let fb_id = u32::from_le_bytes(buf[4..8].try_into().unwrap());
    let flags = u32::from_le_bytes(buf[8..12].try_into().unwrap());
    let user_data = u64::from_le_bytes(buf[16..24].try_into().unwrap());

    // Real DRM returns -EBUSY if a flip event is still pending.
    if flags & 0x01 != 0 && unsafe { *DRM_FLIP_PENDING.get() } {
        return -16; // EBUSY
    }

    unsafe { *DRM_CRTC_FB_ID.get() = fb_id; }

    if let Some(idx) = find_dumb_for_fb(fb_id) {
        let dumbs = unsafe { &*DRM_DUMBS.get() };
        blit_dumb_to_fb(ctx, &dumbs[idx]);
    }

    // If PAGE_FLIP_EVENT flag (0x01) is set, queue a vblank event for read().
    if flags & 0x01 != 0 {
        unsafe {
            *DRM_FLIP_SEQUENCE.get() += 1;
            *DRM_FLIP_PENDING.get() = true;
            *DRM_FLIP_USER_DATA.get() = user_data;
        }
    }

    0
}

/// DRM_IOCTL_MODE_DESTROY_DUMB (0xB4)
///
/// struct drm_mode_destroy_dumb {
///     __u32 handle;
/// };
fn ioctl_destroy_dumb(ctx: &mut SyscallContext, arg: u64) -> i64 {
    let mut buf = [0u8; 4];
    ctx.guest_read(arg, &mut buf);
    let handle = u32::from_le_bytes(buf);

    let dumbs = unsafe { &mut *DRM_DUMBS.get() };
    for d in dumbs.iter_mut() {
        if d.active && d.handle == handle {
            d.active = false;
            print(b"DRM-DESTROY-DUMB handle=");
            print_u64(handle as u64);
            print(b"\n");
            return 0;
        }
    }
    -22 // EINVAL
}

// ---------------------------------------------------------------------------
// Universal planes + properties ioctls (Weston 14 requires these)
// ---------------------------------------------------------------------------

/// DRM_IOCTL_SET_CLIENT_CAP (0x0D)
///
/// struct drm_set_client_cap { __u64 capability; __u64 value; };
fn ioctl_set_client_cap(ctx: &mut SyscallContext, arg: u64) -> i64 {
    let mut buf = [0u8; 16];
    ctx.guest_read(arg, &mut buf);
    let cap = u64::from_le_bytes(buf[0..8].try_into().unwrap());
    match cap {
        DRM_CLIENT_CAP_UNIVERSAL_PLANES => {
            print(b"DRM: universal planes enabled\n");
            0
        }
        DRM_CLIENT_CAP_ATOMIC => {
            print(b"DRM: atomic rejected (legacy mode)\n");
            -95 // EOPNOTSUPP — force legacy DRM path
        }
        _ => 0,
    }
}

/// DRM_IOCTL_MODE_GETPLANERESOURCES (0xB5)
///
/// struct drm_mode_get_plane_res {
///     __u64 plane_id_ptr;    // 0
///     __u32 count_planes;    // 8
/// };
fn ioctl_get_plane_resources(ctx: &mut SyscallContext, arg: u64) -> i64 {
    let mut buf = [0u8; 16];
    ctx.guest_read(arg, &mut buf);

    let plane_id_ptr = u64::from_le_bytes(buf[0..8].try_into().unwrap());
    let count = u32::from_le_bytes(buf[8..12].try_into().unwrap());

    // 1 primary plane
    if count >= 1 && plane_id_ptr != 0 {
        ctx.guest_write(plane_id_ptr, &PLANE_ID_PRIMARY.to_le_bytes());
    }

    buf[8..12].copy_from_slice(&1u32.to_le_bytes());
    ctx.guest_write(arg, &buf);
    print(b"DRM: GETPLANERESOURCES count=1\n");
    0
}

/// DRM_IOCTL_MODE_GETPLANE (0xB6)
///
/// struct drm_mode_get_plane {
///     __u32 plane_id;            // 0
///     __u32 crtc_id;             // 4
///     __u32 fb_id;               // 8
///     __u32 possible_crtcs;      // 12
///     __u32 gamma_size;          // 16
///     __u32 count_format_codes;  // 20
///     __u64 format_type_ptr;     // 24
/// };
fn ioctl_get_plane(ctx: &mut SyscallContext, arg: u64) -> i64 {
    let mut buf = [0u8; 32];
    ctx.guest_read(arg, &mut buf);

    let format_ptr = u64::from_le_bytes(buf[24..32].try_into().unwrap());
    let count = u32::from_le_bytes(buf[20..24].try_into().unwrap());

    // Supported pixel formats
    const XRGB8888: u32 = 0x34325258; // fourcc('X','R','2','4')
    const ARGB8888: u32 = 0x34325241; // fourcc('A','R','2','4')

    if count >= 2 && format_ptr != 0 {
        ctx.guest_write(format_ptr, &XRGB8888.to_le_bytes());
        ctx.guest_write(format_ptr + 4, &ARGB8888.to_le_bytes());
    }

    buf[0..4].copy_from_slice(&PLANE_ID_PRIMARY.to_le_bytes());
    buf[4..8].copy_from_slice(&0u32.to_le_bytes());   // crtc_id (not bound)
    buf[8..12].copy_from_slice(&0u32.to_le_bytes());   // fb_id (not bound)
    buf[12..16].copy_from_slice(&1u32.to_le_bytes());  // possible_crtcs = bit 0
    buf[16..20].copy_from_slice(&0u32.to_le_bytes());  // gamma_size
    buf[20..24].copy_from_slice(&2u32.to_le_bytes());  // count_format_codes

    ctx.guest_write(arg, &buf);
    print(b"DRM: GETPLANE id=");
    print_u64(PLANE_ID_PRIMARY as u64);
    print(b"\n");
    0
}

/// DRM_IOCTL_MODE_OBJ_GETPROPERTIES (0xB9)
///
/// struct drm_mode_obj_get_properties {
///     __u64 props_ptr;       // 0
///     __u64 prop_values_ptr; // 8
///     __u32 count_props;     // 16
///     __u32 obj_id;          // 20
///     __u32 obj_type;        // 24
///     __u32 pad;             // 28
/// };
fn ioctl_obj_get_properties(ctx: &mut SyscallContext, arg: u64) -> i64 {
    let mut buf = [0u8; 32];
    ctx.guest_read(arg, &mut buf);

    let props_ptr  = u64::from_le_bytes(buf[0..8].try_into().unwrap());
    let values_ptr = u64::from_le_bytes(buf[8..16].try_into().unwrap());
    let count      = u32::from_le_bytes(buf[16..20].try_into().unwrap());
    let _obj_id    = u32::from_le_bytes(buf[20..24].try_into().unwrap());
    let obj_type   = u32::from_le_bytes(buf[24..28].try_into().unwrap());

    match obj_type {
        DRM_MODE_OBJECT_PLANE => {
            // Plane properties: type(1), CRTC_ID(2), FB_ID(3)
            let ids: [u32; 3] = [PROP_ID_TYPE, PROP_ID_CRTC_ID, PROP_ID_FB_ID];
            let vals: [u64; 3] = [1, 0, 0]; // type=PRIMARY(1)
            let num = 3u32;
            if count >= num && props_ptr != 0 {
                for i in 0..3usize {
                    ctx.guest_write(props_ptr + (i as u64) * 4, &ids[i].to_le_bytes());
                    ctx.guest_write(values_ptr + (i as u64) * 8, &vals[i].to_le_bytes());
                }
            }
            buf[16..20].copy_from_slice(&num.to_le_bytes());
        }
        DRM_MODE_OBJECT_CRTC => {
            let ids: [u32; 2] = [PROP_ID_ACTIVE, PROP_ID_MODE_ID];
            let vals: [u64; 2] = [1, 0]; // ACTIVE=1, MODE_ID=0
            let num = 2u32;
            if count >= num && props_ptr != 0 {
                for i in 0..2usize {
                    ctx.guest_write(props_ptr + (i as u64) * 4, &ids[i].to_le_bytes());
                    ctx.guest_write(values_ptr + (i as u64) * 8, &vals[i].to_le_bytes());
                }
            }
            buf[16..20].copy_from_slice(&num.to_le_bytes());
        }
        DRM_MODE_OBJECT_CONNECTOR => {
            let ids: [u32; 2] = [PROP_ID_CONN_CRTC, PROP_ID_DPMS];
            let vals: [u64; 2] = [1, 0]; // CRTC_ID=1, DPMS=ON
            let num = 2u32;
            if count >= num && props_ptr != 0 {
                for i in 0..2usize {
                    ctx.guest_write(props_ptr + (i as u64) * 4, &ids[i].to_le_bytes());
                    ctx.guest_write(values_ptr + (i as u64) * 8, &vals[i].to_le_bytes());
                }
            }
            buf[16..20].copy_from_slice(&num.to_le_bytes());
        }
        _ => {
            buf[16..20].copy_from_slice(&0u32.to_le_bytes());
        }
    }

    ctx.guest_write(arg, &buf);
    0
}

/// DRM_IOCTL_MODE_GETPROPERTY (0xAA)
///
/// struct drm_mode_get_property {
///     __u64 values_ptr;       // 0
///     __u64 enum_blob_ptr;    // 8
///     __u32 prop_id;          // 16
///     __u32 flags;            // 20
///     char name[32];          // 24..56
///     __u32 count_values;     // 56
///     __u32 count_enum_blobs; // 60
/// };
fn ioctl_get_property(ctx: &mut SyscallContext, arg: u64) -> i64 {
    let mut buf = [0u8; 64];
    ctx.guest_read(arg, &mut buf);

    let values_ptr = u64::from_le_bytes(buf[0..8].try_into().unwrap());
    let enum_ptr   = u64::from_le_bytes(buf[8..16].try_into().unwrap());
    let prop_id    = u32::from_le_bytes(buf[16..20].try_into().unwrap());
    let count_vals = u32::from_le_bytes(buf[56..60].try_into().unwrap());
    let count_enum = u32::from_le_bytes(buf[60..64].try_into().unwrap());

    // DRM_MODE_PROP flags
    const PROP_RANGE: u32     = 1 << 1;
    const PROP_IMMUTABLE: u32 = 1 << 2;
    const PROP_ENUM: u32      = 1 << 3;
    const PROP_OBJECT: u32    = (1 << 6) | (1 << 1);

    // Zero the name field
    buf[24..56].copy_from_slice(&[0u8; 32]);

    match prop_id {
        PROP_ID_TYPE => {
            // "type" — plane type enum (immutable)
            buf[20..24].copy_from_slice(&(PROP_ENUM | PROP_IMMUTABLE).to_le_bytes());
            buf[24..28].copy_from_slice(b"type");
            buf[56..60].copy_from_slice(&3u32.to_le_bytes());
            buf[60..64].copy_from_slice(&3u32.to_le_bytes());

            if count_enum >= 3 && enum_ptr != 0 {
                // struct drm_mode_property_enum { __u64 value; char name[32]; } = 40 bytes
                let enums: [(&[u8], u64); 3] = [
                    (b"Overlay", 0),
                    (b"Primary", 1),
                    (b"Cursor", 2),
                ];
                for (i, (name, val)) in enums.iter().enumerate() {
                    let off = enum_ptr + (i as u64) * 40;
                    ctx.guest_write(off, &val.to_le_bytes());
                    let mut nbuf = [0u8; 32];
                    let n = name.len().min(31);
                    nbuf[..n].copy_from_slice(&name[..n]);
                    ctx.guest_write(off + 8, &nbuf);
                }
            }
            if count_vals >= 3 && values_ptr != 0 {
                for i in 0..3u64 {
                    ctx.guest_write(values_ptr + i * 8, &i.to_le_bytes());
                }
            }
        }
        PROP_ID_CRTC_ID => {
            buf[20..24].copy_from_slice(&PROP_OBJECT.to_le_bytes());
            buf[24..31].copy_from_slice(b"CRTC_ID");
            buf[56..60].copy_from_slice(&0u32.to_le_bytes());
            buf[60..64].copy_from_slice(&0u32.to_le_bytes());
        }
        PROP_ID_FB_ID => {
            buf[20..24].copy_from_slice(&PROP_OBJECT.to_le_bytes());
            buf[24..29].copy_from_slice(b"FB_ID");
            buf[56..60].copy_from_slice(&0u32.to_le_bytes());
            buf[60..64].copy_from_slice(&0u32.to_le_bytes());
        }
        PROP_ID_ACTIVE => {
            buf[20..24].copy_from_slice(&PROP_RANGE.to_le_bytes());
            buf[24..30].copy_from_slice(b"ACTIVE");
            buf[56..60].copy_from_slice(&2u32.to_le_bytes());
            buf[60..64].copy_from_slice(&0u32.to_le_bytes());
            if count_vals >= 2 && values_ptr != 0 {
                ctx.guest_write(values_ptr, &0u64.to_le_bytes());     // min
                ctx.guest_write(values_ptr + 8, &1u64.to_le_bytes()); // max
            }
        }
        PROP_ID_MODE_ID => {
            buf[20..24].copy_from_slice(&((1u32 << 4) | (1 << 2)).to_le_bytes()); // BLOB | IMMUTABLE
            buf[24..31].copy_from_slice(b"MODE_ID");
            buf[56..60].copy_from_slice(&0u32.to_le_bytes());
            buf[60..64].copy_from_slice(&0u32.to_le_bytes());
        }
        PROP_ID_DPMS => {
            buf[20..24].copy_from_slice(&PROP_ENUM.to_le_bytes());
            buf[24..28].copy_from_slice(b"DPMS");
            buf[56..60].copy_from_slice(&4u32.to_le_bytes());
            buf[60..64].copy_from_slice(&4u32.to_le_bytes());
            if count_enum >= 4 && enum_ptr != 0 {
                let dpms: [(&[u8], u64); 4] = [
                    (b"On", 0), (b"Standby", 1), (b"Suspend", 2), (b"Off", 3),
                ];
                for (i, (name, val)) in dpms.iter().enumerate() {
                    let off = enum_ptr + (i as u64) * 40;
                    ctx.guest_write(off, &val.to_le_bytes());
                    let mut nbuf = [0u8; 32];
                    let n = name.len().min(31);
                    nbuf[..n].copy_from_slice(&name[..n]);
                    ctx.guest_write(off + 8, &nbuf);
                }
            }
            if count_vals >= 4 && values_ptr != 0 {
                for i in 0..4u64 {
                    ctx.guest_write(values_ptr + i * 8, &i.to_le_bytes());
                }
            }
        }
        PROP_ID_CONN_CRTC => {
            buf[20..24].copy_from_slice(&PROP_OBJECT.to_le_bytes());
            buf[24..31].copy_from_slice(b"CRTC_ID");
            buf[56..60].copy_from_slice(&0u32.to_le_bytes());
            buf[60..64].copy_from_slice(&0u32.to_le_bytes());
        }
        _ => {
            // Unknown property — return zeroed
            let mut name = [0u8; 32];
            name[0..8].copy_from_slice(b"unknown\0");
            buf[24..56].copy_from_slice(&name);
            buf[56..60].copy_from_slice(&0u32.to_le_bytes());
            buf[60..64].copy_from_slice(&0u32.to_le_bytes());
        }
    }

    ctx.guest_write(arg, &buf);
    0
}

// ---------------------------------------------------------------------------
// DRM mmap handler
// ---------------------------------------------------------------------------

/// Handle mmap on a DRM fd. Called from sys_mmap when the child does
/// mmap(addr, size, prot, MAP_SHARED, drm_fd, offset).
///
/// Parameters (matching the call site in syscalls/mm.rs):
///   `mmap_offset` — the file offset from the child's mmap (from MAP_DUMB)
///   `size`        — aligned length of the mapping
///   `base`        — virtual address already chosen by sys_mmap
///
/// Finds the dumb buffer matching the offset, maps its frames into the child
/// at `base`, and returns `base` (as i64) on success.
/// On error returns negative errno.
pub(crate) fn drm_mmap(ctx: &mut SyscallContext, mmap_offset: u64, _size: u64, base: u64) -> i64 {
    let dumbs = unsafe { &mut *DRM_DUMBS.get() };

    // Find the dumb buffer whose mmap_offset matches.
    let slot = match dumbs.iter().position(|d| d.active && d.mmap_offset == mmap_offset) {
        Some(s) => s,
        None => {
            print(b"DRM-MMAP no dumb for offset=0x");
            print_hex64(mmap_offset);
            print(b"\n");
            return -22; // EINVAL
        }
    };

    let pages = dumbs[slot].frame_count;

    print(b"DRM-MMAP base=0x");
    print_hex64(base);
    print(b" pages=");
    print_u64(pages as u64);
    print(b"\n");

    // Map each frame into the child's address space (writable)
    const MAP_WRITABLE: u64 = 2;
    for p in 0..pages {
        let frame_cap = dumbs[slot].frames[p];
        if ctx.guest_map(base + (p as u64) * 0x1000, frame_cap, MAP_WRITABLE).is_err() {
            print(b"DRM-MMAP map fail page=");
            print_u64(p as u64);
            print(b"\n");
            return -12; // ENOMEM
        }
        // Zero the page
        ctx.guest_zero_page(base + (p as u64) * 0x1000);
    }

    dumbs[slot].mmap_vaddr = base;
    base as i64
}

/// Handle read() on a DRM fd (kind=30).
/// Returns flip event data if a page flip is pending, otherwise returns 0 (no data).
///
/// struct drm_event_vblank {
///     __u32 type;           // 0: DRM_EVENT_FLIP_COMPLETE = 0x02
///     __u32 length;         // 4: 32
///     __u64 user_data;      // 8
///     __u32 tv_sec;         // 16
///     __u32 tv_usec;        // 20
///     __u32 sequence;       // 24
///     __u32 crtc_id;        // 28
/// };
pub(crate) fn drm_read(ctx: &SyscallContext, buf_ptr: u64, len: usize) -> i64 {
    let pending = unsafe { *DRM_FLIP_PENDING.get() };
    if !pending {
        // No event pending. Return -EAGAIN so callers know to poll/retry.
        return -11; // EAGAIN
    }
    if len < 32 {
        return -22; // EINVAL — buffer too small for drm_event_vblank
    }

    let user_data = unsafe { *DRM_FLIP_USER_DATA.get() };
    let sequence = unsafe { *DRM_FLIP_SEQUENCE.get() };

    // Build drm_event_vblank (32 bytes)
    let mut ev = [0u8; 32];
    ev[0..4].copy_from_slice(&0x02u32.to_le_bytes()); // DRM_EVENT_FLIP_COMPLETE
    ev[4..8].copy_from_slice(&32u32.to_le_bytes());    // length
    ev[8..16].copy_from_slice(&user_data.to_le_bytes());
    // tv_sec, tv_usec: use RDTSC-based fake timestamp
    let tsc = crate::exec::rdtsc();
    let usec_total = tsc / 2000; // ~2 GHz assumed
    let tv_sec = (usec_total / 1_000_000) as u32;
    let tv_usec = (usec_total % 1_000_000) as u32;
    ev[16..20].copy_from_slice(&tv_sec.to_le_bytes());
    ev[20..24].copy_from_slice(&tv_usec.to_le_bytes());
    ev[24..28].copy_from_slice(&sequence.to_le_bytes()); // monotonic sequence counter
    ev[28..32].copy_from_slice(&1u32.to_le_bytes());     // crtc_id = 1

    ctx.guest_write(buf_ptr, &ev);

    unsafe { *DRM_FLIP_PENDING.get() = false; }

    32 // bytes written
}

/// Check if a DRM page-flip event is pending (for poll/epoll).
pub(crate) fn drm_poll_readable() -> bool {
    unsafe { *DRM_FLIP_PENDING.get() }
}

/// Handle fstat on a DRM fd (kind=30).
/// Reports the device as a character device (S_IFCHR) with major 226 (DRM).
pub(crate) fn drm_fstat(ctx: &SyscallContext, stat_ptr: u64) {
    // Build a minimal stat struct (144 bytes).
    let mut st = [0u8; 144];
    // st_dev = 0
    // st_ino = 1 (arbitrary)
    st[8..16].copy_from_slice(&1u64.to_le_bytes());
    // st_nlink = 1
    st[16..20].copy_from_slice(&1u32.to_le_bytes());
    // st_mode = S_IFCHR | 0666
    let mode: u32 = 0o020000 | 0o666; // S_IFCHR = 020000 octal
    st[24..28].copy_from_slice(&mode.to_le_bytes());
    // st_rdev = makedev(226, 0) -- major 226 = DRM
    let rdev: u64 = ((226u64) << 8) | 0;
    st[40..48].copy_from_slice(&rdev.to_le_bytes());
    // st_blksize = 4096
    st[56..60].copy_from_slice(&4096i32.to_le_bytes());

    ctx.guest_write(stat_ptr, &st);
}
