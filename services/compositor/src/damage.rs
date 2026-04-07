//! Damage region tracking for the compositor.
//!
//! Replaces the old single-bool DAMAGE flag with a fixed-size list of
//! dirty rectangles. The compose loop iterates dirty rects and only
//! redraws those regions instead of the whole framebuffer. Backward
//! compatible: damaging the whole screen falls back to one full-screen
//! rect.
//!
//! All operations are O(MAX_DIRTY_RECTS) at worst -- fine for 32.
//!
//! Single-threaded: the compositor is a single userspace thread, so
//! `SyncUnsafeCell` is sufficient (matches the existing pattern in
//! `main.rs`).

use sotos_common::SyncUnsafeCell;

/// Maximum number of dirty rectangles tracked before we coalesce.
pub const MAX_DIRTY_RECTS: usize = 32;

/// When a coalesced union covers more than this fraction of the screen
/// (numerator/denominator = 3/4), escalate to a full-screen repaint.
const ESCALATE_NUM: i64 = 3;
const ESCALATE_DEN: i64 = 4;

/// Axis-aligned rectangle in framebuffer coordinates.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Rect {
    pub x: i32,
    pub y: i32,
    pub w: i32,
    pub h: i32,
}

impl Rect {
    pub const fn new(x: i32, y: i32, w: i32, h: i32) -> Self {
        Self { x, y, w, h }
    }

    /// True if this rect has zero or negative area.
    pub fn is_empty(&self) -> bool {
        self.w <= 0 || self.h <= 0
    }

    /// True if the two rects share any pixels.
    pub fn intersects(&self, other: &Rect) -> bool {
        if self.is_empty() || other.is_empty() {
            return false;
        }
        let ax0 = self.x;
        let ay0 = self.y;
        let ax1 = self.x + self.w;
        let ay1 = self.y + self.h;
        let bx0 = other.x;
        let by0 = other.y;
        let bx1 = other.x + other.w;
        let by1 = other.y + other.h;
        ax0 < bx1 && bx0 < ax1 && ay0 < by1 && by0 < ay1
    }

    /// Smallest rectangle covering both `self` and `other`. Empty
    /// rectangles are treated as the identity element.
    pub fn union(&self, other: &Rect) -> Rect {
        if self.is_empty() {
            return *other;
        }
        if other.is_empty() {
            return *self;
        }
        let x0 = self.x.min(other.x);
        let y0 = self.y.min(other.y);
        let x1 = (self.x + self.w).max(other.x + other.w);
        let y1 = (self.y + self.h).max(other.y + other.h);
        Rect { x: x0, y: y0, w: x1 - x0, h: y1 - y0 }
    }

    /// Area in pixels as i64 to avoid i32 overflow on 4K+ framebuffers.
    pub fn area(&self) -> i64 {
        if self.is_empty() {
            0
        } else {
            self.w as i64 * self.h as i64
        }
    }
}

/// Fixed-capacity collection of dirty rectangles. Once full, the last
/// entry absorbs new additions via union (lossy but safe).
pub struct DamageRegion {
    rects: [Rect; MAX_DIRTY_RECTS],
    count: usize,
    fullscreen: bool,
    /// Cached screen area for escalation heuristic. 0 means unknown
    /// (no escalation -- keep coalescing into the last slot).
    screen_area: i64,
}

impl DamageRegion {
    pub const fn new() -> Self {
        Self {
            rects: [Rect { x: 0, y: 0, w: 0, h: 0 }; MAX_DIRTY_RECTS],
            count: 0,
            fullscreen: false,
            screen_area: 0,
        }
    }

    /// Cache the framebuffer dimensions so we can escalate to a
    /// fullscreen repaint when coalesced damage covers most of it.
    pub fn set_screen_size(&mut self, width: u32, height: u32) {
        self.screen_area = width as i64 * height as i64;
    }

    /// Add a dirty rectangle. Skips empty rects. If the rect list is
    /// full, the new rect is unioned with the last entry. If the
    /// coalesced union would cover most of the screen, escalates to
    /// `fullscreen = true` instead.
    pub fn add_rect(&mut self, r: Rect) {
        if self.fullscreen || r.is_empty() {
            return;
        }

        if self.count < MAX_DIRTY_RECTS {
            self.rects[self.count] = r;
            self.count += 1;
            return;
        }

        // Full: coalesce with the last slot.
        let last = self.rects[MAX_DIRTY_RECTS - 1].union(&r);

        // Escalation: if the union now covers >=3/4 of the framebuffer,
        // drop the rect list and mark fullscreen.
        if self.screen_area > 0 && last.area() * ESCALATE_DEN >= self.screen_area * ESCALATE_NUM {
            self.add_fullscreen();
            return;
        }

        self.rects[MAX_DIRTY_RECTS - 1] = last;
    }

    /// Mark the entire screen dirty. Clears the rect list since a
    /// fullscreen repaint supersedes any subset of rectangles.
    pub fn add_fullscreen(&mut self) {
        self.fullscreen = true;
        self.count = 0;
    }

    /// True if no damage is pending.
    pub fn is_clean(&self) -> bool {
        self.count == 0 && !self.fullscreen
    }

    /// True if a full-screen repaint is pending.
    pub fn is_fullscreen(&self) -> bool {
        self.fullscreen
    }

    /// Valid slice of currently tracked rects (empty if fullscreen).
    pub fn rects(&self) -> &[Rect] {
        &self.rects[..self.count]
    }

    /// Reset to clean state.
    pub fn clear(&mut self) {
        self.count = 0;
        self.fullscreen = false;
    }
}

// ---------------------------------------------------------------------------
// Global singleton + thin wrappers
// ---------------------------------------------------------------------------

static REGION: SyncUnsafeCell<DamageRegion> = SyncUnsafeCell::new(DamageRegion::new());

/// SAFETY: the compositor is single-threaded. All accessors below rely
/// on this invariant, matching the rest of `main.rs`.

pub fn set_screen_size(width: u32, height: u32) {
    unsafe { (*REGION.get()).set_screen_size(width, height) }
}

pub fn add_rect(x: i32, y: i32, w: i32, h: i32) {
    unsafe { (*REGION.get()).add_rect(Rect::new(x, y, w, h)) }
}

pub fn add_fullscreen() {
    unsafe { (*REGION.get()).add_fullscreen() }
}

pub fn is_clean() -> bool {
    unsafe { (*REGION.get()).is_clean() }
}

/// Snapshot the current damage state and reset to clean. Returns
/// `(rects_buffer, valid_count, fullscreen_flag)`. When `fullscreen` is
/// true, callers should ignore the rects and repaint everything.
pub fn take_dirty() -> ([Rect; MAX_DIRTY_RECTS], usize, bool) {
    unsafe {
        let r = &mut *REGION.get();
        let snapshot = r.rects;
        let count = r.count;
        let fullscreen = r.fullscreen;
        r.clear();
        (snapshot, count, fullscreen)
    }
}

// ---------------------------------------------------------------------------
// Unit tests (host-only: gated on `test` cfg so the no_std kernel build is
// unaffected).
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rect_is_empty() {
        assert!(Rect::new(0, 0, 0, 10).is_empty());
        assert!(Rect::new(0, 0, 10, 0).is_empty());
        assert!(Rect::new(0, 0, -1, 10).is_empty());
        assert!(!Rect::new(0, 0, 1, 1).is_empty());
    }

    #[test]
    fn rect_intersects_basic() {
        let a = Rect::new(0, 0, 10, 10);
        let b = Rect::new(5, 5, 10, 10);
        let c = Rect::new(20, 20, 5, 5);
        assert!(a.intersects(&b));
        assert!(b.intersects(&a));
        assert!(!a.intersects(&c));
    }

    #[test]
    fn rect_intersects_edge_touch_is_not_overlap() {
        let a = Rect::new(0, 0, 10, 10);
        let b = Rect::new(10, 0, 10, 10); // touches a's right edge
        assert!(!a.intersects(&b));
    }

    #[test]
    fn rect_intersects_empty_never() {
        let a = Rect::new(0, 0, 10, 10);
        let empty = Rect::new(5, 5, 0, 0);
        assert!(!a.intersects(&empty));
    }

    #[test]
    fn rect_union_covers_both() {
        let a = Rect::new(0, 0, 10, 10);
        let b = Rect::new(20, 20, 5, 5);
        let u = a.union(&b);
        assert_eq!(u, Rect::new(0, 0, 25, 25));
    }

    #[test]
    fn rect_union_with_empty_is_identity() {
        let a = Rect::new(3, 4, 5, 6);
        let empty = Rect::new(0, 0, 0, 0);
        assert_eq!(a.union(&empty), a);
        assert_eq!(empty.union(&a), a);
    }

    #[test]
    fn region_starts_clean() {
        let r = DamageRegion::new();
        assert!(r.is_clean());
        assert!(!r.is_fullscreen());
        assert_eq!(r.rects().len(), 0);
    }

    #[test]
    fn region_add_rect_accumulates() {
        let mut r = DamageRegion::new();
        r.add_rect(Rect::new(0, 0, 10, 10));
        r.add_rect(Rect::new(20, 20, 5, 5));
        assert!(!r.is_clean());
        assert_eq!(r.rects().len(), 2);
    }

    #[test]
    fn region_add_empty_is_noop() {
        let mut r = DamageRegion::new();
        r.add_rect(Rect::new(0, 0, 0, 0));
        assert!(r.is_clean());
    }

    #[test]
    fn region_fullscreen_wipes_rects() {
        let mut r = DamageRegion::new();
        r.add_rect(Rect::new(0, 0, 10, 10));
        r.add_fullscreen();
        assert!(r.is_fullscreen());
        assert!(!r.is_clean());
        assert_eq!(r.rects().len(), 0);
    }

    #[test]
    fn region_fullscreen_ignores_further_rects() {
        let mut r = DamageRegion::new();
        r.add_fullscreen();
        r.add_rect(Rect::new(0, 0, 10, 10));
        assert_eq!(r.rects().len(), 0);
        assert!(r.is_fullscreen());
    }

    #[test]
    fn region_clear_resets_state() {
        let mut r = DamageRegion::new();
        r.add_fullscreen();
        r.clear();
        assert!(r.is_clean());
        assert!(!r.is_fullscreen());
    }

    #[test]
    fn region_coalesces_when_full() {
        let mut r = DamageRegion::new();
        r.set_screen_size(10_000, 10_000); // escalation effectively disabled
        for i in 0..MAX_DIRTY_RECTS {
            r.add_rect(Rect::new(i as i32, i as i32, 2, 2));
        }
        assert_eq!(r.rects().len(), MAX_DIRTY_RECTS);
        // The (MAX+1)-th rect must be absorbed into the last slot.
        r.add_rect(Rect::new(1000, 1000, 2, 2));
        assert_eq!(r.rects().len(), MAX_DIRTY_RECTS);
        let last = r.rects()[MAX_DIRTY_RECTS - 1];
        // Last slot must now cover (1000,1000,2,2) and the original
        // (MAX-1, MAX-1, 2, 2) -- i.e. start at (MAX-1, MAX-1).
        assert_eq!(last.x, (MAX_DIRTY_RECTS - 1) as i32);
        assert_eq!(last.y, (MAX_DIRTY_RECTS - 1) as i32);
        // And it must extend to cover the far rect.
        assert!(last.x + last.w >= 1002);
        assert!(last.y + last.h >= 1002);
        assert!(!r.is_fullscreen());
    }

    #[test]
    fn region_escalates_to_fullscreen_when_coalesced_covers_most_of_screen() {
        let mut r = DamageRegion::new();
        r.set_screen_size(100, 100); // area = 10_000
        for _ in 0..MAX_DIRTY_RECTS {
            r.add_rect(Rect::new(0, 0, 1, 1));
        }
        // One more push whose union with the last slot covers >=3/4.
        r.add_rect(Rect::new(0, 0, 100, 100));
        assert!(r.is_fullscreen());
    }
}
