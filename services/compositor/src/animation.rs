//! Lightweight animation framework for the compositor.
//!
//! Provides interpolation between two `f32` values over a TSC-based
//! duration with selectable easing curves. The compositor allocates
//! animations from a fixed pool, ticks them every frame, and reads
//! the current value to drive things like focus-change title-bar
//! color crossfades and window-appear scale-up.
//!
//! # Design notes
//!
//! - Animations live in a fixed-size pool (`MAX_ANIMATIONS`) — there is no
//!   heap allocation. Slot indices are stable for the lifetime of the
//!   animation; callers can hand the index back to `get_mut` to read or
//!   re-arm an animation.
//! - Time is expressed in raw TSC ticks. Callers provide `now_tsc` so the
//!   module stays free of any direct dependency on the kernel clock.
//! - The math is `f32`-only and **does not** use `.powf()` / `.sqrt()`,
//!   which are not available in `no_std` without an external libm. The
//!   cubic easing curves are written out by hand as `(1 - t) * (1 - t) * (1 - t)`.
//! - Color blending operates per-channel on packed BGRA `u32` words.
//!   Alpha is left at `0xFF` so callers don't have to worry about
//!   premultiplication.
//!
//! Most of the public surface is unused in this PR — it's exercised by
//! the unit tests and will be wired into G3 (decorations) and the focus
//! crossfade in a follow-up.

#![allow(dead_code)]

use sotos_common::SyncUnsafeCell;

/// Maximum number of simultaneously-active animations across the
/// whole compositor.
pub const MAX_ANIMATIONS: usize = 32;

/// Easing curves supported by the animation framework. Input `t` is
/// normalized to `[0, 1]`; output is also `[0, 1]` (or close to it,
/// modulo `f32` rounding).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Easing {
    /// Identity: `f(t) = t`.
    Linear,
    /// Ease-out cubic: `f(t) = 1 - (1 - t)^3`. Fast start, slow end.
    EaseOut,
    /// Ease-in-out cubic. Symmetric S-curve.
    EaseInOut,
}

/// A single animation slot.
///
/// Animations are typically allocated via [`allocate`] but this struct
/// is also `Clone + Copy`, so it can be embedded directly in another
/// struct if a caller wants its own private animation without going
/// through the global pool.
#[derive(Clone, Copy, Debug)]
pub struct Animation {
    /// TSC timestamp at which the animation began. Set by `start`.
    pub start_tsc: u64,
    /// Total duration of the animation, in TSC ticks.
    pub duration_tsc: u64,
    /// Starting value (returned for `now < start_tsc`).
    pub from: f32,
    /// Target value (returned for `now >= start_tsc + duration_tsc`).
    pub to: f32,
    /// Easing curve to apply.
    pub easing: Easing,
    /// Whether this slot holds a live animation. Inactive slots return
    /// `from` from `value_at` and are eligible for re-allocation.
    pub active: bool,
}

impl Animation {
    /// Create a new, inactive animation. Useful as a `const` initializer
    /// for the global pool.
    pub const fn new() -> Self {
        Self {
            start_tsc: 0,
            duration_tsc: 0,
            from: 0.0,
            to: 0.0,
            easing: Easing::Linear,
            active: false,
        }
    }

    /// (Re)arm this animation to interpolate from `from` to `to` over
    /// `duration_tsc` ticks, starting at `now_tsc`.
    pub fn start(
        &mut self,
        from: f32,
        to: f32,
        duration_tsc: u64,
        easing: Easing,
        now_tsc: u64,
    ) {
        self.from = from;
        self.to = to;
        self.duration_tsc = duration_tsc;
        self.easing = easing;
        self.start_tsc = now_tsc;
        self.active = true;
    }

    /// Sample the animation at `now_tsc`.
    ///
    /// - If the animation is inactive, returns `from`.
    /// - If `now_tsc < start_tsc`, returns `from` (animation hasn't begun).
    /// - If `now_tsc >= start_tsc + duration_tsc`, returns `to`.
    /// - Otherwise lerps between `from` and `to` along the chosen easing curve.
    pub fn value_at(&self, now_tsc: u64) -> f32 {
        if !self.active {
            return self.from;
        }
        if now_tsc < self.start_tsc {
            return self.from;
        }
        let elapsed = now_tsc - self.start_tsc;
        if self.duration_tsc == 0 || elapsed >= self.duration_tsc {
            return self.to;
        }
        let t = (elapsed as f32) / (self.duration_tsc as f32);
        let eased = match self.easing {
            Easing::Linear => linear(t),
            Easing::EaseOut => ease_out(t),
            Easing::EaseInOut => ease_in_out(t),
        };
        self.from + (self.to - self.from) * eased
    }

    /// Returns `true` if this animation has reached its end (or was
    /// never active to begin with).
    pub fn is_done(&self, now_tsc: u64) -> bool {
        if !self.active {
            return true;
        }
        if self.duration_tsc == 0 {
            return true;
        }
        now_tsc >= self.start_tsc + self.duration_tsc
    }
}

// ---------------------------------------------------------------------------
// Easing functions
// ---------------------------------------------------------------------------

/// Identity easing.
pub fn linear(t: f32) -> f32 {
    t
}

/// Cubic ease-out: `1 - (1 - t)^3`. Hand-written cube avoids `powf`.
pub fn ease_out(t: f32) -> f32 {
    let inv = 1.0 - t;
    1.0 - inv * inv * inv
}

/// Cubic ease-in-out. Standard formulation:
/// - For `t < 0.5`: `4 * t^3`
/// - Otherwise:    `1 - (-2t + 2)^3 / 2`
pub fn ease_in_out(t: f32) -> f32 {
    if t < 0.5 {
        4.0 * t * t * t
    } else {
        let inv = -2.0 * t + 2.0;
        1.0 - (inv * inv * inv) * 0.5
    }
}

/// Linearly blend two BGRA colors with eased parameter `t`.
///
/// Each of the B/G/R channels is interpolated independently. The output
/// alpha is forced to `0xFF` regardless of the inputs to keep callers
/// out of the premultiplied-alpha business.
pub fn interpolate_color(from: u32, to: u32, t: f32) -> u32 {
    // Clamp so out-of-range easings (e.g. an over-shoot curve added later)
    // can't push channels past 0xFF and wrap.
    let t = t.clamp(0.0, 1.0);

    let blend = |shift: u32| -> u32 {
        let f = ((from >> shift) & 0xFF) as f32;
        let g = ((to >> shift) & 0xFF) as f32;
        (f + (g - f) * t) as u32 & 0xFF
    };

    let b = blend(0);
    let g = blend(8);
    let r = blend(16);
    0xFF000000 | (r << 16) | (g << 8) | b
}

// ---------------------------------------------------------------------------
// Global animation pool
// ---------------------------------------------------------------------------

/// Fixed-size pool of animation slots. Indexed by slot id.
static POOL: SyncUnsafeCell<[Animation; MAX_ANIMATIONS]> =
    SyncUnsafeCell::new([Animation::new(); MAX_ANIMATIONS]);

/// Allocate a free animation slot. Returns the slot index, or `None` if
/// the pool is full. The returned animation is marked `active = true`
/// with zero duration; the caller is expected to call `start()` (via
/// `get_mut`) to actually arm it.
pub fn allocate() -> Option<usize> {
    // SAFETY: single-threaded compositor; SyncUnsafeCell is the userspace
    // equivalent of `static mut`.
    let pool = unsafe { &mut *POOL.get() };
    for (idx, slot) in pool.iter_mut().enumerate() {
        if !slot.active {
            *slot = Animation::new();
            slot.active = true;
            return Some(idx);
        }
    }
    None
}

/// Borrow a previously-allocated animation slot mutably. Returns `None`
/// if `idx` is out of range.
pub fn get_mut(idx: usize) -> Option<&'static mut Animation> {
    if idx >= MAX_ANIMATIONS {
        return None;
    }
    // SAFETY: see `allocate`.
    let pool = unsafe { &mut *POOL.get() };
    Some(&mut pool[idx])
}

/// Tick the global pool, releasing any animation slots whose time has
/// elapsed. Callers should invoke this once per frame after sampling
/// the values they care about.
pub fn tick_all(now_tsc: u64) {
    // SAFETY: see `allocate`.
    let pool = unsafe { &mut *POOL.get() };
    for slot in pool.iter_mut() {
        if slot.active && slot.is_done(now_tsc) {
            slot.active = false;
        }
    }
}

/// Number of currently-active animation slots.
pub fn active_count() -> usize {
    // SAFETY: see `allocate`.
    let pool = unsafe { &*POOL.get() };
    let mut n = 0;
    for slot in pool.iter() {
        if slot.active {
            n += 1;
        }
    }
    n
}

// ---------------------------------------------------------------------------
// Window map/unmap tweens
// ---------------------------------------------------------------------------

/// Maximum simultaneous window tweens (one per toplevel slot).
pub const MAX_TWEENS: usize = 16;

/// Duration of map/unmap animations in TSC ticks (~150ms at 2 GHz).
pub const TWEEN_DURATION_TSC: u64 = 300_000_000;

/// The kind of window tween: appearing or disappearing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TweenKind {
    /// Window mapping in: alpha 0->1, scale 0.92->1.0
    MapIn,
    /// Window unmapping out: alpha 1->0, scale 1.0->0.92
    UnmapOut,
}

/// Per-toplevel animation state for map/unmap transitions.
#[derive(Clone, Copy, Debug)]
pub struct TweenState {
    /// Whether this slot is in use.
    pub active: bool,
    /// Index into the TOPLEVELS array.
    pub toplevel_idx: usize,
    /// Whether this is a map-in or unmap-out tween.
    pub kind: TweenKind,
    /// TSC timestamp when the tween started.
    pub start_tsc: u64,
    /// Total duration in TSC ticks.
    pub duration_tsc: u64,
}

impl TweenState {
    pub const fn empty() -> Self {
        Self {
            active: false,
            toplevel_idx: 0,
            kind: TweenKind::MapIn,
            start_tsc: 0,
            duration_tsc: 0,
        }
    }

    /// Compute the normalized progress `t` in [0.0, 1.0] with ease-out cubic.
    /// Returns the eased value: for MapIn this goes 0->1, for UnmapOut 1->0.
    pub fn progress(&self, now_tsc: u64) -> f32 {
        if !self.active || self.duration_tsc == 0 {
            return match self.kind {
                TweenKind::MapIn => 1.0,
                TweenKind::UnmapOut => 0.0,
            };
        }
        let elapsed = now_tsc.saturating_sub(self.start_tsc);
        let t = if elapsed >= self.duration_tsc {
            1.0
        } else {
            (elapsed as f32) / (self.duration_tsc as f32)
        };
        let eased = ease_out(t);
        match self.kind {
            TweenKind::MapIn => eased,         // 0 -> 1
            TweenKind::UnmapOut => 1.0 - eased, // 1 -> 0
        }
    }

    /// Whether this tween has completed.
    pub fn is_done(&self, now_tsc: u64) -> bool {
        if !self.active {
            return true;
        }
        if self.duration_tsc == 0 {
            return true;
        }
        now_tsc >= self.start_tsc + self.duration_tsc
    }
}

/// Fixed pool of window tweens.
static TWEENS: SyncUnsafeCell<[TweenState; MAX_TWEENS]> =
    SyncUnsafeCell::new([const { TweenState::empty() }; MAX_TWEENS]);

/// Cancel any active tween for the given toplevel.
fn cancel_for(tweens: &mut [TweenState; MAX_TWEENS], toplevel_idx: usize) {
    for tw in tweens.iter_mut() {
        if tw.active && tw.toplevel_idx == toplevel_idx {
            tw.active = false;
        }
    }
}

/// Allocate a tween slot for `toplevel_idx` with the given kind.
/// Cancels any prior tween for the same toplevel first.
/// Returns false only if the pool is full.
fn start_tween(toplevel_idx: usize, kind: TweenKind, now_tsc: u64) -> bool {
    let tweens = unsafe { &mut *TWEENS.get() };
    cancel_for(tweens, toplevel_idx);
    for tw in tweens.iter_mut() {
        if !tw.active {
            tw.active = true;
            tw.toplevel_idx = toplevel_idx;
            tw.kind = kind;
            tw.start_tsc = now_tsc;
            tw.duration_tsc = TWEEN_DURATION_TSC;
            return true;
        }
    }
    false
}

/// Start a map-in tween for the given toplevel index.
pub fn start_map_in(toplevel_idx: usize, now_tsc: u64) {
    let _ = start_tween(toplevel_idx, TweenKind::MapIn, now_tsc);
}

/// Start an unmap-out tween for the given toplevel index.
/// Returns true if the tween was successfully started.
pub fn start_unmap_out(toplevel_idx: usize, now_tsc: u64) -> bool {
    start_tween(toplevel_idx, TweenKind::UnmapOut, now_tsc)
}

/// Query the current alpha (0-255) and scale factor for a toplevel.
/// If no tween is active for that toplevel, returns (255, 1.0) (fully visible).
pub fn get_tween_values(toplevel_idx: usize, now_tsc: u64) -> (u8, f32) {
    let tweens = unsafe { &*TWEENS.get() };
    for tw in tweens.iter() {
        if tw.active && tw.toplevel_idx == toplevel_idx {
            let p = tw.progress(now_tsc);
            let alpha = (p * 255.0) as u8;
            let scale = 0.92 + p * 0.08;
            return (alpha, scale);
        }
    }
    (255, 1.0)
}

/// Tick all tweens: retire finished ones. Returns completed UnmapOut
/// toplevel indices (caller deactivates them) and whether any tweens
/// remain active (caller should keep repainting).
pub fn tick_tweens(now_tsc: u64) -> ([usize; MAX_TWEENS], usize, bool) {
    let tweens = unsafe { &mut *TWEENS.get() };
    let mut completed = [0usize; MAX_TWEENS];
    let mut count = 0;
    let mut still_active = false;
    for tw in tweens.iter_mut() {
        if !tw.active { continue; }
        if tw.is_done(now_tsc) {
            if tw.kind == TweenKind::UnmapOut && count < MAX_TWEENS {
                completed[count] = tw.toplevel_idx;
                count += 1;
            }
            tw.active = false;
        } else {
            still_active = true;
        }
    }
    (completed, count, still_active)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn approx(a: f32, b: f32) -> bool {
        let d = a - b;
        let abs = if d < 0.0 { -d } else { d };
        abs < 1e-5
    }

    #[test]
    fn linear_endpoints() {
        assert!(approx(linear(0.0), 0.0));
        assert!(approx(linear(0.5), 0.5));
        assert!(approx(linear(1.0), 1.0));
    }

    #[test]
    fn ease_out_endpoints() {
        assert!(approx(ease_out(0.0), 0.0));
        assert!(approx(ease_out(1.0), 1.0));
        // Ease-out should be above the linear midpoint at t=0.5.
        assert!(ease_out(0.5) > 0.5);
    }

    #[test]
    fn ease_in_out_endpoints() {
        assert!(approx(ease_in_out(0.0), 0.0));
        assert!(approx(ease_in_out(1.0), 1.0));
        assert!(approx(ease_in_out(0.5), 0.5));
    }

    #[test]
    fn value_at_inactive_returns_from() {
        let mut a = Animation::new();
        a.from = 7.0;
        a.to = 99.0;
        // Not active.
        assert!(approx(a.value_at(123), 7.0));
    }

    #[test]
    fn value_at_before_start() {
        let mut a = Animation::new();
        a.start(10.0, 20.0, 1000, Easing::Linear, 500);
        // Querying before start_tsc returns `from`.
        assert!(approx(a.value_at(100), 10.0));
    }

    #[test]
    fn value_at_after_end() {
        let mut a = Animation::new();
        a.start(10.0, 20.0, 1000, Easing::Linear, 0);
        assert!(approx(a.value_at(2000), 20.0));
        assert!(a.is_done(2000));
    }

    #[test]
    fn value_at_midpoint_linear() {
        let mut a = Animation::new();
        a.start(0.0, 100.0, 1000, Easing::Linear, 0);
        assert!(approx(a.value_at(500), 50.0));
    }

    #[test]
    fn value_at_zero_duration() {
        let mut a = Animation::new();
        a.start(1.0, 2.0, 0, Easing::Linear, 0);
        // Zero duration jumps straight to `to`.
        assert!(approx(a.value_at(0), 2.0));
        assert!(a.is_done(0));
    }

    #[test]
    fn interpolate_color_endpoints() {
        let from = 0xFF112233u32;
        let to = 0xFFAABBCCu32;
        assert_eq!(interpolate_color(from, to, 0.0), from);
        assert_eq!(interpolate_color(from, to, 1.0), to);
    }

    #[test]
    fn interpolate_color_midpoint() {
        let from = 0xFF000000u32;
        let to = 0xFFFFFFFFu32;
        let mid = interpolate_color(from, to, 0.5);
        // Each channel should be ~127.
        let b = mid & 0xFF;
        let g = (mid >> 8) & 0xFF;
        let r = (mid >> 16) & 0xFF;
        let a = (mid >> 24) & 0xFF;
        assert!(b >= 126 && b <= 128);
        assert!(g >= 126 && g <= 128);
        assert!(r >= 126 && r <= 128);
        assert_eq!(a, 0xFF);
    }

    #[test]
    fn interpolate_color_alpha_forced() {
        // Even if the inputs have alpha 0, the output is opaque.
        let mid = interpolate_color(0x00000000, 0x00FFFFFF, 0.5);
        assert_eq!(mid >> 24, 0xFF);
    }

    #[test]
    fn pool_allocate_and_release() {
        // Drain the pool fresh: tick_all with a huge value first.
        tick_all(u64::MAX);
        let before = active_count();
        let idx = allocate().expect("pool not full");
        assert_eq!(active_count(), before + 1);

        {
            let slot = get_mut(idx).expect("valid idx");
            slot.start(0.0, 1.0, 100, Easing::Linear, 0);
        }
        tick_all(u64::MAX);
        assert_eq!(active_count(), before);
    }
}
