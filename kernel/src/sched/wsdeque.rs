//! Chase-Lev work-stealing deque.
//!
//! Lock-free single-producer / multi-consumer deque per:
//!
//!   Lê, Pop, Cohen, Nardelli — *Correct and Efficient Work-Stealing for
//!   Weak Memory Models*, PPoPP 2013.
//!
//! ## API
//!
//! - `push(handle)` — owner-only, single-producer enqueue at the bottom.
//! - `pop()`        — owner-only dequeue at the bottom (LIFO for cache warmth).
//! - `steal()`      — any thief dequeues from the top (FIFO from the producer's
//!   perspective, gives stealers the oldest work).
//!
//! ## Properties (proved in `formal/chase_lev.tla`)
//!
//! - **Linearizability**: every successful pop/steal corresponds to a unique
//!   prior push.
//! - **No lost task**: every pushed value is either still in the deque, in
//!   `deq_history`, or in some thread's `local` scratch.
//! - **No spurious steal**: a successful steal CAS only succeeds when the
//!   loaded handle was authored by a real push linearized before the CAS.
//!
//! ## Memory ordering
//!
//! On x86-TSO most of these compile to plain `mov`, but the spelled-out
//! orderings prevent **compiler** reordering and keep the implementation
//! portable to weakly-ordered ISAs (the TLA+ model uses an explicit
//! per-owner store buffer to model TSO).
//!
//! | Op    | Step                          | Ordering           |
//! |-------|-------------------------------|--------------------|
//! | push  | `b = bottom.load`             | Relaxed            |
//! | push  | `t = top.load` (size check)   | Acquire            |
//! | push  | `buf[b & MASK].store(h)`      | Relaxed            |
//! | push  | `bottom.store(b+1)`           | Release            |
//! | pop   | `bottom.store(b-1)`           | Relaxed            |
//! | pop   | `fence(SeqCst)` (mfence)      | **load-bearing**   |
//! | pop   | `t = top.load`                | Relaxed            |
//! | pop   | CAS `top: t → t+1` (size==1)  | success SeqCst     |
//! | pop   | `bottom.store(b)` (restore)   | Relaxed            |
//! | steal | `t = top.load`                | Acquire            |
//! | steal | `b = bottom.load`             | Acquire            |
//! | steal | `buf[t & MASK].load`          | Relaxed (data dep) |
//! | steal | CAS `top: t → t+1`            | success Release    |
//!
//! The SeqCst fence between `bottom.store(b-1)` and `top.load` in `pop` is
//! the load-bearing piece: it prevents the owner's decrement from being
//! reordered past the read of `top`, which is what allows the
//! single-element pop/steal race to be resolved correctly.
//!
//! ## Capacity & overflow
//!
//! Capacity is a fixed power of two (`CAP = 128`). On overflow `push`
//! returns `Err(Overflow)` and the caller falls back to the global ready
//! queue — the value is never silently dropped.
//!
//! ## ABA
//!
//! The buffer stores `PoolHandle::raw()` (12-bit generation + 20-bit slot
//! index). When the owner-pop or thief-steal returns a handle, the
//! caller validates it via `Pool::get(handle)`, which rejects stale
//! references to recycled slots. There is no ABA on `top`/`bottom`
//! themselves because they are 64-bit monotonic counters that never wrap
//! in any realistic kernel lifetime.

use crate::pool::PoolHandle;
use core::cell::UnsafeCell;
use core::sync::atomic::{fence, AtomicIsize, AtomicU32, Ordering};

/// Buffer capacity per deque. Must be a power of two so `& MASK` indexes.
pub const CAP: usize = 128;
const MASK: isize = (CAP as isize) - 1;

/// Sentinel returned by `steal`/`pop`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Steal<T> {
    /// Deque was empty when observed.
    Empty,
    /// Successfully removed `T` from the deque.
    Success(T),
    /// Lost a CAS race; caller should retry on the same deque.
    Retry,
}

/// Returned by `push` when the deque is full.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Overflow;

/// Single-producer / multi-consumer Chase-Lev deque.
///
/// The owner CPU calls `push` and `pop`; any other CPU may call `steal`.
/// `top` and `bottom` are aligned to (and padded out to) a 64-byte cache
/// line each so the owner's frequent writes to `bottom` do not contend
/// with thieves' reads/CAS of `top`.
#[repr(C, align(64))]
pub struct WsDeque {
    /// Thief end. Monotonic; only thieves CAS it forward, owner reads it.
    top: AtomicIsize,
    _pad0: [u8; 64 - core::mem::size_of::<AtomicIsize>()],
    /// Owner end. Owner stores; thieves only read.
    bottom: AtomicIsize,
    _pad1: [u8; 64 - core::mem::size_of::<AtomicIsize>()],
    /// Ring buffer of packed `PoolHandle::raw()` values.
    buf: UnsafeCell<[AtomicU32; CAP]>,
}

// SAFETY: All access to `buf` goes through atomic operations on its
// `AtomicU32` slots; the `top`/`bottom` indices serialize which slots are
// readable by which thread per the Chase-Lev linearization argument.
unsafe impl Sync for WsDeque {}

impl WsDeque {
    /// Construct an empty deque. `const` so `static` arrays of deques are
    /// possible without an initializer phase.
    pub const fn new() -> Self {
        // `[AtomicU32::new(0); CAP]` requires Copy, which AtomicU32 isn't.
        // Use a const initializer.
        const ZERO: AtomicU32 = AtomicU32::new(0);
        Self {
            top: AtomicIsize::new(0),
            _pad0: [0; 64 - core::mem::size_of::<AtomicIsize>()],
            bottom: AtomicIsize::new(0),
            _pad1: [0; 64 - core::mem::size_of::<AtomicIsize>()],
            buf: UnsafeCell::new([ZERO; CAP]),
        }
    }

    /// Approximate length. Diagnostic only — not synchronized.
    #[allow(dead_code)]
    pub fn len_hint(&self) -> isize {
        let b = self.bottom.load(Ordering::Relaxed);
        let t = self.top.load(Ordering::Relaxed);
        b - t
    }

    /// Owner-only enqueue at the bottom.
    ///
    /// Called only by the CPU that owns this deque, so we treat `bottom`
    /// stores as single-producer. Returns `Err(Overflow)` when the deque
    /// is full; the caller is responsible for falling back to the global
    /// ready queue so the value is never lost.
    pub fn push(&self, handle: PoolHandle) -> Result<(), Overflow> {
        let b = self.bottom.load(Ordering::Relaxed);
        let t = self.top.load(Ordering::Acquire);
        if b - t >= CAP as isize {
            return Err(Overflow);
        }
        // SAFETY: only the owner ever writes `buf[b & MASK]` while
        // `b == bottom`; thieves cannot observe this slot until the
        // subsequent `bottom.store(b+1, Release)` publishes it.
        unsafe {
            let slot = &(*self.buf.get())[(b & MASK) as usize];
            slot.store(handle.raw(), Ordering::Relaxed);
        }
        // Release publishes both the slot write and the bottom advance.
        self.bottom.store(b + 1, Ordering::Release);
        Ok(())
    }

    /// Owner-only dequeue at the bottom (LIFO).
    ///
    /// Returns `Steal::Success` on a normal pop, `Steal::Empty` when the
    /// deque is empty, and `Steal::Retry` when the single-element CAS
    /// race against a concurrent steal was lost. The caller may retry
    /// or move on to the next priority class / victim.
    pub fn pop(&self) -> Steal<PoolHandle> {
        let b = self.bottom.load(Ordering::Relaxed) - 1;
        // Tentatively claim the bottom slot.
        self.bottom.store(b, Ordering::Relaxed);

        // Load-bearing fence: prevents the bottom decrement from being
        // reordered past the top load. On x86 this is `mfence`; on
        // weaker ISAs it is the linchpin of the Lê 2013 correctness
        // argument.
        fence(Ordering::SeqCst);

        let t = self.top.load(Ordering::Relaxed);

        if t > b {
            // Empty: restore bottom and report empty.
            self.bottom.store(b + 1, Ordering::Relaxed);
            return Steal::Empty;
        }

        // SAFETY: indices in `[t, b]` are owned by us until we either
        // commit or release them via `top` or `bottom` updates.
        let raw = unsafe {
            let slot = &(*self.buf.get())[(b & MASK) as usize];
            slot.load(Ordering::Relaxed)
        };

        if t < b {
            // More than one element: the popped slot is exclusively ours,
            // no race possible.
            return Steal::Success(PoolHandle::from_raw(raw));
        }

        // Exactly one element: race with concurrent stealers on `top`.
        // We must CAS `top` from `t` to `t+1` to claim it.
        let won = self
            .top
            .compare_exchange(t, t + 1, Ordering::SeqCst, Ordering::Relaxed)
            .is_ok();

        // Either way, restore `bottom` to `t+1` so the deque is empty
        // from the owner's perspective.
        self.bottom.store(t + 1, Ordering::Relaxed);

        if won {
            Steal::Success(PoolHandle::from_raw(raw))
        } else {
            // Lost the CAS to a stealer: the value the stealer took is
            // the one we read into `raw`, so from this thread's view the
            // deque is now empty (no work for us).
            Steal::Empty
        }
    }

    /// Thief dequeue at the top.
    ///
    /// Any CPU other than the owner may call this. Returns `Steal::Empty`
    /// when the deque is empty, `Steal::Retry` when the CAS lost to a
    /// concurrent steal or owner pop, or `Steal::Success` on a successful
    /// theft.
    pub fn steal(&self) -> Steal<PoolHandle> {
        let t = self.top.load(Ordering::Acquire);
        // Acquire pairs with the owner's `bottom.store(.., Release)` in
        // push, so we can never read a buf slot whose write is not yet
        // visible.
        let b = self.bottom.load(Ordering::Acquire);

        if t >= b {
            return Steal::Empty;
        }

        // SAFETY: data dependency from `t` to the buf load means we
        // observe at least the value written by the owner's push that
        // bumped bottom past `t`.
        let raw = unsafe {
            let slot = &(*self.buf.get())[(t & MASK) as usize];
            slot.load(Ordering::Relaxed)
        };

        // Try to claim the slot by advancing `top`.
        if self
            .top
            .compare_exchange(t, t + 1, Ordering::SeqCst, Ordering::Relaxed)
            .is_ok()
        {
            Steal::Success(PoolHandle::from_raw(raw))
        } else {
            // Lost: another thief or the owner's single-element pop took it.
            Steal::Retry
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn h(idx: u32) -> PoolHandle {
        // Generation 0, slot = idx (assumes idx < 2^20).
        PoolHandle::from_raw(idx)
    }

    #[test]
    fn empty_deque_pops_empty() {
        let d = WsDeque::new();
        assert_eq!(d.pop(), Steal::Empty);
        assert_eq!(d.steal(), Steal::Empty);
    }

    #[test]
    fn lifo_single_thread() {
        let d = WsDeque::new();
        for i in 0..10 {
            d.push(h(i)).unwrap();
        }
        // pop() is LIFO from the bottom.
        for i in (0..10).rev() {
            match d.pop() {
                Steal::Success(handle) => assert_eq!(handle, h(i)),
                other => panic!("expected Success({:?}), got {:?}", i, other),
            }
        }
        assert_eq!(d.pop(), Steal::Empty);
    }

    #[test]
    fn fifo_steal_order() {
        let d = WsDeque::new();
        for i in 0..10 {
            d.push(h(i)).unwrap();
        }
        // steal() takes from the top → FIFO order.
        for i in 0..10 {
            match d.steal() {
                Steal::Success(handle) => assert_eq!(handle, h(i)),
                other => panic!("expected Success({:?}), got {:?}", i, other),
            }
        }
        assert_eq!(d.steal(), Steal::Empty);
    }

    #[test]
    fn overflow_returns_err() {
        let d = WsDeque::new();
        for i in 0..CAP as u32 {
            d.push(h(i)).expect("should fit");
        }
        assert_eq!(d.push(h(999)), Err(Overflow));
        // Drain it and confirm capacity is restored.
        for _ in 0..CAP {
            assert!(matches!(d.pop(), Steal::Success(_)));
        }
        d.push(h(42)).expect("should fit again after drain");
    }

    #[test]
    fn pop_then_steal_single_element() {
        // The classic single-element race; tested single-threaded so the
        // CAS must succeed and steal must observe Empty afterwards.
        let d = WsDeque::new();
        d.push(h(7)).unwrap();
        match d.pop() {
            Steal::Success(handle) => assert_eq!(handle, h(7)),
            other => panic!("expected Success(7), got {:?}", other),
        }
        assert_eq!(d.steal(), Steal::Empty);
    }

    #[test]
    fn interleaved_push_pop_steal() {
        let d = WsDeque::new();
        d.push(h(1)).unwrap();
        d.push(h(2)).unwrap();
        d.push(h(3)).unwrap();
        // Owner takes the bottom (LIFO): 3
        assert_eq!(d.pop(), Steal::Success(h(3)));
        // Thief takes the top (FIFO): 1
        assert_eq!(d.steal(), Steal::Success(h(1)));
        // Owner takes the only remaining: 2 (single-element CAS path)
        assert_eq!(d.pop(), Steal::Success(h(2)));
        assert_eq!(d.pop(), Steal::Empty);
        assert_eq!(d.steal(), Steal::Empty);
    }
}
