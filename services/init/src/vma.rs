// ---------------------------------------------------------------------------
// VMA (Virtual Memory Area) tracking for /proc/self/maps + MAP_FIXED_NOREPLACE.
// Per memory-group VMA list. Sorted by start address, non-overlapping.
// ---------------------------------------------------------------------------

use crate::process::MAX_PROCS;

pub(crate) const MAX_VMAS: usize = 1024;

#[derive(Clone, Copy, PartialEq)]
#[repr(u8)]
pub(crate) enum VmaLabel {
    Anonymous = 0,
    Text = 1,
    Data = 2,
    Heap = 3,
    Stack = 4,
    Vdso = 5,
    Library = 6,
    /// PROT_NONE reservation — no physical frames allocated.
    Reservation = 7,
}

#[derive(Clone, Copy)]
pub(crate) struct Vma {
    pub start: u64,  // page-aligned, inclusive
    pub end: u64,    // page-aligned, exclusive
    pub prot: u8,    // PROT_READ=1 | PROT_WRITE=2 | PROT_EXEC=4
    pub flags: u8,   // MAP_PRIVATE=0x02, MAP_ANONYMOUS=0x20, etc.
    pub label: VmaLabel,
}

impl Vma {
    pub const fn empty() -> Self {
        Self { start: 0, end: 0, prot: 0, flags: 0, label: VmaLabel::Anonymous }
    }

    pub fn is_active(&self) -> bool {
        self.end > self.start
    }

    /// Format permission string: "rwxp" or "r-xp" etc.
    pub fn perm_str(&self) -> [u8; 4] {
        [
            if self.prot & 1 != 0 { b'r' } else { b'-' },
            if self.prot & 2 != 0 { b'w' } else { b'-' },
            if self.prot & 4 != 0 { b'x' } else { b'-' },
            if self.flags & 0x01 != 0 { b's' } else { b'p' }, // MAP_SHARED=1
        ]
    }

    pub fn label_str(&self) -> &'static [u8] {
        match self.label {
            VmaLabel::Anonymous => b"",
            VmaLabel::Text => b"[text]",
            VmaLabel::Data => b"[data]",
            VmaLabel::Heap => b"[heap]",
            VmaLabel::Stack => b"[stack]",
            VmaLabel::Vdso => b"[vdso]",
            VmaLabel::Library => b"",
            VmaLabel::Reservation => b"",
        }
    }
}

pub(crate) struct VmaList {
    pub entries: [Vma; MAX_VMAS],
    pub count: usize,
}

impl VmaList {
    pub const fn new() -> Self {
        Self {
            entries: [Vma::empty(); MAX_VMAS],
            count: 0,
        }
    }

    /// Insert a VMA. Maintains sorted order by start address.
    /// Returns true on success, false if full.
    pub fn insert(&mut self, start: u64, end: u64, prot: u8, flags: u8, label: VmaLabel) -> bool {
        if self.count >= MAX_VMAS || end <= start {
            if self.count >= MAX_VMAS {
                crate::framebuffer::print(b"VMA-FULL ");
                crate::framebuffer::print_u64(self.count as u64);
                crate::framebuffer::print(b" drop=");
                crate::framebuffer::print_hex64(start);
                crate::framebuffer::print(b"-");
                crate::framebuffer::print_hex64(end);
                crate::framebuffer::print(b"\n");
            }
            return false;
        }

        // Find insertion point (keep sorted by start)
        let mut pos = self.count;
        for i in 0..self.count {
            if start < self.entries[i].start {
                pos = i;
                break;
            }
        }

        // Shift entries right
        if pos < self.count {
            let mut i = self.count;
            while i > pos {
                self.entries[i] = self.entries[i - 1];
                i -= 1;
            }
        }

        self.entries[pos] = Vma { start, end, prot, flags, label };
        self.count += 1;
        true
    }

    /// Remove all VMAs that overlap [start, end). Split partially-overlapping ones.
    pub fn remove(&mut self, start: u64, end: u64) {
        let mut i = 0;
        while i < self.count {
            let vma = self.entries[i];
            if vma.end <= start || vma.start >= end {
                // No overlap
                i += 1;
                continue;
            }

            if vma.start >= start && vma.end <= end {
                // Fully contained — remove
                self.remove_at(i);
                // Don't increment i
                continue;
            }

            if vma.start < start && vma.end > end {
                // Hole punch — split into two
                // Left part: [vma.start, start)
                // Right part: [end, vma.end)
                self.entries[i].end = start;
                // Insert right part after
                if self.count < MAX_VMAS {
                    let right = Vma { start: end, end: vma.end, prot: vma.prot, flags: vma.flags, label: vma.label };
                    self.insert_at(i + 1, right);
                }
                i += 2;
                continue;
            }

            if vma.start < start {
                // Trim right side
                self.entries[i].end = start;
            } else {
                // Trim left side (vma.end > end)
                self.entries[i].start = end;
            }
            i += 1;
        }
    }

    /// Check if any VMA overlaps [start, end).
    pub fn overlaps(&self, start: u64, end: u64) -> bool {
        for i in 0..self.count {
            let vma = &self.entries[i];
            if vma.start >= end { break; } // sorted, no more overlaps
            if vma.end > start {
                return true;
            }
        }
        false
    }

    /// Find a free gap of at least `size` bytes, starting from `hint`.
    /// Returns the start address of the gap, or None.
    pub fn find_free(&self, size: u64, hint: u64) -> Option<u64> {
        let aligned_hint = (hint + 0xFFF) & !0xFFF;
        let aligned_size = (size + 0xFFF) & !0xFFF;

        // Check if [hint, hint+size) is free
        if !self.overlaps(aligned_hint, aligned_hint + aligned_size) {
            return Some(aligned_hint);
        }

        // Scan gaps between VMAs
        let mut prev_end = aligned_hint;
        for i in 0..self.count {
            let vma = &self.entries[i];
            if vma.end <= prev_end { continue; }
            let gap_start = if vma.start > prev_end { prev_end } else { vma.end };
            if vma.start > prev_end {
                let gap = vma.start - prev_end;
                if gap >= aligned_size {
                    return Some(prev_end);
                }
            }
            prev_end = vma.end;
        }

        // Gap after last VMA
        Some(prev_end)
    }

    /// Update protection bits for all VMAs overlapping [start, end).
    pub fn update_prot(&mut self, start: u64, end: u64, new_prot: u8) {
        for i in 0..self.count {
            let vma = &mut self.entries[i];
            if vma.start >= end { break; }
            if vma.end <= start { continue; }
            // Overlapping — update prot
            // For simplicity, update the whole VMA even if partially overlapping.
            // A more precise impl would split, but this is good enough.
            vma.prot = new_prot;
        }
    }

    /// Format VMAs as /proc/self/maps output into buf. Returns bytes written.
    pub fn format_maps(&self, buf: &mut [u8]) -> usize {
        let mut pos = 0;
        for i in 0..self.count {
            let vma = &self.entries[i];
            if !vma.is_active() { continue; }
            // Format: "start-end rwxp 00000000 00:00 0          label\n"
            let needed = 16 + 1 + 16 + 1 + 4 + 1 + 8 + 1 + 5 + 1 + 1 + 10 + 20 + 1; // rough max
            if pos + needed > buf.len() { break; }
            pos += write_hex(buf, pos, vma.start);
            buf[pos] = b'-'; pos += 1;
            pos += write_hex(buf, pos, vma.end);
            buf[pos] = b' '; pos += 1;
            let perms = vma.perm_str();
            buf[pos..pos + 4].copy_from_slice(&perms);
            pos += 4;
            buf[pos] = b' '; pos += 1;
            // offset, dev, inode
            let suffix = b"00000000 00:00 0";
            buf[pos..pos + suffix.len()].copy_from_slice(suffix);
            pos += suffix.len();
            let label = vma.label_str();
            if !label.is_empty() {
                // Pad to column 73 (Linux convention)
                let target_col = 73;
                // Each line started at 0, current width is pos since last \n
                let current_width = pos; // approximate
                let pad = if target_col > current_width { target_col - current_width } else { 1 };
                let pad = pad.min(buf.len() - pos - label.len() - 1);
                for j in 0..pad { buf[pos + j] = b' '; }
                pos += pad;
                buf[pos..pos + label.len()].copy_from_slice(label);
                pos += label.len();
            }
            buf[pos] = b'\n'; pos += 1;
        }
        pos
    }

    // --- Internal helpers ---

    fn remove_at(&mut self, idx: usize) {
        if idx >= self.count { return; }
        for i in idx..self.count - 1 {
            self.entries[i] = self.entries[i + 1];
        }
        self.entries[self.count - 1] = Vma::empty();
        self.count -= 1;
    }

    fn insert_at(&mut self, idx: usize, vma: Vma) {
        if self.count >= MAX_VMAS { return; }
        let mut i = self.count;
        while i > idx {
            self.entries[i] = self.entries[i - 1];
            i -= 1;
        }
        self.entries[idx] = vma;
        self.count += 1;
    }
}

/// Write a u64 as lowercase hex (no leading zeros, at least 1 digit) into buf at pos.
/// Returns number of bytes written.
fn write_hex(buf: &mut [u8], pos: usize, val: u64) -> usize {
    if val == 0 {
        buf[pos] = b'0';
        return 1;
    }
    let mut tmp = [0u8; 16];
    let mut n = 0;
    let mut v = val;
    while v > 0 {
        let d = (v & 0xF) as u8;
        tmp[n] = if d < 10 { b'0' + d } else { b'a' + d - 10 };
        n += 1;
        v >>= 4;
    }
    // Reverse into buf
    for i in 0..n {
        buf[pos + i] = tmp[n - 1 - i];
    }
    n
}

/// Per-group VMA lists. Indexed by memory group (same as THREAD_GROUPS).
pub(crate) static mut VMA_LISTS: [VmaList; MAX_PROCS] =
    [const { VmaList::new() }; MAX_PROCS];
