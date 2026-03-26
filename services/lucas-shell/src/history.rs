use crate::syscall::*;

// ---------------------------------------------------------------------------
// Command history
// ---------------------------------------------------------------------------

pub const HIST_SIZE: usize = 64;
pub const HIST_LINE_LEN: usize = 256;

pub struct HistEntry {
    pub data: [u8; HIST_LINE_LEN],
    pub len: usize,
}

impl HistEntry {
    pub const fn empty() -> Self {
        Self { data: [0; HIST_LINE_LEN], len: 0 }
    }
}

pub static mut HISTORY: [HistEntry; HIST_SIZE] = {
    const INIT: HistEntry = HistEntry::empty();
    [INIT; HIST_SIZE]
};
pub static mut HIST_COUNT: usize = 0;
pub static mut HIST_WRITE: usize = 0; // next write index (circular)

#[allow(dead_code)]
pub fn history_slice() -> &'static [HistEntry] {
    unsafe { core::slice::from_raw_parts(core::ptr::addr_of!(HISTORY) as *const HistEntry, HIST_SIZE) }
}

pub fn history_add(line: &[u8]) {
    if line.is_empty() { return; }
    unsafe {
        let idx = HIST_WRITE;
        let entry = &mut (*core::ptr::addr_of_mut!(HISTORY))[idx];
        let l = line.len().min(HIST_LINE_LEN);
        entry.data[..l].copy_from_slice(&line[..l]);
        entry.len = l;
        HIST_WRITE = (HIST_WRITE + 1) % HIST_SIZE;
        if HIST_COUNT < HIST_SIZE { HIST_COUNT += 1; }
    }
}

pub fn history_count() -> usize {
    unsafe { HIST_COUNT }
}

pub fn history_get(index: usize) -> Option<&'static [u8]> {
    let count = history_count();
    if index >= count { return None; }
    unsafe {
        // oldest entry is at (HIST_WRITE - count + index) mod HIST_SIZE
        let actual = (HIST_WRITE + HIST_SIZE - count + index) % HIST_SIZE;
        let entry = &(*core::ptr::addr_of!(HISTORY))[actual];
        Some(&entry.data[..entry.len])
    }
}

// ---------------------------------------------------------------------------
// History command
// ---------------------------------------------------------------------------

pub fn cmd_history() {
    let count = history_count();
    for i in 0..count {
        if let Some(entry) = history_get(i) {
            // Print index (1-based)
            let idx = i + 1;
            if idx < 10 { print(b"   "); }
            else if idx < 100 { print(b"  "); }
            else { print(b" "); }
            print_u64(idx as u64);
            print(b"  ");
            print(entry);
            print(b"\n");
        }
    }
}
