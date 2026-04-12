use crate::syscall::*;

// ---------------------------------------------------------------------------
// Command history
// ---------------------------------------------------------------------------

pub const HIST_SIZE: usize = 64;
pub const HIST_LINE_LEN: usize = 256;

/// Path used by save_to_vfs / load_from_vfs. Lives in root's home so it
/// survives across shell restarts (ObjectStore is the persistent FS).
pub const HIST_FILE: &[u8] = b"/root/.lucas_history\0";

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
// Persistent history — /root/.lucas_history
// ---------------------------------------------------------------------------
//
// File format: one command per line (LF-terminated), most-recent last. We
// cap the file to the last 1000 entries on save, which is a safety net for
// the eventual ring expansion (today HIST_SIZE is only 64 anyway).

const HIST_FILE_CAP: usize = 1000;

/// Serialize the in-memory ring to the persistence file via VFS write.
/// Called on shell exit. Silently no-ops on any I/O failure — we must never
/// panic out of the exit path.
pub fn save_to_vfs() {
    // O_WRONLY(1) | O_CREAT(0x40) | O_TRUNC(0x200) = 0x241
    let fd = linux_open(HIST_FILE.as_ptr(), 0x241);
    if fd < 0 { return; }

    let count = history_count();
    // If somehow we exceed the cap, skip the oldest entries.
    let start = if count > HIST_FILE_CAP { count - HIST_FILE_CAP } else { 0 };

    for i in start..count {
        if let Some(entry) = history_get(i) {
            if !entry.is_empty() {
                let _ = linux_write(fd as u64, entry.as_ptr(), entry.len());
                let lf: u8 = b'\n';
                let _ = linux_write(fd as u64, &lf as *const u8, 1);
            }
        }
    }
    linux_close(fd as u64);
}

/// Load the persistence file into the history ring, appending each line.
/// Silently no-ops when the file does not exist (first run).
pub fn load_from_vfs() {
    let fd = linux_open(HIST_FILE.as_ptr(), 0);
    if fd < 0 { return; }

    // Read the whole file in one gulp. Ring holds at most HIST_SIZE * HIST_LINE_LEN
    // bytes of content — sizing the scratch to match is plenty.
    let mut buf = [0u8; HIST_SIZE * HIST_LINE_LEN];
    let mut total: usize = 0;
    loop {
        let room = buf.len() - total;
        if room == 0 { break; }
        let n = linux_read(fd as u64, buf[total..].as_mut_ptr(), room);
        if n <= 0 { break; }
        total += n as usize;
    }
    linux_close(fd as u64);

    // Split on LF and feed each line to `history_add`. Empty lines are skipped
    // by history_add itself.
    let mut start: usize = 0;
    let mut i: usize = 0;
    while i < total {
        if buf[i] == b'\n' {
            if i > start {
                history_add(&buf[start..i]);
            }
            start = i + 1;
        }
        i += 1;
    }
    // Trailing unterminated line (shouldn't happen given save_to_vfs always
    // writes LF, but handle it for user-edited files).
    if start < total {
        history_add(&buf[start..total]);
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
