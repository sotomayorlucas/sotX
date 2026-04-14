//! In-memory command history for the sotSh REPL (B4c).
//!
//! Replaces the implicit history that `rustyline` provided before the B1
//! `no_std` port. Backed by an `alloc::collections::VecDeque<String>` with
//! a fixed cap so the shell never unboundedly consumes its bump heap.
//!
//! **Persistence status:** as of B1.5e, `vfs_write` exists alongside
//! `vfs_open`/`vfs_read`/`vfs_close`, so `save_to` persists history to
//! the VFS (newline-terminated, oldest-to-newest). `load_from` is
//! symmetric with the save path.

extern crate alloc;

use alloc::collections::VecDeque;
use alloc::string::String;
use alloc::vec::Vec;

use sotos_common::linux_abi::{O_CREAT, O_TRUNC, O_WRONLY};
use sotos_common::vfs;

/// Default ring capacity (matches rustyline's historical default).
pub const DEFAULT_MAX_LEN: usize = 1000;

/// Command history ring + cursor for up/down navigation.
///
/// Newest line is at `lines.front()`. `cursor` holds the currently-focused
/// index (`None` means "past the newest entry"; the line editor shows the
/// in-progress buffer in that state).
pub struct History {
    lines: VecDeque<String>,
    max_len: usize,
    cursor: Option<usize>,
    dirty: bool,
}

/// Write every byte of `buf` to `fd`, looping across VFS_WRITE chunks.
/// Returns an errno on any IPC error or short write stall.
fn write_all(fd: u64, buf: &[u8]) -> Result<(), i64> {
    let mut written = 0usize;
    while written < buf.len() {
        let n = vfs::vfs_write(fd, &buf[written..])?;
        if n == 0 {
            return Err(-5); // EIO — server accepted but wrote nothing.
        }
        written += n;
    }
    Ok(())
}

impl History {
    pub fn new() -> Self {
        Self {
            lines: VecDeque::new(),
            max_len: DEFAULT_MAX_LEN,
            cursor: None,
            dirty: false,
        }
    }

    /// Number of recorded entries.
    pub fn len(&self) -> usize {
        self.lines.len()
    }

    pub fn is_empty(&self) -> bool {
        self.lines.is_empty()
    }

    /// Push a new line. Consecutive duplicates are coalesced (matches the
    /// rustyline default) and empty lines are dropped. Navigation cursor
    /// is always reset after an append.
    pub fn add(&mut self, line: String) {
        if line.is_empty() {
            self.cursor = None;
            return;
        }
        if self.lines.front() == Some(&line) {
            self.cursor = None;
            return;
        }
        if self.lines.len() >= self.max_len {
            self.lines.pop_back();
        }
        self.lines.push_front(line);
        self.cursor = None;
        self.dirty = true;
    }

    /// Reset navigation state without clearing the stored lines. Called by
    /// the editor when the user starts editing a fresh line.
    pub fn reset_cursor(&mut self) {
        self.cursor = None;
    }

    /// Move cursor towards older entries (up arrow). Returns the line at
    /// the new cursor position, or `None` when the history is empty.
    pub fn prev(&mut self) -> Option<&str> {
        if self.lines.is_empty() {
            return None;
        }
        let next = match self.cursor {
            None => 0,
            Some(i) if i + 1 < self.lines.len() => i + 1,
            Some(i) => i, // already at the oldest entry — stay put
        };
        self.cursor = Some(next);
        self.lines.get(next).map(|s| s.as_str())
    }

    /// Move cursor towards newer entries (down arrow). Returns the new
    /// line, or `None` when the cursor walks past the most recent entry
    /// (the editor should restore whatever the user was typing).
    pub fn next(&mut self) -> Option<&str> {
        match self.cursor {
            None => None,
            Some(0) => {
                self.cursor = None;
                None
            }
            Some(i) => {
                let new = i - 1;
                self.cursor = Some(new);
                self.lines.get(new).map(|s| s.as_str())
            }
        }
    }

    /// Whether there are unsaved additions (useful once `save_to` works).
    pub fn is_dirty(&self) -> bool {
        self.dirty
    }

    /// Load history lines from a VFS file (one line per entry, newline
    /// separated). Missing files return an error the caller can ignore on
    /// first boot.
    pub fn load_from(&mut self, path: &[u8]) -> Result<(), i64> {
        let open = vfs::vfs_open(path, 0)?; // O_RDONLY = 0
        // Guard against absurd sizes so a corrupt file can't exhaust the
        // bump heap.
        const MAX_BYTES: usize = 128 * 1024;
        let want = (open.size as usize).min(MAX_BYTES);
        let mut buf: Vec<u8> = Vec::new();
        buf.resize(want, 0);
        let read = vfs::vfs_read(open.fd, &mut buf).unwrap_or(0);
        let _ = vfs::vfs_close(open.fd);
        buf.truncate(read);

        for slice in buf.split(|&b| b == b'\n') {
            if slice.is_empty() {
                continue;
            }
            if let Ok(s) = core::str::from_utf8(slice) {
                if self.lines.len() >= self.max_len {
                    self.lines.pop_back();
                }
                self.lines.push_front(String::from(s));
            }
        }
        self.cursor = None;
        self.dirty = false;
        Ok(())
    }

    /// Persist history to `path` via the VFS IPC server. Lines are
    /// written oldest-first, newline-separated. Truncates any existing
    /// file.
    pub fn save_to(&self, path: &[u8]) -> Result<(), i64> {
        let flags = (O_WRONLY | O_CREAT | O_TRUNC) as u64;
        let open = vfs::vfs_open(path, flags)?;
        // `lines` is newest-first; walk in reverse so the on-disk order
        // matches what `load_from` expects.
        let mut err: Option<i64> = None;
        for line in self.lines.iter().rev() {
            if let Err(e) = write_all(open.fd, line.as_bytes()) {
                err = Some(e);
                break;
            }
            if let Err(e) = write_all(open.fd, b"\n") {
                err = Some(e);
                break;
            }
        }
        let close_res = vfs::vfs_close(open.fd);
        if let Some(e) = err { return Err(e); }
        close_res
    }
}

impl Default for History {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::string::ToString;

    #[test]
    fn add_dedupes_consecutive() {
        let mut h = History::new();
        h.add("ls".to_string());
        h.add("ls".to_string());
        h.add("pwd".to_string());
        assert_eq!(h.len(), 2);
    }

    #[test]
    fn add_ignores_empty() {
        let mut h = History::new();
        h.add(String::new());
        assert!(h.is_empty());
    }

    #[test]
    fn prev_and_next_walk_entries() {
        let mut h = History::new();
        h.add("a".to_string());
        h.add("b".to_string());
        h.add("c".to_string());
        assert_eq!(h.prev(), Some("c"));
        assert_eq!(h.prev(), Some("b"));
        assert_eq!(h.prev(), Some("a"));
        assert_eq!(h.prev(), Some("a")); // clamp at oldest
        assert_eq!(h.next(), Some("b"));
        assert_eq!(h.next(), Some("c"));
        assert_eq!(h.next(), None);
    }

    #[test]
    fn ring_drops_oldest_past_cap() {
        let mut h = History::new();
        h.max_len = 2;
        h.add("a".to_string());
        h.add("b".to_string());
        h.add("c".to_string());
        assert_eq!(h.len(), 2);
        assert_eq!(h.prev(), Some("c"));
        assert_eq!(h.prev(), Some("b"));
        assert_eq!(h.prev(), Some("b"));
    }
}
