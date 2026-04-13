//! Synthetic filesystem overlays for deception.
//!
//! An `FsOverlay` maps paths to fake content and can hide real paths.
//! When a compromised domain reads `/etc/os-release`, the overlay returns
//! "Ubuntu 22.04.3 LTS" instead of the real sotX identity.

use crate::{
    DeceptionError, MAX_CONTENT_LEN, MAX_FS_OVERLAYS, MAX_HIDDEN_PATHS, MAX_PATH_LEN,
};

/// A single path-to-content mapping in the overlay.
#[derive(Clone)]
pub struct FsOverlayEntry {
    /// The path being overlaid (e.g., "/etc/os-release").
    path: [u8; MAX_PATH_LEN],
    path_len: usize,
    /// The synthetic content returned when this path is read.
    content: [u8; MAX_CONTENT_LEN],
    content_len: usize,
    /// If true, the entry represents a directory rather than a file.
    pub is_dir: bool,
}

impl FsOverlayEntry {
    const fn empty() -> Self {
        Self {
            path: [0u8; MAX_PATH_LEN],
            path_len: 0,
            content: [0u8; MAX_CONTENT_LEN],
            content_len: 0,
            is_dir: false,
        }
    }

    /// The path as a byte slice.
    pub fn path(&self) -> &[u8] {
        &self.path[..self.path_len]
    }

    /// The content as a byte slice.
    pub fn content(&self) -> &[u8] {
        &self.content[..self.content_len]
    }
}

/// A hidden-path entry -- reads to this path return ENOENT.
#[derive(Clone)]
struct HiddenPath {
    path: [u8; MAX_PATH_LEN],
    path_len: usize,
}

impl HiddenPath {
    const fn empty() -> Self {
        Self {
            path: [0u8; MAX_PATH_LEN],
            path_len: 0,
        }
    }
}

/// Overlay filesystem for deception.
///
/// Provides path-to-content overrides and a set of hidden paths.
/// All storage is inline (fixed arrays), no heap required for the table.
pub struct FsOverlay {
    entries: [Option<FsOverlayEntry>; MAX_FS_OVERLAYS],
    entry_count: usize,
    hidden: [Option<HiddenPath>; MAX_HIDDEN_PATHS],
    hidden_count: usize,
    /// Fake total disk size in bytes (returned by statfs).
    pub fake_disk_total: u64,
    /// Fake free disk space in bytes.
    pub fake_disk_free: u64,
}

// `Option<FsOverlayEntry>` is too large for `[None; N]` const init, so we
// use a helper to build the default arrays.
const NONE_ENTRY: Option<FsOverlayEntry> = None;
const NONE_HIDDEN: Option<HiddenPath> = None;

impl FsOverlay {
    /// Create an empty overlay.
    pub const fn new() -> Self {
        Self {
            entries: [NONE_ENTRY; MAX_FS_OVERLAYS],
            entry_count: 0,
            hidden: [NONE_HIDDEN; MAX_HIDDEN_PATHS],
            hidden_count: 0,
            fake_disk_total: 500_000_000_000, // 500 GB
            fake_disk_free: 350_000_000_000,  // 350 GB
        }
    }

    /// Add a path-to-content override. Returns the slot index.
    pub fn add_entry(
        &mut self,
        path: &[u8],
        content: &[u8],
        is_dir: bool,
    ) -> Result<usize, DeceptionError> {
        if path.len() > MAX_PATH_LEN {
            return Err(DeceptionError::PathTooLong);
        }
        if content.len() > MAX_CONTENT_LEN {
            return Err(DeceptionError::ContentTooLong);
        }
        for (i, slot) in self.entries.iter_mut().enumerate() {
            if slot.is_none() {
                let mut entry = FsOverlayEntry::empty();
                entry.path[..path.len()].copy_from_slice(path);
                entry.path_len = path.len();
                entry.content[..content.len()].copy_from_slice(content);
                entry.content_len = content.len();
                entry.is_dir = is_dir;
                *slot = Some(entry);
                self.entry_count += 1;
                return Ok(i);
            }
        }
        Err(DeceptionError::TableFull)
    }

    /// Remove the overlay entry at `index`.
    pub fn remove_entry(&mut self, index: usize) -> Result<(), DeceptionError> {
        if index >= MAX_FS_OVERLAYS {
            return Err(DeceptionError::NotFound);
        }
        if self.entries[index].is_none() {
            return Err(DeceptionError::NotFound);
        }
        self.entries[index] = None;
        self.entry_count -= 1;
        Ok(())
    }

    /// Look up a path in the overlay. Returns the content if found.
    pub fn lookup(&self, path: &[u8]) -> Option<&[u8]> {
        for entry in self.entries.iter().flatten() {
            if entry.path() == path {
                return Some(entry.content());
            }
        }
        None
    }

    /// Add a path to the hidden set. Reads to hidden paths should return ENOENT.
    pub fn hide_path(&mut self, path: &[u8]) -> Result<usize, DeceptionError> {
        if path.len() > MAX_PATH_LEN {
            return Err(DeceptionError::PathTooLong);
        }
        for (i, slot) in self.hidden.iter_mut().enumerate() {
            if slot.is_none() {
                let mut hp = HiddenPath::empty();
                hp.path[..path.len()].copy_from_slice(path);
                hp.path_len = path.len();
                *slot = Some(hp);
                self.hidden_count += 1;
                return Ok(i);
            }
        }
        Err(DeceptionError::TableFull)
    }

    /// Check whether `path` is hidden.
    pub fn is_hidden(&self, path: &[u8]) -> bool {
        for hp in self.hidden.iter().flatten() {
            let stored = &hp.path[..hp.path_len];
            if stored == path {
                return true;
            }
            // Also hide children: /sot hides /sot/anything.
            if path.len() > hp.path_len
                && path[hp.path_len] == b'/'
                && &path[..hp.path_len] == stored
            {
                return true;
            }
        }
        false
    }

    /// Resolve a path: returns `Some(content)` for overlaid paths,
    /// `None` if the path is hidden (caller should return ENOENT),
    /// or falls through for unmodified paths.
    pub fn resolve(&self, path: &[u8]) -> FsResolveResult<'_> {
        if self.is_hidden(path) {
            return FsResolveResult::Hidden;
        }
        if let Some(content) = self.lookup(path) {
            return FsResolveResult::Override(content);
        }
        FsResolveResult::RealPath
    }

    /// Number of overlay entries.
    pub fn entry_count(&self) -> usize {
        self.entry_count
    }

    /// Number of hidden paths.
    pub fn hidden_count(&self) -> usize {
        self.hidden_count
    }
}

/// Result of resolving a path through the filesystem overlay.
#[derive(Debug, PartialEq, Eq)]
pub enum FsResolveResult<'a> {
    /// Path is overlaid -- return this content instead of the real file.
    Override(&'a [u8]),
    /// Path is hidden -- return ENOENT.
    Hidden,
    /// No overlay applies -- forward to the real filesystem.
    RealPath,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn overlay_lookup() {
        let mut fs = FsOverlay::new();
        let content = b"NAME=\"Ubuntu\"\nVERSION=\"22.04.3 LTS\"\n";
        fs.add_entry(b"/etc/os-release", content, false).unwrap();

        assert_eq!(fs.lookup(b"/etc/os-release"), Some(content.as_slice()));
        assert_eq!(fs.lookup(b"/etc/hostname"), None);
    }

    #[test]
    fn hidden_paths() {
        let mut fs = FsOverlay::new();
        fs.hide_path(b"/sot").unwrap();
        fs.hide_path(b"/etc/sot").unwrap();

        assert!(fs.is_hidden(b"/sot"));
        assert!(fs.is_hidden(b"/sot/config"));
        assert!(fs.is_hidden(b"/etc/sot"));
        assert!(!fs.is_hidden(b"/etc/passwd"));
    }

    #[test]
    fn resolve_precedence() {
        let mut fs = FsOverlay::new();
        fs.add_entry(b"/etc/hostname", b"webserver01", false).unwrap();
        fs.hide_path(b"/sot").unwrap();

        assert_eq!(
            fs.resolve(b"/etc/hostname"),
            FsResolveResult::Override(b"webserver01")
        );
        assert_eq!(fs.resolve(b"/sot/config"), FsResolveResult::Hidden);
        assert_eq!(fs.resolve(b"/var/log/syslog"), FsResolveResult::RealPath);
    }
}
