//! Deception profiles define what the attacker sees after migration.
//!
//! Each profile describes a fake environment: what files exist, what
//! network services respond, what processes appear to run. The
//! interposition engine consults the active profile to generate
//! convincing fake responses.

use crate::interpose::InterpositionAction;

/// Maximum fake file entries in a profile.
pub const MAX_FAKE_FILES: usize = 32;

/// Maximum fake network services in a profile.
pub const MAX_FAKE_SERVICES: usize = 16;

/// A named deception profile.
pub struct DeceptionProfile {
    /// Profile name (e.g., "honeypot-web", "tarpit-ssh").
    pub name: [u8; 32],
    /// Fake file system entries.
    pub files: [FakeFile; MAX_FAKE_FILES],
    pub file_count: usize,
    /// Fake network services.
    pub services: [FakeService; MAX_FAKE_SERVICES],
    pub service_count: usize,
    /// Default action for capabilities not explicitly mapped.
    pub default_action: InterpositionAction,
}

/// A fake file that appears to exist in the deception environment.
#[derive(Clone, Copy)]
pub struct FakeFile {
    /// Object ID that this fake file replaces.
    pub object_id: u64,
    /// Fake content (first 64 bytes; longer files need chaining).
    pub content: [u8; 64],
    /// Actual length of the fake content.
    pub content_len: u16,
    /// Permissions to report (Unix mode bits).
    pub mode: u16,
}

impl FakeFile {
    pub const fn empty() -> Self {
        Self {
            object_id: 0,
            content: [0; 64],
            content_len: 0,
            mode: 0o644,
        }
    }
}

/// A fake network service that responds to connections.
#[derive(Clone, Copy)]
pub struct FakeService {
    /// Port number.
    pub port: u16,
    /// Protocol (6 = TCP, 17 = UDP).
    pub protocol: u8,
    /// Banner to send on connect (first 48 bytes).
    pub banner: [u8; 48],
    /// Banner length.
    pub banner_len: u8,
}

impl FakeService {
    pub const fn empty() -> Self {
        Self {
            port: 0,
            protocol: 0,
            banner: [0; 48],
            banner_len: 0,
        }
    }
}

impl DeceptionProfile {
    pub const fn empty() -> Self {
        Self {
            name: [0; 32],
            files: [FakeFile::empty(); MAX_FAKE_FILES],
            file_count: 0,
            services: [FakeService::empty(); MAX_FAKE_SERVICES],
            service_count: 0,
            default_action: InterpositionAction::EmptySuccess,
        }
    }

    /// Create a profile with a name.
    pub fn with_name(name: &[u8]) -> Self {
        let mut p = Self::empty();
        let len = core::cmp::min(name.len(), 32);
        p.name[..len].copy_from_slice(&name[..len]);
        p
    }

    /// Add a fake file to the profile. Returns false if full.
    pub fn add_file(&mut self, object_id: u64, content: &[u8], mode: u16) -> bool {
        if self.file_count >= MAX_FAKE_FILES {
            return false;
        }
        let mut f = FakeFile::empty();
        f.object_id = object_id;
        let len = core::cmp::min(content.len(), 64);
        f.content[..len].copy_from_slice(&content[..len]);
        f.content_len = len as u16;
        f.mode = mode;
        self.files[self.file_count] = f;
        self.file_count += 1;
        true
    }

    /// Add a fake network service. Returns false if full.
    pub fn add_service(&mut self, port: u16, protocol: u8, banner: &[u8]) -> bool {
        if self.service_count >= MAX_FAKE_SERVICES {
            return false;
        }
        let mut s = FakeService::empty();
        s.port = port;
        s.protocol = protocol;
        let len = core::cmp::min(banner.len(), 48);
        s.banner[..len].copy_from_slice(&banner[..len]);
        s.banner_len = len as u8;
        self.services[self.service_count] = s;
        self.service_count += 1;
        true
    }

    /// Look up a fake file by object ID.
    pub fn lookup_file(&self, object_id: u64) -> Option<&FakeFile> {
        for i in 0..self.file_count {
            if self.files[i].object_id == object_id {
                return Some(&self.files[i]);
            }
        }
        None
    }

    /// Look up a fake service by port.
    pub fn lookup_service(&self, port: u16) -> Option<&FakeService> {
        for i in 0..self.service_count {
            if self.services[i].port == port {
                return Some(&self.services[i]);
            }
        }
        None
    }
}

// ---------------------------------------------------------------------------
// Minimal profile registry — runtime list of available deception profiles.
//
// This is intentionally tiny: name + `active` bit per entry. It is the
// source of truth for the `arm` builtin (`services/sotsh/src/builtins/arm.rs`)
// which reaches init via the `"deception"` IPC service (see
// `docs/sotsh-ipc-protocols.md` Part B). The full deception machinery
// (fake files, fake services, migration orchestrator) lives elsewhere
// and is driven by `deception_demo.rs`; this registry only advertises
// which builtin profiles exist and which one is currently armed.
// ---------------------------------------------------------------------------

/// Number of builtin profiles known at compile time. Must match the
/// submodule list in `profiles/mod.rs`.
pub const BUILTIN_PROFILE_COUNT: usize = 4;

/// Single entry in the profile registry. Names are NUL-padded in a
/// fixed 32-byte buffer; `name_len` stores the significant byte count so
/// IPC replies know how much to send without scanning for the NUL.
#[derive(Clone, Copy)]
pub struct ProfileEntry {
    pub name: [u8; 32],
    pub name_len: u8,
    pub active: bool,
}

impl ProfileEntry {
    pub const fn empty() -> Self {
        Self {
            name: [0; 32],
            name_len: 0,
            active: false,
        }
    }

    /// Construct from a compile-time name (truncated to 32 bytes).
    pub const fn from_static(name: &'static [u8]) -> Self {
        let mut buf = [0u8; 32];
        let len = if name.len() < 32 { name.len() } else { 32 };
        let mut i = 0;
        while i < len {
            buf[i] = name[i];
            i += 1;
        }
        Self {
            name: buf,
            name_len: len as u8,
            active: false,
        }
    }

    /// Returns the name as a byte slice up to `name_len`.
    pub fn name_bytes(&self) -> &[u8] {
        &self.name[..self.name_len as usize]
    }
}

/// Minimal runtime registry of builtin deception profiles. Owns the
/// `active` bit; does **not** own the full `DeceptionProfile` body (that
/// is constructed lazily by the submodules in `profiles/*` when a
/// profile is actually armed).
pub struct ProfileRegistry {
    entries: [ProfileEntry; BUILTIN_PROFILE_COUNT],
}

impl ProfileRegistry {
    /// Construct the canonical builtin registry. Profile names match the
    /// submodule list at `profiles/mod.rs:6-9`. All profiles start
    /// inactive; callers flip `active` via `set_active()` when they
    /// install a profile (see `deception_demo.rs`).
    pub const fn with_builtins() -> Self {
        Self {
            entries: [
                ProfileEntry::from_static(b"ubuntu_webserver"),
                ProfileEntry::from_static(b"centos_database"),
                ProfileEntry::from_static(b"iot_device"),
                ProfileEntry::from_static(b"windows_workstation"),
            ],
        }
    }

    /// Number of entries currently tracked.
    pub const fn len(&self) -> usize {
        BUILTIN_PROFILE_COUNT
    }

    /// Access entry by index. Returns `None` if out of range.
    pub fn get(&self, index: usize) -> Option<&ProfileEntry> {
        self.entries.get(index)
    }

    /// Iterate over `(index, entry)` pairs.
    pub fn iter(&self) -> impl Iterator<Item = (usize, &ProfileEntry)> {
        self.entries.iter().enumerate()
    }

    /// Mark a profile by its exact name as active (or inactive). Returns
    /// `true` if a match was found.
    pub fn set_active(&mut self, name: &[u8], active: bool) -> bool {
        for e in &mut self.entries {
            if e.name_bytes() == name {
                e.active = active;
                return true;
            }
        }
        false
    }

    /// Set the active flag by index. No-op if out of range.
    pub fn set_active_at(&mut self, index: usize, active: bool) {
        if let Some(e) = self.entries.get_mut(index) {
            e.active = active;
        }
    }
}

impl Default for ProfileRegistry {
    fn default() -> Self {
        Self::with_builtins()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn profile_name() {
        let p = DeceptionProfile::with_name(b"honeypot-web");
        assert_eq!(&p.name[..12], b"honeypot-web");
    }

    #[test]
    fn add_and_lookup_file() {
        let mut p = DeceptionProfile::empty();
        assert!(p.add_file(0xF001, b"root:x:0:0:root:/root:/bin/bash\n", 0o640));
        let f = p.lookup_file(0xF001).unwrap();
        assert_eq!(f.content_len, 32);
        assert_eq!(f.mode, 0o640);
        assert!(p.lookup_file(0xF002).is_none());
    }

    #[test]
    fn add_and_lookup_service() {
        let mut p = DeceptionProfile::empty();
        assert!(p.add_service(22, 6, b"SSH-2.0-OpenSSH_8.9\r\n"));
        let s = p.lookup_service(22).unwrap();
        assert_eq!(s.protocol, 6);
        assert_eq!(s.banner_len, 21);
    }

    #[test]
    fn registry_has_four_builtins() {
        let r = ProfileRegistry::with_builtins();
        assert_eq!(r.len(), 4);
        let names: [&[u8]; 4] = [
            b"ubuntu_webserver",
            b"centos_database",
            b"iot_device",
            b"windows_workstation",
        ];
        for (i, want) in names.iter().enumerate() {
            let e = r.get(i).unwrap();
            assert_eq!(e.name_bytes(), *want);
            assert!(!e.active);
        }
    }

    #[test]
    fn registry_set_active_by_name() {
        let mut r = ProfileRegistry::with_builtins();
        assert!(r.set_active(b"ubuntu_webserver", true));
        assert!(r.get(0).unwrap().active);
        assert!(!r.set_active(b"nonexistent", true));
    }

    #[test]
    fn registry_set_active_at_index() {
        let mut r = ProfileRegistry::with_builtins();
        r.set_active_at(2, true);
        assert!(r.get(2).unwrap().active);
        r.set_active_at(99, true); // out of range no-op
    }

    #[test]
    fn registry_iter() {
        let r = ProfileRegistry::with_builtins();
        let count = r.iter().count();
        assert_eq!(count, 4);
        let first = r.iter().next().unwrap();
        assert_eq!(first.0, 0);
    }
}
