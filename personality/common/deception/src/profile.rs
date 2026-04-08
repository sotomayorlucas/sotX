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
}
