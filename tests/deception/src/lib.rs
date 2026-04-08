//! Deception engine tests for sotBSD.
//!
//! These tests verify that the deception system correctly fabricates
//! OS personalities, maintains cross-channel consistency, and resists
//! fingerprinting and detection attempts.

mod fingerprint_detect;
mod consistency;
mod migration;

// ---------------------------------------------------------------------------
// Deception test infrastructure
// ---------------------------------------------------------------------------

/// A fabricated file entry in a deception profile.
#[derive(Debug, Clone)]
pub struct FakeFile {
    pub path: String,
    pub content: String,
    pub mode: u32,
}

impl FakeFile {
    /// Returns the file size (derived from content length).
    pub fn size(&self) -> u64 {
        self.content.len() as u64
    }
}

/// A fabricated process entry in a deception profile.
#[derive(Debug, Clone)]
pub struct FakeProcess {
    pub pid: u32,
    pub name: String,
    pub user: String,
    pub cmdline: String,
}

/// A deception profile for testing.
#[derive(Debug, Clone)]
pub struct TestProfile {
    pub name: String,
    pub hostname: String,
    pub os_release: String,
    pub kernel_version: String,
    pub files: Vec<FakeFile>,
    pub processes: Vec<FakeProcess>,
}

impl TestProfile {
    /// Create a minimal Ubuntu 22.04 test profile.
    pub fn ubuntu_2204() -> Self {
        Self {
            name: "ubuntu-22.04-test".into(),
            hostname: "test-host".into(),
            os_release: "Ubuntu 22.04.3 LTS".into(),
            kernel_version: "5.15.0-88-generic".into(),
            files: vec![
                FakeFile {
                    path: "/etc/os-release".into(),
                    content: "NAME=\"Ubuntu\"\nVERSION=\"22.04.3 LTS\"\nID=ubuntu\n".into(),
                    mode: 0o644,
                },
                FakeFile {
                    path: "/etc/hostname".into(),
                    content: "test-host\n".into(),
                    mode: 0o644,
                },
            ],
            processes: vec![
                FakeProcess { pid: 1, name: "/sbin/init".into(), user: "root".into(), cmdline: "/sbin/init".into() },
                FakeProcess { pid: 423, name: "/usr/sbin/sshd".into(), user: "root".into(), cmdline: "/usr/sbin/sshd -D".into() },
            ],
        }
    }
}

/// Verify that a profile's files are internally consistent.
pub fn verify_profile_consistency(profile: &TestProfile) -> Vec<String> {
    let mut errors = Vec::new();

    // Check hostname consistency
    let hostname_file = profile.files.iter().find(|f| f.path == "/etc/hostname");
    if let Some(f) = hostname_file {
        let file_hostname = f.content.trim();
        if file_hostname != profile.hostname {
            errors.push(format!(
                "/etc/hostname ({}) does not match profile hostname ({})",
                file_hostname, profile.hostname
            ));
        }
    }

    // Check os-release consistency
    let os_release = profile.files.iter().find(|f| f.path == "/etc/os-release");
    if let Some(f) = os_release {
        if !f.content.contains("ubuntu") && profile.os_release.contains("Ubuntu") {
            errors.push(
                "/etc/os-release ID does not match profile OS".into()
            );
        }
    }

    // Verify file sizes are non-zero (empty content is suspicious)
    for file in &profile.files {
        if file.size() == 0 {
            errors.push(format!("{}: file has empty content", file.path));
        }
    }

    errors
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ubuntu_profile_is_consistent() {
        let profile = TestProfile::ubuntu_2204();
        let errors = verify_profile_consistency(&profile);
        assert!(
            errors.is_empty(),
            "profile consistency errors: {:?}",
            errors
        );
    }

    #[test]
    fn detect_hostname_mismatch() {
        let mut profile = TestProfile::ubuntu_2204();
        profile.hostname = "wrong-host".into();
        let errors = verify_profile_consistency(&profile);
        assert!(!errors.is_empty(), "should detect hostname mismatch");
    }
}
