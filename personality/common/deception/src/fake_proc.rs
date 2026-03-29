//! Synthetic /proc entries for deception.
//!
//! Provides a fake process list and spoofed /proc virtual files so that
//! an attacker sees a convincing Ubuntu-like system with expected services.

use crate::{DeceptionError, MAX_FAKE_PROCS, MAX_FIELD_LEN};

/// A single fake process entry visible in `ps` / `/proc`.
#[derive(Clone)]
pub struct FakeProcess {
    pub pid: u32,
    pub ppid: u32,
    /// Process name (e.g., "apache2", "mysqld").
    name: [u8; 64],
    name_len: usize,
    /// User who owns the process (e.g., "www-data", "mysql").
    user: [u8; 32],
    user_len: usize,
    /// Fake RSS in KiB.
    pub rss_kb: u32,
    /// Fake virtual size in KiB.
    pub vsz_kb: u32,
    /// State character: S=sleeping, R=running, etc.
    pub state: u8,
}

impl FakeProcess {
    const fn empty() -> Self {
        Self {
            pid: 0,
            ppid: 0,
            name: [0u8; 64],
            name_len: 0,
            user: [0u8; 32],
            user_len: 0,
            rss_kb: 0,
            vsz_kb: 0,
            state: b'S',
        }
    }

    /// Process name as a byte slice.
    pub fn name(&self) -> &[u8] {
        &self.name[..self.name_len]
    }

    /// User name as a byte slice.
    pub fn user(&self) -> &[u8] {
        &self.user[..self.user_len]
    }
}

/// Manages a synthetic process list and /proc spoofing strings.
pub struct FakeProcessList {
    procs: [Option<FakeProcess>; MAX_FAKE_PROCS],
    proc_count: usize,

    /// Spoofed /proc/version content.
    version: [u8; MAX_FIELD_LEN],
    version_len: usize,

    /// Spoofed /proc/cpuinfo model name.
    cpu_model: [u8; MAX_FIELD_LEN],
    cpu_model_len: usize,

    /// Number of fake CPU cores.
    pub cpu_cores: u32,

    /// Spoofed total memory in KiB.
    pub mem_total_kb: u64,

    /// Spoofed free memory in KiB.
    pub mem_free_kb: u64,
}

const NONE_PROC: Option<FakeProcess> = None;

impl FakeProcessList {
    /// Create a new empty process list with default /proc values.
    pub const fn new() -> Self {
        Self {
            procs: [NONE_PROC; MAX_FAKE_PROCS],
            proc_count: 0,
            version: [0u8; MAX_FIELD_LEN],
            version_len: 0,
            cpu_model: [0u8; MAX_FIELD_LEN],
            cpu_model_len: 0,
            cpu_cores: 4,
            mem_total_kb: 8_000_000,
            mem_free_kb: 4_500_000,
        }
    }

    /// Set the spoofed /proc/version string.
    pub fn set_version(&mut self, v: &[u8]) -> Result<(), DeceptionError> {
        if v.len() > MAX_FIELD_LEN {
            return Err(DeceptionError::FieldTooLong);
        }
        self.version[..v.len()].copy_from_slice(v);
        self.version_len = v.len();
        Ok(())
    }

    /// Get the spoofed /proc/version string.
    pub fn version(&self) -> &[u8] {
        &self.version[..self.version_len]
    }

    /// Set the spoofed CPU model name for /proc/cpuinfo.
    pub fn set_cpu_model(&mut self, m: &[u8]) -> Result<(), DeceptionError> {
        if m.len() > MAX_FIELD_LEN {
            return Err(DeceptionError::FieldTooLong);
        }
        self.cpu_model[..m.len()].copy_from_slice(m);
        self.cpu_model_len = m.len();
        Ok(())
    }

    /// Get the spoofed CPU model name.
    pub fn cpu_model(&self) -> &[u8] {
        &self.cpu_model[..self.cpu_model_len]
    }

    /// Add a fake process. Returns the slot index.
    pub fn add_process(
        &mut self,
        pid: u32,
        ppid: u32,
        name: &[u8],
        user: &[u8],
        rss_kb: u32,
        vsz_kb: u32,
        state: u8,
    ) -> Result<usize, DeceptionError> {
        if name.len() > 64 || user.len() > 32 {
            return Err(DeceptionError::FieldTooLong);
        }
        for (i, slot) in self.procs.iter_mut().enumerate() {
            if slot.is_none() {
                let mut p = FakeProcess::empty();
                p.pid = pid;
                p.ppid = ppid;
                p.name[..name.len()].copy_from_slice(name);
                p.name_len = name.len();
                p.user[..user.len()].copy_from_slice(user);
                p.user_len = user.len();
                p.rss_kb = rss_kb;
                p.vsz_kb = vsz_kb;
                p.state = state;
                *slot = Some(p);
                self.proc_count += 1;
                return Ok(i);
            }
        }
        Err(DeceptionError::TableFull)
    }

    /// Remove the fake process at `index`.
    pub fn remove_process(&mut self, index: usize) -> Result<(), DeceptionError> {
        if index >= MAX_FAKE_PROCS {
            return Err(DeceptionError::NotFound);
        }
        if self.procs[index].is_none() {
            return Err(DeceptionError::NotFound);
        }
        self.procs[index] = None;
        self.proc_count -= 1;
        Ok(())
    }

    /// Look up a fake process by PID.
    pub fn find_by_pid(&self, pid: u32) -> Option<&FakeProcess> {
        self.procs.iter().flatten().find(|p| p.pid == pid)
    }

    /// Iterate over all fake processes.
    pub fn iter_processes(&self) -> impl Iterator<Item = &FakeProcess> {
        self.procs.iter().flatten()
    }

    /// Number of fake processes.
    pub fn process_count(&self) -> usize {
        self.proc_count
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn add_and_find_process() {
        let mut list = FakeProcessList::new();
        list.add_process(1, 0, b"systemd", b"root", 12000, 170000, b'S')
            .unwrap();
        list.add_process(1234, 1, b"apache2", b"www-data", 45000, 320000, b'S')
            .unwrap();

        let p = list.find_by_pid(1234).unwrap();
        assert_eq!(p.name(), b"apache2");
        assert_eq!(p.user(), b"www-data");
        assert_eq!(p.rss_kb, 45000);

        assert!(list.find_by_pid(9999).is_none());
    }

    #[test]
    fn spoofed_version() {
        let mut list = FakeProcessList::new();
        list.set_version(
            b"Linux version 5.15.0-88-generic (buildd@lcy02-amd64-045) (gcc 11.4.0, GNU ld 2.38)",
        )
        .unwrap();
        assert!(list.version().starts_with(b"Linux version 5.15.0"));
    }
}
