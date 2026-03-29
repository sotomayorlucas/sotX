//! Deception profiles -- pre-built system personas.
//!
//! A `DeceptionProfile` bundles filesystem overlays, fake processes, network
//! deception, and system spoofing into a coherent identity that an attacker
//! will perceive as real.
//!
//! Use `ProfileRegistry::with_builtins()` to get a registry pre-loaded with
//! all built-in profiles, or construct an empty one and register custom profiles.

use crate::fake_fs::FsOverlay;
use crate::fake_net::{HoneypotHandler, NetworkDeception, Protocol};
use crate::fake_proc::FakeProcessList;
use crate::profiles;

/// Paths that must be hidden from every deception profile to prevent
/// an attacker from discovering the real sotOS identity.
pub static COMMON_HIDDEN_PATHS: &[&[u8]] = &[
    b"/sot",
    b"/etc/sot",
    b"/etc/sotos",
    b"/boot/limine",
    b"/boot/limine.conf",
];

/// System-level spoofing configuration (uname, cpuinfo, memory).
pub struct SystemSpoofConfig {
    /// uname -s (e.g., "Linux").
    pub sysname: &'static [u8],
    /// uname -r (e.g., "5.15.0-88-generic").
    pub release: &'static [u8],
    /// uname -v (e.g., "#98-Ubuntu SMP ...").
    pub version: &'static [u8],
    /// uname -m (e.g., "x86_64").
    pub machine: &'static [u8],
    /// uname -n override (None = use network hostname).
    pub nodename: Option<&'static [u8]>,
    /// /proc/cpuinfo model name.
    pub cpu_model: &'static [u8],
}

/// Network portion of a deception profile, using static data for built-in profiles.
pub struct NetworkDeceptionConfig {
    pub hostname: &'static [u8],
    pub interfaces: &'static [StaticInterface],
    pub ports: &'static [StaticPort],
}

/// Static interface definition for built-in profiles.
pub struct StaticInterface {
    pub name: &'static [u8],
    pub ipv4: [u8; 4],
    pub netmask: [u8; 4],
    pub mac: [u8; 6],
}

/// Static port definition for built-in profiles.
pub struct StaticPort {
    pub port: u16,
    pub protocol: Protocol,
    pub banner: &'static [u8],
    pub handler: HoneypotHandler,
}

/// A complete deception profile.
pub struct DeceptionProfile {
    /// Profile name (e.g., "ubuntu-22.04-webserver").
    pub name: &'static str,
    /// Filesystem overlays: (path, content, is_dir).
    pub fs_overlays: &'static [(&'static [u8], &'static [u8], bool)],
    /// Paths to hide from the domain.
    pub hidden_paths: &'static [&'static [u8]],
    /// Fake process definitions: (pid, ppid, name, user, rss_kb, vsz_kb, state).
    pub fake_processes: &'static [(u32, u32, &'static [u8], &'static [u8], u32, u32, u8)],
    /// Network deception settings.
    pub network: NetworkDeceptionConfig,
    /// System-level spoofing (uname, etc.).
    pub system: SystemSpoofConfig,
}

impl DeceptionProfile {
    /// Apply this profile to live deception structures.
    ///
    /// Populates an `FsOverlay`, `FakeProcessList`, and `NetworkDeception`
    /// from the static profile data. Returns `Ok(())` if all entries fit.
    pub fn apply(
        &self,
        fs: &mut FsOverlay,
        procs: &mut FakeProcessList,
        net: &mut NetworkDeception,
    ) -> Result<(), crate::DeceptionError> {
        for &(path, content, is_dir) in self.fs_overlays {
            fs.add_entry(path, content, is_dir)?;
        }
        for &path in self.hidden_paths {
            fs.hide_path(path)?;
        }
        for &(pid, ppid, name, user, rss, vsz, state) in self.fake_processes {
            procs.add_process(pid, ppid, name, user, rss, vsz, state)?;
        }
        procs.set_version(self.system.release)?;
        procs.set_cpu_model(self.system.cpu_model)?;

        net.set_hostname(self.network.hostname)?;
        for iface in self.network.interfaces {
            net.add_interface(iface.name, iface.ipv4, iface.netmask, iface.mac)?;
        }
        for p in self.network.ports {
            net.add_port(p.port, p.protocol, p.banner, p.handler)?;
        }

        Ok(())
    }
}

// ---------------------------------------------------------------------------
// ProfileRegistry -- stores and retrieves profiles by name
// ---------------------------------------------------------------------------

/// Maximum number of profiles the registry can hold.
const MAX_PROFILES: usize = 16;

/// Registry of deception profiles, indexed by name.
///
/// Pre-load all built-in profiles with `with_builtins()`, or start empty
/// and register custom profiles with `register()`.
pub struct ProfileRegistry {
    profiles: [Option<&'static DeceptionProfile>; MAX_PROFILES],
    count: usize,
}

impl ProfileRegistry {
    /// Create an empty registry.
    pub const fn new() -> Self {
        Self {
            profiles: [None; MAX_PROFILES],
            count: 0,
        }
    }

    /// Create a registry pre-loaded with all built-in profiles.
    pub fn with_builtins() -> Self {
        let mut reg = Self::new();
        // Infallible: 4 profiles, 16 slots.
        let _ = reg.register(&profiles::ubuntu_webserver::PROFILE);
        let _ = reg.register(&profiles::centos_database::PROFILE);
        let _ = reg.register(&profiles::windows_workstation::PROFILE);
        let _ = reg.register(&profiles::iot_device::PROFILE);
        reg
    }

    /// Register a profile. Returns `true` if added, `false` if full.
    pub fn register(&mut self, profile: &'static DeceptionProfile) -> bool {
        for slot in self.profiles.iter_mut() {
            if slot.is_none() {
                *slot = Some(profile);
                self.count += 1;
                return true;
            }
        }
        false
    }

    /// Look up a profile by name (byte-string comparison).
    pub fn get(&self, name: &[u8]) -> Option<&'static DeceptionProfile> {
        for slot in self.profiles.iter().flatten() {
            if slot.name.as_bytes() == name {
                return Some(slot);
            }
        }
        None
    }

    /// Number of registered profiles.
    pub fn count(&self) -> usize {
        self.count
    }

    /// Iterate over all registered profiles.
    pub fn iter(&self) -> impl Iterator<Item = &'static DeceptionProfile> + '_ {
        self.profiles.iter().flatten().copied()
    }
}

/// Backward-compatible alias for the Ubuntu webserver profile.
///
/// Prefer `profiles::ubuntu_webserver::PROFILE` or
/// `ProfileRegistry::with_builtins()` for new code.
pub use crate::profiles::ubuntu_webserver::PROFILE as UBUNTU_WEBSERVER;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn apply_ubuntu_profile() {
        let mut fs = FsOverlay::new();
        let mut procs = FakeProcessList::new();
        let mut net = NetworkDeception::new();

        UBUNTU_WEBSERVER.apply(&mut fs, &mut procs, &mut net).unwrap();

        // FS: os-release is overlaid, /sot is hidden.
        assert!(fs.lookup(b"/etc/os-release").is_some());
        assert!(fs.is_hidden(b"/sot/config"));

        // Procs: apache2 and mysqld are present.
        assert!(procs.find_by_pid(710).is_some());
        assert!(procs.find_by_pid(850).is_some());
        assert_eq!(procs.find_by_pid(850).unwrap().name(), b"mysqld");

        // Net: SSH banner on port 22.
        let ssh = net.lookup_port(22, Protocol::Tcp).unwrap();
        assert!(ssh.banner().starts_with(b"SSH-2.0-OpenSSH_8.9p1"));
    }

    #[test]
    fn registry_with_builtins() {
        let reg = ProfileRegistry::with_builtins();
        assert_eq!(reg.count(), 4);

        // Look up each profile by name.
        assert!(reg.get(b"ubuntu-22.04-webserver").is_some());
        assert!(reg.get(b"centos-8-database").is_some());
        assert!(reg.get(b"windows-10-workstation").is_some());
        assert!(reg.get(b"iot-ipcamera").is_some());

        // Unknown name returns None.
        assert!(reg.get(b"nonexistent").is_none());
    }

    #[test]
    fn registry_iteration() {
        let reg = ProfileRegistry::with_builtins();
        let names: alloc::vec::Vec<&str> = reg.iter().map(|p| p.name).collect();
        assert_eq!(names.len(), 4);
        assert!(names.contains(&"ubuntu-22.04-webserver"));
        assert!(names.contains(&"centos-8-database"));
        assert!(names.contains(&"windows-10-workstation"));
        assert!(names.contains(&"iot-ipcamera"));
    }

    #[test]
    fn apply_centos_profile() {
        let mut fs = FsOverlay::new();
        let mut procs = FakeProcessList::new();
        let mut net = NetworkDeception::new();

        profiles::centos_database::PROFILE
            .apply(&mut fs, &mut procs, &mut net)
            .unwrap();

        assert!(fs.lookup(b"/etc/centos-release").is_some());
        assert!(procs.find_by_pid(800).is_some()); // postgres main
        assert_eq!(procs.find_by_pid(800).unwrap().name(), b"postgres");
        let pg = net.lookup_port(5432, Protocol::Tcp).unwrap();
        assert_eq!(pg.handler, HoneypotHandler::BasicResponse);
    }

    #[test]
    fn apply_windows_profile() {
        let mut fs = FsOverlay::new();
        let mut procs = FakeProcessList::new();
        let mut net = NetworkDeception::new();

        profiles::windows_workstation::PROFILE
            .apply(&mut fs, &mut procs, &mut net)
            .unwrap();

        // Windows-style paths.
        assert!(fs.lookup(b"/systeminfo.txt").is_some());
        assert!(procs.find_by_pid(2100).is_some()); // explorer.exe
        assert_eq!(procs.find_by_pid(2100).unwrap().name(), b"explorer.exe");

        // RDP port.
        assert!(net.lookup_port(3389, Protocol::Tcp).is_some());
        // IIS banner.
        let http = net.lookup_port(80, Protocol::Tcp).unwrap();
        assert!(http.banner().starts_with(b"HTTP/1.1 200 OK\r\nServer: Microsoft-IIS"));
    }

    #[test]
    fn apply_iot_profile() {
        let mut fs = FsOverlay::new();
        let mut procs = FakeProcessList::new();
        let mut net = NetworkDeception::new();

        profiles::iot_device::PROFILE
            .apply(&mut fs, &mut procs, &mut net)
            .unwrap();

        // BusyBox filesystem.
        assert!(fs.lookup(b"/www/login.htm").is_some());
        assert!(procs.find_by_pid(85).is_some()); // telnetd
        assert_eq!(procs.find_by_pid(85).unwrap().name(), b"telnetd");

        // Telnet and HTTP ports.
        assert!(net.lookup_port(23, Protocol::Tcp).is_some());
        let http = net.lookup_port(80, Protocol::Tcp).unwrap();
        assert!(http.banner().starts_with(b"HTTP/1.0 200 OK\r\nServer: GoAhead-Webs"));
        // RTSP.
        let rtsp = net.lookup_port(554, Protocol::Tcp).unwrap();
        assert!(rtsp.banner().starts_with(b"RTSP/1.0"));
    }
}
