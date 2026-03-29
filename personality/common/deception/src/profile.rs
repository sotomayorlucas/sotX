//! Deception profiles -- pre-built system personas.
//!
//! A `DeceptionProfile` bundles filesystem overlays, fake processes, network
//! deception, and system spoofing into a coherent identity that an attacker
//! will perceive as real.

use crate::fake_fs::FsOverlay;
use crate::fake_net::{HoneypotHandler, NetworkDeception, Protocol};
use crate::fake_proc::FakeProcessList;

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
// Built-in profile: Ubuntu 22.04 Webserver
// ---------------------------------------------------------------------------

/// /etc/os-release content for Ubuntu 22.04.
const UBUNTU_OS_RELEASE: &[u8] = b"\
PRETTY_NAME=\"Ubuntu 22.04.3 LTS\"\n\
NAME=\"Ubuntu\"\n\
VERSION_ID=\"22.04\"\n\
VERSION=\"22.04.3 LTS (Jammy Jellyfish)\"\n\
VERSION_CODENAME=jammy\n\
ID=ubuntu\n\
ID_LIKE=debian\n\
HOME_URL=\"https://www.ubuntu.com/\"\n\
SUPPORT_URL=\"https://help.ubuntu.com/\"\n\
BUG_REPORT_URL=\"https://bugs.launchpad.net/ubuntu/\"\n\
PRIVACY_POLICY_URL=\"https://www.ubuntu.com/legal/terms-and-policies/privacy-policy\"\n\
UBUNTU_CODENAME=jammy\n";

const UBUNTU_HOSTNAME: &[u8] = b"webserver01\n";

const UBUNTU_PASSWD_EXCERPT: &[u8] = b"\
root:x:0:0:root:/root:/bin/bash\n\
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\n\
mysql:x:27:27:MySQL Server:/var/lib/mysql:/bin/false\n\
sshd:x:74:74:Privilege-separated SSH:/var/empty/sshd:/usr/sbin/nologin\n\
ubuntu:x:1000:1000:Ubuntu:/home/ubuntu:/bin/bash\n";

const UBUNTU_ISSUE: &[u8] = b"Ubuntu 22.04.3 LTS \\n \\l\n\n";

/// Static filesystem overlays for the Ubuntu webserver profile.
static UBUNTU_FS_OVERLAYS: &[(&[u8], &[u8], bool)] = &[
    (b"/etc/os-release", UBUNTU_OS_RELEASE, false),
    (b"/etc/hostname", UBUNTU_HOSTNAME, false),
    (b"/etc/passwd", UBUNTU_PASSWD_EXCERPT, false),
    (b"/etc/issue", UBUNTU_ISSUE, false),
    (b"/etc/debian_version", b"bookworm/sid\n", false),
    (
        b"/etc/lsb-release",
        b"DISTRIB_ID=Ubuntu\nDISTRIB_RELEASE=22.04\nDISTRIB_CODENAME=jammy\nDISTRIB_DESCRIPTION=\"Ubuntu 22.04.3 LTS\"\n",
        false,
    ),
];

/// Paths hidden from the deception domain.
static UBUNTU_HIDDEN_PATHS: &[&[u8]] = &[
    b"/sot",
    b"/etc/sot",
    b"/etc/sotos",
    b"/boot/limine",
    b"/boot/limine.conf",
];

/// Fake process list for a typical Ubuntu webserver.
static UBUNTU_FAKE_PROCS: &[(u32, u32, &[u8], &[u8], u32, u32, u8)] = &[
    (1, 0, b"systemd", b"root", 12_000, 170_000, b'S'),
    (402, 1, b"systemd-journald", b"root", 48_000, 50_000, b'S'),
    (428, 1, b"systemd-udevd", b"root", 5_000, 22_000, b'S'),
    (620, 1, b"cron", b"root", 2_500, 8_000, b'S'),
    (625, 1, b"sshd", b"root", 6_000, 15_000, b'S'),
    (710, 1, b"apache2", b"root", 10_000, 320_000, b'S'),
    (720, 710, b"apache2", b"www-data", 45_000, 320_000, b'S'),
    (721, 710, b"apache2", b"www-data", 43_000, 320_000, b'S'),
    (722, 710, b"apache2", b"www-data", 42_000, 320_000, b'S'),
    (850, 1, b"mysqld", b"mysql", 180_000, 1_200_000, b'S'),
    (900, 1, b"rsyslogd", b"syslog", 3_500, 25_000, b'S'),
];

/// Fake network interfaces.
static UBUNTU_NET_IFACES: &[StaticInterface] = &[
    StaticInterface {
        name: b"eth0",
        ipv4: [10, 0, 1, 50],
        netmask: [255, 255, 255, 0],
        mac: [0x02, 0x42, 0xAC, 0x11, 0x00, 0x02],
    },
    StaticInterface {
        name: b"lo",
        ipv4: [127, 0, 0, 1],
        netmask: [255, 0, 0, 0],
        mac: [0x00; 6],
    },
];

/// Fake open ports with service banners.
static UBUNTU_NET_PORTS: &[StaticPort] = &[
    StaticPort {
        port: 22,
        protocol: Protocol::Tcp,
        banner: b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.4\r\n",
        handler: HoneypotHandler::BannerOnly,
    },
    StaticPort {
        port: 80,
        protocol: Protocol::Tcp,
        banner: b"HTTP/1.1 200 OK\r\nServer: Apache/2.4.52 (Ubuntu)\r\nContent-Length: 0\r\n\r\n",
        handler: HoneypotHandler::BasicResponse,
    },
    StaticPort {
        port: 3306,
        protocol: Protocol::Tcp,
        banner: b"5.7.42-0ubuntu0.22.04.1",
        handler: HoneypotHandler::BannerOnly,
    },
];

/// Built-in deception profile: Ubuntu 22.04 LTS Webserver.
///
/// Presents the system as a typical cloud Ubuntu VM running Apache + MySQL + SSH.
pub static UBUNTU_WEBSERVER: DeceptionProfile = DeceptionProfile {
    name: "ubuntu-22.04-webserver",
    fs_overlays: UBUNTU_FS_OVERLAYS,
    hidden_paths: UBUNTU_HIDDEN_PATHS,
    fake_processes: UBUNTU_FAKE_PROCS,
    network: NetworkDeceptionConfig {
        hostname: b"webserver01",
        interfaces: UBUNTU_NET_IFACES,
        ports: UBUNTU_NET_PORTS,
    },
    system: SystemSpoofConfig {
        sysname: b"Linux",
        release: b"5.15.0-88-generic",
        version: b"#98-Ubuntu SMP Mon Oct  2 15:18:56 UTC 2023",
        machine: b"x86_64",
        nodename: Some(b"webserver01"),
        cpu_model: b"Intel(R) Xeon(R) CPU E5-2686 v4 @ 2.30GHz",
    },
};

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
}
