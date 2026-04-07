//! Built-in deception profile: Ubuntu 22.04 LTS LAMP stack webserver.
//!
//! Presents the system as a typical cloud Ubuntu VM running
//! Apache + MySQL + SSH -- a high-value target that lures attackers
//! into interacting with the deception layer.

use crate::fake_net::{HoneypotHandler, Protocol};
use crate::profile::{DeceptionProfile, NetworkDeceptionConfig, StaticInterface, StaticPort, SystemSpoofConfig, COMMON_HIDDEN_PATHS};

// ---------------------------------------------------------------------------
// Filesystem content
// ---------------------------------------------------------------------------

const OS_RELEASE: &[u8] = b"\
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

const PASSWD: &[u8] = b"\
root:x:0:0:root:/root:/bin/bash\n\
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n\
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\n\
mysql:x:27:27:MySQL Server:/var/lib/mysql:/bin/false\n\
sshd:x:74:74:Privilege-separated SSH:/var/empty/sshd:/usr/sbin/nologin\n\
ubuntu:x:1000:1000:Ubuntu:/home/ubuntu:/bin/bash\n";

const PROC_VERSION: &[u8] =
    b"Linux version 5.15.0-91-generic (buildd@lcy02-amd64-080) \
(gcc (Ubuntu 11.4.0-1ubuntu1~22.04) 11.4.0, GNU ld (GNU Binutils for Ubuntu) 2.38) \
#101-Ubuntu SMP Tue Nov 14 13:30:08 UTC 2023\n";

const PROC_CPUINFO: &[u8] = b"\
processor\t: 0\n\
vendor_id\t: GenuineIntel\n\
cpu family\t: 6\n\
model\t\t: 79\n\
model name\t: Intel(R) Xeon(R) CPU E5-2686 v4 @ 2.30GHz\n\
stepping\t: 1\n\
cpu MHz\t\t: 2300.000\n\
cache size\t: 46080 KB\n\
physical id\t: 0\n\
siblings\t: 4\n\
core id\t\t: 0\n\
cpu cores\t: 4\n\
bogomips\t: 4600.00\n\
flags\t\t: fpu vme de pse tsc msr pae mce cx8 apic sep mtrr pge mca cmov pat pse36 clflush mmx fxsr sse sse2 ht syscall nx rdtscp lm constant_tsc rep_good nopl xtopology cpuid pni pclmulqdq ssse3 fma cx16 pcid sse4_1 sse4_2 x2apic movbe popcnt aes xsave avx f16c rdrand hypervisor lahf_lm\n\n";

const PROC_MEMINFO: &[u8] = b"\
MemTotal:        8145672 kB\n\
MemFree:         4523408 kB\n\
MemAvailable:    6234560 kB\n\
Buffers:          187432 kB\n\
Cached:          1623720 kB\n\
SwapTotal:       2097148 kB\n\
SwapFree:        2097148 kB\n";

const INDEX_HTML: &[u8] = b"<!DOCTYPE html>\n\
<html><head><title>Welcome</title></head>\n\
<body><h1>It works!</h1>\n\
<p>This is the default web page for this server.</p>\n\
<p>The web server software is running but no content has been added, yet.</p>\n\
</body></html>\n";

const ISSUE: &[u8] = b"Ubuntu 22.04.3 LTS \\n \\l\n\n";

const LSB_RELEASE: &[u8] = b"\
DISTRIB_ID=Ubuntu\n\
DISTRIB_RELEASE=22.04\n\
DISTRIB_CODENAME=jammy\n\
DISTRIB_DESCRIPTION=\"Ubuntu 22.04.3 LTS\"\n";

// ---------------------------------------------------------------------------
// Static tables
// ---------------------------------------------------------------------------

static FS_OVERLAYS: &[(&[u8], &[u8], bool)] = &[
    (b"/etc/os-release", OS_RELEASE, false),
    (b"/etc/hostname", b"webserver01\n", false),
    (b"/etc/passwd", PASSWD, false),
    (b"/etc/issue", ISSUE, false),
    (b"/etc/debian_version", b"bookworm/sid\n", false),
    (b"/etc/lsb-release", LSB_RELEASE, false),
    (b"/proc/version", PROC_VERSION, false),
    (b"/proc/cpuinfo", PROC_CPUINFO, false),
    (b"/proc/meminfo", PROC_MEMINFO, false),
    (b"/var/www/html/index.html", INDEX_HTML, false),
    (b"/var/www/html", b"", true),
    (b"/var/log/apache2", b"", true),
    (b"/var/lib/mysql", b"", true),
];

static HIDDEN_PATHS: &[&[u8]] = COMMON_HIDDEN_PATHS;

/// Fake process list for a typical Ubuntu LAMP webserver.
static FAKE_PROCS: &[(u32, u32, &[u8], &[u8], u32, u32, u8)] = &[
    (1, 0, b"systemd", b"root", 12_000, 170_000, b'S'),
    (402, 1, b"systemd-journald", b"root", 48_000, 50_000, b'S'),
    (428, 1, b"systemd-udevd", b"root", 5_000, 22_000, b'S'),
    (620, 1, b"cron", b"root", 2_500, 8_000, b'S'),
    (625, 1, b"sshd", b"root", 6_000, 15_000, b'S'),
    (710, 1, b"apache2", b"root", 10_000, 320_000, b'S'),
    (720, 710, b"apache2", b"www-data", 45_000, 320_000, b'S'),
    (721, 710, b"apache2", b"www-data", 43_000, 320_000, b'S'),
    (722, 710, b"apache2", b"www-data", 42_000, 320_000, b'S'),
    (723, 710, b"apache2", b"www-data", 41_000, 320_000, b'S'),
    (724, 710, b"apache2", b"www-data", 44_000, 320_000, b'S'),
    (850, 1, b"mysqld", b"mysql", 180_000, 1_200_000, b'S'),
    (900, 1, b"rsyslogd", b"syslog", 3_500, 25_000, b'S'),
];

static NET_IFACES: &[StaticInterface] = &[
    StaticInterface {
        name: b"eth0",
        ipv4: [10, 0, 1, 15],
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

static NET_PORTS: &[StaticPort] = &[
    StaticPort {
        port: 22,
        protocol: Protocol::Tcp,
        banner: b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6\r\n",
        handler: HoneypotHandler::BannerOnly,
    },
    StaticPort {
        port: 80,
        protocol: Protocol::Tcp,
        banner: b"HTTP/1.1 200 OK\r\nServer: Apache/2.4.52 (Ubuntu)\r\nContent-Length: 0\r\n\r\n",
        handler: HoneypotHandler::BasicResponse,
    },
    StaticPort {
        port: 443,
        protocol: Protocol::Tcp,
        banner: b"",
        handler: HoneypotHandler::BasicResponse,
    },
    StaticPort {
        port: 3306,
        protocol: Protocol::Tcp,
        banner: b"J\x00\x00\x008.0.33-0ubuntu0.22.04.4",
        handler: HoneypotHandler::BannerOnly,
    },
];

/// Built-in deception profile: Ubuntu 22.04 LTS LAMP webserver.
pub static PROFILE: DeceptionProfile = DeceptionProfile {
    name: "ubuntu-22.04-webserver",
    fs_overlays: FS_OVERLAYS,
    hidden_paths: HIDDEN_PATHS,
    fake_processes: FAKE_PROCS,
    network: NetworkDeceptionConfig {
        hostname: b"webserver01",
        interfaces: NET_IFACES,
        ports: NET_PORTS,
    },
    system: SystemSpoofConfig {
        sysname: b"Linux",
        release: b"5.15.0-91-generic",
        version: b"#101-Ubuntu SMP Tue Nov 14 13:30:08 UTC 2023",
        machine: b"x86_64",
        nodename: Some(b"webserver01"),
        cpu_model: b"Intel(R) Xeon(R) CPU E5-2686 v4 @ 2.30GHz",
    },
};
