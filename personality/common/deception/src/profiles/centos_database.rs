//! Built-in deception profile: CentOS Stream 8 PostgreSQL database server.
//!
//! Presents the system as an enterprise RHEL-family database server
//! running PostgreSQL 15 -- a compelling target for data exfiltration
//! attempts that the deception layer can observe and contain.

use crate::fake_net::{HoneypotHandler, Protocol};
use crate::profile::{DeceptionProfile, NetworkDeceptionConfig, StaticInterface, StaticPort, SystemSpoofConfig, COMMON_HIDDEN_PATHS};

// ---------------------------------------------------------------------------
// Filesystem content
// ---------------------------------------------------------------------------

const OS_RELEASE: &[u8] = b"\
NAME=\"CentOS Stream\"\n\
VERSION=\"8\"\n\
ID=\"centos\"\n\
ID_LIKE=\"rhel fedora\"\n\
VERSION_ID=\"8\"\n\
PLATFORM_ID=\"platform:el8\"\n\
PRETTY_NAME=\"CentOS Stream 8\"\n\
ANSI_COLOR=\"0;31\"\n\
CPE_NAME=\"cpe:/o:centos:centos:8\"\n\
HOME_URL=\"https://centos.org/\"\n\
BUG_REPORT_URL=\"https://bugzilla.redhat.com/\"\n\
REDHAT_SUPPORT_PRODUCT=\"Red Hat Enterprise Linux 8\"\n\
REDHAT_SUPPORT_PRODUCT_VERSION=\"CentOS Stream\"\n";

const PASSWD: &[u8] = b"\
root:x:0:0:root:/root:/bin/bash\n\
bin:x:1:1:bin:/bin:/sbin/nologin\n\
daemon:x:2:2:daemon:/sbin:/sbin/nologin\n\
postgres:x:26:26:PostgreSQL Server:/var/lib/pgsql:/bin/bash\n\
sshd:x:74:74:Privilege-separated SSH:/var/empty/sshd:/sbin/nologin\n\
dbus:x:81:81:System message bus:/:/sbin/nologin\n\
polkitd:x:998:996:User for polkitd:/:/sbin/nologin\n";

const PROC_VERSION: &[u8] =
    b"Linux version 4.18.0-513.el8.x86_64 \
(mockbuild@x86-064-04.build.eng.rdu2.redhat.com) \
(gcc (GCC) 8.5.0 20210514 (Red Hat 8.5.0-20), GNU ld version 2.30-123.el8) \
#1 SMP Fri Sep 29 10:07:23 EDT 2023\n";

const PROC_CPUINFO: &[u8] = b"\
processor\t: 0\n\
vendor_id\t: GenuineIntel\n\
cpu family\t: 6\n\
model\t\t: 85\n\
model name\t: Intel(R) Xeon(R) Gold 6248 CPU @ 2.50GHz\n\
stepping\t: 7\n\
cpu MHz\t\t: 2500.000\n\
cache size\t: 28160 KB\n\
physical id\t: 0\n\
siblings\t: 8\n\
core id\t\t: 0\n\
cpu cores\t: 8\n\
bogomips\t: 5000.00\n\
flags\t\t: fpu vme de pse tsc msr pae mce cx8 apic sep mtrr pge mca cmov pat pse36 clflush mmx fxsr sse sse2 ht syscall nx rdtscp lm constant_tsc rep_good nopl xtopology cpuid pni pclmulqdq ssse3 fma cx16 pcid sse4_1 sse4_2 x2apic movbe popcnt aes xsave avx f16c rdrand\n\n";

const PROC_MEMINFO: &[u8] = b"\
MemTotal:       16309264 kB\n\
MemFree:         8734512 kB\n\
MemAvailable:   12456320 kB\n\
Buffers:          345216 kB\n\
Cached:          3476592 kB\n\
SwapTotal:       4194300 kB\n\
SwapFree:        4194300 kB\n";

const CENTOS_RELEASE: &[u8] = b"CentOS Stream release 8\n";

const PG_HBA_CONF: &[u8] = b"\
# TYPE  DATABASE        USER            ADDRESS                 METHOD\n\
local   all             all                                     peer\n\
host    all             all             127.0.0.1/32            scram-sha-256\n\
host    all             all             10.0.2.0/24             scram-sha-256\n\
host    replication     all             10.0.2.0/24             scram-sha-256\n";

// ---------------------------------------------------------------------------
// Static tables
// ---------------------------------------------------------------------------

static FS_OVERLAYS: &[(&[u8], &[u8], bool)] = &[
    (b"/etc/os-release", OS_RELEASE, false),
    (b"/etc/centos-release", CENTOS_RELEASE, false),
    (b"/etc/redhat-release", CENTOS_RELEASE, false),
    (b"/etc/hostname", b"db-primary01\n", false),
    (b"/etc/passwd", PASSWD, false),
    (b"/proc/version", PROC_VERSION, false),
    (b"/proc/cpuinfo", PROC_CPUINFO, false),
    (b"/proc/meminfo", PROC_MEMINFO, false),
    (b"/var/lib/pgsql/15/data/pg_hba.conf", PG_HBA_CONF, false),
    (b"/var/lib/pgsql/15/data", b"", true),
    (b"/var/log/postgresql", b"", true),
];

static HIDDEN_PATHS: &[&[u8]] = COMMON_HIDDEN_PATHS;

static FAKE_PROCS: &[(u32, u32, &[u8], &[u8], u32, u32, u8)] = &[
    (1, 0, b"systemd", b"root", 14_000, 180_000, b'S'),
    (380, 1, b"systemd-journald", b"root", 52_000, 55_000, b'S'),
    (420, 1, b"systemd-udevd", b"root", 5_500, 24_000, b'S'),
    (610, 1, b"sshd", b"root", 6_200, 16_000, b'S'),
    (650, 1, b"firewalld", b"root", 28_000, 420_000, b'S'),
    (700, 1, b"dbus-daemon", b"dbus", 3_800, 12_000, b'S'),
    (750, 1, b"crond", b"root", 2_200, 7_500, b'S'),
    (800, 1, b"postgres", b"postgres", 32_000, 380_000, b'S'),
    (810, 800, b"postgres", b"postgres", 18_000, 380_000, b'S'),
    (811, 800, b"postgres", b"postgres", 17_500, 380_000, b'S'),
    (812, 800, b"postgres", b"postgres", 16_800, 380_000, b'S'),
    (813, 800, b"postgres", b"postgres", 19_200, 380_000, b'S'),
    (814, 800, b"postgres", b"postgres", 15_400, 380_000, b'S'),
    (815, 800, b"postgres", b"postgres", 14_000, 380_000, b'S'),
    (900, 1, b"tuned", b"root", 18_000, 320_000, b'S'),
    (950, 1, b"rsyslogd", b"root", 3_800, 28_000, b'S'),
];

static NET_IFACES: &[StaticInterface] = &[
    StaticInterface {
        name: b"ens192",
        ipv4: [10, 0, 2, 50],
        netmask: [255, 255, 255, 0],
        mac: [0x00, 0x50, 0x56, 0xA1, 0x2B, 0x3C],
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
        banner: b"SSH-2.0-OpenSSH_8.0\r\n",
        handler: HoneypotHandler::BannerOnly,
    },
    StaticPort {
        port: 5432,
        protocol: Protocol::Tcp,
        banner: b"E\x00\x00\x00\x63SFATAL\x00C28000\x00Mno pg_hba.conf entry\x00",
        handler: HoneypotHandler::BasicResponse,
    },
];

/// Built-in deception profile: CentOS Stream 8 PostgreSQL 15 database server.
pub static PROFILE: DeceptionProfile = DeceptionProfile {
    name: "centos-8-database",
    fs_overlays: FS_OVERLAYS,
    hidden_paths: HIDDEN_PATHS,
    fake_processes: FAKE_PROCS,
    network: NetworkDeceptionConfig {
        hostname: b"db-primary01",
        interfaces: NET_IFACES,
        ports: NET_PORTS,
    },
    system: SystemSpoofConfig {
        sysname: b"Linux",
        release: b"4.18.0-513.el8.x86_64",
        version: b"#1 SMP Fri Sep 29 10:07:23 EDT 2023",
        machine: b"x86_64",
        nodename: Some(b"db-primary01"),
        cpu_model: b"Intel(R) Xeon(R) Gold 6248 CPU @ 2.50GHz",
    },
};
