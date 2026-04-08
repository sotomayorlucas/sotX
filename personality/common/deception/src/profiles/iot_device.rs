//! Built-in deception profile: IoT IP camera (BusyBox-based).
//!
//! Presents the system as a vulnerable consumer IP camera running
//! BusyBox with telnet and a web admin interface -- a common target
//! for botnets (Mirai-style). Lures automated scanners into the
//! deception layer where their behavior can be observed.

use crate::fake_net::{HoneypotHandler, Protocol};
use crate::profile::{DeceptionProfile, NetworkDeceptionConfig, StaticInterface, StaticPort, SystemSpoofConfig};

// ---------------------------------------------------------------------------
// Filesystem content -- minimal BusyBox-based embedded system
// ---------------------------------------------------------------------------

const PASSWD: &[u8] = b"\
root:$1$abc$fakehash:0:0:root:/:/bin/sh\n\
admin:$1$def$fakehash:1000:1000:admin:/home/admin:/bin/sh\n\
nobody:x:99:99:Nobody:/:/sbin/nologin\n";

const PROC_VERSION: &[u8] =
    b"Linux version 3.10.14 (build@cam-builder) \
(gcc version 4.6.3 (Buildroot 2012.11.1)) \
#1 Mon Aug 21 09:15:42 CST 2023\n";

const PROC_CPUINFO: &[u8] = b"\
system type\t\t: Hisilicon Hi3516EV300\n\
processor\t\t: 0\n\
cpu model\t\t: ARM926EJ-S rev 5 (v5l)\n\
BogoMIPS\t\t: 498.07\n\
Hardware\t\t: hi3516ev300\n\n";

const PROC_MEMINFO: &[u8] = b"\
MemTotal:          128256 kB\n\
MemFree:            32768 kB\n\
MemAvailable:       45056 kB\n\
Buffers:             4096 kB\n\
Cached:             12288 kB\n\
SwapTotal:              0 kB\n\
SwapFree:               0 kB\n";

const WEB_INDEX: &[u8] = b"<html><head><title>IP Camera</title>\
<meta http-equiv=\"refresh\" content=\"0;url=/login.htm\"></head>\
<body>Redirecting...</body></html>\n";

const WEB_LOGIN: &[u8] = b"<html><head><title>Login - IP Camera</title></head>\
<body><h2>Network Camera Login</h2>\
<form method=\"post\" action=\"/check_user.cgi\">\
<p>Username: <input name=\"user\" type=\"text\"></p>\
<p>Password: <input name=\"pass\" type=\"password\"></p>\
<p><input type=\"submit\" value=\"Login\"></p>\
</form></body></html>\n";

// ---------------------------------------------------------------------------
// Static tables
// ---------------------------------------------------------------------------

static FS_OVERLAYS: &[(&[u8], &[u8], bool)] = &[
    (b"/etc/passwd", PASSWD, false),
    (b"/etc/hostname", b"IPC-3516EV300\n", false),
    (b"/etc/init.d", b"", true),
    (b"/proc/version", PROC_VERSION, false),
    (b"/proc/cpuinfo", PROC_CPUINFO, false),
    (b"/proc/meminfo", PROC_MEMINFO, false),
    (b"/mnt/mtd", b"", true),
    (b"/mnt/mtd/Config", b"", true),
    (b"/www/index.htm", WEB_INDEX, false),
    (b"/www/login.htm", WEB_LOGIN, false),
    (b"/www", b"", true),
    (b"/bin/busybox", b"", false),
];

static HIDDEN_PATHS: &[&[u8]] = &[
    b"/sot",
    b"/etc/sot",
    b"/etc/sotos",
    b"/boot/limine",
    b"/boot/limine.conf",
    b"/usr/lib",
    b"/usr/share",
];

static FAKE_PROCS: &[(u32, u32, &[u8], &[u8], u32, u32, u8)] = &[
    (1, 0, b"init", b"root", 512, 1_800, b'S'),
    (85, 1, b"telnetd", b"root", 256, 1_200, b'S'),
    (92, 1, b"httpd", b"root", 1_024, 3_200, b'S'),
    (110, 1, b"rtspd", b"root", 8_192, 24_000, b'S'),
    (125, 1, b"encoder", b"root", 16_384, 48_000, b'R'),
    (140, 1, b"syslogd", b"root", 384, 1_400, b'S'),
    (145, 1, b"klogd", b"root", 256, 1_000, b'S'),
    (160, 1, b"udhcpc", b"root", 320, 1_100, b'S'),
];

static NET_IFACES: &[StaticInterface] = &[
    StaticInterface {
        name: b"eth0",
        ipv4: [192, 168, 1, 100],
        netmask: [255, 255, 255, 0],
        mac: [0x00, 0x12, 0x41, 0xA0, 0x5C, 0x3E],
    },
];

static NET_PORTS: &[StaticPort] = &[
    StaticPort {
        port: 23,
        protocol: Protocol::Tcp,
        banner: b"\xff\xfd\x01\xff\xfd\x1flogin: ",
        handler: HoneypotHandler::BasicResponse,
    },
    StaticPort {
        port: 80,
        protocol: Protocol::Tcp,
        banner: b"HTTP/1.0 200 OK\r\nServer: GoAhead-Webs\r\nContent-Type: text/html\r\n\r\n",
        handler: HoneypotHandler::BasicResponse,
    },
    StaticPort {
        port: 554,
        protocol: Protocol::Tcp,
        banner: b"RTSP/1.0 200 OK\r\nCSeq: 1\r\nPublic: DESCRIBE, SETUP, PLAY, TEARDOWN\r\n\r\n",
        handler: HoneypotHandler::BasicResponse,
    },
    StaticPort {
        port: 8080,
        protocol: Protocol::Tcp,
        banner: b"HTTP/1.0 200 OK\r\nServer: GoAhead-Webs\r\nContent-Type: text/html\r\n\r\n",
        handler: HoneypotHandler::BasicResponse,
    },
];

/// Built-in deception profile: IoT IP camera (BusyBox/HiSilicon).
pub static PROFILE: DeceptionProfile = DeceptionProfile {
    name: "iot-ipcamera",
    fs_overlays: FS_OVERLAYS,
    hidden_paths: HIDDEN_PATHS,
    fake_processes: FAKE_PROCS,
    network: NetworkDeceptionConfig {
        hostname: b"IPC-3516EV300",
        interfaces: NET_IFACES,
        ports: NET_PORTS,
    },
    system: SystemSpoofConfig {
        sysname: b"Linux",
        release: b"3.10.14",
        version: b"#1 Mon Aug 21 09:15:42 CST 2023",
        machine: b"armv7l",
        nodename: Some(b"IPC-3516EV300"),
        cpu_model: b"ARM926EJ-S rev 5 (v5l)",
    },
};
