//! Built-in deception profile: Windows 10 Enterprise workstation.
//!
//! Presents the system as a typical corporate Windows 10 workstation
//! with IIS and RDP enabled. Useful for cross-platform deception where
//! an attacker expects a Windows environment. The filesystem overlay
//! provides Windows-style paths and the network layer exposes Windows
//! service banners.

use crate::fake_net::{HoneypotHandler, Protocol};
use crate::profile::{DeceptionProfile, NetworkDeceptionConfig, StaticInterface, StaticPort, SystemSpoofConfig};

// ---------------------------------------------------------------------------
// Filesystem content -- Windows-style paths for cross-platform deception
// ---------------------------------------------------------------------------

const SYSTEM_INFO: &[u8] = b"\
Host Name:                 DESKTOP-A4F8K2Q\r\n\
OS Name:                   Microsoft Windows 10 Enterprise\r\n\
OS Version:                10.0.19045 N/A Build 19045\r\n\
OS Manufacturer:           Microsoft Corporation\r\n\
OS Configuration:          Member Workstation\r\n\
OS Build Type:             Multiprocessor Free\r\n\
Registered Organization:   Contoso Ltd\r\n\
System Type:               x64-based PC\r\n\
Processor(s):              1 Processor(s) Installed.\r\n\
                           [01]: Intel64 Family 6 Model 142 Stepping 12 GenuineIntel ~1800 MHz\r\n\
Total Physical Memory:     16,384 MB\r\n\
Available Physical Memory: 8,192 MB\r\n";

const HOSTS_FILE: &[u8] = b"\
# Copyright (c) 1993-2009 Microsoft Corp.\r\n\
#\r\n\
# This is a sample HOSTS file used by Microsoft TCP/IP for Windows.\r\n\
127.0.0.1       localhost\r\n\
::1             localhost\r\n\
10.0.3.10       dc01.contoso.local dc01\r\n\
10.0.3.20       filesvr.contoso.local filesvr\r\n";

const IIS_INDEX: &[u8] = b"<!DOCTYPE html PUBLIC \"-//W3C//DTD XHTML 1.0 Strict//EN\" \
\"http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd\">\r\n\
<html xmlns=\"http://www.w3.org/1999/xhtml\">\r\n\
<head><title>IIS Windows Server</title></head>\r\n\
<body><h1>Internet Information Services</h1></body>\r\n\
</html>\r\n";

// ---------------------------------------------------------------------------
// Static tables
// ---------------------------------------------------------------------------

static FS_OVERLAYS: &[(&[u8], &[u8], bool)] = &[
    (b"/C:/Windows/System32", b"", true),
    (b"/C:/Windows/System32/drivers/etc/hosts", HOSTS_FILE, false),
    (b"/C:/Windows/Temp", b"", true),
    (b"/C:/Users/Administrator/Desktop", b"", true),
    (b"/C:/inetpub/wwwroot/iisstart.htm", IIS_INDEX, false),
    (b"/C:/inetpub/wwwroot", b"", true),
    (b"/C:/Program Files", b"", true),
    (b"/C:/Program Files (x86)", b"", true),
    (b"/systeminfo.txt", SYSTEM_INFO, false),
];

static HIDDEN_PATHS: &[&[u8]] = &[
    b"/sot",
    b"/etc/sot",
    b"/etc/sotos",
    b"/boot/limine",
    b"/boot/limine.conf",
    b"/etc",
    b"/proc",
    b"/var",
    b"/usr",
];

static FAKE_PROCS: &[(u32, u32, &[u8], &[u8], u32, u32, u8)] = &[
    (4, 0, b"System", b"SYSTEM", 140, 4_096, b'R'),
    (612, 4, b"smss.exe", b"SYSTEM", 1_024, 2_048, b'S'),
    (700, 612, b"csrss.exe", b"SYSTEM", 5_120, 8_192, b'S'),
    (780, 612, b"wininit.exe", b"SYSTEM", 3_600, 6_400, b'S'),
    (800, 780, b"services.exe", b"SYSTEM", 9_600, 15_000, b'S'),
    (820, 800, b"svchost.exe", b"SYSTEM", 28_000, 45_000, b'S'),
    (830, 800, b"svchost.exe", b"LOCAL SERVICE", 15_000, 32_000, b'S'),
    (850, 800, b"svchost.exe", b"NETWORK SERVICE", 22_000, 38_000, b'S'),
    (1020, 800, b"spoolsv.exe", b"SYSTEM", 12_000, 24_000, b'S'),
    (1100, 800, b"MsMpEng.exe", b"SYSTEM", 180_000, 420_000, b'S'),
    (1250, 800, b"w3wp.exe", b"IIS APPPOOL", 85_000, 320_000, b'S'),
    (1400, 800, b"TermService", b"NETWORK SERVICE", 18_000, 35_000, b'S'),
    (2100, 780, b"explorer.exe", b"contoso\\admin", 95_000, 210_000, b'R'),
    (2300, 2100, b"RuntimeBroker.exe", b"contoso\\admin", 22_000, 48_000, b'S'),
];

static NET_IFACES: &[StaticInterface] = &[
    StaticInterface {
        name: b"Ethernet0",
        ipv4: [10, 0, 3, 100],
        netmask: [255, 255, 255, 0],
        mac: [0x00, 0x0C, 0x29, 0x5A, 0x3B, 0x7E],
    },
];

static NET_PORTS: &[StaticPort] = &[
    StaticPort {
        port: 80,
        protocol: Protocol::Tcp,
        banner: b"HTTP/1.1 200 OK\r\nServer: Microsoft-IIS/10.0\r\nX-Powered-By: ASP.NET\r\nContent-Length: 0\r\n\r\n",
        handler: HoneypotHandler::BasicResponse,
    },
    StaticPort {
        port: 135,
        protocol: Protocol::Tcp,
        banner: b"",
        handler: HoneypotHandler::BannerOnly,
    },
    StaticPort {
        port: 445,
        protocol: Protocol::Tcp,
        banner: b"",
        handler: HoneypotHandler::BannerOnly,
    },
    StaticPort {
        port: 3389,
        protocol: Protocol::Tcp,
        banner: b"\x03\x00\x00\x13\x0e\xd0\x00\x00\x124\x00\x02\x01\x08\x00\x02\x00\x00\x00",
        handler: HoneypotHandler::BasicResponse,
    },
];

/// Built-in deception profile: Windows 10 Enterprise workstation.
pub static PROFILE: DeceptionProfile = DeceptionProfile {
    name: "windows-10-workstation",
    fs_overlays: FS_OVERLAYS,
    hidden_paths: HIDDEN_PATHS,
    fake_processes: FAKE_PROCS,
    network: NetworkDeceptionConfig {
        hostname: b"DESKTOP-A4F8K2Q",
        interfaces: NET_IFACES,
        ports: NET_PORTS,
    },
    system: SystemSpoofConfig {
        sysname: b"Windows NT",
        release: b"10.0.19045",
        version: b"Windows 10 Enterprise Build 19045",
        machine: b"x86_64",
        nodename: Some(b"DESKTOP-A4F8K2Q"),
        cpu_model: b"Intel(R) Core(TM) i7-8565U CPU @ 1.80GHz",
    },
};
