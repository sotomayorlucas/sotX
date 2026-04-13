//! /proc filesystem emulation for Linux domains.
//!
//! Generates virtual procfs/sysfs content from SOT domain metadata.
//! When a Linux process reads `/proc/self/maps` or `/proc/cpuinfo`, this
//! module synthesizes a response that matches Linux kernel output format.
//!
//! # Deception mode
//!
//! If a domain is flagged for deception (e.g., to satisfy DRM checks or
//! anti-cheat), procfs responses can be modified to present fake hardware,
//! kernel version, or memory layout information. The deception layer is
//! controlled by `DeceptionPolicy` and applied transparently.

extern crate alloc;
use alloc::string::String;
use alloc::fmt::Write;

/// Domain metadata used to populate procfs entries.
#[derive(Debug, Clone)]
pub struct DomainInfo {
    /// Domain (process) ID.
    pub pid: u32,
    /// Thread group ID.
    pub tgid: u32,
    /// Domain name (from exec path).
    pub name: [u8; 16],
    /// Name length in bytes.
    pub name_len: usize,
    /// Current state: 'R' running, 'S' sleeping, 'Z' zombie, etc.
    pub state: u8,
    /// Number of capabilities held by this domain.
    pub cap_count: u32,
    /// Number of memory SOs (mapped regions).
    pub mem_region_count: u32,
    /// Virtual memory size in bytes.
    pub vm_size_kb: u64,
    /// Resident set size in pages.
    pub rss_pages: u64,
    /// Number of threads.
    pub thread_count: u32,
}

/// A single memory region entry for /proc/self/maps.
#[derive(Debug, Clone, Copy)]
pub struct MemRegion {
    /// Start virtual address.
    pub start: u64,
    /// End virtual address (exclusive).
    pub end: u64,
    /// Readable.
    pub r: bool,
    /// Writable.
    pub w: bool,
    /// Executable.
    pub x: bool,
    /// Private (vs shared).
    pub private: bool,
    /// File offset (for file-backed mappings).
    pub offset: u64,
    /// Device major:minor (0:0 for anonymous).
    pub dev_major: u8,
    pub dev_minor: u8,
    /// Inode (0 for anonymous).
    pub inode: u64,
}

/// A capability entry for /proc/self/fd/ emulation.
#[derive(Debug, Clone, Copy)]
pub struct FdEntry {
    /// Linux-visible file descriptor number.
    pub fd: u32,
    /// SOT capability index backing this fd.
    pub cap_index: u32,
    /// Type description (e.g., "pipe", "socket", "anon_inode", "SO:path").
    pub kind: FdKind,
}

/// Fd kind for procfs display.
#[derive(Debug, Clone, Copy)]
pub enum FdKind {
    File,
    Pipe,
    Socket,
    Eventfd,
    Timerfd,
    Epoll,
    Signalfd,
    AnonInode,
}

/// Controls what fake data to inject when deception mode is active.
#[derive(Debug, Clone)]
pub struct DeceptionPolicy {
    /// If true, procfs returns fake data for this domain.
    pub active: bool,
    /// Fake kernel version string (e.g., "6.1.0-generic").
    pub kernel_version: Option<[u8; 64]>,
    pub kernel_version_len: usize,
    /// Fake CPU model name.
    pub cpu_model: Option<[u8; 64]>,
    pub cpu_model_len: usize,
    /// Fake total memory in KB.
    pub fake_mem_total_kb: Option<u64>,
    /// Fake CPU count.
    pub fake_cpu_count: Option<u32>,
}

impl DeceptionPolicy {
    /// No deception -- return real data.
    pub const fn none() -> Self {
        Self {
            active: false,
            kernel_version: None,
            kernel_version_len: 0,
            cpu_model: None,
            cpu_model_len: 0,
            fake_mem_total_kb: None,
            fake_cpu_count: None,
        }
    }
}

/// System-wide information for procfs entries like /proc/cpuinfo.
#[derive(Debug, Clone, Copy)]
pub struct SystemInfo {
    /// Number of logical CPUs.
    pub cpu_count: u32,
    /// CPU model name (from CPUID).
    pub cpu_model: [u8; 48],
    pub cpu_model_len: usize,
    /// CPU frequency in MHz.
    pub cpu_mhz: u32,
    /// Total physical memory in KB.
    pub mem_total_kb: u64,
    /// Free physical memory in KB.
    pub mem_free_kb: u64,
    /// Cached memory in KB.
    pub mem_cached_kb: u64,
    /// System uptime in seconds.
    pub uptime_secs: u64,
}

// ---------------------------------------------------------------------------
// Public API: generate procfs content for a given path
// ---------------------------------------------------------------------------

/// Generate the content for a procfs/sysfs virtual file.
///
/// Returns `Some(content)` if the path is recognized, `None` otherwise.
/// The caller should serve this content to the Linux process on read().
pub fn generate(
    path: &str,
    domain: &DomainInfo,
    sys: &SystemInfo,
    regions: &[MemRegion],
    fds: &[FdEntry],
    deception: &DeceptionPolicy,
) -> Option<String> {
    // Normalize: strip leading slash, handle /proc/self/ and /proc/<pid>/
    let path = path.strip_prefix('/').unwrap_or(path);

    if let Some(rest) = path.strip_prefix("proc/") {
        return generate_proc(rest, domain, sys, regions, fds, deception);
    }
    if let Some(rest) = path.strip_prefix("sys/") {
        return generate_sys(rest, sys, deception);
    }

    None
}

fn generate_proc(
    path: &str,
    domain: &DomainInfo,
    sys: &SystemInfo,
    regions: &[MemRegion],
    fds: &[FdEntry],
    deception: &DeceptionPolicy,
) -> Option<String> {
    // Handle /proc/self/* and /proc/<pid>/*
    let inner = if let Some(rest) = path.strip_prefix("self/") {
        rest
    } else if path.starts_with(|c: char| c.is_ascii_digit()) {
        // /proc/<pid>/... -- extract the sub-path after the pid
        path.split_once('/').map(|(_, rest)| rest)?
    } else {
        // Top-level /proc files
        return generate_proc_toplevel(path, sys, deception);
    };

    match inner {
        "maps" => Some(generate_maps(regions, domain)),
        "status" => Some(generate_status(domain)),
        "stat" => Some(generate_stat(domain)),
        "environ" => Some(String::new()), // Empty for now
        "auxv" => Some(String::new()),    // Binary, return empty
        "exe" => Some(generate_exe_link(domain)),
        "cmdline" => Some(generate_cmdline(domain)),
        _ if inner.starts_with("fd/") => Some(generate_fd_link(inner, fds)),
        _ => None,
    }
}

fn generate_proc_toplevel(
    path: &str,
    sys: &SystemInfo,
    deception: &DeceptionPolicy,
) -> Option<String> {
    match path {
        "cpuinfo" => Some(generate_cpuinfo(sys, deception)),
        "meminfo" => Some(generate_meminfo(sys, deception)),
        "version" => Some(generate_version(deception)),
        "stat" => Some(generate_proc_stat(sys)),
        "uptime" => Some(generate_uptime(sys)),
        "loadavg" => Some(String::from("0.00 0.00 0.00 1/1 1\n")),
        _ => None,
    }
}

fn generate_sys(
    path: &str,
    sys: &SystemInfo,
    deception: &DeceptionPolicy,
) -> Option<String> {
    match path {
        "devices/system/cpu/online" => {
            let count = if deception.active {
                deception.fake_cpu_count.unwrap_or(sys.cpu_count)
            } else {
                sys.cpu_count
            };
            if count <= 1 {
                Some(String::from("0\n"))
            } else {
                let mut s = String::new();
                let _ = write!(s, "0-{}\n", count - 1);
                Some(s)
            }
        }
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Individual generators
// ---------------------------------------------------------------------------

fn generate_maps(regions: &[MemRegion], _domain: &DomainInfo) -> String {
    let mut out = String::new();
    for r in regions {
        let perm_r = if r.r { 'r' } else { '-' };
        let perm_w = if r.w { 'w' } else { '-' };
        let perm_x = if r.x { 'x' } else { '-' };
        let perm_p = if r.private { 'p' } else { 's' };
        let _ = write!(
            out,
            "{:012x}-{:012x} {}{}{}{} {:08x} {:02x}:{:02x} {}\n",
            r.start, r.end, perm_r, perm_w, perm_x, perm_p,
            r.offset, r.dev_major, r.dev_minor, r.inode,
        );
    }
    out
}

fn generate_status(domain: &DomainInfo) -> String {
    let name = core::str::from_utf8(&domain.name[..domain.name_len]).unwrap_or("unknown");
    let state_char = domain.state as char;
    let state_word = match domain.state {
        b'R' => "running",
        b'S' => "sleeping",
        b'D' => "disk sleep",
        b'Z' => "zombie",
        b'T' => "stopped",
        _ => "unknown",
    };

    let mut out = String::new();
    let _ = write!(out, "Name:\t{}\n", name);
    let _ = write!(out, "Umask:\t0022\n");
    let _ = write!(out, "State:\t{} ({})\n", state_char, state_word);
    let _ = write!(out, "Tgid:\t{}\n", domain.tgid);
    let _ = write!(out, "Pid:\t{}\n", domain.pid);
    let _ = write!(out, "PPid:\t1\n");
    let _ = write!(out, "Threads:\t{}\n", domain.thread_count);
    let _ = write!(out, "VmSize:\t{} kB\n", domain.vm_size_kb);
    let _ = write!(out, "VmRSS:\t{} kB\n", domain.rss_pages * 4);
    let _ = write!(out, "CapInh:\t0000000000000000\n");
    let _ = write!(out, "CapPrm:\t0000000000000000\n");
    let _ = write!(out, "CapEff:\t0000000000000000\n");
    out
}

fn generate_stat(domain: &DomainInfo) -> String {
    let name = core::str::from_utf8(&domain.name[..domain.name_len]).unwrap_or("unknown");
    let state = domain.state as char;
    // pid (comm) state ppid pgrp session tty_nr tpgid flags ...
    let mut out = String::new();
    let _ = write!(
        out,
        "{} ({}) {} 1 {} {} 0 0 0 0 0 0 0 0 0 0 {} 0 0 0 {} 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0\n",
        domain.pid, name, state, domain.pid, domain.pid,
        domain.thread_count, domain.vm_size_kb * 1024,
    );
    out
}

fn generate_exe_link(domain: &DomainInfo) -> String {
    let name = core::str::from_utf8(&domain.name[..domain.name_len]).unwrap_or("program");
    let mut out = String::from("/bin/");
    out.push_str(name);
    out
}

fn generate_cmdline(domain: &DomainInfo) -> String {
    let name = core::str::from_utf8(&domain.name[..domain.name_len]).unwrap_or("program");
    // NUL-separated argv; just the program name for now.
    let mut out = String::new();
    out.push_str(name);
    out.push('\0');
    out
}

fn generate_fd_link(inner: &str, fds: &[FdEntry]) -> String {
    // inner = "fd/<n>"
    let fd_str = inner.strip_prefix("fd/").unwrap_or("0");
    let fd_num: u32 = {
        let mut n = 0u32;
        for b in fd_str.bytes() {
            if b.is_ascii_digit() {
                n = n * 10 + (b - b'0') as u32;
            } else {
                break;
            }
        }
        n
    };

    for entry in fds {
        if entry.fd == fd_num {
            return match entry.kind {
                FdKind::File => String::from("/dev/fd/file"),
                FdKind::Pipe => String::from("pipe:[0]"),
                FdKind::Socket => String::from("socket:[0]"),
                FdKind::Eventfd => String::from("anon_inode:[eventfd]"),
                FdKind::Timerfd => String::from("anon_inode:[timerfd]"),
                FdKind::Epoll => String::from("anon_inode:[eventpoll]"),
                FdKind::Signalfd => String::from("anon_inode:[signalfd]"),
                FdKind::AnonInode => String::from("anon_inode:[unknown]"),
            };
        }
    }
    String::from("/dev/null")
}

fn generate_cpuinfo(sys: &SystemInfo, deception: &DeceptionPolicy) -> String {
    let cpu_count = if deception.active {
        deception.fake_cpu_count.unwrap_or(sys.cpu_count)
    } else {
        sys.cpu_count
    };

    let model = if deception.active {
        if let Some(ref m) = deception.cpu_model {
            core::str::from_utf8(&m[..deception.cpu_model_len]).unwrap_or("SOT CPU")
        } else {
            core::str::from_utf8(&sys.cpu_model[..sys.cpu_model_len]).unwrap_or("SOT CPU")
        }
    } else {
        core::str::from_utf8(&sys.cpu_model[..sys.cpu_model_len]).unwrap_or("SOT CPU")
    };

    let mut out = String::new();
    for i in 0..cpu_count {
        let _ = write!(out, "processor\t: {}\n", i);
        let _ = write!(out, "vendor_id\t: GenuineIntel\n");
        let _ = write!(out, "cpu family\t: 6\n");
        let _ = write!(out, "model\t\t: 142\n");
        let _ = write!(out, "model name\t: {}\n", model);
        let _ = write!(out, "stepping\t: 10\n");
        let _ = write!(out, "cpu MHz\t\t: {}.000\n", sys.cpu_mhz);
        let _ = write!(out, "cache size\t: 8192 KB\n");
        let _ = write!(out, "physical id\t: 0\n");
        let _ = write!(out, "siblings\t: {}\n", cpu_count);
        let _ = write!(out, "core id\t\t: {}\n", i);
        let _ = write!(out, "cpu cores\t: {}\n", cpu_count);
        let _ = write!(out, "flags\t\t: fpu vme de pse tsc msr pae mce cx8 apic sep mtrr pge mca cmov pat pse36 clflush mmx fxsr sse sse2 ss ht syscall nx rdtscp lm\n");
        let _ = write!(out, "bogomips\t: {}.00\n", sys.cpu_mhz * 2);
        let _ = write!(out, "clflush size\t: 64\n");
        let _ = write!(out, "cache_alignment\t: 64\n");
        let _ = write!(out, "address sizes\t: 48 bits physical, 48 bits virtual\n");
        let _ = write!(out, "\n");
    }
    out
}

fn generate_meminfo(sys: &SystemInfo, deception: &DeceptionPolicy) -> String {
    let total = if deception.active {
        deception.fake_mem_total_kb.unwrap_or(sys.mem_total_kb)
    } else {
        sys.mem_total_kb
    };
    let free = sys.mem_free_kb;
    let cached = sys.mem_cached_kb;
    let available = free + cached;
    let buffers = cached / 4;

    let mut out = String::new();
    let _ = write!(out, "MemTotal:       {} kB\n", total);
    let _ = write!(out, "MemFree:        {} kB\n", free);
    let _ = write!(out, "MemAvailable:   {} kB\n", available);
    let _ = write!(out, "Buffers:        {} kB\n", buffers);
    let _ = write!(out, "Cached:         {} kB\n", cached);
    let _ = write!(out, "SwapTotal:      0 kB\n");
    let _ = write!(out, "SwapFree:       0 kB\n");
    out
}

fn generate_version(deception: &DeceptionPolicy) -> String {
    if deception.active {
        if let Some(ref kv) = deception.kernel_version {
            let ver = core::str::from_utf8(&kv[..deception.kernel_version_len])
                .unwrap_or("6.1.0-sot");
            let mut out = String::from("Linux version ");
            out.push_str(ver);
            out.push_str(" (sot@sot) (gcc 12.2.0) #1 SMP PREEMPT_DYNAMIC\n");
            return out;
        }
    }
    String::from("Linux version 6.1.0-sot (sot@sot) (gcc 12.2.0) #1 SMP PREEMPT_DYNAMIC sotX\n")
}

fn generate_proc_stat(sys: &SystemInfo) -> String {
    let mut out = String::new();
    // Aggregate CPU line (all zeros -- we don't track jiffies)
    let _ = write!(out, "cpu  0 0 0 0 0 0 0 0 0 0\n");
    for i in 0..sys.cpu_count {
        let _ = write!(out, "cpu{} 0 0 0 0 0 0 0 0 0 0\n", i);
    }
    let _ = write!(out, "intr 0\n");
    let _ = write!(out, "ctxt 0\n");
    let _ = write!(out, "btime {}\n", sys.uptime_secs);
    let _ = write!(out, "processes 1\n");
    let _ = write!(out, "procs_running 1\n");
    let _ = write!(out, "procs_blocked 0\n");
    out
}

fn generate_uptime(sys: &SystemInfo) -> String {
    let mut out = String::new();
    let _ = write!(out, "{}.00 {}.00\n", sys.uptime_secs, sys.uptime_secs);
    out
}
