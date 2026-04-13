// ---------------------------------------------------------------------------
// virtual_files.rs: Virtual file system emulation (/etc/*, /proc/*, /sys/*).
// Extracted from child_handler.rs.
// ---------------------------------------------------------------------------

use crate::exec::{starts_with, rdtsc};
use crate::child_handler::fmt_u64;
use crate::process::{PROCESSES, MAX_PROCS};

/// Format /proc/uptime as "SECS.00 SECS.00\n"
fn fmt_uptime(secs: u64, buf: &mut [u8; 32]) -> usize {
    let mut i = 0usize;
    // Write seconds as decimal
    if secs == 0 { buf[i] = b'0'; i += 1; }
    else {
        let mut tmp = [0u8; 20];
        let mut n = 0;
        let mut v = secs;
        while v > 0 { tmp[n] = b'0' + (v % 10) as u8; n += 1; v /= 10; }
        for j in (0..n).rev() { buf[i] = tmp[j]; i += 1; }
    }
    buf[i] = b'.'; i += 1;
    buf[i] = b'0'; i += 1;
    buf[i] = b'0'; i += 1;
    buf[i] = b' '; i += 1;
    // Idle time = same
    if secs == 0 { buf[i] = b'0'; i += 1; }
    else {
        let mut tmp = [0u8; 20];
        let mut n = 0;
        let mut v = secs;
        while v > 0 { tmp[n] = b'0' + (v % 10) as u8; n += 1; v /= 10; }
        for j in (0..n).rev() { buf[i] = tmp[j]; i += 1; }
    }
    buf[i] = b'.'; i += 1;
    buf[i] = b'0'; i += 1;
    buf[i] = b'0'; i += 1;
    buf[i] = b'\n'; i += 1;
    i
}

/// Open a virtual file (/etc/*, /proc/*, /sys/*). Returns Some(content_len) or None.
pub(crate) fn open_virtual_file(name: &[u8], dir_buf: &mut [u8]) -> Option<usize> {
    if starts_with(name, b"/etc/") {
        let gen_len: usize;
        if name == b"/etc/nanorc" {
            let c = b"set nohelp\nset nonewlines\n";
            dir_buf[..c.len()].copy_from_slice(c);
            gen_len = c.len();
        } else if name == b"/etc/resolv.conf" {
            let c = b"nameserver 10.0.2.3\n";
            dir_buf[..c.len()].copy_from_slice(c);
            gen_len = c.len();
        } else if name == b"/etc/hosts" {
            let c = b"127.0.0.1 localhost\n::1 localhost\n104.18.27.120 example.com\n151.101.130.132 dl-cdn.alpinelinux.org\n";
            dir_buf[..c.len()].copy_from_slice(c);
            gen_len = c.len();
        } else if name == b"/etc/nsswitch.conf" {
            let c = b"hosts: files dns\n";
            dir_buf[..c.len()].copy_from_slice(c);
            gen_len = c.len();
        } else if name == b"/etc/ld.so.cache" {
            return None;
        } else if name == b"/etc/ld.so.preload" {
            gen_len = 0;
        } else if name == b"/etc/passwd" {
            let c = b"root:x:0:0:root:/root:/bin/sh\nnobody:x:65534:65534:nobody:/:/usr/bin/nologin\n";
            let n = c.len().min(dir_buf.len());
            dir_buf[..n].copy_from_slice(&c[..n]);
            gen_len = n;
        } else if name == b"/etc/group" {
            let c = b"root:x:0:\nnogroup:x:65534:\n";
            let n = c.len().min(dir_buf.len());
            dir_buf[..n].copy_from_slice(&c[..n]);
            gen_len = n;
        } else if name == b"/etc/os-release" {
            let c = b"PRETTY_NAME=\"sotX (Exokernel)\"\nNAME=\"sotX\"\nID=sotos\nVERSION=\"1.0\"\nVERSION_ID=\"1.0\"\nHOME_URL=\"https://github.com/nicksotomern/sotX\"\n";
            let n = c.len().min(dir_buf.len());
            dir_buf[..n].copy_from_slice(&c[..n]);
            gen_len = n;
        } else if name == b"/etc/apk/repositories" {
            // Alpine repos via HTTPS proxy on host (10.0.2.2:8080)
            // Use `just run-https` to auto-start the proxy
            let c = b"http://10.0.2.2:8080/https://dl-cdn.alpinelinux.org/alpine/v3.20/main\nhttp://10.0.2.2:8080/https://dl-cdn.alpinelinux.org/alpine/v3.20/community\n";
            let n = c.len().min(dir_buf.len());
            dir_buf[..n].copy_from_slice(&c[..n]);
            gen_len = n;
        } else if name == b"/etc/apk/world" {
            gen_len = 0; // empty world file (no manually installed packages)
        } else if name == b"/etc/apk/arch" {
            let c = b"x86_64\n";
            dir_buf[..c.len()].copy_from_slice(c);
            gen_len = c.len();
        } else if starts_with(name, b"/etc/apk/keys/") {
            gen_len = 0; // empty key stubs
        } else if name == b"/lib/apk/db/installed"
               || name == b"/lib/apk/db/triggers"
               || name == b"/lib/apk/db/scripts.tar"
               || name == b"/lib/apk/db/lock" {
            gen_len = 0; // empty apk db files (bootstrap)
        } else if name == b"/etc/ssl/certs/ca-certificates.crt"
               || name == b"/etc/ssl/cert.pem"
               || name == b"/etc/pki/tls/certs/ca-bundle.crt"
               || name == b"/etc/ssl/certs/ca-bundle.crt" {
            // TLS CA certificate bundle placeholder.
            // When using the HTTPS proxy (just run-https), TLS is handled
            // by the host proxy so the guest doesn't need real certificates.
            // Return an empty file so programs don't fail with "no CA certs".
            // For direct TLS (without proxy), real CA certs would be needed
            // on the sysroot disk image.
            gen_len = 0;
        } else if name == b"/etc/gai.conf" || name == b"/etc/host.conf"
               || name == b"/etc/services" || name == b"/etc/protocols"
               || name == b"/etc/shells" || name == b"/etc/inputrc"
               || name == b"/etc/terminfo" || name == b"/etc/mime.types"
               || name == b"/etc/localtime" || name == b"/etc/locale.alias" {
            gen_len = 0;
        } else {
            return None;
        }
        Some(gen_len)
    } else if name == b"/usr/share/terminfo/x/xterm"
           || name == b"/usr/share/terminfo/d/dumb" {
        // Serve terminfo data directly from initrd
        if let Ok(sz) = sotos_common::sys::initrd_read(
            b"xterm\0".as_ptr() as u64, 5, dir_buf.as_mut_ptr() as u64,
            dir_buf.len() as u64,
        ) {
            return Some(sz as usize);
        }
        return Some(0);
    } else if starts_with(name, b"/proc/") || starts_with(name, b"/sys/") {
        let gen_len: usize;
        if name == b"/proc/self/maps" || name == b"/proc/self/smaps" {
            // Dynamic VMA-based output (pid is not available here, use group 0)
            gen_len = crate::syscalls::mm::format_proc_maps(0, dir_buf);
        } else if name == b"/proc/cpuinfo" {
            let info = b"processor\t: 0\nvendor_id\t: GenuineIntel\ncpu family\t: 6\nmodel name\t: QEMU Virtual CPU\ncache size\t: 4096 KB\nflags\t\t: fpu sse sse2 ssse3 sse4_1 sse4_2 rdtsc\n\n";
            let n = info.len().min(dir_buf.len());
            dir_buf[..n].copy_from_slice(&info[..n]);
            gen_len = n;
        } else if name == b"/proc/meminfo" {
            let info = b"MemTotal:       262144 kB\nMemFree:        131072 kB\nMemAvailable:   196608 kB\nBuffers:         8192 kB\nCached:         32768 kB\n";
            let n = info.len().min(dir_buf.len());
            dir_buf[..n].copy_from_slice(&info[..n]);
            gen_len = n;
        } else if name == b"/proc/stat" {
            // Global CPU stats -- htop needs this to start
            let tsc = rdtsc();
            let jiffies = tsc / 20_000_000; // ~100Hz jiffies at 2GHz
            let idle = jiffies * 95 / 100; // 95% idle
            let user = jiffies * 3 / 100;
            let sys = jiffies * 2 / 100;
            let mut w = [0u8; 512];
            let mut p = 0usize;
            // "cpu  user nice system idle iowait irq softirq steal"
            let hdr = b"cpu  ";
            w[p..p+hdr.len()].copy_from_slice(hdr); p += hdr.len();
            p += fmt_u64(user, &mut w[p..]);
            w[p] = b' '; p += 1;
            p += fmt_u64(0, &mut w[p..]); // nice
            w[p] = b' '; p += 1;
            p += fmt_u64(sys, &mut w[p..]);
            w[p] = b' '; p += 1;
            p += fmt_u64(idle, &mut w[p..]);
            w[p..p+8].copy_from_slice(b" 0 0 0 0"); p += 8;
            w[p] = b'\n'; p += 1;
            // cpu0 line (same values, single CPU)
            let cpu0 = b"cpu0 ";
            w[p..p+cpu0.len()].copy_from_slice(cpu0); p += cpu0.len();
            p += fmt_u64(user, &mut w[p..]);
            w[p] = b' '; p += 1;
            p += fmt_u64(0, &mut w[p..]);
            w[p] = b' '; p += 1;
            p += fmt_u64(sys, &mut w[p..]);
            w[p] = b' '; p += 1;
            p += fmt_u64(idle, &mut w[p..]);
            w[p..p+8].copy_from_slice(b" 0 0 0 0"); p += 8;
            w[p] = b'\n'; p += 1;
            // Mandatory extra lines
            let extra = b"intr 0\nctxt 0\nbtime 0\nprocesses 1\nprocs_running 1\nprocs_blocked 0\n";
            let e = extra.len().min(w.len() - p);
            w[p..p+e].copy_from_slice(&extra[..e]); p += e;
            let n = p.min(dir_buf.len());
            dir_buf[..n].copy_from_slice(&w[..n]);
            gen_len = n;
        } else if name == b"/proc/version" {
            let info = b"Linux version 5.15.0-sotX (root@sotX) (gcc 12.0) #1 SMP PREEMPT\n";
            let n = info.len().min(dir_buf.len());
            dir_buf[..n].copy_from_slice(&info[..n]);
            gen_len = n;
        } else if name == b"/proc/self/exe" {
            gen_len = 0;
        } else if name == b"/sys/devices/system/cpu/online" {
            let c = b"0\n";
            dir_buf[..c.len()].copy_from_slice(c);
            gen_len = c.len();
        } else if name == b"/proc/uptime" {
            let tsc = rdtsc();
            let secs = tsc / 2_000_000_000; // ~2GHz assumed
            let mut buf = [0u8; 32];
            let n = fmt_uptime(secs, &mut buf);
            dir_buf[..n].copy_from_slice(&buf[..n]);
            gen_len = n;
        } else if name == b"/proc/loadavg" {
            let c = b"0.00 0.00 0.00 1/1 1\n";
            dir_buf[..c.len()].copy_from_slice(c);
            gen_len = c.len();
        } else if name == b"/proc/sys/kernel/hostname" {
            let c = b"sotX\n";
            dir_buf[..c.len()].copy_from_slice(c);
            gen_len = c.len();
        } else if name == b"/proc/sys/kernel/osrelease" {
            let c = b"5.15.0-sotX\n";
            dir_buf[..c.len()].copy_from_slice(c);
            gen_len = c.len();
        } else if starts_with(name, b"/sys/devices/virtual/dmi/id/") {
            // DMI/SMBIOS: board_name, board_vendor, product_name, etc.
            let c = b"QEMU Virtual Machine\n";
            dir_buf[..c.len()].copy_from_slice(c);
            gen_len = c.len();
        } else if let Some(content) = crate::udev::sys_class_drm_content(name) {
            // DRM/input device sysfs entries (for libudev device enumeration)
            let n = content.len().min(dir_buf.len());
            dir_buf[..n].copy_from_slice(&content[..n]);
            gen_len = n;
        } else if starts_with(name, b"/sys/class/") || starts_with(name, b"/sys/bus/")
               || starts_with(name, b"/sys/devices/") || starts_with(name, b"/sys/dev/") {
            // Generic /sys stub: return empty
            gen_len = 0;
        } else if name == b"/proc" || name == b"/proc/" {
            // /proc directory listing -- generate PID entries for htop
            let mut p = 0usize;
            // Standard procfs entries
            for entry_name in [b"stat" as &[u8], b"meminfo", b"cpuinfo", b"uptime",
                               b"loadavg", b"version", b"self"] {
                if p + entry_name.len() + 1 >= dir_buf.len() { break; }
                dir_buf[p..p+entry_name.len()].copy_from_slice(entry_name);
                p += entry_name.len();
                dir_buf[p] = b'\n'; p += 1;
            }
            // Add PID entries for active processes
            for i in 0..MAX_PROCS {
                if PROCESSES[i].state.load(core::sync::atomic::Ordering::Acquire) == 1 {
                    let pid = i + 1;
                    let n = fmt_u64(pid as u64, &mut dir_buf[p..]);
                    p += n;
                    dir_buf[p] = b'\n'; p += 1;
                }
            }
            gen_len = p;
        } else if starts_with(name, b"/proc/self/") || starts_with(name, b"/proc/1/") {
            // Unhandled /proc/self/* paths: return empty (non-fatal for fastfetch)
            gen_len = 0;
        } else if starts_with(name, b"/proc/") {
            // /proc/N/stat, /proc/N/statm, /proc/N/cmdline for arbitrary PIDs (htop)
            let rest = &name[6..];
            // Parse PID (digits before '/')
            let mut pid_val = 0u64;
            let mut slash_pos = 0;
            for j in 0..rest.len() {
                if rest[j] == b'/' { slash_pos = j; break; }
                if rest[j] >= b'0' && rest[j] <= b'9' {
                    pid_val = pid_val * 10 + (rest[j] - b'0') as u64;
                }
            }
            if slash_pos > 0 && pid_val > 0 {
                let subpath = &rest[slash_pos+1..];
                if subpath == b"stat" {
                    let n = crate::exec::format_proc_self_stat(dir_buf, pid_val as usize);
                    gen_len = n;
                } else if subpath == b"statm" {
                    // Real memory stats: size resident shared text lib data dt
                    let p = &PROCESSES[pid_val as usize - 1];
                    let brk_sz = p.brk_current.load(core::sync::atomic::Ordering::Acquire)
                        .saturating_sub(p.brk_base.load(core::sync::atomic::Ordering::Acquire));
                    let mmap_sz = p.mmap_next.load(core::sync::atomic::Ordering::Acquire)
                        .saturating_sub(p.mmap_base.load(core::sync::atomic::Ordering::Acquire));
                    let elf_sz = p.elf_hi.load(core::sync::atomic::Ordering::Acquire)
                        .saturating_sub(p.elf_lo.load(core::sync::atomic::Ordering::Acquire));
                    let pages = (brk_sz + mmap_sz + elf_sz + 0x4000) / 4096;
                    let rss = pages;
                    let mut w = [0u8; 64];
                    let mut pos = 0;
                    pos += fmt_u64(pages, &mut w[pos..]); w[pos] = b' '; pos += 1;
                    pos += fmt_u64(rss, &mut w[pos..]); w[pos] = b' '; pos += 1;
                    pos += fmt_u64(0, &mut w[pos..]); w[pos] = b' '; pos += 1; // shared
                    pos += fmt_u64(elf_sz / 4096, &mut w[pos..]); w[pos] = b' '; pos += 1; // text
                    pos += fmt_u64(0, &mut w[pos..]); w[pos] = b' '; pos += 1; // lib
                    pos += fmt_u64((brk_sz + mmap_sz) / 4096, &mut w[pos..]); w[pos] = b' '; pos += 1; // data
                    pos += fmt_u64(0, &mut w[pos..]); w[pos] = b'\n'; pos += 1; // dt
                    dir_buf[..pos].copy_from_slice(&w[..pos]);
                    gen_len = pos;
                } else if subpath == b"cmdline" {
                    let c = b"[sotX]\0";
                    dir_buf[..c.len()].copy_from_slice(c);
                    gen_len = c.len();
                } else if subpath == b"status" {
                    let p = &PROCESSES[pid_val as usize - 1];
                    let st = p.state.load(core::sync::atomic::Ordering::Acquire);
                    let ppid = p.parent.load(core::sync::atomic::Ordering::Acquire);
                    let state_str = match st { 1 => b"R (running)" as &[u8], 2 => b"Z (zombie)", _ => b"S (sleeping)" };
                    let brk_sz = p.brk_current.load(core::sync::atomic::Ordering::Acquire)
                        .saturating_sub(p.brk_base.load(core::sync::atomic::Ordering::Acquire));
                    let mmap_sz = p.mmap_next.load(core::sync::atomic::Ordering::Acquire)
                        .saturating_sub(p.mmap_base.load(core::sync::atomic::Ordering::Acquire));
                    let elf_sz = p.elf_hi.load(core::sync::atomic::Ordering::Acquire)
                        .saturating_sub(p.elf_lo.load(core::sync::atomic::Ordering::Acquire));
                    let vm_kb = (brk_sz + mmap_sz + elf_sz + 0x4000) / 1024;
                    let mut w = [0u8; 256];
                    let mut pos = 0;
                    let hdr = b"Name:\tsotX\nState:\t";
                    w[pos..pos+hdr.len()].copy_from_slice(hdr); pos += hdr.len();
                    w[pos..pos+state_str.len()].copy_from_slice(state_str); pos += state_str.len();
                    w[pos] = b'\n'; pos += 1;
                    let pid_hdr = b"Pid:\t";
                    w[pos..pos+pid_hdr.len()].copy_from_slice(pid_hdr); pos += pid_hdr.len();
                    pos += fmt_u64(pid_val, &mut w[pos..]);
                    w[pos] = b'\n'; pos += 1;
                    let ppid_hdr = b"PPid:\t";
                    w[pos..pos+ppid_hdr.len()].copy_from_slice(ppid_hdr); pos += ppid_hdr.len();
                    pos += fmt_u64(ppid, &mut w[pos..]);
                    let rest = b"\nUid:\t0\t0\t0\t0\nGid:\t0\t0\t0\t0\nVmSize:\t";
                    w[pos..pos+rest.len()].copy_from_slice(rest); pos += rest.len();
                    pos += fmt_u64(vm_kb, &mut w[pos..]);
                    let kb_end = b" kB\nVmRSS:\t";
                    w[pos..pos+kb_end.len()].copy_from_slice(kb_end); pos += kb_end.len();
                    pos += fmt_u64(vm_kb, &mut w[pos..]);
                    let end = b" kB\nThreads:\t1\n";
                    w[pos..pos+end.len()].copy_from_slice(end); pos += end.len();
                    dir_buf[..pos].copy_from_slice(&w[..pos]);
                    gen_len = pos;
                } else {
                    gen_len = 0; // unknown subpath
                }
            } else {
                gen_len = 0;
            }
        } else {
            return None;
        }
        Some(gen_len)
    } else if starts_with(name, b"/run/udev/") {
        // libudev database files (device properties/tags)
        if let Some(content) = crate::udev::sys_class_drm_content(name) {
            let n = content.len().min(dir_buf.len());
            dir_buf[..n].copy_from_slice(&content[..n]);
            Some(n)
        } else {
            None // file not found → -ENOENT
        }
    } else {
        None
    }
}

/// CSPRNG: ChaCha20-based, seeded from RDTSC.
pub(crate) fn fill_random(buf: &mut [u8]) {
    use rand_core::{RngCore, SeedableRng};
    use rand_chacha::ChaCha20Rng;
    static mut RNG: Option<ChaCha20Rng> = None;
    unsafe {
        if RNG.is_none() {
            let mut seed = [0u8; 32];
            let tsc = rdtsc();
            seed[0..8].copy_from_slice(&tsc.to_le_bytes());
            let tsc2 = rdtsc();
            seed[8..16].copy_from_slice(&tsc2.to_le_bytes());
            let tsc3 = rdtsc();
            seed[16..24].copy_from_slice(&tsc3.to_le_bytes());
            RNG = Some(ChaCha20Rng::from_seed(seed));
        }
        RNG.as_mut().unwrap().fill_bytes(buf);
    }
}
