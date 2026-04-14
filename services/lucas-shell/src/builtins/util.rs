//! Miscellaneous built-ins and kernel-syscall glue used by sibling modules:
//! trace, read, sleep, type, services, caps, bench, snap, cd, pwd, source,
//! plus `kernel_syscall{0,2,3}`, `rdtsc`, `print_bench_result`, and
//! `capture_command` (used by pipes/redirects).

use crate::syscall::*;
use crate::util::*;
use crate::env::*;
use crate::{err, usage};

// ---------------------------------------------------------------------------
// Kernel syscall helpers (bypass Linux translation layer)
// ---------------------------------------------------------------------------

/// SOTX_NATIVE_FLAG: bit 63 in rax tells the kernel "skip the LUCAS
/// redirect, dispatch this as a sotX-native syscall directly". Without it,
/// every raw `syscall` from a redirected thread is sent to init's
/// lucas_handler for Linux-ABI translation, which can't make sense of
/// numbers like 252 (DebugFreeFrames) / 142 (ThreadCount) / 131 (SvcLookup)
/// — they overlap unrelated Linux numbers (ioprio_get / sched_setparam /
/// sigaltstack). Mirror of `sotos_common::SOTX_NATIVE_FLAG`.
const SOTX_NATIVE_FLAG: u64 = 1 << 63;

/// Issue a sotX kernel syscall with zero arguments (syscall number > 127).
/// Bypasses init's Linux-ABI translation via SOTX_NATIVE_FLAG.
#[inline(always)]
pub(crate) fn kernel_syscall0(nr: u64) -> i64 {
    let ret: i64;
    unsafe {
        core::arch::asm!(
            "syscall",
            inlateout("rax") nr | SOTX_NATIVE_FLAG => ret,
            lateout("rcx") _,
            lateout("r11") _,
            options(nostack),
        );
    }
    ret
}

/// Issue a sotX kernel syscall with two arguments.
#[inline(always)]
fn kernel_syscall2(nr: u64, a1: u64, a2: u64) -> i64 {
    let ret: i64;
    unsafe {
        core::arch::asm!(
            "syscall",
            inlateout("rax") nr | SOTX_NATIVE_FLAG => ret,
            in("rdi") a1,
            in("rsi") a2,
            lateout("rcx") _,
            lateout("r11") _,
            options(nostack),
        );
    }
    ret
}

/// Issue a sotX kernel syscall with three arguments.
#[inline(always)]
fn kernel_syscall3(nr: u64, a1: u64, a2: u64, a3: u64) -> i64 {
    let ret: i64;
    unsafe {
        core::arch::asm!(
            "syscall",
            inlateout("rax") nr | SOTX_NATIVE_FLAG => ret,
            in("rdi") a1,
            in("rsi") a2,
            in("rdx") a3,
            lateout("rcx") _,
            lateout("r11") _,
            options(nostack),
        );
    }
    ret
}

/// Read the CPU timestamp counter.
#[inline(always)]
fn rdtsc() -> u64 {
    let lo: u32;
    let hi: u32;
    unsafe {
        core::arch::asm!("rdtsc", out("eax") lo, out("edx") hi, options(nostack, nomem));
    }
    ((hi as u64) << 32) | (lo as u64)
}

/// Print benchmark results: "<label> x<iters>: <total> cycles total, <avg> cycles/call avg\n"
fn print_bench_result(label: &[u8], iters: u64, total_cycles: u64) {
    print(label);
    print(b" x");
    print_u64(iters);
    print(b": ");
    print_u64(total_cycles);
    print(b" cycles total, ");
    print_u64(total_cycles / iters);
    print(b" cycles/call avg\n");
}

// --- services ---

/// List registered kernel services by probing svc_lookup for known names.
pub fn cmd_services() {
    print(b"Registered services:\n");
    const NAMES: &[&[u8]] = &[
        b"net", b"blk", b"lkl", b"kbd", b"nvme", b"xhci", b"compositor",
    ];
    let mut found: u64 = 0;
    for &name in NAMES.iter() {
        let ret = kernel_syscall2(131, name.as_ptr() as u64, name.len() as u64);
        if ret > 0 {
            print(b"  [+] ");
            print(name);
            print(b"  (cap ");
            print_u64(ret as u64);
            print(b")\n");
            found += 1;
        } else {
            print(b"  [-] ");
            print(name);
            print(b"  (not found)\n");
        }
    }
    print_u64(found);
    print(b" of ");
    print_u64(NAMES.len() as u64);
    print(b" services registered\n");
}

// --- bench ---

/// Quick IPC round-trip benchmark using RDTSC.
pub fn cmd_bench() {
    const ITERS: u64 = 100;
    print(b"IPC benchmark: ");
    print_u64(ITERS);
    print(b" round-trips...\n");

    // Always-available syscall-overhead baseline (getpid, no IPC).
    let start = rdtsc();
    for _ in 0..ITERS {
        crate::syscall::syscall0(39); // getpid
    }
    let elapsed = rdtsc().wrapping_sub(start);
    print_bench_result(b"Syscall overhead (getpid)", ITERS, elapsed);

    // Try the IPC path on top: create an endpoint and measure the cost
    // of `call_timeout` returning -ETIMEDOUT (no receiver). Previous code
    // used SYS_SEND (sync, blocks forever without a receiver) which hung
    // the shell. SYS_CALL_TIMEOUT (135) with timeout=1 tick fails fast.
    let ep = kernel_syscall0(10); // SYS_ENDPOINT_CREATE
    if ep <= 0 {
        print(b"bench: endpoint_create failed (ep=");
        print_u64((-ep) as u64);
        print(b"), skipping IPC measurement\n");
        return;
    }

    // SYS_CALL_TIMEOUT: rdi packs ep_cap (low 32) + timeout_ticks (high 32).
    let timeout_ticks: u64 = 1;
    let rdi = (ep as u64 & 0xFFFFFFFF) | (timeout_ticks << 32);
    let start = rdtsc();
    for _ in 0..ITERS {
        kernel_syscall3(135, rdi, 0, 0);
    }
    let elapsed = rdtsc().wrapping_sub(start);
    print_bench_result(b"IPC call (timed out)", ITERS, elapsed);
}

// --- caps ---

/// Placeholder for capability audit (Unit 6).
pub fn cmd_caps() {
    print(b"Capability audit not yet implemented\n");
}

// --- cd ---

pub fn cmd_cd(name: &[u8]) {
    let mut path_buf = [0u8; 64];
    let path = null_terminate(name, &mut path_buf);
    let ret = linux_chdir(path);
    if ret < 0 {
        err!(b"cd", b"not a directory or not found", name);
    }
}

// --- pwd ---

pub fn cmd_pwd() {
    let mut buf = [0u8; 128];
    let ret = linux_getcwd(buf.as_mut_ptr(), buf.len() as u64);
    if ret > 0 {
        // Find NUL or use full buf
        let mut len = 0;
        while len < buf.len() && buf[len] != 0 {
            len += 1;
        }
        linux_write(1, buf.as_ptr(), len);
        print(b"\n");
    } else {
        print(b"/\n");
    }
}

// --- snap ---

pub fn cmd_snap(args: &[u8]) {
    if starts_with(args, b"create ") {
        let name = trim(&args[7..]);
        if name.is_empty() { usage!(b"snap", b"snap create <name>"); return; }
        if !open_virtual_and_print(b"/snap/create/", name) {
            err!(b"snap create", b"failed", name);
        }
    } else if eq(args, b"list") {
        if !open_virtual_and_print(b"/snap/list", b"") {
            err!(b"snap list", b"failed");
        }
    } else if starts_with(args, b"restore ") {
        let name = trim(&args[8..]);
        if name.is_empty() { usage!(b"snap", b"snap restore <name>"); return; }
        if !open_virtual_and_print(b"/snap/restore/", name) {
            err!(b"snap restore", b"failed", name);
        }
    } else if starts_with(args, b"delete ") {
        let name = trim(&args[7..]);
        if name.is_empty() { usage!(b"snap", b"snap delete <name>"); return; }
        if !open_virtual_and_print(b"/snap/delete/", name) {
            err!(b"snap delete", b"failed", name);
        }
    } else {
        usage!(b"snap", b"snap create|list|restore|delete [<name>]");
    }
}

// --- trace ---

pub fn cmd_trace(args: &[u8]) {
    if args.is_empty() || eq(args, b"help") {
        usage!(b"trace", b"trace level <error|warn|info|debug|trace>");
        print(b"       trace cat <+syscall|-net|all|none>\n");
        print(b"       trace status\n");
        return;
    }

    if eq(args, b"status") {
        let lvl = crate::trace::get_level();
        let cats = crate::trace::get_categories();
        print(b"trace level: ");
        let name: &[u8] = match lvl {
            0 => b"error",
            1 => b"warn",
            2 => b"info",
            3 => b"debug",
            4 => b"trace",
            _ => b"?",
        };
        print(name);
        print(b" (");
        print_u64(lvl as u64);
        print(b")\ntrace cats:  0x");
        // Print hex
        let hex = b"0123456789abcdef";
        let digits: [u8; 4] = [
            hex[((cats >> 12) & 0xF) as usize],
            hex[((cats >> 8) & 0xF) as usize],
            hex[((cats >> 4) & 0xF) as usize],
            hex[(cats & 0xF) as usize],
        ];
        print(&digits);
        print(b"\n");
        return;
    }

    if starts_with(args, b"level ") {
        let val = trim(&args[6..]);
        let lvl: u8 = if eq(val, b"error") { 0 }
            else if eq(val, b"warn") { 1 }
            else if eq(val, b"info") { 2 }
            else if eq(val, b"debug") { 3 }
            else if eq(val, b"trace") { 4 }
            else {
                err!(b"trace", b"unknown level", val);
                return;
            };
        crate::trace::set_level(lvl);
        print(b"trace level set to ");
        print(val);
        print(b"\n");
        return;
    }

    if starts_with(args, b"cat ") {
        let val = trim(&args[4..]);
        if eq(val, b"all") {
            crate::trace::set_categories(0xFFFF);
            print(b"trace cats: all\n");
        } else if eq(val, b"none") {
            crate::trace::set_categories(0);
            print(b"trace cats: none\n");
        } else if val.len() > 1 && (val[0] == b'+' || val[0] == b'-') {
            let adding = val[0] == b'+';
            let name = &val[1..];
            let mask = parse_cat_name(name);
            if mask == 0 {
                err!(b"trace", b"unknown category", name);
                return;
            }
            let cur = crate::trace::get_categories();
            let new = if adding { cur | mask } else { cur & !mask };
            crate::trace::set_categories(new);
            if adding { print(b"trace cat +"); } else { print(b"trace cat -"); }
            print(name);
            print(b"\n");
        } else {
            err!(b"trace", b"expected +name, -name, all, or none");
        }
        return;
    }

    err!(b"trace", b"unknown subcommand", args);
}

fn parse_cat_name(name: &[u8]) -> u16 {
    use sotos_common::trace::cat;
    if eq(name, b"syscall") { cat::SYSCALL }
    else if eq(name, b"ipc")     { cat::IPC }
    else if eq(name, b"sched")   { cat::SCHED }
    else if eq(name, b"mm")      { cat::MM }
    else if eq(name, b"fs")      { cat::FS }
    else if eq(name, b"net")     { cat::NET }
    else if eq(name, b"signal")  { cat::SIGNAL }
    else if eq(name, b"process") { cat::PROCESS }
    else if eq(name, b"register"){ cat::REGISTER }
    else { 0 }
}

// ---------------------------------------------------------------------------
// capture_command
// Captures output from built-in commands into a buffer (used for pipes and
// redirects).
// ---------------------------------------------------------------------------

pub fn capture_command(cmd: &[u8], buf: &mut [u8]) -> usize {
    if starts_with(cmd, b"cat ") {
        let n = slurp_file(trim(&cmd[4..]), buf);
        return if n < 0 { 0 } else { n as usize };
    }
    if eq(cmd, b"ls") || starts_with(cmd, b"ls ") {
        let n = slurp_file(b".", buf);
        return if n < 0 { 0 } else { n as usize };
    }
    if eq(cmd, b"env") {
        let mut total: usize = 0;
        for e in env_slice() {
            if e.active && total + e.key_len + e.val_len + 2 < buf.len() {
                buf[total..total + e.key_len].copy_from_slice(&e.key[..e.key_len]);
                total += e.key_len;
                buf[total] = b'=';
                total += 1;
                buf[total..total + e.val_len].copy_from_slice(&e.val[..e.val_len]);
                total += e.val_len;
                buf[total] = b'\n';
                total += 1;
            }
        }
        return total;
    }
    if starts_with(cmd, b"echo ") {
        let rest = &cmd[5..];
        let l = rest.len().min(buf.len() - 1);
        buf[..l].copy_from_slice(&rest[..l]);
        buf[l] = b'\n';
        return l + 1;
    }
    if eq(cmd, b"echo") {
        if buf.len() > 0 { buf[0] = b'\n'; return 1; }
        return 0;
    }
    if eq(cmd, b"ps") {
        let n = slurp_file(b"/proc", buf);
        return if n < 0 { 0 } else { n as usize };
    }
    if eq(cmd, b"uname") {
        let s = b"sotX 0.1.0 x86_64 LUCAS\n";
        let l = s.len().min(buf.len());
        buf[..l].copy_from_slice(&s[..l]);
        return l;
    }
    if starts_with(cmd, b"head ") {
        let args = trim(&cmd[5..]);
        let mut num_lines: usize = 10;
        let name;
        if starts_with(args, b"-n ") {
            let rest = trim(&args[3..]);
            if let Some(sp) = find_space(rest) {
                num_lines = parse_u64_simple(&rest[..sp]) as usize;
                name = trim(&rest[sp + 1..]);
            } else { return 0; }
        } else { name = args; }
        if name.is_empty() { return 0; }
        let mut data = [0u8; 4096];
        let dlen = slurp_file(name, &mut data);
        if dlen < 0 { return 0; }
        let dlen = dlen as usize;
        let mut total: usize = 0;
        let mut lines: usize = 0;
        for i in 0..dlen {
            if lines >= num_lines { break; }
            if total >= buf.len() { break; }
            buf[total] = data[i];
            total += 1;
            if data[i] == b'\n' { lines += 1; }
        }
        return total;
    }
    if starts_with(cmd, b"tail ") {
        let args = trim(&cmd[5..]);
        let mut num_lines: usize = 10;
        let name;
        if starts_with(args, b"-n ") {
            let rest = trim(&args[3..]);
            if let Some(sp) = find_space(rest) {
                num_lines = parse_u64_simple(&rest[..sp]) as usize;
                name = trim(&rest[sp + 1..]);
            } else { return 0; }
        } else { name = args; }
        if name.is_empty() { return 0; }
        let mut data = [0u8; 4096];
        let dlen = slurp_file(name, &mut data);
        if dlen < 0 { return 0; }
        let dlen = dlen as usize;
        let mut line_count: usize = 0;
        for i in 0..dlen { if data[i] == b'\n' { line_count += 1; } }
        let skip = if line_count > num_lines { line_count - num_lines } else { 0 };
        let mut seen: usize = 0;
        let mut total: usize = 0;
        for i in 0..dlen {
            if seen >= skip {
                if total >= buf.len() { break; }
                buf[total] = data[i];
                total += 1;
            }
            if data[i] == b'\n' { seen += 1; }
        }
        return total;
    }
    if starts_with(cmd, b"grep ") {
        let args = trim(&cmd[5..]);
        if let Some(sp) = find_space(args) {
            let pattern = &args[..sp];
            let name = trim(&args[sp + 1..]);
            if name.is_empty() { return 0; }
            let mut data = [0u8; 4096];
            let dlen = slurp_file(name, &mut data);
            if dlen < 0 { return 0; }
            let dlen = dlen as usize;
            let mut total: usize = 0;
            let mut line_start: usize = 0;
            let mut i: usize = 0;
            while i <= dlen {
                if i == dlen || data[i] == b'\n' {
                    let line = &data[line_start..i];
                    if contains(line, pattern) {
                        let l = line.len().min(buf.len() - total);
                        buf[total..total + l].copy_from_slice(&line[..l]);
                        total += l;
                        if total < buf.len() { buf[total] = b'\n'; total += 1; }
                    }
                    line_start = i + 1;
                }
                i += 1;
            }
            return total;
        }
        return 0;
    }
    if starts_with(cmd, b"stat ") {
        let name = trim(&cmd[5..]);
        if name.is_empty() { return 0; }
        let mut path_buf = [0u8; 64];
        let path = null_terminate(name, &mut path_buf);
        let mut stat_buf = [0u8; 144];
        let ret = linux_stat(path, stat_buf.as_mut_ptr());
        if ret < 0 { return 0; }
        let mode = u32::from_le_bytes([stat_buf[24], stat_buf[25], stat_buf[26], stat_buf[27]]);
        let size = u64::from_le_bytes([
            stat_buf[48], stat_buf[49], stat_buf[50], stat_buf[51],
            stat_buf[52], stat_buf[53], stat_buf[54], stat_buf[55],
        ]);
        let ino = u64::from_le_bytes([
            stat_buf[8], stat_buf[9], stat_buf[10], stat_buf[11],
            stat_buf[12], stat_buf[13], stat_buf[14], stat_buf[15],
        ]);
        let mut total: usize = 0;
        // "  file: <name>\n"
        let prefix = b"  file: ";
        let l = prefix.len().min(buf.len() - total);
        buf[total..total + l].copy_from_slice(&prefix[..l]);
        total += l;
        let l = name.len().min(buf.len() - total);
        buf[total..total + l].copy_from_slice(&name[..l]);
        total += l;
        if total < buf.len() { buf[total] = b'\n'; total += 1; }
        // "  size: <size>\n"
        let prefix = b"  size: ";
        let l = prefix.len().min(buf.len() - total);
        buf[total..total + l].copy_from_slice(&prefix[..l]);
        total += l;
        let n = format_u64_right(size, 0, &mut buf[total..]);
        total += n;
        if total < buf.len() { buf[total] = b'\n'; total += 1; }
        // "  inode: <ino>\n"
        let prefix = b"  inode: ";
        let l = prefix.len().min(buf.len() - total);
        buf[total..total + l].copy_from_slice(&prefix[..l]);
        total += l;
        let n = format_u64_right(ino, 0, &mut buf[total..]);
        total += n;
        if total < buf.len() { buf[total] = b'\n'; total += 1; }
        // "  type: <type>\n"
        let prefix = b"  type: ";
        let l = prefix.len().min(buf.len() - total);
        buf[total..total + l].copy_from_slice(&prefix[..l]);
        total += l;
        let type_str: &[u8] = if mode & 0o170000 == 0o40000 {
            b"directory"
        } else if mode & 0o170000 == 0o100000 {
            b"regular file"
        } else if mode & 0o170000 == 0o20000 {
            b"character device"
        } else {
            b"unknown"
        };
        let l = type_str.len().min(buf.len() - total);
        buf[total..total + l].copy_from_slice(&type_str[..l]);
        total += l;
        if total < buf.len() { buf[total] = b'\n'; total += 1; }
        return total;
    }
    0
}

// ---------------------------------------------------------------------------
// sleep -pause for N seconds
// ---------------------------------------------------------------------------

pub fn cmd_sleep(args: &[u8]) {
    let secs = parse_u64_simple(args);
    if secs == 0 { return; }
    // Build a timespec struct: { tv_sec: u64, tv_nsec: u64 }
    let mut timespec = [0u8; 16];
    let sec_bytes = secs.to_le_bytes();
    timespec[..8].copy_from_slice(&sec_bytes);
    // tv_nsec = 0 (already zero)
    linux_nanosleep(timespec.as_ptr());
}

// ---------------------------------------------------------------------------
// type -identify command type
// ---------------------------------------------------------------------------

pub fn cmd_type(name: &[u8]) {
    if name.is_empty() { return; }
    // Check builtins
    static BUILTINS: &[&[u8]] = &[
        b"help", b"echo", b"uname", b"uptime", b"caps", b"ls", b"cat", b"write",
        b"rm", b"stat", b"hexdump", b"head", b"tail", b"grep", b"mkdir", b"rmdir",
        b"cd", b"pwd", b"snap", b"fork", b"getpid", b"exec", b"ps", b"top", b"kill",
        b"resolve", b"ping", b"traceroute", b"wget", b"export", b"env", b"unset",
        b"exit", b"jobs", b"fg", b"bg", b"history", b"wc", b"sort", b"uniq", b"diff",
        b"function", b"syslog", b"netmirror", b"snapshot", b"lua",
        b"services", b"threads", b"meminfo", b"bench", b"read", b"source", b"sleep",
        b"true", b"false", b"type", b"break", b"continue", b"trace",
    ];
    for &b in BUILTINS.iter() {
        if eq(name, b) {
            print(name);
            print(b" is a shell builtin\n");
            return;
        }
    }
    // Check functions
    if crate::functions::func_find(name).is_some() {
        print(name);
        print(b" is a shell function\n");
        return;
    }
    // Check external (would resolve to /bin/<name>)
    let mut path_buf = [0u8; 70];
    path_buf[..5].copy_from_slice(b"/bin/");
    let nl = name.len().min(64);
    path_buf[5..5 + nl].copy_from_slice(&name[..nl]);
    path_buf[5 + nl] = 0;
    let mut stat_buf = [0u8; 144];
    if linux_stat(path_buf.as_ptr(), stat_buf.as_mut_ptr()) >= 0 {
        print(name);
        print(b" is /bin/");
        print(name);
        print(b"\n");
        return;
    }
    err!(b"type", b"not found", name);
}

// ---------------------------------------------------------------------------
// source / . -execute script file
// ---------------------------------------------------------------------------

/// source <filename> -execute commands from a file in the current shell context.
pub fn cmd_source(filename: &[u8]) {
    use crate::functions::expand_vars;
    use crate::parse::{dispatch_with_redirects, execute_if_block,
                       execute_for_block, execute_while_block, execute_until_block};

    let mut data = [0u8; 4096];
    let total = slurp_file(filename, &mut data);
    if total < 0 {
        err!(b"source", b"cannot read file:", filename);
        return;
    }
    let total = total as usize;

    // Process each line
    let mut line_start = 0;
    let mut i = 0;
    let mut accum_buf = [0u8; 2048];
    let mut line_buf = [0u8; 512];

    while i <= total {
        if i == total || data[i] == b'\n' {
            let raw_line = trim(&data[line_start..i]);
            if !raw_line.is_empty() && raw_line[0] != b'#' {
                // Expand variables
                let mut expanded = [0u8; 512];
                let exp_len = expand_vars(raw_line, &mut expanded);
                let line = trim(&expanded[..exp_len]);

                if !line.is_empty() {
                    // Handle control structures
                    if starts_with(line, b"if ") || starts_with(line, b"for ")
                        || starts_with(line, b"while ") || starts_with(line, b"until ")
                    {
                        // For scripts, accumulate remaining lines manually if block is incomplete
                        let block_kw_end = if starts_with(line, b"if ") { b"fi" as &[u8] }
                            else { b"done" as &[u8] };
                        // Check if this line alone is complete
                        let is_complete = find_substr(line, block_kw_end).is_some();
                        if is_complete {
                            let acc_len = line.len().min(accum_buf.len() - 1);
                            accum_buf[..acc_len].copy_from_slice(&line[..acc_len]);
                            let block = trim(&accum_buf[..acc_len]);
                            if starts_with(block, b"if ") { execute_if_block(block, &mut line_buf); }
                            else if starts_with(block, b"for ") { execute_for_block(block, &mut line_buf); }
                            else if starts_with(block, b"while ") { execute_while_block(block, &mut line_buf); }
                            else if starts_with(block, b"until ") { execute_until_block(block, &mut line_buf); }
                        } else {
                            // Accumulate lines from the script data until block is complete
                            let mut acc_len = line.len().min(accum_buf.len() - 1);
                            accum_buf[..acc_len].copy_from_slice(&line[..acc_len]);
                            i += 1; // move past newline
                            line_start = i;
                            while i <= total {
                                if i == total || data[i] == b'\n' {
                                    let next_line = trim(&data[line_start..i]);
                                    if !next_line.is_empty() && acc_len + 2 + next_line.len() < accum_buf.len() {
                                        accum_buf[acc_len] = b';';
                                        accum_buf[acc_len + 1] = b' ';
                                        acc_len += 2;
                                        accum_buf[acc_len..acc_len + next_line.len()].copy_from_slice(next_line);
                                        acc_len += next_line.len();
                                    }
                                    if find_substr(&accum_buf[..acc_len], block_kw_end).is_some() {
                                        break;
                                    }
                                    line_start = i + 1;
                                }
                                i += 1;
                            }
                            let block = trim(&accum_buf[..acc_len]);
                            if starts_with(block, b"if ") { execute_if_block(block, &mut line_buf); }
                            else if starts_with(block, b"for ") { execute_for_block(block, &mut line_buf); }
                            else if starts_with(block, b"while ") { execute_while_block(block, &mut line_buf); }
                            else if starts_with(block, b"until ") { execute_until_block(block, &mut line_buf); }
                        }
                    } else {
                        dispatch_with_redirects(line);
                    }
                }
            }
            line_start = i + 1;
        }
        i += 1;
    }
}

// ---------------------------------------------------------------------------
// read builtin
// ---------------------------------------------------------------------------

/// read [-p "prompt"] VAR1 [VAR2 ...] -read a line from stdin into variables.
/// If multiple vars, splits on spaces: first=VAR1, second=VAR2, rest=last var.
/// If no var name given, stores in REPLY.
pub fn cmd_read(args: &[u8]) {
    let mut prompt: &[u8] = b"";
    let mut rest = args;

    // Parse -p "prompt"
    if starts_with(rest, b"-p ") {
        rest = trim(&rest[3..]);
        // Extract prompt string (may be quoted)
        if !rest.is_empty() && (rest[0] == b'"' || rest[0] == b'\'') {
            let quote = rest[0];
            let start = 1;
            let mut end = start;
            while end < rest.len() && rest[end] != quote { end += 1; }
            prompt = &rest[start..end];
            rest = if end + 1 < rest.len() { trim(&rest[end + 1..]) } else { b"" };
        } else {
            // Unquoted prompt: take first word
            let end = find_space(rest).unwrap_or(rest.len());
            prompt = &rest[..end];
            rest = if end < rest.len() { trim(&rest[end..]) } else { b"" };
        }
    }

    // Print prompt if given
    if !prompt.is_empty() {
        print(prompt);
    }

    // Read a line from stdin
    let mut input = [0u8; 256];
    let input_len = read_simple_line(&mut input);
    let input_data = trim(&input[..input_len]);

    // Parse variable names
    let mut var_names: [&[u8]; 8] = [b""; 8];
    let mut var_count = 0;
    let mut pos = 0;
    while pos < rest.len() && var_count < 8 {
        while pos < rest.len() && rest[pos] == b' ' { pos += 1; }
        let start = pos;
        while pos < rest.len() && rest[pos] != b' ' { pos += 1; }
        if start < pos {
            var_names[var_count] = &rest[start..pos];
            var_count += 1;
        }
    }

    if var_count == 0 {
        // No variable name -store in REPLY
        env_set(b"REPLY", input_data);
        return;
    }

    // Split input on spaces and assign to variables
    let mut ipos = 0;
    for vi in 0..var_count {
        while ipos < input_data.len() && input_data[ipos] == b' ' { ipos += 1; }
        if vi == var_count - 1 {
            // Last variable gets the rest of the line
            env_set(var_names[vi], &input_data[ipos..]);
        } else {
            let start = ipos;
            while ipos < input_data.len() && input_data[ipos] != b' ' { ipos += 1; }
            env_set(var_names[vi], &input_data[start..ipos]);
        }
    }
}
