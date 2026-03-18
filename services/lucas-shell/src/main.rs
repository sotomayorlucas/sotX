#![no_std]
#![no_main]

// ---------------------------------------------------------------------------
// Stack canary support
// ---------------------------------------------------------------------------

#[used]
#[no_mangle]
static mut __stack_chk_guard: u64 = 0x00000aff0a0d0000;

#[no_mangle]
pub extern "C" fn __stack_chk_fail() -> ! {
    let msg = b"!!! STACK SMASH DETECTED (shell) !!!\n";
    linux_write(1, msg.as_ptr(), msg.len());
    linux_exit(137);
}

// ---------------------------------------------------------------------------
// Linux syscall primitives (x86_64 ABI: rdi, rsi, rdx, r10, r8, r9)
// ---------------------------------------------------------------------------

#[inline(always)]
fn syscall0(nr: u64) -> i64 {
    let ret: i64;
    unsafe { core::arch::asm!("syscall", inlateout("rax") nr => ret,
        lateout("rcx") _, lateout("r11") _, options(nostack)); }
    ret
}

#[inline(always)]
fn syscall1(nr: u64, a1: u64) -> i64 {
    let ret: i64;
    unsafe { core::arch::asm!("syscall", inlateout("rax") nr => ret,
        in("rdi") a1, lateout("rcx") _, lateout("r11") _, options(nostack)); }
    ret
}

#[inline(always)]
fn syscall2(nr: u64, a1: u64, a2: u64) -> i64 {
    let ret: i64;
    unsafe { core::arch::asm!("syscall", inlateout("rax") nr => ret,
        in("rdi") a1, in("rsi") a2,
        lateout("rcx") _, lateout("r11") _, options(nostack)); }
    ret
}

#[inline(always)]
fn syscall3(nr: u64, a1: u64, a2: u64, a3: u64) -> i64 {
    let ret: i64;
    unsafe { core::arch::asm!("syscall", inlateout("rax") nr => ret,
        in("rdi") a1, in("rsi") a2, in("rdx") a3,
        lateout("rcx") _, lateout("r11") _, options(nostack)); }
    ret
}

#[inline(always)]
fn syscall6(nr: u64, a1: u64, a2: u64, a3: u64, a4: u64, a5: u64, a6: u64) -> i64 {
    let ret: i64;
    unsafe { core::arch::asm!("syscall", inlateout("rax") nr => ret,
        in("rdi") a1, in("rsi") a2, in("rdx") a3,
        in("r10") a4, in("r8") a5, in("r9") a6,
        lateout("rcx") _, lateout("r11") _, options(nostack)); }
    ret
}

// ---------------------------------------------------------------------------
// Linux syscall wrappers (one-liners atop primitives)
// ---------------------------------------------------------------------------

#[inline(always)] fn linux_write(fd: u64, buf: *const u8, len: usize) -> i64 { syscall3(1, fd, buf as u64, len as u64) }
#[inline(always)] fn linux_read(fd: u64, buf: *mut u8, len: usize) -> i64 { syscall3(0, fd, buf as u64, len as u64) }
#[inline(always)] fn linux_open(path: *const u8, flags: u64) -> i64 { syscall3(2, path as u64, flags, 0) }
#[inline(always)] fn linux_close(fd: u64) -> i64 { syscall1(3, fd) }
#[inline(always)] fn linux_stat(path: *const u8, buf: *mut u8) -> i64 { syscall2(4, path as u64, buf as u64) }
#[allow(dead_code)] #[inline(always)] fn linux_fstat(fd: u64, buf: *mut u8) -> i64 { syscall2(5, fd, buf as u64) }
#[allow(dead_code)] #[inline(always)] fn linux_lseek(fd: u64, off: i64, whence: u64) -> i64 { syscall3(8, fd, off as u64, whence) }
#[allow(dead_code)] #[inline(always)] fn linux_mmap(a: u64, l: u64, p: u64, f: u64, fd: u64, o: u64) -> i64 { syscall6(9, a, l, p, f, fd, o) }
#[allow(dead_code)] #[inline(always)] fn linux_brk(addr: u64) -> i64 { syscall1(12, addr) }
#[inline(always)] fn linux_getpid() -> i64 { syscall0(39) }
#[inline(always)] fn linux_clone(child_fn: u64) -> i64 { syscall2(56, child_fn, 0) }
#[inline(always)] fn linux_execve(path: *const u8, argv: *const u64, envp: *const u64) -> i64 { syscall3(59, path as u64, argv as u64, envp as u64) }
#[inline(always)] fn linux_waitpid(pid: u64) -> i64 { syscall2(61, pid, 0) }
#[inline(always)] fn linux_kill(pid: u64, sig: u64) -> i64 { syscall2(62, pid, sig) }
#[inline(always)] fn linux_getcwd(buf: *mut u8, size: u64) -> i64 { syscall2(79, buf as u64, size) }
#[inline(always)] fn linux_chdir(path: *const u8) -> i64 { syscall1(80, path as u64) }
#[inline(always)] fn linux_mkdir(path: *const u8, mode: u64) -> i64 { syscall2(83, path as u64, mode) }
#[inline(always)] fn linux_rmdir(path: *const u8) -> i64 { syscall1(84, path as u64) }
#[inline(always)] fn linux_unlink(path: *const u8) -> i64 { syscall1(87, path as u64) }
#[allow(dead_code)] #[inline(always)] fn linux_getppid() -> i64 { syscall0(110) }
#[inline(always)] fn linux_socket(dom: u64, typ: u64, proto: u64) -> i64 { syscall3(41, dom, typ, proto) }
#[inline(always)] fn linux_connect(fd: u64, addr: *const u8, len: u64) -> i64 { syscall3(42, fd, addr as u64, len) }
#[inline(always)] fn linux_sendto(fd: u64, buf: *const u8, len: u64, flags: u64) -> i64 { syscall6(44, fd, buf as u64, len, flags, 0, 0) }
#[inline(always)] fn linux_recvfrom(fd: u64, buf: *mut u8, len: u64, flags: u64) -> i64 { syscall6(45, fd, buf as u64, len, flags, 0, 0) }
// Custom sotOS syscalls (intercepted by LUCAS)
#[inline(always)] fn linux_dns_resolve(name: *const u8, len: usize) -> u64 { syscall2(200, name as u64, len as u64) as u64 }
#[inline(always)] fn linux_traceroute_hop(dst: u64, ttl: u64) -> u64 { syscall2(201, dst, ttl) as u64 }
#[inline(always)] fn linux_icmp_ping(dst: u64, seq: u64) -> u64 { syscall2(202, dst, seq) as u64 }

#[inline(always)]
fn linux_exit(status: u64) -> ! {
    unsafe {
        core::arch::asm!("syscall", in("rax") 60u64, in("rdi") status,
            options(nostack, noreturn));
    }
}

// ---------------------------------------------------------------------------
// Output helpers
// ---------------------------------------------------------------------------

fn print(s: &[u8]) {
    linux_write(1, s.as_ptr(), s.len());
}

fn print_u64(mut n: u64) {
    if n == 0 {
        print(b"0");
        return;
    }
    let mut buf = [0u8; 20];
    let mut i = 0;
    while n > 0 {
        buf[i] = b'0' + (n % 10) as u8;
        n /= 10;
        i += 1;
    }
    // Print in reverse
    while i > 0 {
        i -= 1;
        linux_write(1, &buf[i] as *const u8, 1);
    }
}

// ---------------------------------------------------------------------------
// String helpers
// ---------------------------------------------------------------------------

fn starts_with(hay: &[u8], needle: &[u8]) -> bool {
    if hay.len() < needle.len() {
        return false;
    }
    &hay[..needle.len()] == needle
}

fn trim(s: &[u8]) -> &[u8] {
    let mut start = 0;
    while start < s.len() && (s[start] == b' ' || s[start] == b'\t') {
        start += 1;
    }
    let mut end = s.len();
    while end > start && (s[end - 1] == b' ' || s[end - 1] == b'\t') {
        end -= 1;
    }
    &s[start..end]
}

fn eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a == b
}

/// Copy name into buf with NUL terminator. Returns pointer to buf.
fn null_terminate<'a>(name: &[u8], buf: &'a mut [u8]) -> *const u8 {
    let len = name.len().min(buf.len() - 1);
    buf[..len].copy_from_slice(&name[..len]);
    buf[len] = 0;
    buf.as_ptr()
}

/// Find the first space in a byte slice, returning the index or None.
fn find_space(s: &[u8]) -> Option<usize> {
    let mut i = 0;
    while i < s.len() {
        if s[i] == b' ' {
            return Some(i);
        }
        i += 1;
    }
    None
}

/// Parse a decimal u64 from byte slice.
fn parse_u64_simple(s: &[u8]) -> u64 {
    let mut val: u64 = 0;
    let mut i = 0;
    while i < s.len() && s[i] >= b'0' && s[i] <= b'9' {
        val = val * 10 + (s[i] - b'0') as u64;
        i += 1;
    }
    val
}

// ---------------------------------------------------------------------------
// File I/O helpers
// ---------------------------------------------------------------------------

/// Read from an open fd until EOF or buf full. Returns bytes read.
fn read_all(fd: u64, buf: &mut [u8]) -> usize {
    let mut total: usize = 0;
    loop {
        let n = linux_read(fd, buf[total..].as_mut_ptr(), buf.len() - total);
        if n <= 0 { break; }
        total += n as usize;
        if total >= buf.len() { break; }
    }
    total
}

/// Open file by name, read contents into buf, close. Returns bytes read or -1 on error.
fn slurp_file(name: &[u8], buf: &mut [u8]) -> i64 {
    let mut path_buf = [0u8; 64];
    let path = null_terminate(name, &mut path_buf);
    let fd = linux_open(path, 0);
    if fd < 0 { return -1; }
    let total = read_all(fd as u64, buf);
    linux_close(fd as u64);
    total as i64
}

/// Read a line of input (simple: no history/completion). Returns length.
fn read_simple_line(buf: &mut [u8]) -> usize {
    let mut pos: usize = 0;
    loop {
        let mut ch = [0u8; 1];
        let n = linux_read(0, ch.as_mut_ptr(), 1);
        if n <= 0 { continue; }
        match ch[0] {
            b'\r' | b'\n' => { print(b"\n"); return pos; }
            0x08 | 0x7F => {
                if pos > 0 { pos -= 1; print(b"\x08 \x08"); }
            }
            0x20..=0x7E => {
                if pos < buf.len() - 1 {
                    buf[pos] = ch[0];
                    pos += 1;
                    linux_write(1, &ch[0] as *const u8, 1);
                }
            }
            _ => {}
        }
    }
}

/// Open a virtual file (prefix + name), read and print response.
fn open_virtual_and_print(prefix: &[u8], name: &[u8], on_error: &[u8]) {
    let mut path_buf = [0u8; 64];
    let mut pos = prefix.len();
    path_buf[..pos].copy_from_slice(prefix);
    if !name.is_empty() {
        let n = name.len().min(path_buf.len() - pos - 1);
        path_buf[pos..pos + n].copy_from_slice(&name[..n]);
        pos += n;
    }
    path_buf[pos] = 0;
    let fd = linux_open(path_buf.as_ptr(), 0);
    if fd >= 0 {
        let mut buf = [0u8; 256];
        let n = linux_read(fd as u64, buf.as_mut_ptr(), buf.len());
        if n > 0 { linux_write(1, buf.as_ptr(), n as usize); }
        linux_close(fd as u64);
    } else {
        print(on_error);
    }
}

// ---------------------------------------------------------------------------
// Environment variables
// ---------------------------------------------------------------------------

const MAX_ENV_VARS: usize = 32;
const MAX_KEY_LEN: usize = 32;
const MAX_VAL_LEN: usize = 128;

struct EnvVar {
    key: [u8; MAX_KEY_LEN],
    key_len: usize,
    val: [u8; MAX_VAL_LEN],
    val_len: usize,
    active: bool,
}

impl EnvVar {
    const fn empty() -> Self {
        Self { key: [0; MAX_KEY_LEN], key_len: 0, val: [0; MAX_VAL_LEN], val_len: 0, active: false }
    }
}

static mut ENV: [EnvVar; MAX_ENV_VARS] = {
    const INIT: EnvVar = EnvVar::empty();
    [INIT; MAX_ENV_VARS]
};

fn env_slice() -> &'static [EnvVar] {
    unsafe { core::slice::from_raw_parts(core::ptr::addr_of!(ENV) as *const EnvVar, MAX_ENV_VARS) }
}

fn env_slice_mut() -> &'static mut [EnvVar] {
    unsafe { core::slice::from_raw_parts_mut(core::ptr::addr_of_mut!(ENV) as *mut EnvVar, MAX_ENV_VARS) }
}

fn env_set(key: &[u8], val: &[u8]) {
    // Update existing.
    for e in env_slice_mut().iter_mut() {
        if e.active && e.key_len == key.len() && e.key[..e.key_len] == *key {
            let vl = val.len().min(MAX_VAL_LEN);
            e.val[..vl].copy_from_slice(&val[..vl]);
            e.val_len = vl;
            return;
        }
    }
    // Insert new.
    for e in env_slice_mut().iter_mut() {
        if !e.active {
            let kl = key.len().min(MAX_KEY_LEN);
            let vl = val.len().min(MAX_VAL_LEN);
            e.key[..kl].copy_from_slice(&key[..kl]);
            e.key_len = kl;
            e.val[..vl].copy_from_slice(&val[..vl]);
            e.val_len = vl;
            e.active = true;
            return;
        }
    }
}

fn env_get(key: &[u8]) -> Option<&'static [u8]> {
    for e in env_slice() {
        if e.active && e.key_len == key.len() && e.key[..e.key_len] == *key {
            return Some(&e.val[..e.val_len]);
        }
    }
    None
}

fn env_unset(key: &[u8]) {
    for e in env_slice_mut().iter_mut() {
        if e.active && e.key_len == key.len() && e.key[..e.key_len] == *key {
            e.active = false;
            return;
        }
    }
}

// ---------------------------------------------------------------------------
// Job control
// ---------------------------------------------------------------------------

const MAX_JOBS: usize = 16;
const MAX_JOB_CMD: usize = 128;

const JOB_NONE: u8 = 0;
const JOB_RUNNING: u8 = 1;
const JOB_STOPPED: u8 = 2;
const JOB_DONE: u8 = 3;

struct Job {
    active: bool,
    pid: u64,
    status: u8,
    cmd: [u8; MAX_JOB_CMD],
    cmd_len: usize,
}

impl Job {
    const fn empty() -> Self {
        Self { active: false, pid: 0, status: JOB_NONE, cmd: [0; MAX_JOB_CMD], cmd_len: 0 }
    }
}

static mut JOBS: [Job; MAX_JOBS] = {
    const INIT: Job = Job::empty();
    [INIT; MAX_JOBS]
};

fn jobs_slice() -> &'static [Job] {
    unsafe { core::slice::from_raw_parts(core::ptr::addr_of!(JOBS) as *const Job, MAX_JOBS) }
}

fn jobs_slice_mut() -> &'static mut [Job] {
    unsafe { core::slice::from_raw_parts_mut(core::ptr::addr_of_mut!(JOBS) as *mut Job, MAX_JOBS) }
}

fn job_add(pid: u64, status: u8, cmd: &[u8]) -> usize {
    for (i, j) in jobs_slice_mut().iter_mut().enumerate() {
        if !j.active {
            j.active = true;
            j.pid = pid;
            j.status = status;
            let cl = cmd.len().min(MAX_JOB_CMD);
            j.cmd[..cl].copy_from_slice(&cmd[..cl]);
            j.cmd_len = cl;
            return i + 1; // 1-based job IDs
        }
    }
    0 // no free slot
}

fn job_find_by_id(id: usize) -> Option<&'static mut Job> {
    if id == 0 || id > MAX_JOBS { return None; }
    let j = &mut jobs_slice_mut()[id - 1];
    if j.active { Some(j) } else { None }
}

/// Track the PID of the foreground child (0 = none).
static mut FG_PID: u64 = 0;

fn set_fg_pid(pid: u64) {
    unsafe { FG_PID = pid; }
}

fn get_fg_pid() -> u64 {
    unsafe { FG_PID }
}

// ---------------------------------------------------------------------------
// Command history
// ---------------------------------------------------------------------------

const HIST_SIZE: usize = 64;
const HIST_LINE_LEN: usize = 256;

struct HistEntry {
    data: [u8; HIST_LINE_LEN],
    len: usize,
}

impl HistEntry {
    const fn empty() -> Self {
        Self { data: [0; HIST_LINE_LEN], len: 0 }
    }
}

static mut HISTORY: [HistEntry; HIST_SIZE] = {
    const INIT: HistEntry = HistEntry::empty();
    [INIT; HIST_SIZE]
};
static mut HIST_COUNT: usize = 0;
static mut HIST_WRITE: usize = 0; // next write index (circular)

#[allow(dead_code)]
fn history_slice() -> &'static [HistEntry] {
    unsafe { core::slice::from_raw_parts(core::ptr::addr_of!(HISTORY) as *const HistEntry, HIST_SIZE) }
}

fn history_add(line: &[u8]) {
    if line.is_empty() { return; }
    unsafe {
        let idx = HIST_WRITE;
        let entry = &mut (*core::ptr::addr_of_mut!(HISTORY))[idx];
        let l = line.len().min(HIST_LINE_LEN);
        entry.data[..l].copy_from_slice(&line[..l]);
        entry.len = l;
        HIST_WRITE = (HIST_WRITE + 1) % HIST_SIZE;
        if HIST_COUNT < HIST_SIZE { HIST_COUNT += 1; }
    }
}

fn history_count() -> usize {
    unsafe { HIST_COUNT }
}

fn history_get(index: usize) -> Option<&'static [u8]> {
    let count = history_count();
    if index >= count { return None; }
    unsafe {
        // oldest entry is at (HIST_WRITE - count + index) mod HIST_SIZE
        let actual = (HIST_WRITE + HIST_SIZE - count + index) % HIST_SIZE;
        let entry = &(*core::ptr::addr_of!(HISTORY))[actual];
        Some(&entry.data[..entry.len])
    }
}

// ---------------------------------------------------------------------------
// Shell functions
// ---------------------------------------------------------------------------

const MAX_FUNCTIONS: usize = 16;
const MAX_FUNC_NAME: usize = 32;
const MAX_FUNC_BODY: usize = 1024;

struct ShellFunction {
    active: bool,
    name: [u8; MAX_FUNC_NAME],
    name_len: usize,
    body: [u8; MAX_FUNC_BODY],
    body_len: usize,
}

impl ShellFunction {
    const fn empty() -> Self {
        Self {
            active: false,
            name: [0; MAX_FUNC_NAME],
            name_len: 0,
            body: [0; MAX_FUNC_BODY],
            body_len: 0,
        }
    }
}

static mut FUNCTIONS: [ShellFunction; MAX_FUNCTIONS] = {
    const INIT: ShellFunction = ShellFunction::empty();
    [INIT; MAX_FUNCTIONS]
};

fn funcs_slice() -> &'static [ShellFunction] {
    unsafe { core::slice::from_raw_parts(core::ptr::addr_of!(FUNCTIONS) as *const ShellFunction, MAX_FUNCTIONS) }
}

fn funcs_slice_mut() -> &'static mut [ShellFunction] {
    unsafe { core::slice::from_raw_parts_mut(core::ptr::addr_of_mut!(FUNCTIONS) as *mut ShellFunction, MAX_FUNCTIONS) }
}

fn func_define(name: &[u8], body: &[u8]) {
    // Update existing
    for f in funcs_slice_mut().iter_mut() {
        if f.active && f.name_len == name.len() && f.name[..f.name_len] == *name {
            let bl = body.len().min(MAX_FUNC_BODY);
            f.body[..bl].copy_from_slice(&body[..bl]);
            f.body_len = bl;
            return;
        }
    }
    // Insert new
    for f in funcs_slice_mut().iter_mut() {
        if !f.active {
            let nl = name.len().min(MAX_FUNC_NAME);
            f.name[..nl].copy_from_slice(&name[..nl]);
            f.name_len = nl;
            let bl = body.len().min(MAX_FUNC_BODY);
            f.body[..bl].copy_from_slice(&body[..bl]);
            f.body_len = bl;
            f.active = true;
            return;
        }
    }
    print(b"error: too many functions defined\n");
}

fn func_find(name: &[u8]) -> Option<usize> {
    for (i, f) in funcs_slice().iter().enumerate() {
        if f.active && f.name_len == name.len() && f.name[..f.name_len] == *name {
            return Some(i);
        }
    }
    None
}

/// Positional args for the currently executing function ($1, $2, ...).
const MAX_FUNC_ARGS: usize = 8;
static mut FUNC_ARGS: [[u8; 128]; MAX_FUNC_ARGS] = [[0; 128]; MAX_FUNC_ARGS];
static mut FUNC_ARG_LENS: [usize; MAX_FUNC_ARGS] = [0; MAX_FUNC_ARGS];
static mut FUNC_ARG_COUNT: usize = 0;

/// Expand $VAR references (and $1-$8 positional args) in a command line.
fn expand_vars(input: &[u8], output: &mut [u8]) -> usize {
    let mut out_pos = 0;
    let mut i = 0;
    while i < input.len() && out_pos < output.len() - 1 {
        if input[i] == b'$' && i + 1 < input.len() && input[i + 1] != b' ' {
            // Check for positional argument $1-$8
            let next = input[i + 1];
            if next >= b'1' && next <= b'8' {
                let arg_idx = (next - b'1') as usize;
                unsafe {
                    if arg_idx < FUNC_ARG_COUNT {
                        let arg_len = FUNC_ARG_LENS[arg_idx];
                        let copy_len = arg_len.min(output.len() - 1 - out_pos);
                        output[out_pos..out_pos + copy_len].copy_from_slice(&FUNC_ARGS[arg_idx][..copy_len]);
                        out_pos += copy_len;
                    }
                }
                i += 2;
                continue;
            }
            // Extract variable name.
            let start = i + 1;
            let mut end = start;
            while end < input.len() && (input[end].is_ascii_alphanumeric() || input[end] == b'_') {
                end += 1;
            }
            if end > start {
                if let Some(val) = env_get(&input[start..end]) {
                    let copy_len = val.len().min(output.len() - 1 - out_pos);
                    output[out_pos..out_pos + copy_len].copy_from_slice(&val[..copy_len]);
                    out_pos += copy_len;
                }
                i = end;
            } else {
                output[out_pos] = input[i];
                out_pos += 1;
                i += 1;
            }
        } else {
            output[out_pos] = input[i];
            out_pos += 1;
            i += 1;
        }
    }
    out_pos
}

/// Find a byte in a slice.
fn find_byte(s: &[u8], b: u8) -> Option<usize> {
    let mut i = 0;
    while i < s.len() {
        if s[i] == b { return Some(i); }
        i += 1;
    }
    None
}

/// Find a pipe operator `|` outside of single/double quotes.
fn find_pipe_unquoted(s: &[u8]) -> Option<usize> {
    let mut i = 0;
    let mut in_single = false;
    let mut in_double = false;
    while i < s.len() {
        match s[i] {
            b'\'' if !in_double => in_single = !in_single,
            b'"'  if !in_single => in_double = !in_double,
            b'|'  if !in_single && !in_double => return Some(i),
            _ => {}
        }
        i += 1;
    }
    None
}

/// Glob pattern match: supports leading `*suffix`, trailing `prefix*`, and exact match.
#[allow(dead_code)]
fn pattern_match(pattern: &[u8], text: &[u8]) -> bool {
    if eq(pattern, b"*") { return true; }
    if pattern.is_empty() { return text.is_empty(); }
    // "foo*" — starts with
    if pattern[pattern.len() - 1] == b'*' {
        let prefix = &pattern[..pattern.len() - 1];
        return starts_with(text, prefix);
    }
    // "*foo" — ends with
    if pattern[0] == b'*' {
        let suffix = &pattern[1..];
        return text.len() >= suffix.len() && &text[text.len() - suffix.len()..] == suffix;
    }
    // Exact match.
    eq(pattern, text)
}

// ---------------------------------------------------------------------------
// Shell
// ---------------------------------------------------------------------------

fn shell_loop() {
    let mut line_buf = [0u8; 256];

    // Set default env vars.
    env_set(b"SHELL", b"lucas");
    env_set(b"OS", b"sotOS");
    env_set(b"VERSION", b"0.1.0");

    // --- Auto-run disabled: CoW fork signal delivery causes page fault ---
    // {
    //     print(b"AUTORUN: busybox sh -c 'echo cowfork-ok | cat'\n");
    //     cmd_exec(b"busybox sh -c 'echo cowfork-ok | cat'");
    //     print(b"AUTORUN: done\n");
    // }

    loop {
        // Reap finished background jobs
        reap_done_jobs();

        // Prompt
        print(b"$ ");

        // Read line with history navigation and tab completion
        let mut pos: usize = 0;
        let mut hist_nav: isize = -1; // -1 = not navigating, 0..count-1 = history index
        let mut saved_line = [0u8; 256]; // save current line when navigating history
        let mut saved_len: usize = 0;
        let mut esc_state: u8 = 0; // 0=normal, 1=got ESC, 2=got ESC+[

        loop {
            let mut ch = [0u8; 1];
            let n = linux_read(0, ch.as_mut_ptr(), 1);
            if n == -4 {
                // -EINTR (Ctrl+C) — send to fg job if any
                let fg = get_fg_pid();
                if fg != 0 {
                    linux_kill(fg, 2); // SIGINT
                }
                print(b"^C\n");
                pos = 0;
                break;
            }
            if n <= 0 {
                continue;
            }
            let c = ch[0];

            // Handle escape sequences for arrow keys
            if esc_state == 1 {
                if c == b'[' {
                    esc_state = 2;
                    continue;
                } else {
                    esc_state = 0;
                    // fall through to normal processing
                }
            }
            if esc_state == 2 {
                esc_state = 0;
                match c {
                    b'A' => {
                        // Up arrow — previous history
                        let count = history_count();
                        if count == 0 { continue; }
                        if hist_nav < 0 {
                            // Save current line
                            saved_line[..pos].copy_from_slice(&line_buf[..pos]);
                            saved_len = pos;
                            hist_nav = (count as isize) - 1;
                        } else if hist_nav > 0 {
                            hist_nav -= 1;
                        } else {
                            continue; // already at oldest
                        }
                        // Erase current line on terminal
                        erase_line(pos);
                        // Copy history entry
                        if let Some(entry) = history_get(hist_nav as usize) {
                            let l = entry.len().min(line_buf.len() - 1);
                            line_buf[..l].copy_from_slice(&entry[..l]);
                            pos = l;
                            linux_write(1, line_buf[..pos].as_ptr(), pos);
                        }
                        continue;
                    }
                    b'B' => {
                        // Down arrow — next history
                        if hist_nav < 0 { continue; }
                        let count = history_count();
                        erase_line(pos);
                        if (hist_nav as usize) < count - 1 {
                            hist_nav += 1;
                            if let Some(entry) = history_get(hist_nav as usize) {
                                let l = entry.len().min(line_buf.len() - 1);
                                line_buf[..l].copy_from_slice(&entry[..l]);
                                pos = l;
                                linux_write(1, line_buf[..pos].as_ptr(), pos);
                            }
                        } else {
                            // Restore saved line
                            hist_nav = -1;
                            line_buf[..saved_len].copy_from_slice(&saved_line[..saved_len]);
                            pos = saved_len;
                            linux_write(1, line_buf[..pos].as_ptr(), pos);
                        }
                        continue;
                    }
                    _ => { continue; } // ignore other escape sequences
                }
            }

            match c {
                0x1B => {
                    // ESC — start of escape sequence
                    esc_state = 1;
                }
                // Enter
                b'\r' | b'\n' => {
                    print(b"\n");
                    let _ = hist_nav;
                    break;
                }
                // Backspace (0x08) or DEL (0x7F)
                0x08 | 0x7F => {
                    if pos > 0 {
                        pos -= 1;
                        print(b"\x08 \x08");
                    }
                }
                // Tab — completion
                b'\t' => {
                    do_tab_completion(&mut line_buf, &mut pos);
                }
                // Ctrl+Z
                0x1A => {
                    let fg = get_fg_pid();
                    if fg != 0 {
                        linux_kill(fg, 20); // SIGTSTP
                        print(b"^Z\n");
                        // Add to jobs as stopped
                        let jid = job_add(fg, JOB_STOPPED, b"(stopped)");
                        if jid > 0 {
                            print(b"[");
                            print_u64(jid as u64);
                            print(b"]  Stopped\n");
                        }
                        set_fg_pid(0);
                        pos = 0;
                        break;
                    }
                }
                // Printable character
                0x20..=0x7E => {
                    if pos < line_buf.len() - 1 {
                        line_buf[pos] = c;
                        pos += 1;
                        linux_write(1, &c as *const u8, 1);
                    }
                }
                _ => {}
            }
        }

        // Copy raw line into its own buffer to avoid borrow conflicts
        let mut raw_copy = [0u8; 256];
        let raw_trimmed = trim(&line_buf[..pos]);
        if raw_trimmed.is_empty() {
            continue;
        }
        let raw_len = raw_trimmed.len();
        raw_copy[..raw_len].copy_from_slice(raw_trimmed);
        let raw_line = &raw_copy[..raw_len];

        // Add to history
        history_add(raw_line);

        // Check for function definition: "function NAME() {"
        if starts_with(raw_line, b"function ") {
            read_function_def(raw_line, &mut line_buf);
            continue;
        }

        // Expand environment variables ($VAR).
        let mut expanded = [0u8; 256];
        let exp_len = expand_vars(raw_line, &mut expanded);
        let line = trim(&expanded[..exp_len]);
        if line.is_empty() {
            continue;
        }

        // Check for here-document (<<DELIM).
        if let Some(heredoc_pos) = find_substr(line, b"<<") {
            let cmd_part = trim(&line[..heredoc_pos]);
            let delim = trim(&line[heredoc_pos + 2..]);
            if !delim.is_empty() && !cmd_part.is_empty() {
                execute_heredoc(cmd_part, delim, &mut line_buf);
                continue;
            }
        }

        // Check for pipe operator (respects quotes).
        if let Some(pipe_pos) = find_pipe_unquoted(line) {
            let left = trim(&line[..pipe_pos]);
            let right = trim(&line[pipe_pos + 1..]);
            if !left.is_empty() && !right.is_empty() {
                execute_pipe(left, right);
                continue;
            }
        }

        // Check for background execution (&).
        let (line, background) = if line.len() > 0 && line[line.len() - 1] == b'&' {
            (trim(&line[..line.len() - 1]), true)
        } else {
            (line, false)
        };

        if background {
            let child_fn = child_shell_main as *const () as u64;
            let pid = linux_clone(child_fn);
            if pid > 0 {
                let jid = job_add(pid as u64, JOB_RUNNING, line);
                print(b"[");
                print_u64(jid as u64);
                print(b"] ");
                print_u64(pid as u64);
                print(b"\n");
            }
            continue;
        }

        // --- Shell scripting: if/then/fi ---
        if starts_with(line, b"if ") {
            execute_if_block(line, &mut line_buf);
            continue;
        }

        // --- Shell scripting: for/do/done ---
        if starts_with(line, b"for ") {
            execute_for_block(line, &mut line_buf);
            continue;
        }

        // Parse and handle redirects, then dispatch
        dispatch_with_redirects(line);
    }
}

/// Erase the current line on terminal (move cursor back, overwrite, move back).
fn erase_line(len: usize) {
    for _ in 0..len {
        print(b"\x08 \x08");
    }
}

/// Reap background jobs that have finished.
fn reap_done_jobs() {
    for j in jobs_slice_mut().iter_mut() {
        if j.active && j.status == JOB_RUNNING {
            // Non-blocking waitpid check: we just mark done if pid finished.
            // In this OS the waitpid is blocking, so we skip actual wait here.
            // Jobs will be cleaned up when user runs `jobs`.
        }
    }
}

// ---------------------------------------------------------------------------
// Tab completion
// ---------------------------------------------------------------------------

fn do_tab_completion(line_buf: &mut [u8; 256], pos: &mut usize) {
    if *pos == 0 { return; }
    // Extract the current word (last token) — copy to avoid borrow conflict
    let mut word_start = *pos;
    while word_start > 0 && line_buf[word_start - 1] != b' ' {
        word_start -= 1;
    }
    if word_start >= *pos { return; }
    let mut word_buf = [0u8; 128];
    let word_len = (*pos - word_start).min(127);
    word_buf[..word_len].copy_from_slice(&line_buf[word_start..*pos]);
    let word = &word_buf[..word_len];

    // Check if word contains '/' — do file completion
    let has_slash = find_byte(word, b'/').is_some();

    if has_slash {
        tab_complete_file(word, line_buf, pos, word_start);
    } else {
        tab_complete_builtin(word, line_buf, pos, word_start);
    }
}

fn tab_complete_builtin(prefix: &[u8], line_buf: &mut [u8; 256], pos: &mut usize, word_start: usize) {
    static BUILTINS: &[&[u8]] = &[
        b"help", b"echo", b"uname", b"uptime", b"caps", b"ls", b"cat", b"write",
        b"rm", b"stat", b"hexdump", b"head", b"tail", b"grep", b"mkdir", b"rmdir",
        b"cd", b"pwd", b"snap", b"fork", b"getpid", b"exec", b"ps", b"top", b"kill",
        b"resolve", b"ping", b"traceroute", b"wget", b"export", b"env", b"unset",
        b"exit", b"jobs", b"fg", b"bg", b"history", b"wc", b"sort", b"uniq", b"diff",
        b"function", b"syslog", b"netmirror", b"snapshot",
    ];

    let mut matches: [usize; 40] = [0; 40];
    let mut match_count: usize = 0;

    for (i, &builtin) in BUILTINS.iter().enumerate() {
        if starts_with(builtin, prefix) && match_count < 40 {
            matches[match_count] = i;
            match_count += 1;
        }
    }

    if match_count == 0 {
        return;
    }
    if match_count == 1 {
        // Single match — complete it
        let builtin = BUILTINS[matches[0]];
        let suffix = &builtin[prefix.len()..];
        if *pos + suffix.len() + 1 < line_buf.len() {
            line_buf[*pos..*pos + suffix.len()].copy_from_slice(suffix);
            *pos += suffix.len();
            line_buf[*pos] = b' ';
            *pos += 1;
            linux_write(1, suffix.as_ptr(), suffix.len());
            print(b" ");
        }
    } else {
        // Multiple matches — show all
        print(b"\n");
        for i in 0..match_count {
            print(BUILTINS[matches[i]]);
            print(b"  ");
        }
        print(b"\n$ ");
        linux_write(1, line_buf[..word_start].as_ptr(), word_start);
        // Find common prefix among matches
        let first = BUILTINS[matches[0]];
        let mut common_len = first.len();
        for i in 1..match_count {
            let other = BUILTINS[matches[i]];
            let mut cl = 0;
            while cl < common_len && cl < other.len() && first[cl] == other[cl] {
                cl += 1;
            }
            common_len = cl;
        }
        if common_len > prefix.len() {
            let extra = &first[prefix.len()..common_len];
            line_buf[*pos..*pos + extra.len()].copy_from_slice(extra);
            *pos += extra.len();
        }
        linux_write(1, line_buf[word_start..*pos].as_ptr(), *pos - word_start);
    }
}

fn tab_complete_file(prefix: &[u8], line_buf: &mut [u8; 256], pos: &mut usize, _word_start: usize) {
    // Split prefix into directory part and name part
    let mut last_slash = 0;
    for i in 0..prefix.len() {
        if prefix[i] == b'/' { last_slash = i + 1; }
    }
    let dir_part = if last_slash > 0 { &prefix[..last_slash] } else { b"." as &[u8] };
    let name_prefix = &prefix[last_slash..];

    // Open directory and list entries
    let mut dir_buf = [0u8; 128];
    let dir_path = null_terminate(dir_part, &mut dir_buf);

    // Save/restore cwd for listing the target dir
    let mut old_cwd = [0u8; 128];
    let cwd_ret = linux_getcwd(old_cwd.as_mut_ptr(), old_cwd.len() as u64);

    if last_slash > 0 {
        if linux_chdir(dir_path) < 0 { return; }
    }

    let mut dot_buf = [0u8; 4];
    let dot_path = null_terminate(b".", &mut dot_buf);
    let fd = linux_open(dot_path, 0);
    if fd < 0 {
        if cwd_ret > 0 && last_slash > 0 { linux_chdir(old_cwd.as_ptr()); }
        return;
    }

    let mut listing = [0u8; 2048];
    let total = read_all(fd as u64, &mut listing);
    linux_close(fd as u64);

    if cwd_ret > 0 && last_slash > 0 { linux_chdir(old_cwd.as_ptr()); }

    // Parse directory listing lines and find matches
    let mut match_names: [[u8; 64]; 16] = [[0; 64]; 16];
    let mut match_lens: [usize; 16] = [0; 16];
    let mut match_count: usize = 0;

    let mut line_start: usize = 0;
    let mut i: usize = 0;
    while i <= total && match_count < 16 {
        if i == total || listing[i] == b'\n' {
            let entry_line = &listing[line_start..i];
            // Entry line format might be "name" or "name  SIZE  TYPE" etc
            // Extract just the first word/name
            let entry_name = if let Some(sp) = find_space(entry_line) {
                &entry_line[..sp]
            } else {
                entry_line
            };
            if !entry_name.is_empty() && starts_with(entry_name, name_prefix) {
                let l = entry_name.len().min(64);
                match_names[match_count][..l].copy_from_slice(&entry_name[..l]);
                match_lens[match_count] = l;
                match_count += 1;
            }
            line_start = i + 1;
        }
        i += 1;
    }

    if match_count == 0 { return; }
    if match_count == 1 {
        let suffix = &match_names[0][name_prefix.len()..match_lens[0]];
        if *pos + suffix.len() + 1 < line_buf.len() {
            line_buf[*pos..*pos + suffix.len()].copy_from_slice(suffix);
            *pos += suffix.len();
            line_buf[*pos] = b' ';
            *pos += 1;
            linux_write(1, suffix.as_ptr(), suffix.len());
            print(b" ");
        }
    } else {
        print(b"\n");
        for j in 0..match_count {
            linux_write(1, match_names[j][..match_lens[j]].as_ptr(), match_lens[j]);
            print(b"  ");
        }
        print(b"\n$ ");
        linux_write(1, line_buf[..*pos].as_ptr(), *pos);
    }
}

// ---------------------------------------------------------------------------
// Redirect parsing and execution
// ---------------------------------------------------------------------------

struct Redirects {
    stdin_file: [u8; 64],
    stdin_file_len: usize,
    stdout_file: [u8; 64],
    stdout_file_len: usize,
    stdout_append: bool,
}

impl Redirects {
    const fn empty() -> Self {
        Self {
            stdin_file: [0; 64],
            stdin_file_len: 0,
            stdout_file: [0; 64],
            stdout_file_len: 0,
            stdout_append: false,
        }
    }
}

/// Parse redirects from command line and return the cleaned command + redirect info.
fn parse_redirects<'a>(line: &'a [u8], redir: &mut Redirects, clean: &mut [u8; 256]) -> usize {
    let mut clean_len: usize = 0;
    let mut i: usize = 0;

    while i < line.len() {
        if line[i] == b'>' {
            // Output redirect
            if i + 1 < line.len() && line[i + 1] == b'>' {
                // >> append
                redir.stdout_append = true;
                i += 2;
            } else {
                // > truncate
                redir.stdout_append = false;
                i += 1;
            }
            // Skip spaces
            while i < line.len() && line[i] == b' ' { i += 1; }
            // Read filename
            let start = i;
            while i < line.len() && line[i] != b' ' && line[i] != b'<' && line[i] != b'>' { i += 1; }
            let fname = &line[start..i];
            let fl = fname.len().min(63);
            redir.stdout_file[..fl].copy_from_slice(&fname[..fl]);
            redir.stdout_file_len = fl;
        } else if line[i] == b'<' {
            // Input redirect
            i += 1;
            while i < line.len() && line[i] == b' ' { i += 1; }
            let start = i;
            while i < line.len() && line[i] != b' ' && line[i] != b'<' && line[i] != b'>' { i += 1; }
            let fname = &line[start..i];
            let fl = fname.len().min(63);
            redir.stdin_file[..fl].copy_from_slice(&fname[..fl]);
            redir.stdin_file_len = fl;
        } else {
            if clean_len < 255 {
                clean[clean_len] = line[i];
                clean_len += 1;
            }
            i += 1;
        }
    }
    clean_len
}

/// Check if a line contains redirect operators (outside of quoted strings).
fn has_redirects(line: &[u8]) -> bool {
    for &b in line.iter() {
        if b == b'>' || b == b'<' { return true; }
    }
    false
}

/// Dispatch a command with redirect support.
fn dispatch_with_redirects(line: &[u8]) {
    if !has_redirects(line) {
        dispatch_or_call_func(line);
        return;
    }

    let mut redir = Redirects::empty();
    let mut clean = [0u8; 256];
    let clean_len = parse_redirects(line, &mut redir, &mut clean);
    let cmd = trim(&clean[..clean_len]);
    if cmd.is_empty() { return; }

    // Set up input redirect
    let mut in_fd: i64 = -1;
    if redir.stdin_file_len > 0 {
        let mut path_buf = [0u8; 65];
        let path = null_terminate(&redir.stdin_file[..redir.stdin_file_len], &mut path_buf);
        in_fd = linux_open(path, 0); // O_RDONLY
        if in_fd < 0 {
            print(b"redirect: cannot open input file: ");
            print(&redir.stdin_file[..redir.stdin_file_len]);
            print(b"\n");
            return;
        }
    }

    // Set up output redirect
    let mut out_fd: i64 = -1;
    if redir.stdout_file_len > 0 {
        let mut path_buf = [0u8; 65];
        let path = null_terminate(&redir.stdout_file[..redir.stdout_file_len], &mut path_buf);
        let flags: u64 = if redir.stdout_append {
            0x441 // O_WRONLY | O_CREAT | O_APPEND
        } else {
            0x41 // O_WRONLY | O_CREAT (truncate)
        };
        out_fd = linux_open(path, flags);
        if out_fd < 0 {
            print(b"redirect: cannot open output file: ");
            print(&redir.stdout_file[..redir.stdout_file_len]);
            print(b"\n");
            if in_fd >= 0 { linux_close(in_fd as u64); }
            return;
        }
    }

    // For output redirect, capture command output and write to file
    if out_fd >= 0 {
        let mut capture_buf = [0u8; 4096];
        let cap_len = capture_command_extended(cmd, &mut capture_buf, in_fd);
        if cap_len > 0 {
            linux_write(out_fd as u64, capture_buf[..cap_len].as_ptr(), cap_len);
        }
        linux_close(out_fd as u64);
    } else if in_fd >= 0 {
        // Input redirect only — read from file and feed to command as stdin
        let mut input_data = [0u8; 4096];
        let input_len = read_all(in_fd as u64, &mut input_data);
        linux_close(in_fd as u64);
        dispatch_command_with_stdin(cmd, &input_data[..input_len]);
    } else {
        dispatch_or_call_func(cmd);
    }

    if in_fd >= 0 { linux_close(in_fd as u64); }
}

/// Extended capture: supports more commands than capture_command
fn capture_command_extended(cmd: &[u8], buf: &mut [u8], in_fd: i64) -> usize {
    // Try the existing capture_command first
    let len = capture_command(cmd, buf);
    if len > 0 { return len; }

    // Handle echo
    if starts_with(cmd, b"echo ") {
        let rest = &cmd[5..];
        let l = rest.len().min(buf.len());
        buf[..l].copy_from_slice(&rest[..l]);
        if l < buf.len() { buf[l] = b'\n'; return l + 1; }
        return l;
    }
    if eq(cmd, b"echo") {
        if buf.len() > 0 { buf[0] = b'\n'; return 1; }
        return 0;
    }
    if eq(cmd, b"pwd") {
        let ret = linux_getcwd(buf.as_mut_ptr(), buf.len() as u64);
        if ret > 0 {
            let mut len = 0;
            while len < buf.len() && buf[len] != 0 { len += 1; }
            if len < buf.len() { buf[len] = b'\n'; len += 1; }
            return len;
        }
        return 0;
    }
    if eq(cmd, b"uname") {
        let s = b"sotOS 0.1.0 x86_64 LUCAS\n";
        let l = s.len().min(buf.len());
        buf[..l].copy_from_slice(&s[..l]);
        return l;
    }

    // For commands with stdin, read stdin data and process
    if in_fd >= 0 {
        let mut input_data = [0u8; 4096];
        let input_len = read_all(in_fd as u64, &mut input_data);
        return capture_command_with_stdin(cmd, &input_data[..input_len], buf);
    }

    // Fallback: just dispatch normally and return 0
    dispatch_or_call_func(cmd);
    0
}

/// Capture output from commands that can read from stdin data
fn capture_command_with_stdin(cmd: &[u8], stdin_data: &[u8], buf: &mut [u8]) -> usize {
    if eq(cmd, b"wc") {
        return wc_data(stdin_data, buf);
    }
    if eq(cmd, b"sort") {
        return sort_data(stdin_data, buf);
    }
    if eq(cmd, b"uniq") {
        return uniq_data(stdin_data, buf);
    }
    0
}

// ---------------------------------------------------------------------------
// Here-document support
// ---------------------------------------------------------------------------

fn execute_heredoc(cmd: &[u8], delim: &[u8], line_buf: &mut [u8; 256]) {
    let mut heredoc_data = [0u8; 4096];
    let mut heredoc_len: usize = 0;

    // Read lines until we see the delimiter
    loop {
        print(b"> ");
        let pos = read_simple_line(line_buf);
        let input_line = trim(&line_buf[..pos]);
        // Check if this is the delimiter
        if eq(input_line, delim) {
            break;
        }
        // Append to heredoc data
        let l = input_line.len();
        if heredoc_len + l + 1 < heredoc_data.len() {
            heredoc_data[heredoc_len..heredoc_len + l].copy_from_slice(input_line);
            heredoc_len += l;
            heredoc_data[heredoc_len] = b'\n';
            heredoc_len += 1;
        }
    }

    // Feed heredoc data as stdin to the command
    dispatch_command_with_stdin(cmd, &heredoc_data[..heredoc_len]);
}

/// Dispatch a command that has stdin data available
fn dispatch_command_with_stdin(cmd: &[u8], stdin_data: &[u8]) {
    // Handle commands that accept stdin
    if eq(cmd, b"cat") {
        // cat with no file reads stdin
        linux_write(1, stdin_data.as_ptr(), stdin_data.len());
        return;
    }
    if eq(cmd, b"wc") {
        let mut buf = [0u8; 128];
        let len = wc_data(stdin_data, &mut buf);
        linux_write(1, buf[..len].as_ptr(), len);
        return;
    }
    if eq(cmd, b"sort") {
        let mut buf = [0u8; 4096];
        let len = sort_data(stdin_data, &mut buf);
        linux_write(1, buf[..len].as_ptr(), len);
        return;
    }
    if eq(cmd, b"uniq") {
        let mut buf = [0u8; 4096];
        let len = uniq_data(stdin_data, &mut buf);
        linux_write(1, buf[..len].as_ptr(), len);
        return;
    }
    if starts_with(cmd, b"grep ") {
        let pattern = trim(&cmd[5..]);
        // Filter stdin_data lines by pattern
        let mut line_start: usize = 0;
        let mut i: usize = 0;
        while i <= stdin_data.len() {
            if i == stdin_data.len() || stdin_data[i] == b'\n' {
                let line = &stdin_data[line_start..i];
                if contains(line, pattern) {
                    linux_write(1, line.as_ptr(), line.len());
                    print(b"\n");
                }
                line_start = i + 1;
            }
            i += 1;
        }
        return;
    }
    // For other commands, just dispatch normally (ignore stdin data)
    dispatch_or_call_func(cmd);
}

// ---------------------------------------------------------------------------
// Function definition and invocation
// ---------------------------------------------------------------------------

fn read_function_def(first_line: &[u8], line_buf: &mut [u8; 256]) {
    // Parse "function NAME() {" or "function NAME {"
    let after_func = trim(&first_line[9..]);

    // Extract function name
    let mut name_end: usize = 0;
    while name_end < after_func.len()
        && after_func[name_end] != b'('
        && after_func[name_end] != b' '
        && after_func[name_end] != b'{'
    {
        name_end += 1;
    }
    let func_name = &after_func[..name_end];
    if func_name.is_empty() {
        print(b"syntax error: function name expected\n");
        return;
    }

    // Check if first line contains '{' — if not, it's an error
    let has_brace = find_byte(after_func, b'{').is_some();
    if !has_brace {
        print(b"syntax error: expected '{'\n");
        return;
    }

    // Read body lines until we see "}"
    let mut body = [0u8; MAX_FUNC_BODY];
    let mut body_len: usize = 0;

    loop {
        print(b"> ");
        let pos = read_simple_line(line_buf);
        let input_line = trim(&line_buf[..pos]);
        if eq(input_line, b"}") {
            break;
        }
        // Append line to body with newline separator
        if body_len + input_line.len() + 1 < MAX_FUNC_BODY {
            body[body_len..body_len + input_line.len()].copy_from_slice(input_line);
            body_len += input_line.len();
            body[body_len] = b'\n';
            body_len += 1;
        }
    }

    func_define(func_name, &body[..body_len]);
}

/// Try to call a shell function. Returns true if found and called.
fn call_function(name: &[u8], args: &[u8]) -> bool {
    let idx = match func_find(name) {
        Some(i) => i,
        None => return false,
    };

    // Save old positional args
    let mut old_args: [[u8; 128]; MAX_FUNC_ARGS] = [[0; 128]; MAX_FUNC_ARGS];
    let mut old_arg_lens: [usize; MAX_FUNC_ARGS] = [0; MAX_FUNC_ARGS];
    let old_count: usize;
    unsafe {
        old_count = FUNC_ARG_COUNT;
        for i in 0..MAX_FUNC_ARGS {
            old_arg_lens[i] = FUNC_ARG_LENS[i];
            old_args[i][..old_arg_lens[i]].copy_from_slice(&FUNC_ARGS[i][..old_arg_lens[i]]);
        }
    }

    // Parse new positional args from args string
    unsafe {
        FUNC_ARG_COUNT = 0;
        let mut pos: usize = 0;
        while pos < args.len() && FUNC_ARG_COUNT < MAX_FUNC_ARGS {
            while pos < args.len() && args[pos] == b' ' { pos += 1; }
            let start = pos;
            while pos < args.len() && args[pos] != b' ' { pos += 1; }
            if start < pos {
                let l = (pos - start).min(128);
                FUNC_ARGS[FUNC_ARG_COUNT][..l].copy_from_slice(&args[start..start + l]);
                FUNC_ARG_LENS[FUNC_ARG_COUNT] = l;
                FUNC_ARG_COUNT += 1;
            }
        }
    }

    // Copy the body before execution (func_define might modify FUNCTIONS)
    let mut body_copy = [0u8; MAX_FUNC_BODY];
    let body_len;
    {
        let f = &funcs_slice()[idx];
        body_len = f.body_len;
        body_copy[..body_len].copy_from_slice(&f.body[..body_len]);
    }

    // Execute each line in the body
    let mut line_start: usize = 0;
    let mut i: usize = 0;
    while i <= body_len {
        if i == body_len || body_copy[i] == b'\n' {
            let func_line = trim(&body_copy[line_start..i]);
            if !func_line.is_empty() {
                if eq(func_line, b"return") {
                    break; // early return
                }
                if starts_with(func_line, b"return ") {
                    break; // return with value (just exit)
                }
                // Expand variables (including $1, $2, etc.)
                let mut exp_buf = [0u8; 256];
                let exp_len = expand_vars(func_line, &mut exp_buf);
                let expanded = trim(&exp_buf[..exp_len]);
                if !expanded.is_empty() {
                    dispatch_or_call_func(expanded);
                }
            }
            line_start = i + 1;
        }
        i += 1;
    }

    // Restore old positional args
    unsafe {
        FUNC_ARG_COUNT = old_count;
        for i in 0..MAX_FUNC_ARGS {
            FUNC_ARG_LENS[i] = old_arg_lens[i];
            FUNC_ARGS[i][..old_arg_lens[i]].copy_from_slice(&old_args[i][..old_arg_lens[i]]);
        }
    }

    true
}

/// Dispatch a command, trying functions first, then builtins.
fn dispatch_or_call_func(line: &[u8]) {
    // Extract command name (first word)
    let cmd_name = if let Some(sp) = find_space(line) {
        &line[..sp]
    } else {
        line
    };
    let args = if let Some(sp) = find_space(line) {
        trim(&line[sp + 1..])
    } else {
        b"" as &[u8]
    };

    // Try function call first
    if call_function(cmd_name, args) {
        return;
    }

    // Fall through to builtin dispatch
    dispatch_command(line);
}

fn dispatch_command(line: &[u8]) {
        // --- Command dispatch ---
        if eq(line, b"help") {
            print(b"commands: help, echo, uname, uptime, caps, ls, cat, write, rm,\n");
            print(b"  stat, hexdump, head, tail, grep, mkdir, rmdir, cd, pwd, snap,\n");
            print(b"  fork, getpid, exec, ps, top, kill, resolve, ping, traceroute,\n");
            print(b"  wget [-O file] [-q] <url>, export, env, unset, exit,\n");
            print(b"  jobs, fg, bg, history, wc, sort, uniq, diff\n");
            print(b"operators: cmd > file, cmd >> file, cmd < file, cmd1 | cmd2, cmd &\n");
            print(b"scripting: if COND; then CMD; fi, for VAR in A B C; do CMD; done\n");
            print(b"  function NAME() { body; }, <<EOF heredocs\n");
            print(b"network: resolve <host>, ping <host>, traceroute <host>\n");
            print(b"  wget <url>                  -- fetch and display\n");
            print(b"  wget -O <file> <url>        -- download to file\n");
            print(b"  wget -q <url>               -- quiet mode\n");
        } else if eq(line, b"uname") {
            print(b"sotOS 0.1.0 x86_64 LUCAS\n");
        } else if eq(line, b"uptime") {
            cmd_uptime();
        } else if eq(line, b"ps") {
            cmd_ps();
        } else if starts_with(line, b"kill ") {
            let args = trim(&line[5..]);
            if args.is_empty() {
                print(b"usage: kill <pid> [signal]\n");
            } else {
                cmd_kill(args);
            }
        } else if eq(line, b"caps") {
            print(b"capability system active (query via sotOS ABI)\n");
        } else if starts_with(line, b"echo ") {
            let rest = &line[5..];
            print(rest);
            print(b"\n");
        } else if eq(line, b"echo") {
            print(b"\n");
        } else if eq(line, b"ls") {
            cmd_ls();
        } else if starts_with(line, b"ls ") {
            let path = trim(&line[3..]);
            if path.is_empty() {
                cmd_ls();
            } else {
                cmd_ls_path(path);
            }
        } else if starts_with(line, b"cat ") {
            let name = trim(&line[4..]);
            if name.is_empty() {
                print(b"usage: cat <file>\n");
            } else {
                cmd_cat(name);
            }
        } else if starts_with(line, b"write ") {
            let args = trim(&line[6..]);
            match find_space(args) {
                Some(sp) => {
                    let name = &args[..sp];
                    let text = trim(&args[sp + 1..]);
                    cmd_write(name, text);
                }
                None => {
                    print(b"usage: write <file> <text>\n");
                }
            }
        } else if starts_with(line, b"rm ") {
            let name = trim(&line[3..]);
            if name.is_empty() {
                print(b"usage: rm <file>\n");
            } else {
                cmd_rm(name);
            }
        } else if starts_with(line, b"stat ") {
            let name = trim(&line[5..]);
            if name.is_empty() {
                print(b"usage: stat <file>\n");
            } else {
                cmd_stat(name);
            }
        } else if eq(line, b"stat") {
            cmd_stat(b".");
        } else if starts_with(line, b"hexdump ") {
            let name = trim(&line[8..]);
            if name.is_empty() {
                print(b"usage: hexdump <file>\n");
            } else {
                cmd_hexdump(name);
            }
        } else if starts_with(line, b"mkdir ") {
            let name = trim(&line[6..]);
            if name.is_empty() {
                print(b"usage: mkdir <dir>\n");
            } else {
                cmd_mkdir(name);
            }
        } else if starts_with(line, b"rmdir ") {
            let name = trim(&line[6..]);
            if name.is_empty() {
                print(b"usage: rmdir <dir>\n");
            } else {
                cmd_rmdir(name);
            }
        } else if starts_with(line, b"cd ") {
            let name = trim(&line[3..]);
            if name.is_empty() {
                print(b"usage: cd <dir>\n");
            } else {
                cmd_cd(name);
            }
        } else if eq(line, b"cd") {
            // cd with no args goes to root
            cmd_cd(b"/");
        } else if eq(line, b"pwd") {
            cmd_pwd();
        } else if eq(line, b"fork") {
            cmd_fork();
        } else if eq(line, b"getpid") {
            print(b"pid=");
            print_u64(linux_getpid() as u64);
            print(b"\n");
        } else if starts_with(line, b"exec ") {
            let name = trim(&line[5..]);
            if name.is_empty() {
                print(b"usage: exec <program>\n");
            } else {
                cmd_exec(name);
            }
        } else if starts_with(line, b"resolve ") {
            let name = trim(&line[8..]);
            if name.is_empty() {
                print(b"usage: resolve <hostname>\n");
            } else {
                cmd_resolve(name);
            }
        } else if eq(line, b"ping") {
            print(b"usage: ping <host|ip>\n");
        } else if starts_with(line, b"ping ") {
            let host = trim(&line[5..]);
            if host.is_empty() {
                print(b"usage: ping <host|ip>\n");
            } else {
                cmd_ping(host);
            }
        } else if eq(line, b"traceroute") {
            print(b"usage: traceroute <host|ip>\n");
        } else if starts_with(line, b"traceroute ") {
            let host = trim(&line[11..]);
            if host.is_empty() {
                print(b"usage: traceroute <host|ip>\n");
            } else {
                cmd_traceroute(host);
            }
        } else if eq(line, b"wget") || eq(line, b"curl") {
            print(b"usage: wget [-O file] [-q] <url>\n");
        } else if starts_with(line, b"curl ") {
            let args = trim(&line[5..]);
            if args.is_empty() {
                print(b"usage: wget [-O file] [-q] <url>\n");
            } else {
                cmd_wget(args);
            }
        } else if starts_with(line, b"wget ") {
            let args = trim(&line[5..]);
            if args.is_empty() {
                print(b"usage: wget [-O file] [-q] <url>\n");
            } else {
                cmd_wget(args);
            }
        } else if starts_with(line, b"snap ") {
            let args = trim(&line[5..]);
            cmd_snap(args);
        } else if starts_with(line, b"export ") {
            let args = trim(&line[7..]);
            if let Some(eq_pos) = find_byte(args, b'=') {
                let key = trim(&args[..eq_pos]);
                let val = trim(&args[eq_pos + 1..]);
                env_set(key, val);
            } else {
                print(b"usage: export KEY=VALUE\n");
            }
        } else if eq(line, b"env") {
            cmd_env();
        } else if starts_with(line, b"unset ") {
            let key = trim(&line[6..]);
            if !key.is_empty() {
                env_unset(key);
            }
        } else if starts_with(line, b"head ") {
            let args = trim(&line[5..]);
            cmd_head(args);
        } else if starts_with(line, b"tail ") {
            let args = trim(&line[5..]);
            cmd_tail(args);
        } else if starts_with(line, b"grep ") {
            let args = trim(&line[5..]);
            cmd_grep(args);
        } else if eq(line, b"top") {
            cmd_top();
        } else if eq(line, b"jobs") {
            cmd_jobs();
        } else if starts_with(line, b"fg ") {
            let n = parse_u64_simple(trim(&line[3..])) as usize;
            cmd_fg(n);
        } else if eq(line, b"fg") {
            cmd_fg(0);
        } else if starts_with(line, b"bg ") {
            let n = parse_u64_simple(trim(&line[3..])) as usize;
            cmd_bg(n);
        } else if eq(line, b"bg") {
            cmd_bg(0);
        } else if eq(line, b"history") {
            cmd_history();
        } else if starts_with(line, b"wc ") {
            let name = trim(&line[3..]);
            cmd_wc(name);
        } else if eq(line, b"wc") {
            // wc with no args — read from stdin (only meaningful with pipe/redirect)
            print(b"      0       0       0\n");
        } else if starts_with(line, b"sort ") {
            let name = trim(&line[5..]);
            cmd_sort(name);
        } else if eq(line, b"sort") {
            print(b"usage: sort <file>\n");
        } else if starts_with(line, b"uniq ") {
            let name = trim(&line[5..]);
            cmd_uniq(name);
        } else if eq(line, b"uniq") {
            print(b"usage: uniq <file>\n");
        } else if starts_with(line, b"diff ") {
            let args = trim(&line[5..]);
            cmd_diff(args);
        } else if starts_with(line, b"syslog") {
            let n = if line.len() > 7 { parse_u64_simple(trim(&line[7..])) } else { 10 };
            cmd_syslog(n);
        } else if starts_with(line, b"netmirror ") {
            let arg = trim(&line[10..]);
            cmd_netmirror(arg);
        } else if eq(line, b"netmirror") {
            print(b"usage: netmirror on|off\n");
        } else if starts_with(line, b"snapshot ") {
            let arg = trim(&line[9..]);
            cmd_snap(arg);
        } else if eq(line, b"snapshot") {
            cmd_snap(b"list");
        } else if starts_with(line, b"lua ") {
            let code = trim(&line[4..]);
            cmd_lua(code);
        } else if eq(line, b"lua") {
            print(b"usage: lua <code>\nexample: lua print(1+2)\n");
        } else if eq(line, b"exit") {
            print(b"bye!\n");
            linux_exit(0);
        } else {
            // Try auto-exec: treat first word as initrd binary name
            cmd_exec(line);
        }
}

// ---------------------------------------------------------------------------
// Job control commands
// ---------------------------------------------------------------------------

fn cmd_jobs() {
    for (i, j) in jobs_slice().iter().enumerate() {
        if j.active {
            print(b"[");
            print_u64((i + 1) as u64);
            print(b"]  ");
            match j.status {
                JOB_RUNNING => print(b"Running    "),
                JOB_STOPPED => print(b"Stopped    "),
                JOB_DONE    => print(b"Done       "),
                _           => print(b"Unknown    "),
            }
            print(&j.cmd[..j.cmd_len]);
            print(b"\n");
        }
    }
    // Clean up done jobs after listing
    for j in jobs_slice_mut().iter_mut() {
        if j.active && j.status == JOB_DONE {
            j.active = false;
        }
    }
}

fn cmd_fg(id: usize) {
    // If id==0, find most recent running/stopped job
    let job_id = if id == 0 {
        let mut last: usize = 0;
        for (i, j) in jobs_slice().iter().enumerate() {
            if j.active && (j.status == JOB_RUNNING || j.status == JOB_STOPPED) {
                last = i + 1;
            }
        }
        last
    } else {
        id
    };

    if let Some(j) = job_find_by_id(job_id) {
        let pid = j.pid;
        print(&j.cmd[..j.cmd_len]);
        print(b"\n");
        if j.status == JOB_STOPPED {
            // Resume the process
            linux_kill(pid, 18); // SIGCONT
            j.status = JOB_RUNNING;
        }
        // Wait for it
        set_fg_pid(pid);
        linux_waitpid(pid);
        set_fg_pid(0);
        j.status = JOB_DONE;
        j.active = false;
    } else {
        print(b"fg: no such job\n");
    }
}

fn cmd_bg(id: usize) {
    let job_id = if id == 0 {
        let mut last: usize = 0;
        for (i, j) in jobs_slice().iter().enumerate() {
            if j.active && j.status == JOB_STOPPED {
                last = i + 1;
            }
        }
        last
    } else {
        id
    };

    if let Some(j) = job_find_by_id(job_id) {
        if j.status == JOB_STOPPED {
            linux_kill(j.pid, 18); // SIGCONT
            j.status = JOB_RUNNING;
            print(b"[");
            print_u64(job_id as u64);
            print(b"]  ");
            print(&j.cmd[..j.cmd_len]);
            print(b" &\n");
        } else {
            print(b"bg: job not stopped\n");
        }
    } else {
        print(b"bg: no such job\n");
    }
}

// ---------------------------------------------------------------------------
// History command
// ---------------------------------------------------------------------------

fn cmd_history() {
    let count = history_count();
    for i in 0..count {
        if let Some(entry) = history_get(i) {
            // Print index (1-based)
            let idx = i + 1;
            if idx < 10 { print(b"   "); }
            else if idx < 100 { print(b"  "); }
            else { print(b" "); }
            print_u64(idx as u64);
            print(b"  ");
            print(entry);
            print(b"\n");
        }
    }
}

// ---------------------------------------------------------------------------
// wc, sort, uniq, diff commands
// ---------------------------------------------------------------------------

fn cmd_wc(name: &[u8]) {
    if name.is_empty() {
        print(b"usage: wc <file>\n");
        return;
    }
    let mut data = [0u8; 4096];
    let total = slurp_file(name, &mut data);
    if total < 0 { print(b"wc: file not found\n"); return; }
    let total = total as usize;

    let mut out_buf = [0u8; 128];
    let len = wc_data(&data[..total], &mut out_buf);
    linux_write(1, out_buf[..len].as_ptr(), len);
    print(b" ");
    print(name);
    print(b"\n");
}

/// Count lines, words, chars in data. Returns formatted string in buf.
fn wc_data(data: &[u8], buf: &mut [u8]) -> usize {
    let mut lines: u64 = 0;
    let mut words: u64 = 0;
    let chars = data.len() as u64;
    let mut in_word = false;

    for &b in data.iter() {
        if b == b'\n' { lines += 1; }
        if b == b' ' || b == b'\t' || b == b'\n' || b == b'\r' {
            in_word = false;
        } else {
            if !in_word { words += 1; }
            in_word = true;
        }
    }

    // Format: "  LINES  WORDS  CHARS"
    let mut pos: usize = 0;
    pos += format_u64_right(lines, 7, &mut buf[pos..]);
    buf[pos] = b' ';
    pos += 1;
    pos += format_u64_right(words, 7, &mut buf[pos..]);
    buf[pos] = b' ';
    pos += 1;
    pos += format_u64_right(chars, 7, &mut buf[pos..]);
    pos
}

/// Format a u64 right-aligned in a field of given width.
fn format_u64_right(n: u64, width: usize, buf: &mut [u8]) -> usize {
    let mut tmp = [0u8; 20];
    let mut len: usize = 0;
    let mut val = n;
    if val == 0 {
        tmp[0] = b'0';
        len = 1;
    } else {
        while val > 0 {
            tmp[len] = b'0' + (val % 10) as u8;
            val /= 10;
            len += 1;
        }
    }
    let padding = if width > len { width - len } else { 0 };
    let total = padding + len;
    if total > buf.len() { return 0; }
    for i in 0..padding { buf[i] = b' '; }
    for i in 0..len { buf[padding + i] = tmp[len - 1 - i]; }
    total
}

fn cmd_sort(name: &[u8]) {
    if name.is_empty() {
        print(b"usage: sort <file>\n");
        return;
    }
    let mut data = [0u8; 4096];
    let total = slurp_file(name, &mut data);
    if total < 0 { print(b"sort: file not found\n"); return; }
    let total = total as usize;

    let mut out_buf = [0u8; 4096];
    let len = sort_data(&data[..total], &mut out_buf);
    linux_write(1, out_buf[..len].as_ptr(), len);
}

/// Sort lines in data alphabetically (bubble sort). Returns sorted text in buf.
fn sort_data(data: &[u8], buf: &mut [u8]) -> usize {
    const MAX_LINES: usize = 256;
    let mut line_starts: [usize; MAX_LINES] = [0; MAX_LINES];
    let mut line_ends: [usize; MAX_LINES] = [0; MAX_LINES];
    let mut line_count: usize = 0;

    // Parse lines
    let mut start: usize = 0;
    let mut i: usize = 0;
    while i <= data.len() && line_count < MAX_LINES {
        if i == data.len() || data[i] == b'\n' {
            if start < i {
                line_starts[line_count] = start;
                line_ends[line_count] = i;
                line_count += 1;
            }
            start = i + 1;
        }
        i += 1;
    }

    // Create index array for sorting
    let mut indices: [usize; MAX_LINES] = [0; MAX_LINES];
    for j in 0..line_count { indices[j] = j; }

    // Bubble sort by line content
    let mut swapped = true;
    while swapped {
        swapped = false;
        for j in 0..line_count.saturating_sub(1) {
            let a = &data[line_starts[indices[j]]..line_ends[indices[j]]];
            let b_line = &data[line_starts[indices[j + 1]]..line_ends[indices[j + 1]]];
            if compare_bytes(a, b_line) > 0 {
                let tmp = indices[j];
                indices[j] = indices[j + 1];
                indices[j + 1] = tmp;
                swapped = true;
            }
        }
    }

    // Write sorted output
    let mut out_pos: usize = 0;
    for j in 0..line_count {
        let line = &data[line_starts[indices[j]]..line_ends[indices[j]]];
        let l = line.len().min(buf.len() - out_pos - 1);
        buf[out_pos..out_pos + l].copy_from_slice(&line[..l]);
        out_pos += l;
        if out_pos < buf.len() { buf[out_pos] = b'\n'; out_pos += 1; }
    }
    out_pos
}

/// Compare two byte slices lexicographically. Returns <0, 0, >0.
fn compare_bytes(a: &[u8], b: &[u8]) -> i32 {
    let min_len = a.len().min(b.len());
    for i in 0..min_len {
        if a[i] != b[i] {
            return (a[i] as i32) - (b[i] as i32);
        }
    }
    (a.len() as i32) - (b.len() as i32)
}

fn cmd_uniq(name: &[u8]) {
    if name.is_empty() {
        print(b"usage: uniq <file>\n");
        return;
    }
    let mut data = [0u8; 4096];
    let total = slurp_file(name, &mut data);
    if total < 0 { print(b"uniq: file not found\n"); return; }
    let total = total as usize;

    let mut out_buf = [0u8; 4096];
    let len = uniq_data(&data[..total], &mut out_buf);
    linux_write(1, out_buf[..len].as_ptr(), len);
}

/// Filter adjacent duplicate lines. Returns result in buf.
fn uniq_data(data: &[u8], buf: &mut [u8]) -> usize {
    let mut out_pos: usize = 0;
    let mut prev_start: usize = 0;
    let mut prev_end: usize = 0;
    let mut has_prev = false;

    let mut line_start: usize = 0;
    let mut i: usize = 0;
    while i <= data.len() {
        if i == data.len() || data[i] == b'\n' {
            let line = &data[line_start..i];
            if has_prev {
                let prev = &data[prev_start..prev_end];
                if !eq(line, prev) {
                    // Different from previous — output it
                    let l = line.len().min(buf.len() - out_pos - 1);
                    buf[out_pos..out_pos + l].copy_from_slice(&line[..l]);
                    out_pos += l;
                    if out_pos < buf.len() { buf[out_pos] = b'\n'; out_pos += 1; }
                }
            } else if !line.is_empty() {
                // First line — always output
                let l = line.len().min(buf.len() - out_pos - 1);
                buf[out_pos..out_pos + l].copy_from_slice(&line[..l]);
                out_pos += l;
                if out_pos < buf.len() { buf[out_pos] = b'\n'; out_pos += 1; }
            }
            prev_start = line_start;
            prev_end = i;
            has_prev = true;
            line_start = i + 1;
        }
        i += 1;
    }
    out_pos
}

fn cmd_diff(args: &[u8]) {
    if let Some(sp) = find_space(args) {
        let file1 = trim(&args[..sp]);
        let file2 = trim(&args[sp + 1..]);
        if file1.is_empty() || file2.is_empty() {
            print(b"usage: diff <file1> <file2>\n");
            return;
        }

        // Read file1
        let mut data1 = [0u8; 4096];
        let len1 = slurp_file(file1, &mut data1);
        if len1 < 0 { print(b"diff: cannot open "); print(file1); print(b"\n"); return; }
        let len1 = len1 as usize;

        // Read file2
        let mut data2 = [0u8; 4096];
        let len2 = slurp_file(file2, &mut data2);
        if len2 < 0 { print(b"diff: cannot open "); print(file2); print(b"\n"); return; }
        let len2 = len2 as usize;

        // Line-by-line comparison
        diff_data(&data1[..len1], &data2[..len2]);
    } else {
        print(b"usage: diff <file1> <file2>\n");
    }
}

fn diff_data(data1: &[u8], data2: &[u8]) {
    const MAX_LINES: usize = 256;

    // Extract lines from file1
    let mut lines1_start: [usize; MAX_LINES] = [0; MAX_LINES];
    let mut lines1_end: [usize; MAX_LINES] = [0; MAX_LINES];
    let mut count1: usize = 0;
    {
        let mut start: usize = 0;
        let mut i: usize = 0;
        while i <= data1.len() && count1 < MAX_LINES {
            if i == data1.len() || data1[i] == b'\n' {
                lines1_start[count1] = start;
                lines1_end[count1] = i;
                count1 += 1;
                start = i + 1;
            }
            i += 1;
        }
    }

    // Extract lines from file2
    let mut lines2_start: [usize; MAX_LINES] = [0; MAX_LINES];
    let mut lines2_end: [usize; MAX_LINES] = [0; MAX_LINES];
    let mut count2: usize = 0;
    {
        let mut start: usize = 0;
        let mut i: usize = 0;
        while i <= data2.len() && count2 < MAX_LINES {
            if i == data2.len() || data2[i] == b'\n' {
                lines2_start[count2] = start;
                lines2_end[count2] = i;
                count2 += 1;
                start = i + 1;
            }
            i += 1;
        }
    }

    // Simple line-by-line diff
    let max_lines = if count1 > count2 { count1 } else { count2 };
    let mut had_diff = false;
    for i in 0..max_lines {
        if i < count1 && i < count2 {
            let line1 = &data1[lines1_start[i]..lines1_end[i]];
            let line2 = &data2[lines2_start[i]..lines2_end[i]];
            if !eq(line1, line2) {
                had_diff = true;
                print_u64((i + 1) as u64);
                print(b"c");
                print_u64((i + 1) as u64);
                print(b"\n< ");
                print(line1);
                print(b"\n---\n> ");
                print(line2);
                print(b"\n");
            }
        } else if i < count1 {
            had_diff = true;
            print_u64((i + 1) as u64);
            print(b"d");
            print_u64(count2 as u64);
            print(b"\n< ");
            print(&data1[lines1_start[i]..lines1_end[i]]);
            print(b"\n");
        } else if i < count2 {
            had_diff = true;
            print_u64(count1 as u64);
            print(b"a");
            print_u64((i + 1) as u64);
            print(b"\n> ");
            print(&data2[lines2_start[i]..lines2_end[i]]);
            print(b"\n");
        }
    }
    if !had_diff {
        print(b"files are identical\n");
    }
}

// ---------------------------------------------------------------------------
// Existing commands: env, head, tail, grep, top, pipe support, scripting
// ---------------------------------------------------------------------------

fn cmd_env() {
    for e in env_slice() {
        if e.active {
            print(&e.key[..e.key_len]);
            print(b"=");
            print(&e.val[..e.val_len]);
            print(b"\n");
        }
    }
}

fn cmd_head(args: &[u8]) {
    let mut num_lines: usize = 10;
    let name;
    if starts_with(args, b"-n ") {
        let rest = trim(&args[3..]);
        if let Some(sp) = find_space(rest) {
            num_lines = parse_u64_simple(&rest[..sp]) as usize;
            name = trim(&rest[sp + 1..]);
        } else { print(b"usage: head [-n N] <file>\n"); return; }
    } else { name = args; }
    if name.is_empty() { print(b"usage: head [-n N] <file>\n"); return; }

    let mut path_buf = [0u8; 64];
    let path = null_terminate(name, &mut path_buf);
    let fd = linux_open(path, 0);
    if fd < 0 { print(b"head: file not found\n"); return; }

    let mut buf = [0u8; 1];
    let mut lines_printed: usize = 0;
    loop {
        if lines_printed >= num_lines { break; }
        let n = linux_read(fd as u64, buf.as_mut_ptr(), 1);
        if n <= 0 { break; }
        linux_write(1, buf.as_ptr(), 1);
        if buf[0] == b'\n' { lines_printed += 1; }
    }
    linux_close(fd as u64);
}

fn cmd_tail(args: &[u8]) {
    let mut num_lines: usize = 10;
    let name;
    if starts_with(args, b"-n ") {
        let rest = trim(&args[3..]);
        if let Some(sp) = find_space(rest) {
            num_lines = parse_u64_simple(&rest[..sp]) as usize;
            name = trim(&rest[sp + 1..]);
        } else { print(b"usage: tail [-n N] <file>\n"); return; }
    } else { name = args; }
    if name.is_empty() { print(b"usage: tail [-n N] <file>\n"); return; }

    let mut data = [0u8; 4096];
    let total = slurp_file(name, &mut data);
    if total < 0 { print(b"tail: file not found\n"); return; }
    let total = total as usize;

    // Count total lines, find start of last N.
    let mut line_count: usize = 0;
    for i in 0..total { if data[i] == b'\n' { line_count += 1; } }
    let skip_lines = if line_count > num_lines { line_count - num_lines } else { 0 };
    let mut lines_seen: usize = 0;
    let mut start: usize = 0;
    for i in 0..total {
        if data[i] == b'\n' {
            lines_seen += 1;
            if lines_seen >= skip_lines { start = if lines_seen == skip_lines { i + 1 } else { start }; break; }
        }
    }
    if skip_lines == 0 { start = 0; }
    if start < total {
        linux_write(1, data[start..total].as_ptr(), total - start);
    }
}

fn cmd_grep(args: &[u8]) {
    if let Some(sp) = find_space(args) {
        let pattern = &args[..sp];
        let name = trim(&args[sp + 1..]);
        if name.is_empty() { print(b"usage: grep <pattern> <file>\n"); return; }

        let mut buf = [0u8; 4096];
        let total = slurp_file(name, &mut buf);
        if total < 0 { print(b"grep: file not found\n"); return; }
        let total = total as usize;

        // Scan for lines containing the pattern.
        let mut line_start: usize = 0;
        let mut i: usize = 0;
        while i <= total {
            if i == total || buf[i] == b'\n' {
                let line = &buf[line_start..i];
                if contains(line, pattern) {
                    linux_write(1, line.as_ptr(), line.len());
                    print(b"\n");
                }
                line_start = i + 1;
            }
            i += 1;
        }
    } else {
        print(b"usage: grep <pattern> <file>\n");
    }
}

/// Check if `hay` contains `needle` as a substring.
fn contains(hay: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() { return true; }
    if hay.len() < needle.len() { return false; }
    let mut i = 0;
    while i + needle.len() <= hay.len() {
        if &hay[i..i + needle.len()] == needle {
            return true;
        }
        i += 1;
    }
    false
}

/// top — list threads with CPU usage.
fn cmd_top() {
    // Use custom syscall 142 to get thread count, 140 to get thread info.
    print(b"  TID  STATE   PRI  CPU_TICKS  MEM  TYPE\n");
    // Iterate up to 256 thread pool slots.
    for idx in 0..256u64 {
        let ret: u64;
        let tid: u64;
        let state: u64;
        let pri: u64;
        let ticks: u64;
        let mem: u64;
        let is_user: u64;
        unsafe {
            core::arch::asm!(
                "syscall",
                inlateout("rax") 140u64 => ret,
                inlateout("rdi") idx => tid,
                lateout("rsi") state,
                lateout("rdx") pri,
                lateout("rcx") _,
                lateout("r11") _,
                lateout("r8") ticks,
                lateout("r9") mem,
                lateout("r10") is_user,
                options(nostack),
            );
        }
        if (ret as i64) < 0 { continue; }
        // Format: TID STATE PRI CPU_TICKS MEM TYPE
        print(b"  ");
        if tid < 10 { print(b"  "); } else if tid < 100 { print(b" "); }
        print_u64(tid);
        print(b"  ");
        match state {
            0 => print(b"READY  "),
            1 => print(b"RUN    "),
            2 => print(b"BLOCK  "),
            3 => print(b"FAULT  "),
            _ => print(b"DEAD   "),
        }
        if pri < 10 { print(b"  "); } else if pri < 100 { print(b" "); }
        print_u64(pri);
        print(b"  ");
        // Right-align ticks in 9 chars.
        let mut tstr = [b' '; 9];
        let mut t = ticks;
        let mut ti = 8;
        if t == 0 { tstr[ti] = b'0'; }
        while t > 0 { tstr[ti] = b'0' + (t % 10) as u8; t /= 10; if ti > 0 { ti -= 1; } }
        print(&tstr);
        print(b"  ");
        if mem < 10 { print(b"  "); } else if mem < 100 { print(b" "); }
        print_u64(mem);
        print(b"  ");
        if is_user != 0 { print(b"user\n"); } else { print(b"kern\n"); }
    }
}

/// Execute a pipe: capture output of left command, feed as input to right command.
/// Simple implementation: left command's output goes to a temp file, right reads it.
fn execute_pipe(left: &[u8], right: &[u8]) {
    // Capture left command's output into a buffer, then feed it to the right command.
    // Supports cat, ls, echo, env, ps, uname, head, tail, grep, stat as pipe sources.

    // Simplified pipe: if right is "grep PATTERN", capture left output and filter.
    if starts_with(right, b"grep ") {
        let pattern = trim(&right[5..]);
        // Run left into a buffer.
        let mut capture = [0u8; 4096];
        let cap_len = capture_command(left, &mut capture);
        if cap_len > 0 {
            // Filter lines containing pattern.
            let mut line_start: usize = 0;
            let mut i: usize = 0;
            while i <= cap_len {
                if i == cap_len || capture[i] == b'\n' {
                    let line = &capture[line_start..i];
                    if contains(line, pattern) {
                        linux_write(1, line.as_ptr(), line.len());
                        print(b"\n");
                    }
                    line_start = i + 1;
                }
                i += 1;
            }
        }
    } else if starts_with(right, b"head") || starts_with(right, b"tail") {
        let mut capture = [0u8; 4096];
        let cap_len = capture_command(left, &mut capture);
        if cap_len > 0 {
            let num_lines: usize = 10; // default
            if starts_with(right, b"head") {
                let mut lines_printed: usize = 0;
                for i in 0..cap_len {
                    if lines_printed >= num_lines { break; }
                    linux_write(1, &capture[i] as *const u8, 1);
                    if capture[i] == b'\n' { lines_printed += 1; }
                }
            } else {
                // tail: print last N lines
                let mut line_count: usize = 0;
                for i in 0..cap_len { if capture[i] == b'\n' { line_count += 1; } }
                let skip = if line_count > num_lines { line_count - num_lines } else { 0 };
                let mut seen: usize = 0;
                for i in 0..cap_len {
                    if seen >= skip { linux_write(1, &capture[i] as *const u8, 1); }
                    if capture[i] == b'\n' { seen += 1; }
                }
            }
        }
    } else if eq(right, b"wc") {
        let mut capture = [0u8; 4096];
        let cap_len = capture_command(left, &mut capture);
        if cap_len > 0 {
            let mut out_buf = [0u8; 128];
            let len = wc_data(&capture[..cap_len], &mut out_buf);
            linux_write(1, out_buf[..len].as_ptr(), len);
            print(b"\n");
        }
    } else if eq(right, b"sort") {
        let mut capture = [0u8; 4096];
        let cap_len = capture_command(left, &mut capture);
        if cap_len > 0 {
            let mut out_buf = [0u8; 4096];
            let len = sort_data(&capture[..cap_len], &mut out_buf);
            linux_write(1, out_buf[..len].as_ptr(), len);
        }
    } else if eq(right, b"uniq") {
        let mut capture = [0u8; 4096];
        let cap_len = capture_command(left, &mut capture);
        if cap_len > 0 {
            let mut out_buf = [0u8; 4096];
            let len = uniq_data(&capture[..cap_len], &mut out_buf);
            linux_write(1, out_buf[..len].as_ptr(), len);
        }
    } else {
        // General fallback: capture left, feed as stdin to right
        let mut capture = [0u8; 4096];
        let cap_len = capture_command(left, &mut capture);
        if cap_len > 0 {
            dispatch_command_with_stdin(right, &capture[..cap_len]);
        } else {
            dispatch_command(left);
            dispatch_command(right);
        }
    }
}

/// Capture a command's output into a buffer for piping.
fn capture_command(cmd: &[u8], buf: &mut [u8]) -> usize {
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
        let s = b"sotOS 0.1.0 x86_64 LUCAS\n";
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

/// Basic if/then/fi scripting.
/// Format: if CONDITION; then COMMAND; fi
/// CONDITION: "test -f FILE" or "test -d FILE" or "test VAR = VALUE"
fn execute_if_block(line: &[u8], _line_buf: &mut [u8; 256]) {
    // Parse: "if COND; then CMD; fi"
    let after_if = trim(&line[3..]);
    // Find "; then "
    let then_pos = find_substr(after_if, b"; then ");
    if then_pos.is_none() { print(b"syntax error: expected '; then'\n"); return; }
    let then_pos = then_pos.unwrap();
    let condition = trim(&after_if[..then_pos]);
    let after_then = &after_if[then_pos + 7..];
    // Find "; fi"
    let fi_pos = find_substr(after_then, b"; fi");
    if fi_pos.is_none() { print(b"syntax error: expected '; fi'\n"); return; }
    let fi_pos = fi_pos.unwrap();
    let command = trim(&after_then[..fi_pos]);

    if evaluate_condition(condition) {
        dispatch_command(command);
    }
}

/// Basic for loop.
/// Format: for VAR in A B C; do CMD; done
fn execute_for_block(line: &[u8], _line_buf: &mut [u8; 256]) {
    let after_for = trim(&line[4..]);
    // Parse "VAR in ITEMS; do CMD; done"
    if let Some(in_pos) = find_substr(after_for, b" in ") {
        let var_name = trim(&after_for[..in_pos]);
        let after_in = &after_for[in_pos + 4..];
        if let Some(do_pos) = find_substr(after_in, b"; do ") {
            let items_str = trim(&after_in[..do_pos]);
            let after_do = &after_in[do_pos + 5..];
            if let Some(done_pos) = find_substr(after_do, b"; done") {
                let command_template = trim(&after_do[..done_pos]);
                // Split items by space and run command for each.
                let mut pos = 0;
                while pos < items_str.len() {
                    // Skip spaces.
                    while pos < items_str.len() && items_str[pos] == b' ' { pos += 1; }
                    let start = pos;
                    while pos < items_str.len() && items_str[pos] != b' ' { pos += 1; }
                    if start < pos {
                        let item = &items_str[start..pos];
                        env_set(var_name, item);
                        // Expand command template with the new variable.
                        let mut cmd_buf = [0u8; 256];
                        let cmd_len = expand_vars(command_template, &mut cmd_buf);
                        dispatch_command(trim(&cmd_buf[..cmd_len]));
                    }
                }
                return;
            }
        }
    }
    print(b"syntax error: for VAR in ITEMS; do CMD; done\n");
}

fn find_substr(hay: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() { return Some(0); }
    if hay.len() < needle.len() { return None; }
    let mut i = 0;
    while i + needle.len() <= hay.len() {
        if &hay[i..i + needle.len()] == needle { return Some(i); }
        i += 1;
    }
    None
}

fn evaluate_condition(cond: &[u8]) -> bool {
    // "test -f FILE" — file exists
    if starts_with(cond, b"test -f ") {
        let name = trim(&cond[8..]);
        let mut path_buf = [0u8; 64];
        let path = null_terminate(name, &mut path_buf);
        let mut stat_buf = [0u8; 144];
        return linux_stat(path, stat_buf.as_mut_ptr()) >= 0;
    }
    // "test -d FILE" — directory exists
    if starts_with(cond, b"test -d ") {
        let name = trim(&cond[8..]);
        let mut path_buf = [0u8; 64];
        let path = null_terminate(name, &mut path_buf);
        let mut stat_buf = [0u8; 144];
        if linux_stat(path, stat_buf.as_mut_ptr()) < 0 { return false; }
        let mode = u32::from_le_bytes([stat_buf[24], stat_buf[25], stat_buf[26], stat_buf[27]]);
        return mode & 0o170000 == 0o40000;
    }
    // "test STR = STR" — string equality
    if starts_with(cond, b"test ") {
        let rest = trim(&cond[5..]);
        if let Some(eq_pos) = find_substr(rest, b" = ") {
            let left = trim(&rest[..eq_pos]);
            let right = trim(&rest[eq_pos + 3..]);
            return eq(left, right);
        }
    }
    false
}

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    print(b"sotOS LUCAS shell v0.2\n");
    shell_loop();
    linux_exit(0);
}

#[unsafe(no_mangle)]
pub extern "C" fn child_shell_main() -> ! {
    let pid = linux_getpid();
    print(b"[child shell pid=");
    print_u64(pid as u64);
    print(b"]\n");
    shell_loop();
    linux_exit(0);
}

// ---------------------------------------------------------------------------
// File commands
// ---------------------------------------------------------------------------

fn cmd_ls() {
    let mut path_buf = [0u8; 4];
    let path = null_terminate(b".", &mut path_buf);
    let fd = linux_open(path, 0); // O_RDONLY
    if fd < 0 {
        print(b"ls: cannot open directory\n");
        return;
    }
    let mut buf = [0u8; 1024];
    loop {
        let n = linux_read(fd as u64, buf.as_mut_ptr(), buf.len());
        if n <= 0 {
            break;
        }
        linux_write(1, buf.as_ptr(), n as usize);
    }
    linux_close(fd as u64);
}

fn cmd_cat(name: &[u8]) {
    let mut path_buf = [0u8; 64];
    let path = null_terminate(name, &mut path_buf);
    let fd = linux_open(path, 0); // O_RDONLY
    if fd < 0 {
        print(b"cat: file not found\n");
        return;
    }
    let mut buf = [0u8; 512];
    loop {
        let n = linux_read(fd as u64, buf.as_mut_ptr(), buf.len());
        if n <= 0 {
            break;
        }
        linux_write(1, buf.as_ptr(), n as usize);
    }
    print(b"\n");
    linux_close(fd as u64);
}

fn cmd_write(name: &[u8], text: &[u8]) {
    let mut path_buf = [0u8; 64];
    let path = null_terminate(name, &mut path_buf);
    // O_WRONLY(1) | O_CREAT(0x40) = 0x41
    let fd = linux_open(path, 0x41);
    if fd < 0 {
        print(b"write: cannot open file\n");
        return;
    }
    let n = linux_write(fd as u64, text.as_ptr(), text.len());
    if n > 0 {
        print(b"wrote ");
        print_u64(n as u64);
        print(b" bytes\n");
    } else {
        print(b"write: error\n");
    }
    linux_close(fd as u64);
}

fn cmd_stat(name: &[u8]) {
    let mut path_buf = [0u8; 64];
    let path = null_terminate(name, &mut path_buf);
    let mut stat_buf = [0u8; 144];
    let ret = linux_stat(path, stat_buf.as_mut_ptr());
    if ret < 0 {
        print(b"stat: not found\n");
        return;
    }
    // st_mode at offset 24 (u32)
    let mode = u32::from_le_bytes([stat_buf[24], stat_buf[25], stat_buf[26], stat_buf[27]]);
    // st_size at offset 48 (u64)
    let size = u64::from_le_bytes([
        stat_buf[48], stat_buf[49], stat_buf[50], stat_buf[51],
        stat_buf[52], stat_buf[53], stat_buf[54], stat_buf[55],
    ]);
    // st_ino at offset 8 (u64)
    let ino = u64::from_le_bytes([
        stat_buf[8], stat_buf[9], stat_buf[10], stat_buf[11],
        stat_buf[12], stat_buf[13], stat_buf[14], stat_buf[15],
    ]);

    print(b"  file: ");
    print(name);
    print(b"\n  size: ");
    print_u64(size);
    print(b"\n  inode: ");
    print_u64(ino);
    print(b"\n  type: ");
    if mode & 0o170000 == 0o40000 {
        print(b"directory");
    } else if mode & 0o170000 == 0o100000 {
        print(b"regular file");
    } else if mode & 0o170000 == 0o20000 {
        print(b"character device");
    } else {
        print(b"unknown");
    }
    print(b"\n");
}

fn cmd_hexdump(name: &[u8]) {
    let mut path_buf = [0u8; 64];
    let path = null_terminate(name, &mut path_buf);
    let fd = linux_open(path, 0);
    if fd < 0 {
        print(b"hexdump: file not found\n");
        return;
    }
    let hex = b"0123456789abcdef";
    let mut offset: u64 = 0;
    let mut buf = [0u8; 16];
    loop {
        let n = linux_read(fd as u64, buf.as_mut_ptr(), 16);
        if n <= 0 {
            break;
        }
        let count = n as usize;
        // Print offset (8 hex digits)
        for i in (0..8).rev() {
            let nibble = ((offset >> (i * 4)) & 0xF) as usize;
            linux_write(1, &hex[nibble] as *const u8, 1);
        }
        print(b"  ");
        // Hex bytes
        for i in 0..16 {
            if i < count {
                linux_write(1, &hex[(buf[i] >> 4) as usize] as *const u8, 1);
                linux_write(1, &hex[(buf[i] & 0xF) as usize] as *const u8, 1);
            } else {
                print(b"  ");
            }
            print(b" ");
            if i == 7 {
                print(b" ");
            }
        }
        print(b" |");
        // ASCII
        for i in 0..count {
            if buf[i] >= 0x20 && buf[i] < 0x7F {
                linux_write(1, &buf[i] as *const u8, 1);
            } else {
                print(b".");
            }
        }
        print(b"|\n");
        offset += count as u64;
    }
    linux_close(fd as u64);
}

fn cmd_rm(name: &[u8]) {
    let mut path_buf = [0u8; 64];
    let path = null_terminate(name, &mut path_buf);
    let ret = linux_unlink(path);
    if ret == 0 {
        print(b"removed\n");
    } else {
        print(b"rm: file not found\n");
    }
}

fn cmd_ls_path(path: &[u8]) {
    // Save cwd, cd to path, ls, cd back
    let mut old_cwd = [0u8; 128];
    let cwd_ret = linux_getcwd(old_cwd.as_mut_ptr(), old_cwd.len() as u64);

    let mut path_buf = [0u8; 64];
    let p = null_terminate(path, &mut path_buf);
    if linux_chdir(p) < 0 {
        print(b"ls: cannot access ");
        print(path);
        print(b"\n");
        return;
    }
    cmd_ls();
    // Restore cwd
    if cwd_ret > 0 {
        linux_chdir(old_cwd.as_ptr());
    }
}

fn cmd_mkdir(name: &[u8]) {
    let mut path_buf = [0u8; 64];
    let path = null_terminate(name, &mut path_buf);
    let ret = linux_mkdir(path, 0o755);
    if ret == 0 {
        print(b"directory created\n");
    } else {
        print(b"mkdir: failed\n");
    }
}

fn cmd_rmdir(name: &[u8]) {
    let mut path_buf = [0u8; 64];
    let path = null_terminate(name, &mut path_buf);
    let ret = linux_rmdir(path);
    if ret == 0 {
        print(b"directory removed\n");
    } else {
        print(b"rmdir: failed (not empty or not found)\n");
    }
}

fn cmd_cd(name: &[u8]) {
    let mut path_buf = [0u8; 64];
    let path = null_terminate(name, &mut path_buf);
    let ret = linux_chdir(path);
    if ret < 0 {
        print(b"cd: not a directory or not found\n");
    }
}

fn cmd_pwd() {
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

fn cmd_syslog(max_entries: u64) {
    let mut num_buf = [0u8; 10];
    let num_len = u64_to_dec(max_entries, &mut num_buf);
    open_virtual_and_print(b"/proc/syslog/", &num_buf[..num_len], b"syslog: cannot read\n");
}

fn cmd_netmirror(arg: &[u8]) {
    open_virtual_and_print(b"/proc/netmirror/", arg, b"netmirror: failed\n");
}

fn u64_to_dec(mut val: u64, buf: &mut [u8; 10]) -> usize {
    if val == 0 {
        buf[0] = b'0';
        return 1;
    }
    let mut tmp = [0u8; 10];
    let mut i = 0;
    while val > 0 && i < 10 {
        tmp[i] = b'0' + (val % 10) as u8;
        val /= 10;
        i += 1;
    }
    for j in 0..i {
        buf[j] = tmp[i - 1 - j];
    }
    i
}

fn cmd_snap(args: &[u8]) {
    if starts_with(args, b"create ") {
        let name = trim(&args[7..]);
        if name.is_empty() { print(b"usage: snap create <name>\n"); return; }
        open_virtual_and_print(b"/snap/create/", name, b"snap create: failed\n");
    } else if eq(args, b"list") {
        open_virtual_and_print(b"/snap/list", b"", b"snap list: failed\n");
    } else if starts_with(args, b"restore ") {
        let name = trim(&args[8..]);
        if name.is_empty() { print(b"usage: snap restore <name>\n"); return; }
        open_virtual_and_print(b"/snap/restore/", name, b"snap restore: failed\n");
    } else if starts_with(args, b"delete ") {
        let name = trim(&args[7..]);
        if name.is_empty() { print(b"usage: snap delete <name>\n"); return; }
        open_virtual_and_print(b"/snap/delete/", name, b"snap delete: failed\n");
    } else {
        print(b"usage: snap create|list|restore|delete [<name>]\n");
    }
}

fn cmd_fork() {
    let child_fn = child_shell_main as *const () as u64;
    let child_pid = linux_clone(child_fn);
    if child_pid < 0 {
        print(b"fork: failed\n");
        return;
    }
    print(b"forked child pid=");
    print_u64(child_pid as u64);
    print(b"\nwaiting...\n");
    let status = linux_waitpid(child_pid as u64);
    print(b"child exited status=");
    print_u64(status as u64);
    print(b"\n");
}

/// Buffer for passing exec path to child_exec_main.
static mut EXEC_NAME_BUF: [u8; 64] = [0u8; 64];
static mut EXEC_NAME_LEN: usize = 0;
/// Argv string storage (null-separated).
static mut EXEC_ARGV_STRS: [u8; 512] = [0u8; 512];
/// Argv pointer array (u64 pointers + NULL terminator).
static mut EXEC_ARGV_PTRS: [u64; 17] = [0u64; 17];
/// Envp string storage (null-separated).
static mut EXEC_ENVP_STRS: [u8; 512] = [0u8; 512];
/// Envp pointer array (u64 pointers + NULL terminator).
static mut EXEC_ENVP_PTRS: [u64; 17] = [0u64; 17];

/// Child function that immediately calls execve with the name in EXEC_NAME_BUF.
extern "C" fn child_exec_main() -> ! {
    let name = unsafe { &EXEC_NAME_BUF[..EXEC_NAME_LEN + 1] }; // includes NUL
    let argv = unsafe { EXEC_ARGV_PTRS.as_ptr() };
    let envp = unsafe { EXEC_ENVP_PTRS.as_ptr() };
    let ret = linux_execve(name.as_ptr(), argv, envp);
    // execve failed — print error and exit
    print(b"exec: failed (errno=");
    print_u64((-ret) as u64);
    print(b")\n");
    linux_exit(1);
}

/// Check if a word looks like VAR=value (contains '=' and starts with a letter/underscore).
fn is_env_assignment(word: &[u8]) -> bool {
    if word.is_empty() { return false; }
    // Must start with letter or underscore
    let c = word[0];
    if !((c >= b'A' && c <= b'Z') || (c >= b'a' && c <= b'z') || c == b'_') { return false; }
    // Must contain '=' before any space
    for i in 1..word.len() {
        if word[i] == b'=' { return true; }
        if word[i] == b' ' { return false; }
    }
    false
}

fn cmd_exec(line: &[u8]) {
    // Parse leading VAR=value tokens, then command + arguments.
    // e.g., "HOME=/tmp PATH=/bin git init" -> envp=["HOME=/tmp","PATH=/bin"], prog="git", argv=["git","init"]
    let mut pos: usize = 0;

    unsafe {
        // Parse envp: leading VAR=value words
        let mut epos: usize = 0; // position in EXEC_ENVP_STRS
        let mut envc: usize = 0;
        loop {
            // Skip whitespace
            while pos < line.len() && line[pos] == b' ' { pos += 1; }
            if pos >= line.len() { break; }

            // Find end of this word
            let word_start = pos;
            while pos < line.len() && line[pos] != b' ' { pos += 1; }
            let word = &line[word_start..pos];

            if is_env_assignment(word) && envc < 16 {
                // Store as env var
                EXEC_ENVP_PTRS[envc] = EXEC_ENVP_STRS.as_ptr().add(epos) as u64;
                if epos + word.len() < 511 {
                    EXEC_ENVP_STRS[epos..epos + word.len()].copy_from_slice(word);
                    epos += word.len();
                    EXEC_ENVP_STRS[epos] = 0;
                    epos += 1;
                }
                envc += 1;
            } else {
                // Not an env assignment — this is the command. Rewind.
                pos = word_start;
                break;
            }
        }
        EXEC_ENVP_PTRS[envc] = 0; // NULL terminator

        // Remaining line is the actual command + args
        let cmd_line = &line[pos..];

        // Parse: first word = program name
        let mut prog_end = cmd_line.len();
        for i in 0..cmd_line.len() {
            if cmd_line[i] == b' ' { prog_end = i; break; }
        }
        let prog_name = &cmd_line[..prog_end];
        if prog_name.is_empty() {
            // Only env assignments, no command — nothing to exec
            return;
        }

        // Build path into EXEC_NAME_BUF: absolute paths pass through, relative get /bin/ prefix
        let is_absolute = prog_name[0] == b'/';
        let total = if is_absolute { prog_name.len() } else { 5 + prog_name.len() };
        if total >= 63 {
            print(b"exec: name too long\n");
            return;
        }
        if is_absolute {
            EXEC_NAME_BUF[..prog_name.len()].copy_from_slice(prog_name);
        } else {
            EXEC_NAME_BUF[..5].copy_from_slice(b"/bin/");
            EXEC_NAME_BUF[5..total].copy_from_slice(prog_name);
        }
        EXEC_NAME_BUF[total] = 0;
        EXEC_NAME_LEN = total;

        // Build argv: split remaining line on spaces
        let mut spos: usize = 0;
        let mut argc: usize = 0;

        // argv[0] = program name (what the binary sees as its own name)
        EXEC_ARGV_PTRS[argc] = EXEC_ARGV_STRS.as_ptr().add(spos) as u64;
        EXEC_ARGV_STRS[spos..spos + prog_name.len()].copy_from_slice(prog_name);
        spos += prog_name.len();
        EXEC_ARGV_STRS[spos] = 0;
        spos += 1;
        argc += 1;

        // Remaining arguments (handles single and double quotes)
        if prog_end < cmd_line.len() {
            let args = &cmd_line[prog_end + 1..];
            let mut i = 0;
            while i < args.len() && argc < 16 {
                // Skip whitespace
                while i < args.len() && args[i] == b' ' { i += 1; }
                if i >= args.len() { break; }

                // Parse one argument, stripping quotes
                let arg_start = spos;
                EXEC_ARGV_PTRS[argc] = EXEC_ARGV_STRS.as_ptr().add(spos) as u64;

                if args[i] == b'\'' || args[i] == b'"' {
                    // Quoted argument: collect until matching close quote
                    let quote = args[i];
                    i += 1; // skip opening quote
                    while i < args.len() && args[i] != quote {
                        if spos < 511 {
                            EXEC_ARGV_STRS[spos] = args[i];
                            spos += 1;
                        }
                        i += 1;
                    }
                    if i < args.len() { i += 1; } // skip closing quote
                } else {
                    // Unquoted argument: collect until space
                    while i < args.len() && args[i] != b' ' {
                        if spos < 511 {
                            EXEC_ARGV_STRS[spos] = args[i];
                            spos += 1;
                        }
                        i += 1;
                    }
                }

                if spos == arg_start { continue; } // empty arg, skip
                EXEC_ARGV_STRS[spos] = 0;
                spos += 1;
                argc += 1;
            }
        }
        EXEC_ARGV_PTRS[argc] = 0; // NULL terminator
    }

    // Fork child, which immediately does execve
    let child_pid = linux_clone(child_exec_main as *const () as u64);
    if child_pid < 0 {
        print(b"exec: fork failed\n");
        return;
    }

    // Wait for child to complete
    let status = linux_waitpid(child_pid as u64);
    let _ = status;
}

fn cmd_ps() {
    let mut path_buf = [0u8; 8];
    let path = null_terminate(b"/proc", &mut path_buf);
    let fd = linux_open(path, 0);
    if fd < 0 {
        print(b"ps: cannot open /proc\n");
        return;
    }
    let mut buf = [0u8; 1024];
    loop {
        let n = linux_read(fd as u64, buf.as_mut_ptr(), buf.len());
        if n <= 0 { break; }
        linux_write(1, buf.as_ptr(), n as usize);
    }
    linux_close(fd as u64);
}

fn cmd_uptime() {
    let mut path_buf = [0u8; 16];
    let path = null_terminate(b"/proc/uptime", &mut path_buf);
    let fd = linux_open(path, 0);
    if fd < 0 {
        print(b"uptime: cannot read\n");
        return;
    }
    let mut buf = [0u8; 64];
    let n = linux_read(fd as u64, buf.as_mut_ptr(), buf.len());
    if n > 0 {
        print(b"up ");
        linux_write(1, buf.as_ptr(), n as usize);
        print(b" ticks\n");
    }
    linux_close(fd as u64);
}

fn cmd_kill(args: &[u8]) {
    match find_space(args) {
        Some(sp) => {
            let pid = parse_u64_simple(&args[..sp]);
            let sig = parse_u64_simple(trim(&args[sp + 1..]));
            let ret = linux_kill(pid, sig);
            if ret < 0 {
                print(b"kill: no such process\n");
            }
        }
        None => {
            // No signal specified, default to SIGKILL(9)
            let pid = parse_u64_simple(args);
            let ret = linux_kill(pid, 9);
            if ret < 0 {
                print(b"kill: no such process\n");
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Networking helpers
// ---------------------------------------------------------------------------

/// Print an IPv4 address in dotted-decimal.
fn print_ip(ip: u32) {
    let bytes = ip.to_be_bytes();
    for (i, &b) in bytes.iter().enumerate() {
        if i > 0 { print(b"."); }
        print_u64(b as u64);
    }
}

/// Resolve a hostname to an IP address. Tries parse_ip first, then DNS.
fn resolve_host(host: &[u8]) -> Option<u32> {
    if let Some(ip) = parse_ip(host) {
        return Some(ip);
    }
    // Try DNS resolution.
    let ip = linux_dns_resolve(host.as_ptr(), host.len());
    if ip != 0 {
        Some(ip as u32)
    } else {
        None
    }
}

/// Parse an IPv4 dotted-decimal address. Returns big-endian u32.
fn parse_ip(s: &[u8]) -> Option<u32> {
    let mut octets = [0u8; 4];
    let mut octet_idx = 0;
    let mut val: u32 = 0;
    let mut has_digit = false;

    for &b in s {
        if b >= b'0' && b <= b'9' {
            val = val * 10 + (b - b'0') as u32;
            if val > 255 { return None; }
            has_digit = true;
        } else if b == b'.' {
            if !has_digit || octet_idx >= 3 { return None; }
            octets[octet_idx] = val as u8;
            octet_idx += 1;
            val = 0;
            has_digit = false;
        } else {
            return None;
        }
    }
    if !has_digit || octet_idx != 3 { return None; }
    octets[3] = val as u8;
    Some(u32::from_be_bytes(octets))
}

/// Build a sockaddr_in structure.
fn build_sockaddr(ip: u32, port: u16) -> [u8; 16] {
    let mut sa = [0u8; 16];
    sa[0] = 2; // AF_INET (low byte)
    sa[1] = 0;
    sa[2..4].copy_from_slice(&port.to_be_bytes());
    sa[4..8].copy_from_slice(&ip.to_be_bytes());
    sa
}

fn cmd_ping(host: &[u8]) {
    let ip = match resolve_host(host) {
        Some(ip) => ip,
        None => {
            print(b"ping: cannot resolve host\n");
            return;
        }
    };

    print(b"PING ");
    print(host);
    print(b" (");
    print_ip(ip);
    print(b") 56 data bytes\n");

    let mut sent = 0u32;
    let mut received = 0u32;

    for seq in 0..4u64 {
        sent += 1;
        let result = linux_icmp_ping(ip as u64, seq);
        if result != 0 {
            received += 1;
            let ttl = (result >> 32) as u32;
            print(b"64 bytes from ");
            print_ip(ip);
            print(b": icmp_seq=");
            print_u64(seq);
            print(b" ttl=");
            print_u64(ttl as u64);
            print(b"\n");
        } else {
            print(b"Request timeout for icmp_seq ");
            print_u64(seq);
            print(b"\n");
        }
    }

    // Statistics.
    print(b"--- ");
    print(host);
    print(b" ping statistics ---\n");
    print_u64(sent as u64);
    print(b" packets transmitted, ");
    print_u64(received as u64);
    print(b" received");
    if sent > 0 {
        let loss = ((sent - received) * 100) / sent;
        print(b", ");
        print_u64(loss as u64);
        print(b"% packet loss");
    }
    print(b"\n");
}

fn cmd_wget(args: &[u8]) {
    // Parse options: wget [-O file] [-q] <url>
    let mut output_file: &[u8] = b"";
    let mut quiet = false;
    let mut url: &[u8] = b"";

    let mut i = 0;
    while i < args.len() {
        while i < args.len() && args[i] == b' ' { i += 1; }
        if i >= args.len() { break; }

        if i + 2 <= args.len() && args[i] == b'-' && args[i + 1] == b'O' {
            // -O filename
            i += 2;
            while i < args.len() && args[i] == b' ' { i += 1; }
            let start = i;
            while i < args.len() && args[i] != b' ' { i += 1; }
            output_file = &args[start..i];
        } else if i + 2 <= args.len() && args[i] == b'-' && args[i + 1] == b'q' {
            quiet = true;
            i += 2;
        } else {
            let start = i;
            while i < args.len() && args[i] != b' ' { i += 1; }
            url = &args[start..i];
        }
    }

    if url.is_empty() {
        print(b"usage: wget [-O file] [-q] <url>\n");
        return;
    }

    // Check for https:// — TLS requires a full crypto handshake not yet implemented
    if starts_with(url, b"https://") {
        print(b"wget: HTTPS requires TLS (not yet implemented)\n");
        print(b"hint: use http:// or a plain HTTP mirror\n");
        return;
    }

    // Parse URL: http://host[:port]/path
    if !starts_with(url, b"http://") {
        print(b"wget: unsupported protocol (use http://)\n");
        return;
    }
    let after_scheme = &url[7..]; // skip "http://"

    // Find host and path.
    let mut host_end = after_scheme.len();
    let mut path_start = after_scheme.len();
    for j in 0..after_scheme.len() {
        if after_scheme[j] == b'/' {
            host_end = j;
            path_start = j;
            break;
        }
    }
    let host = &after_scheme[..host_end];
    let path = if path_start < after_scheme.len() {
        &after_scheme[path_start..]
    } else {
        b"/" as &[u8]
    };

    // Parse host:port.
    let mut port: u16 = 80;
    let mut hostname = host;
    for j in 0..host.len() {
        if host[j] == b':' {
            hostname = &host[..j];
            port = parse_u64_simple(&host[j + 1..]) as u16;
            break;
        }
    }

    // Resolve hostname (IP or DNS).
    let ip = match resolve_host(hostname) {
        Some(ip) => ip,
        None => {
            print(b"wget: cannot resolve '");
            print(hostname);
            print(b"'\n");
            return;
        }
    };

    if !quiet {
        print(b"Connecting to ");
        print(hostname);
        print(b" (");
        print_ip(ip);
        print(b"):");
        print_u64(port as u64);
        print(b"...\n");
    }

    // Create socket.
    let fd = linux_socket(2, 1, 0); // AF_INET, SOCK_STREAM
    if fd < 0 {
        print(b"wget: socket failed\n");
        return;
    }

    // Connect.
    let sa = build_sockaddr(ip, port);
    if linux_connect(fd as u64, sa.as_ptr(), 16) < 0 {
        print(b"wget: connect failed\n");
        linux_close(fd as u64);
        return;
    }

    if !quiet {
        print(b"HTTP request sent: GET ");
        print(path);
        print(b"\n");
    }

    // Build HTTP GET request.
    let mut req = [0u8; 512];
    let mut pos = 0;
    let prefix = b"GET ";
    req[pos..pos + prefix.len()].copy_from_slice(prefix);
    pos += prefix.len();
    let plen = path.len().min(200);
    req[pos..pos + plen].copy_from_slice(&path[..plen]);
    pos += plen;
    let suffix = b" HTTP/1.0\r\nHost: ";
    req[pos..pos + suffix.len()].copy_from_slice(suffix);
    pos += suffix.len();
    let hlen = hostname.len().min(64);
    req[pos..pos + hlen].copy_from_slice(&hostname[..hlen]);
    pos += hlen;
    let ua = b"\r\nUser-Agent: sotOS-wget/1.0\r\nConnection: close\r\n\r\n";
    req[pos..pos + ua.len()].copy_from_slice(ua);
    pos += ua.len();

    // Send request — may need multiple sends for larger requests.
    let mut sent_total: usize = 0;
    while sent_total < pos {
        let chunk = (pos - sent_total).min(40); // IPC inline limit
        let sent = linux_sendto(
            fd as u64,
            req[sent_total..].as_ptr(),
            chunk as u64,
            0,
        );
        if sent <= 0 {
            print(b"wget: send failed\n");
            linux_close(fd as u64);
            return;
        }
        sent_total += sent as usize;
    }

    // Read response in chunks, accumulate into a large buffer.
    // We accumulate the full response (headers + body) first, then parse.
    let mut response = [0u8; 8192];
    let mut resp_len: usize = 0;
    let mut consecutive_empty = 0u32;

    loop {
        let mut buf = [0u8; 56]; // IPC inline limit per recv
        let n = linux_recvfrom(fd as u64, buf.as_mut_ptr(), buf.len() as u64, 0);
        if n <= 0 {
            consecutive_empty += 1;
            if consecutive_empty > 5 || n < 0 { break; }
            continue;
        }
        consecutive_empty = 0;
        let copy_len = (n as usize).min(response.len() - resp_len);
        if copy_len == 0 { break; } // buffer full
        response[resp_len..resp_len + copy_len].copy_from_slice(&buf[..copy_len]);
        resp_len += copy_len;
    }

    linux_close(fd as u64);

    if resp_len == 0 {
        print(b"wget: empty response\n");
        return;
    }

    // Find end of HTTP headers (\r\n\r\n).
    let mut header_end: usize = 0;
    let mut body_start: usize = 0;
    for j in 0..resp_len.saturating_sub(3) {
        if response[j] == b'\r' && response[j + 1] == b'\n'
            && response[j + 2] == b'\r' && response[j + 3] == b'\n'
        {
            header_end = j;
            body_start = j + 4;
            break;
        }
    }

    // Parse status line from headers.
    if !quiet && header_end > 0 {
        // Find first line (status line).
        let mut status_end = 0;
        while status_end < header_end && response[status_end] != b'\r' {
            status_end += 1;
        }
        print(b"Response: ");
        linux_write(1, response[..status_end].as_ptr(), status_end);
        print(b"\n");

        // Look for Content-Length header.
        let headers = &response[..header_end];
        if let Some(cl) = find_header_value(headers, b"Content-Length") {
            print(b"Length: ");
            print(cl);
            print(b" bytes\n");
        }
        if let Some(ct) = find_header_value(headers, b"Content-Type") {
            print(b"Type: ");
            print(ct);
            print(b"\n");
        }
    }

    // If no body found, just use the whole response.
    if body_start == 0 {
        body_start = 0;
    }

    let body = &response[body_start..resp_len];
    let body_len = body.len();

    // Output body to file or stdout.
    if !output_file.is_empty() {
        // Save to file.
        let mut path_buf = [0u8; 128];
        let fpath = null_terminate(output_file, &mut path_buf);
        let out_fd = linux_open(fpath, 0x41); // O_WRONLY | O_CREAT
        if out_fd < 0 {
            print(b"wget: cannot create file '");
            print(output_file);
            print(b"'\n");
            // Fall back to stdout.
            linux_write(1, body.as_ptr(), body_len);
            print(b"\n");
        } else {
            linux_write(out_fd as u64, body.as_ptr(), body_len);
            linux_close(out_fd as u64);
            if !quiet {
                print(b"Saved to '");
                print(output_file);
                print(b"' (");
                print_u64(body_len as u64);
                print(b" bytes)\n");
            }
        }
    } else {
        // Print body to stdout.
        linux_write(1, body.as_ptr(), body_len);
        if body_len > 0 && body[body_len - 1] != b'\n' {
            print(b"\n");
        }
    }

    if !quiet {
        print_u64(resp_len as u64);
        print(b" bytes total received\n");
    }
}

/// Find the value of an HTTP header (case-insensitive search for name).
fn find_header_value<'a>(headers: &'a [u8], name: &[u8]) -> Option<&'a [u8]> {
    let mut i: usize = 0;
    while i + name.len() + 1 < headers.len() {
        // Check if this position matches the header name (case-insensitive).
        if headers[i] == b'\n' || i == 0 {
            let start = if headers[i] == b'\n' { i + 1 } else { i };
            if start + name.len() + 1 < headers.len() {
                let mut matches = true;
                for k in 0..name.len() {
                    let a = headers[start + k];
                    let b = name[k];
                    if a != b && a != (b ^ 0x20) {
                        // Simple case toggle for ASCII letters
                        if !(a.is_ascii_alphabetic() && b.is_ascii_alphabetic()
                            && (a & 0xDF) == (b & 0xDF)) {
                            matches = false;
                            break;
                        }
                    }
                }
                if matches && headers[start + name.len()] == b':' {
                    // Found it. Skip ": " and find end of value.
                    let mut val_start = start + name.len() + 1;
                    while val_start < headers.len() && headers[val_start] == b' ' {
                        val_start += 1;
                    }
                    let mut val_end = val_start;
                    while val_end < headers.len() && headers[val_end] != b'\r' && headers[val_end] != b'\n' {
                        val_end += 1;
                    }
                    return Some(&headers[val_start..val_end]);
                }
            }
        }
        i += 1;
    }
    None
}

fn cmd_resolve(name: &[u8]) {
    match resolve_host(name) {
        Some(ip) => {
            print(name);
            print(b" -> ");
            print_ip(ip);
            print(b"\n");
        }
        None => {
            print(b"resolve: cannot resolve ");
            print(name);
            print(b"\n");
        }
    }
}

fn cmd_traceroute(host: &[u8]) {
    let ip = match resolve_host(host) {
        Some(ip) => ip,
        None => {
            print(b"traceroute: cannot resolve host\n");
            return;
        }
    };

    print(b"traceroute to ");
    print(host);
    print(b" (");
    print_ip(ip);
    print(b"), 30 hops max\n");

    for ttl in 1..=30u64 {
        // Print TTL number with padding.
        if ttl < 10 { print(b" "); }
        print_u64(ttl);
        print(b"  ");

        let result = linux_traceroute_hop(ip as u64, ttl);
        if result == 0 {
            print(b"* * *\n");
        } else {
            let hop_ip = (result & 0xFFFFFFFF) as u32;
            let reached = (result >> 32) != 0;
            print_ip(hop_ip);
            print(b"\n");
            if reached {
                break;
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Lua interpreter
// ---------------------------------------------------------------------------

/// Lua output callback — writes to stdout.
fn lua_output(s: &[u8]) {
    linux_write(1, s.as_ptr(), s.len());
}

/// Execute Lua code from the command line.
fn cmd_lua(code: &[u8]) {
    let mut vm = sotos_lua::LuaVm::new();
    vm.init_stdlib();
    vm.set_output(lua_output);
    let _result = vm.run(code);
}

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    print(b"PANIC in lucas-shell\n");
    linux_exit(1);
}
