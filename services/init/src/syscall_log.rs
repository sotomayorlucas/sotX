use core::sync::atomic::{AtomicU64, Ordering};
use crate::framebuffer::{print, print_u64, print_hex64};
use crate::exec::{rdtsc, format_u64_into};

// ---------------------------------------------------------------------------
// Syscall Shadow Log (Phase 5: security instrumentation)
// Ring buffer in userspace that LUCAS fills on every child syscall.
// ---------------------------------------------------------------------------
const SYSCALL_LOG_SIZE: usize = 1024;

#[derive(Clone, Copy)]
pub(crate) struct SyscallLogEntry {
    timestamp: u64,  // RDTSC value
    pid: u16,
    syscall_nr: u16,
    arg0: u64,
    retval: i64,
}

impl SyscallLogEntry {
    const fn empty() -> Self {
        Self { timestamp: 0, pid: 0, syscall_nr: 0, arg0: 0, retval: 0 }
    }
}

static mut SYSCALL_LOG: [SyscallLogEntry; SYSCALL_LOG_SIZE] = [SyscallLogEntry::empty(); SYSCALL_LOG_SIZE];
static SYSCALL_LOG_HEAD: AtomicU64 = AtomicU64::new(0);
pub(crate) static SYSCALL_LOG_COUNT: AtomicU64 = AtomicU64::new(0);

/// Record a syscall into the shadow log ring buffer.
pub(crate) fn syscall_log_record(pid: u16, nr: u16, arg0: u64, retval: i64) {
    let idx = SYSCALL_LOG_HEAD.fetch_add(1, Ordering::Relaxed) as usize % SYSCALL_LOG_SIZE;
    unsafe {
        SYSCALL_LOG[idx] = SyscallLogEntry {
            timestamp: rdtsc(),
            pid,
            syscall_nr: nr,
            arg0,
            retval,
        };
    }
    SYSCALL_LOG_COUNT.fetch_add(1, Ordering::Relaxed);
}

/// Dump the last N entries from the syscall log to serial.
pub(crate) fn syscall_log_dump(max_entries: usize) {
    let total = SYSCALL_LOG_COUNT.load(Ordering::Relaxed) as usize;
    let head = SYSCALL_LOG_HEAD.load(Ordering::Relaxed) as usize;
    let count = total.min(SYSCALL_LOG_SIZE).min(max_entries);
    if count == 0 {
        print(b"[syslog] no entries recorded\n");
        return;
    }
    print(b"[syslog] last ");
    print_u64(count as u64);
    print(b" syscalls (");
    print_u64(total as u64);
    print(b" total):\n");
    for i in 0..count {
        let idx = (head + SYSCALL_LOG_SIZE - count + i) % SYSCALL_LOG_SIZE;
        let e = unsafe { &SYSCALL_LOG[idx] };
        print(b"  pid=");
        print_u64(e.pid as u64);
        print(b" ");
        print(sotos_common::trace::syscall_name(e.syscall_nr as u64));
        print(b"(");
        print_u64(e.syscall_nr as u64);
        print(b") arg0=0x");
        print_hex64(e.arg0);
        print(b" ret=");
        if e.retval < 0 {
            print(b"-");
            print_u64((-e.retval) as u64);
        } else {
            print_u64(e.retval as u64);
        }
        print(b"\n");
    }
}

/// Format syscall log entries into a buffer (for /proc/syslog/N virtual file).
pub(crate) fn format_syslog_into(buf: &mut [u8], max_entries: usize) -> usize {
    let total = SYSCALL_LOG_COUNT.load(Ordering::Relaxed) as usize;
    let head = SYSCALL_LOG_HEAD.load(Ordering::Relaxed) as usize;
    let count = total.min(SYSCALL_LOG_SIZE).min(max_entries);
    if count == 0 {
        let msg = b"[syslog] no entries recorded\n";
        let n = msg.len().min(buf.len());
        buf[..n].copy_from_slice(&msg[..n]);
        return n;
    }
    // Header
    let hdr = b"[syslog] last entries:\n";
    let n = hdr.len().min(buf.len());
    buf[..n].copy_from_slice(&hdr[..n]);
    let mut pos = n;
    for i in 0..count {
        if pos + 100 > buf.len() { break; }
        let idx = (head + SYSCALL_LOG_SIZE - count + i) % SYSCALL_LOG_SIZE;
        let e = unsafe { &SYSCALL_LOG[idx] };
        // "  pid=N nr=N arg0=0xH ret=N\n"
        let prefix = b"  pid=";
        buf[pos..pos + prefix.len()].copy_from_slice(prefix);
        pos += prefix.len();
        pos += format_u64_into(&mut buf[pos..], e.pid as u64);
        if pos < buf.len() { buf[pos] = b' '; pos += 1; }
        let sname = sotos_common::trace::syscall_name(e.syscall_nr as u64);
        let sn_len = sname.len().min(buf.len() - pos);
        buf[pos..pos + sn_len].copy_from_slice(&sname[..sn_len]);
        pos += sn_len;
        if pos < buf.len() { buf[pos] = b'('; pos += 1; }
        pos += format_u64_into(&mut buf[pos..], e.syscall_nr as u64);
        if pos < buf.len() { buf[pos] = b')'; pos += 1; }
        let arg_s = b" arg0=0x";
        buf[pos..pos + arg_s.len()].copy_from_slice(arg_s);
        pos += arg_s.len();
        pos += format_hex_into(&mut buf[pos..], e.arg0);
        let ret_s = b" ret=";
        buf[pos..pos + ret_s.len()].copy_from_slice(ret_s);
        pos += ret_s.len();
        if e.retval < 0 {
            buf[pos] = b'-';
            pos += 1;
            pos += format_u64_into(&mut buf[pos..], (-e.retval) as u64);
        } else {
            pos += format_u64_into(&mut buf[pos..], e.retval as u64);
        }
        buf[pos] = b'\n';
        pos += 1;
    }
    pos
}

/// Format a u64 as hex into buffer, return bytes written.
pub(crate) fn format_hex_into(buf: &mut [u8], mut val: u64) -> usize {
    if buf.is_empty() { return 0; }
    if val == 0 {
        buf[0] = b'0';
        return 1;
    }
    let mut tmp = [0u8; 16];
    let mut i = 0;
    while val > 0 && i < 16 {
        let d = (val & 0xF) as u8;
        tmp[i] = if d < 10 { b'0' + d } else { b'a' + d - 10 };
        val >>= 4;
        i += 1;
    }
    let n = i.min(buf.len());
    for j in 0..n {
        buf[j] = tmp[i - 1 - j];
    }
    n
}
