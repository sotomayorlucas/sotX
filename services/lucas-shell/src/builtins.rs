use crate::syscall::*;
use crate::util::*;
use crate::env::*;

// ---------------------------------------------------------------------------
// Built-in commands: wc, sort, uniq, diff, head, tail, grep, top,
//   ls, cat, write, rm, stat, hexdump, mkdir, rmdir, cd, pwd,
//   ps, uptime, kill, fork, syslog, netmirror, snap
// ---------------------------------------------------------------------------

// --- wc ---

pub fn cmd_wc(name: &[u8]) {
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
pub fn wc_data(data: &[u8], buf: &mut [u8]) -> usize {
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

// --- sort ---

pub fn cmd_sort(name: &[u8]) {
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
pub fn sort_data(data: &[u8], buf: &mut [u8]) -> usize {
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

// --- uniq ---

pub fn cmd_uniq(name: &[u8]) {
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
pub fn uniq_data(data: &[u8], buf: &mut [u8]) -> usize {
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

// --- diff ---

pub fn cmd_diff(args: &[u8]) {
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

// --- head ---

pub fn cmd_head(args: &[u8]) {
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

// --- tail ---

pub fn cmd_tail(args: &[u8]) {
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

// --- grep ---

pub fn cmd_grep(args: &[u8]) {
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

// --- top ---

/// top — list threads with CPU usage.
pub fn cmd_top() {
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

// --- ls ---

pub fn cmd_ls() {
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

pub fn cmd_ls_path(path: &[u8]) {
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

// --- cat ---

pub fn cmd_cat(name: &[u8]) {
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

// --- write ---

pub fn cmd_write(name: &[u8], text: &[u8]) {
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

// --- rm ---

pub fn cmd_rm(name: &[u8]) {
    let mut path_buf = [0u8; 64];
    let path = null_terminate(name, &mut path_buf);
    let ret = linux_unlink(path);
    if ret == 0 {
        print(b"removed\n");
    } else {
        print(b"rm: file not found\n");
    }
}

// --- stat ---

pub fn cmd_stat(name: &[u8]) {
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

// --- hexdump ---

pub fn cmd_hexdump(name: &[u8]) {
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

// --- mkdir ---

pub fn cmd_mkdir(name: &[u8]) {
    let mut path_buf = [0u8; 64];
    let path = null_terminate(name, &mut path_buf);
    let ret = linux_mkdir(path, 0o755);
    if ret == 0 {
        print(b"directory created\n");
    } else {
        print(b"mkdir: failed\n");
    }
}

// --- rmdir ---

pub fn cmd_rmdir(name: &[u8]) {
    let mut path_buf = [0u8; 64];
    let path = null_terminate(name, &mut path_buf);
    let ret = linux_rmdir(path);
    if ret == 0 {
        print(b"directory removed\n");
    } else {
        print(b"rmdir: failed (not empty or not found)\n");
    }
}

// --- cd ---

pub fn cmd_cd(name: &[u8]) {
    let mut path_buf = [0u8; 64];
    let path = null_terminate(name, &mut path_buf);
    let ret = linux_chdir(path);
    if ret < 0 {
        print(b"cd: not a directory or not found\n");
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

// --- ps ---

pub fn cmd_ps() {
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

// --- uptime ---

pub fn cmd_uptime() {
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

// --- kill ---

pub fn cmd_kill(args: &[u8]) {
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

// --- fork ---

pub fn cmd_fork() {
    let child_fn = crate::exec::child_shell_main as *const () as u64;
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

// --- syslog ---

pub fn cmd_syslog(max_entries: u64) {
    let mut num_buf = [0u8; 10];
    let num_len = u64_to_dec(max_entries, &mut num_buf);
    open_virtual_and_print(b"/proc/syslog/", &num_buf[..num_len], b"syslog: cannot read\n");
}

// --- netmirror ---

pub fn cmd_netmirror(arg: &[u8]) {
    open_virtual_and_print(b"/proc/netmirror/", arg, b"netmirror: failed\n");
}

// --- snap ---

pub fn cmd_snap(args: &[u8]) {
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

// --- unlink (alias for rm) ---

pub fn cmd_unlink(name: &[u8]) {
    cmd_rm(name);
}

// --- trace ---

pub fn cmd_trace(args: &[u8]) {
    if args.is_empty() || eq(args, b"help") {
        print(b"usage: trace level <error|warn|info|debug|trace>\n");
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
                print(b"trace: unknown level\n");
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
                print(b"trace: unknown category\n");
                return;
            }
            let cur = crate::trace::get_categories();
            let new = if adding { cur | mask } else { cur & !mask };
            crate::trace::set_categories(new);
            if adding { print(b"trace cat +"); } else { print(b"trace cat -"); }
            print(name);
            print(b"\n");
        } else {
            print(b"trace: expected +name, -name, all, or none\n");
        }
        return;
    }

    print(b"trace: unknown subcommand\n");
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

// --- capture_command ---
// Captures output from built-in commands into a buffer (used for pipes and redirects).

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
