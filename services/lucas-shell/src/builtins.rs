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
                    // Different from previous -output it
                    let l = line.len().min(buf.len() - out_pos - 1);
                    buf[out_pos..out_pos + l].copy_from_slice(&line[..l]);
                    out_pos += l;
                    if out_pos < buf.len() { buf[out_pos] = b'\n'; out_pos += 1; }
                }
            } else if !line.is_empty() {
                // First line -always output
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

/// top -list threads with CPU usage.
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

// ---------------------------------------------------------------------------
// Service-aware builtins: services, threads, meminfo, bench, caps
// ---------------------------------------------------------------------------

/// Issue a sotOS kernel syscall with zero arguments (syscall number > 127).
/// Separate from the Linux-ABI wrappers in syscall.rs because these bypass
/// the child_handler Linux translation layer.
#[inline(always)]
fn kernel_syscall0(nr: u64) -> i64 {
    let ret: i64;
    unsafe {
        core::arch::asm!(
            "syscall",
            inlateout("rax") nr => ret,
            lateout("rcx") _,
            lateout("r11") _,
            options(nostack),
        );
    }
    ret
}

/// Issue a sotOS kernel syscall with two arguments.
#[inline(always)]
fn kernel_syscall2(nr: u64, a1: u64, a2: u64) -> i64 {
    let ret: i64;
    unsafe {
        core::arch::asm!(
            "syscall",
            inlateout("rax") nr => ret,
            in("rdi") a1,
            in("rsi") a2,
            lateout("rcx") _,
            lateout("r11") _,
            options(nostack),
        );
    }
    ret
}

/// Issue a sotOS kernel syscall with three arguments.
#[inline(always)]
fn kernel_syscall3(nr: u64, a1: u64, a2: u64, a3: u64) -> i64 {
    let ret: i64;
    unsafe {
        core::arch::asm!(
            "syscall",
            inlateout("rax") nr => ret,
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

// --- threads ---

/// Show total kernel thread count (syscall 142 = ThreadCount).
pub fn cmd_threads() {
    let count = kernel_syscall0(142) as u64;
    print(b"Total threads: ");
    print_u64(count);
    print(b"\n");
}

// --- meminfo ---

/// Show free physical memory (syscall 252 = DebugFreeFrames).
pub fn cmd_meminfo() {
    let frames = kernel_syscall0(252) as u64;
    let bytes = frames * 4096;
    let mb = bytes / (1024 * 1024);
    print(b"Free frames: ");
    print_u64(frames);
    print(b"\nFree memory: ");
    print_u64(mb);
    print(b" MiB (");
    print_u64(bytes / 1024);
    print(b" KiB)\n");
}

// --- bench ---

/// Quick IPC round-trip benchmark using RDTSC.
pub fn cmd_bench() {
    const ITERS: u64 = 100;
    print(b"IPC benchmark: ");
    print_u64(ITERS);
    print(b" round-trips...\n");

    // Try creating an IPC endpoint (syscall 10 = EndpointCreate).
    let ep = kernel_syscall0(10);
    if ep <= 0 {
        print(b"bench: endpoint_create failed, falling back to syscall-only timing\n");
        let start = rdtsc();
        for _ in 0..ITERS {
            crate::syscall::syscall0(39); // getpid
        }
        let elapsed = rdtsc().wrapping_sub(start);
        print_bench_result(b"Syscall overhead (getpid)", ITERS, elapsed);
        return;
    }

    // Measure IPC send (syscall 1) which returns immediately with no receiver.
    let start = rdtsc();
    for _ in 0..ITERS {
        kernel_syscall3(1, ep as u64, 0, 0);
    }
    let elapsed = rdtsc().wrapping_sub(start);
    print_bench_result(b"IPC send", ITERS, elapsed);
}

// --- caps ---

/// Placeholder for capability audit (Unit 6).
pub fn cmd_caps() {
    print(b"Capability audit not yet implemented\n");
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

// ---------------------------------------------------------------------------
// pkg -package management
// ---------------------------------------------------------------------------

/// pkg list | info <name> | which <name> | count
pub fn cmd_pkg(args: &[u8]) {
    if args.is_empty() || eq(args, b"help") {
        print(b"usage: pkg list           -list available executables\n");
        print(b"       pkg info <name>    -show binary info\n");
        print(b"       pkg which <name>   -show full path\n");
        print(b"       pkg count          -count executables\n");
        return;
    }

    if eq(args, b"list") {
        pkg_list();
    } else if eq(args, b"count") {
        pkg_count();
    } else if starts_with(args, b"info ") {
        let name = trim(&args[5..]);
        if !name.is_empty() { pkg_info(name); }
        else { print(b"usage: pkg info <name>\n"); }
    } else if starts_with(args, b"which ") {
        let name = trim(&args[6..]);
        if !name.is_empty() { pkg_which(name); }
        else { print(b"usage: pkg which <name>\n"); }
    } else {
        print(b"pkg: unknown subcommand. Try 'pkg help'\n");
        crate::parse::set_exit_status(1);
    }
}

fn pkg_list() {
    // List /bin/ contents
    print(b"--- /bin/ ---\n");
    pkg_list_dir(b"/bin");
    // List /usr/bin/ contents
    print(b"--- /usr/bin/ ---\n");
    pkg_list_dir(b"/usr/bin");
}

fn pkg_list_dir(dir: &[u8]) {
    let mut path_buf = [0u8; 64];
    let path = null_terminate(dir, &mut path_buf);
    let fd = linux_open(path, 0); // O_RDONLY
    if fd < 0 {
        print(b"  (empty)\n");
        return;
    }
    let mut listing = [0u8; 4096];
    let total = read_all(fd as u64, &mut listing);
    linux_close(fd as u64);

    if total == 0 {
        print(b"  (empty)\n");
        return;
    }

    // Parse listing: one entry per line
    let mut count = 0u64;
    let mut line_start = 0;
    let mut i = 0;
    while i <= total {
        if i == total || listing[i] == b'\n' {
            let entry = trim(&listing[line_start..i]);
            if !entry.is_empty() {
                // Extract just the name (before any whitespace metadata)
                let name_end = find_space(entry).unwrap_or(entry.len());
                let name = &entry[..name_end];
                if !name.is_empty() {
                    print(b"  ");
                    print(name);
                    print(b"\n");
                    count += 1;
                }
            }
            line_start = i + 1;
        }
        i += 1;
    }
    if count == 0 { print(b"  (empty)\n"); }
}

fn pkg_count() {
    let mut total = 0u64;
    for dir in &[b"/bin" as &[u8], b"/usr/bin"] {
        let mut path_buf = [0u8; 64];
        let path = null_terminate(dir, &mut path_buf);
        let fd = linux_open(path, 0);
        if fd < 0 { continue; }
        let mut listing = [0u8; 4096];
        let n = read_all(fd as u64, &mut listing);
        linux_close(fd as u64);
        for j in 0..n {
            if listing[j] == b'\n' { total += 1; }
        }
    }
    print_u64(total);
    print(b" executables available\n");
}

fn pkg_info(name: &[u8]) {
    // Try to stat the binary
    let mut resolved = [0u8; 128];
    let len = crate::exec::resolve_command(name, &mut resolved);
    if len == 0 {
        print(name);
        print(b": not found\n");
        crate::parse::set_exit_status(1);
        return;
    }

    let path = &resolved[..len];
    print(b"Name:    ");
    print(name);
    print(b"\n");
    print(b"Path:    ");
    print(path);
    print(b"\n");

    // Stat for size
    let mut stat_buf_nul = [0u8; 130];
    stat_buf_nul[..len].copy_from_slice(path);
    stat_buf_nul[len] = 0;
    let mut stat_buf = [0u8; 144];
    if linux_stat(stat_buf_nul.as_ptr(), stat_buf.as_mut_ptr()) >= 0 {
        let size = u64::from_le_bytes([stat_buf[48], stat_buf[49], stat_buf[50], stat_buf[51],
                                       stat_buf[52], stat_buf[53], stat_buf[54], stat_buf[55]]);
        print(b"Size:    ");
        print_u64(size);
        print(b" bytes\n");

        let mode = u32::from_le_bytes([stat_buf[24], stat_buf[25], stat_buf[26], stat_buf[27]]);
        print(b"Mode:    0o");
        // Print octal
        let mut oct_buf = [0u8; 8];
        let mut oct_len = 0;
        let mut m = mode & 0o7777;
        if m == 0 { oct_buf[0] = b'0'; oct_len = 1; }
        else {
            while m > 0 { oct_buf[oct_len] = b'0' + (m & 7) as u8; m >>= 3; oct_len += 1; }
        }
        let mut j = oct_len;
        while j > 0 { j -= 1; linux_write(1, &oct_buf[j] as *const u8, 1); }
        print(b"\n");
    }

    // Try to read ELF header to detect type
    let fd = linux_open(stat_buf_nul.as_ptr(), 0);
    if fd >= 0 {
        let mut hdr = [0u8; 64];
        let n = linux_read(fd as u64, hdr.as_mut_ptr(), 64);
        linux_close(fd as u64);
        if n >= 20 && hdr[0] == 0x7F && hdr[1] == b'E' && hdr[2] == b'L' && hdr[3] == b'F' {
            print(b"Type:    ELF ");
            // e_type at offset 16 (2 bytes LE)
            let etype = u16::from_le_bytes([hdr[16], hdr[17]]);
            match etype {
                2 => print(b"executable (ET_EXEC)"),
                3 => print(b"shared object/PIE (ET_DYN)"),
                _ => { print(b"type="); print_u64(etype as u64); }
            }
            print(b"\n");
            // Check for PT_INTERP to detect static vs dynamic
            if n >= 64 {
                let phoff = u64::from_le_bytes([hdr[32], hdr[33], hdr[34], hdr[35], hdr[36], hdr[37], hdr[38], hdr[39]]);
                let phnum = u16::from_le_bytes([hdr[56], hdr[57]]);
                if phoff > 0 && phnum > 0 {
                    print(b"Linking: ");
                    // We can't easily check PT_INTERP without reading more, so just report phnum
                    if phnum > 4 {
                        print(b"dynamic (");
                    } else {
                        print(b"static (");
                    }
                    print_u64(phnum as u64);
                    print(b" program headers)\n");
                }
            }
        } else {
            print(b"Type:    script/data\n");
        }
    }
}

fn pkg_which(name: &[u8]) {
    let mut resolved = [0u8; 128];
    let len = crate::exec::resolve_command(name, &mut resolved);
    if len > 0 {
        print(&resolved[..len]);
        print(b"\n");
    } else {
        print(name);
        print(b": not found\n");
        crate::parse::set_exit_status(1);
    }
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
    print(b"type: ");
    print(name);
    print(b" not found\n");
    crate::parse::set_exit_status(1);
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
        print(b"source: cannot read file: ");
        print(filename);
        print(b"\n");
        crate::parse::set_exit_status(1);
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

// ---------------------------------------------------------------------------
// apt -sotOS package manager
// ---------------------------------------------------------------------------

/// Package registry: tracks up to 64 packages (name, installed flag)
static mut APT_PKG_NAMES: [[u8; 32]; 64] = [[0u8; 32]; 64];
static mut APT_PKG_LENS: [u8; 64] = [0u8; 64];
static mut APT_PKG_INSTALLED: [bool; 64] = [false; 64];
static mut APT_PKG_COUNT: usize = 0;
static mut APT_INITIALIZED: bool = false;

/// Scan /bin/ and /pkg/ to discover available packages.
fn apt_init() {
    unsafe {
        if APT_INITIALIZED { return; }
        APT_INITIALIZED = true;
        APT_PKG_COUNT = 0;
    }
    apt_scan_dir(b"/bin", true);
    apt_scan_dir(b"/pkg", false);
}

fn apt_scan_dir(dir: &[u8], mark_installed: bool) {
    let mut path_buf = [0u8; 64];
    let path = null_terminate(dir, &mut path_buf);
    let fd = linux_open(path, 0);
    if fd < 0 { return; }
    let mut listing = [0u8; 4096];
    let total = read_all(fd as u64, &mut listing);
    linux_close(fd as u64);

    let mut line_start = 0;
    let mut i = 0;
    while i <= total {
        if i == total || listing[i] == b'\n' {
            let entry = trim(&listing[line_start..i]);
            let name_end = find_space(entry).unwrap_or(entry.len());
            let name = &entry[..name_end];
            if !name.is_empty() && name[0] != b'.' {
                apt_register(name, mark_installed);
            }
            line_start = i + 1;
        }
        i += 1;
    }
}

fn apt_register(name: &[u8], installed: bool) {
    unsafe {
        for j in 0..APT_PKG_COUNT {
            let plen = APT_PKG_LENS[j] as usize;
            if plen == name.len() && APT_PKG_NAMES[j][..plen] == *name {
                if installed { APT_PKG_INSTALLED[j] = true; }
                return;
            }
        }
        if APT_PKG_COUNT >= 64 { return; }
        let idx = APT_PKG_COUNT;
        let nl = name.len().min(31);
        APT_PKG_NAMES[idx][..nl].copy_from_slice(&name[..nl]);
        APT_PKG_LENS[idx] = nl as u8;
        APT_PKG_INSTALLED[idx] = installed;
        APT_PKG_COUNT += 1;
    }
}

pub fn cmd_apt(args: &[u8]) {
    apt_init();

    if args.is_empty() || eq(args, b"help") || eq(args, b"--help") {
        print(b"sotOS package manager\n");
        print(b"usage: apt install <pkg>    install package from /pkg/ to /bin/\n");
        print(b"       apt remove <pkg>     remove package from /bin/\n");
        print(b"       apt list             list all packages\n");
        print(b"       apt list --installed list installed packages\n");
        print(b"       apt search <term>    search packages by name\n");
        print(b"       apt update           rescan package directories\n");
        print(b"       apt fetch <url>      download package via HTTP\n");
        return;
    }

    if eq(args, b"update") {
        unsafe { APT_INITIALIZED = false; }
        apt_init();
        unsafe {
            print_u64(APT_PKG_COUNT as u64);
        }
        print(b" packages scanned\n");
    } else if eq(args, b"list") {
        apt_list(false);
    } else if eq(args, b"list --installed") {
        apt_list(true);
    } else if starts_with(args, b"install ") {
        let name = trim(&args[8..]);
        if !name.is_empty() { apt_install(name); }
        else { print(b"usage: apt install <pkg>\n"); }
    } else if starts_with(args, b"remove ") {
        let name = trim(&args[7..]);
        if !name.is_empty() { apt_remove(name); }
        else { print(b"usage: apt remove <pkg>\n"); }
    } else if starts_with(args, b"search ") {
        let term = trim(&args[7..]);
        if !term.is_empty() { apt_search(term); }
        else { print(b"usage: apt search <term>\n"); }
    } else if starts_with(args, b"fetch ") {
        let url = trim(&args[6..]);
        if !url.is_empty() { apt_fetch(url); }
        else { print(b"usage: apt fetch <url>\n"); }
    } else {
        print(b"apt: unknown command. Try 'apt help'\n");
        crate::parse::set_exit_status(1);
    }
}

fn apt_list(installed_only: bool) {
    unsafe {
        let mut count = 0u64;
        for i in 0..APT_PKG_COUNT {
            if installed_only && !APT_PKG_INSTALLED[i] { continue; }
            let plen = APT_PKG_LENS[i] as usize;
            print(&APT_PKG_NAMES[i][..plen]);
            if APT_PKG_INSTALLED[i] {
                print(b" [installed]");
            } else {
                print(b" [available]");
            }
            print(b"\n");
            count += 1;
        }
        if count == 0 { print(b"No packages found\n"); }
    }
}

fn apt_search(term: &[u8]) {
    unsafe {
        let mut found = false;
        for i in 0..APT_PKG_COUNT {
            let plen = APT_PKG_LENS[i] as usize;
            let name = &APT_PKG_NAMES[i][..plen];
            if contains(name, term) {
                print(name);
                if APT_PKG_INSTALLED[i] { print(b" [installed]"); }
                else { print(b" [available]"); }
                print(b"\n");
                found = true;
            }
        }
        if !found {
            print(b"No packages matching '");
            print(term);
            print(b"'\n");
        }
    }
}

fn apt_install(name: &[u8]) {
    // Check if already in /bin/
    let mut bin_path = [0u8; 70];
    bin_path[..5].copy_from_slice(b"/bin/");
    let nl = name.len().min(63);
    bin_path[5..5 + nl].copy_from_slice(&name[..nl]);
    bin_path[5 + nl] = 0;
    let mut stat_buf = [0u8; 144];
    if linux_stat(bin_path.as_ptr(), stat_buf.as_mut_ptr()) >= 0 {
        print(name);
        print(b" is already installed\n");
        return;
    }

    // Try /pkg/<name>
    let mut pkg_path = [0u8; 70];
    pkg_path[..5].copy_from_slice(b"/pkg/");
    pkg_path[5..5 + nl].copy_from_slice(&name[..nl]);
    pkg_path[5 + nl] = 0;

    if linux_stat(pkg_path.as_ptr(), stat_buf.as_mut_ptr()) < 0 {
        print(b"E: Unable to locate package ");
        print(name);
        print(b"\n");
        print(b"   Put packages in /pkg/ or use: apt fetch <url>\n");
        crate::parse::set_exit_status(100);
        return;
    }

    // Copy /pkg/<name> -> /bin/<name>
    let src_fd = linux_open(pkg_path.as_ptr(), 0);
    if src_fd < 0 {
        print(b"E: Failed to read /pkg/");
        print(name);
        print(b"\n");
        crate::parse::set_exit_status(1);
        return;
    }
    let mut data = [0u8; 4096];
    let mut total = 0usize;
    loop {
        let n = linux_read(src_fd as u64, data[total..].as_mut_ptr(), data.len() - total);
        if n <= 0 { break; }
        total += n as usize;
        if total >= data.len() { break; }
    }
    linux_close(src_fd as u64);

    let dst_fd = linux_open(bin_path.as_ptr(), 0x41); // O_WRONLY | O_CREAT
    if dst_fd < 0 {
        print(b"E: Failed to write /bin/");
        print(name);
        print(b"\n");
        crate::parse::set_exit_status(1);
        return;
    }
    if total > 0 {
        linux_write(dst_fd as u64, data.as_ptr(), total);
    }
    linux_close(dst_fd as u64);

    apt_register(name, true);
    print(b"Installing ");
    print(name);
    print(b" ... done (");
    print_u64(total as u64);
    print(b" bytes)\n");
}

fn apt_remove(name: &[u8]) {
    let mut bin_path = [0u8; 70];
    bin_path[..5].copy_from_slice(b"/bin/");
    let nl = name.len().min(63);
    bin_path[5..5 + nl].copy_from_slice(&name[..nl]);
    bin_path[5 + nl] = 0;

    let ret = linux_unlink(bin_path.as_ptr());
    if ret < 0 {
        print(b"E: ");
        print(name);
        print(b" is not installed\n");
        crate::parse::set_exit_status(1);
        return;
    }

    unsafe {
        for i in 0..APT_PKG_COUNT {
            let plen = APT_PKG_LENS[i] as usize;
            if plen == name.len() && APT_PKG_NAMES[i][..plen] == *name {
                APT_PKG_INSTALLED[i] = false;
            }
        }
    }
    print(b"Removing ");
    print(name);
    print(b" ... done\n");
}

fn apt_fetch(url: &[u8]) {
    let mut last_slash = 0;
    for i in 0..url.len() {
        if url[i] == b'/' { last_slash = i; }
    }
    if last_slash == 0 || last_slash + 1 >= url.len() {
        print(b"E: Cannot determine filename from URL\n");
        crate::parse::set_exit_status(1);
        return;
    }
    let filename = &url[last_slash + 1..];

    print(b"Fetching ");
    print(filename);
    print(b" ...\n");

    // Build wget command: wget -O /pkg/<filename> <url>
    let mut cmd = [0u8; 512];
    let mut pos = 0;
    let prefix = b"wget -O /pkg/";
    cmd[..prefix.len()].copy_from_slice(prefix);
    pos += prefix.len();
    let fl = filename.len().min(64);
    cmd[pos..pos + fl].copy_from_slice(&filename[..fl]);
    pos += fl;
    cmd[pos] = b' ';
    pos += 1;
    let ul = url.len().min(400);
    cmd[pos..pos + ul].copy_from_slice(&url[..ul]);
    pos += ul;

    crate::parse::dispatch_command(trim(&cmd[..pos]));

    if crate::parse::get_exit_status() == 0 {
        apt_register(filename, false);
        print(b"Done. Run: apt install ");
        print(filename);
        print(b"\n");
    }
}
