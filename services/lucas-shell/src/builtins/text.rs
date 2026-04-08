//! Text-processing built-ins: wc, sort, uniq, diff, head, tail, grep.

use crate::syscall::*;
use crate::util::*;

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
