use crate::syscall::*;
use crate::util::*;
use crate::history::*;
use crate::jobs::*;

// ---------------------------------------------------------------------------
// Shell line editor
// ---------------------------------------------------------------------------

/// Erase the current line on terminal (move cursor back, overwrite, move back).
pub fn erase_line(len: usize) {
    for _ in 0..len {
        print(b"\x08 \x08");
    }
}

/// Read a line with history navigation and tab completion. Returns number of bytes read.
pub fn read_line(line_buf: &mut [u8; 512]) -> usize {
    let mut pos: usize = 0;
    let mut hist_nav: isize = -1; // -1 = not navigating, 0..count-1 = history index
    let mut saved_line = [0u8; 512]; // save current line when navigating history
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
                do_tab_completion(line_buf, &mut pos);
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

    pos
}

// ---------------------------------------------------------------------------
// Tab completion
// ---------------------------------------------------------------------------

fn do_tab_completion(line_buf: &mut [u8; 512], pos: &mut usize) {
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

fn tab_complete_builtin(prefix: &[u8], line_buf: &mut [u8; 512], pos: &mut usize, word_start: usize) {
    static BUILTINS: &[&[u8]] = &[
        b"help", b"echo", b"uname", b"uptime", b"caps", b"ls", b"cat", b"write",
        b"rm", b"stat", b"hexdump", b"head", b"tail", b"grep", b"mkdir", b"rmdir",
        b"cd", b"pwd", b"snap", b"fork", b"getpid", b"exec", b"ps", b"top", b"kill",
        b"resolve", b"ping", b"traceroute", b"wget", b"export", b"env", b"unset",
        b"exit", b"jobs", b"fg", b"bg", b"history", b"wc", b"sort", b"uniq", b"diff",
        b"function", b"syslog", b"netmirror", b"snapshot",
        b"services", b"threads", b"meminfo", b"bench",
        b"read", b"source", b"true", b"false", b"sleep", b"type", b"trace", b"pkg", b"apt",
        b"while", b"until", b"break", b"continue",
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

fn tab_complete_file(prefix: &[u8], line_buf: &mut [u8; 512], pos: &mut usize, _word_start: usize) {
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
