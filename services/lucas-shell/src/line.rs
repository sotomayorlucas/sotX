use crate::syscall::*;
use crate::util::*;
use crate::history::*;
use crate::jobs::*;
use crate::parse::BUILTIN_NAMES;
use crate::env::env_for_each_name;

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
//
// Context-aware completion with three modes:
//   1. Command: first token on the line → builtins + `/bin` + `/usr/bin`.
//   2. Env var: token starts with `$` → matching `ENV` keys.
//   3. Path:    everything else → directory entries filtered by the trailing
//               prefix; completion adds `/` for directories.
//
// All buffers are fixed-size — no heap. At most 128 candidates per attempt.

const MAX_CANDIDATES: usize = 128;
const CAND_NAME_LEN: usize = 64;
const TN_BLUE: &[u8] = b"\x1b[38;2;122;162;247m";
const TN_RESET: &[u8] = b"\x1b[0m";

/// Candidate list used by all completion modes. Kept in BSS (not on the
/// stack) because the shell's guest thread only has a 16KB stack and the
/// candidate buffer alone is ~8KB. Tab completion is non-reentrant — the
/// user can't press Tab while the shell is already handling a Tab — so a
/// single global instance is safe.
struct Candidates {
    names: [[u8; CAND_NAME_LEN]; MAX_CANDIDATES],
    lens:  [u8; MAX_CANDIDATES],
    is_dir: [bool; MAX_CANDIDATES],
    count: usize,
}

static mut CANDS: Candidates = Candidates {
    names: [[0; CAND_NAME_LEN]; MAX_CANDIDATES],
    lens:  [0; MAX_CANDIDATES],
    is_dir: [false; MAX_CANDIDATES],
    count: 0,
};

impl Candidates {
    fn reset(&mut self) { self.count = 0; }

    fn push(&mut self, name: &[u8], is_dir: bool) {
        if self.count >= MAX_CANDIDATES || name.is_empty() { return; }
        let n = name.len().min(CAND_NAME_LEN);
        // Deduplicate — a builtin `ls` and a `/bin/ls` binary shouldn't both
        // clutter the candidate grid.
        for i in 0..self.count {
            if self.lens[i] as usize == n && self.names[i][..n] == name[..n] {
                return;
            }
        }
        self.names[self.count][..n].copy_from_slice(&name[..n]);
        self.lens[self.count] = n as u8;
        self.is_dir[self.count] = is_dir;
        self.count += 1;
    }

    fn name(&self, i: usize) -> &[u8] {
        &self.names[i][..self.lens[i] as usize]
    }
}

fn do_tab_completion(line_buf: &mut [u8; 512], pos: &mut usize) {
    // Find current word start: search backward for space.
    let mut word_start = *pos;
    while word_start > 0 && line_buf[word_start - 1] != b' ' {
        word_start -= 1;
    }
    // Copy word into a local buffer to avoid aliasing line_buf.
    let mut word_buf = [0u8; 128];
    let word_len = (*pos - word_start).min(127);
    word_buf[..word_len].copy_from_slice(&line_buf[word_start..*pos]);
    let word = &word_buf[..word_len];

    // Determine context: first token vs argument.
    let is_first = {
        let mut only_ws = true;
        for i in 0..word_start {
            if line_buf[i] != b' ' && line_buf[i] != b'\t' {
                only_ws = false;
                break;
            }
        }
        only_ws
    };

    // Safety: tab completion is strictly sequential — there's no way for the
    // user to press Tab while the shell is already mid-completion.
    let cands = unsafe { &mut *core::ptr::addr_of_mut!(CANDS) };
    cands.reset();

    if !word.is_empty() && word[0] == b'$' {
        // Env var completion: word is "$PRE" — match against env names.
        let var_prefix = &word[1..];
        env_for_each_name(|name| {
            if starts_with(name, var_prefix) {
                cands.push(name, false);
            }
        });
        finish_completion(cands, word, line_buf, pos, CompletionMode::NoTrailingSpace);
    } else if is_first && find_byte(word, b'/').is_none() {
        // Command completion: builtins + /bin + /usr/bin.
        for &b in BUILTIN_NAMES {
            if starts_with(b, word) {
                cands.push(b, false);
            }
        }
        collect_dir_matches(b"/bin", word, false, cands);
        collect_dir_matches(b"/usr/bin", word, false, cands);
        finish_completion(cands, word, line_buf, pos, CompletionMode::AppendSpace);
    } else {
        // Path completion.
        let (dir, name_prefix) = split_path(word);
        collect_dir_matches(dir, name_prefix, true, cands);
        finish_completion(cands, name_prefix, line_buf, pos, CompletionMode::AppendSpace);
    }
}

/// Controls what `finish_completion` appends after a unique match.
/// - `AppendSpace` is the bash default; cursor ready for the next argument.
/// - `NoTrailingSpace` is used for `$VAR` completion so the user can keep
///   typing (e.g. `$HOME/bin`) without having to delete a stray space.
#[derive(Clone, Copy, PartialEq)]
enum CompletionMode {
    AppendSpace,
    NoTrailingSpace,
}

/// Split a path into (dir, basename_prefix). `foo/bar` → (`foo`, `bar`).
/// `/abs/path/` → (`/abs/path`, ``). No slash → (`.`, word).
fn split_path(word: &[u8]) -> (&[u8], &[u8]) {
    let mut last = None;
    for (i, &b) in word.iter().enumerate() {
        if b == b'/' { last = Some(i); }
    }
    match last {
        None => (b".".as_slice(), word),
        Some(0) => (b"/".as_slice(), &word[1..]),
        Some(i) => (&word[..i], &word[i + 1..]),
    }
}

/// Read `dir` via getdents64 and push entries starting with `prefix` into `cands`.
/// Skips `.` and `..`. `track_type=true` marks directories so single-match
/// completion can append `/`.
fn collect_dir_matches(dir: &[u8], prefix: &[u8], track_type: bool, cands: &mut Candidates) {
    let mut dir_buf = [0u8; 128];
    let dir_path = null_terminate(dir, &mut dir_buf);
    let flags = (sotos_common::linux_abi::O_RDONLY | sotos_common::linux_abi::O_DIRECTORY) as u64;
    let fd = linux_open(dir_path, flags);
    if fd < 0 { return; }

    let mut buf = [0u8; 4096];
    loop {
        let n = linux_getdents64(fd as u64, buf.as_mut_ptr(), buf.len());
        if n <= 0 { break; }
        let n = n as usize;
        let mut off = 0usize;
        while off + 19 <= n {
            let reclen = u16::from_le_bytes([buf[off + 16], buf[off + 17]]) as usize;
            if reclen == 0 || off + reclen > n { break; }
            let d_type = buf[off + 18];
            // Name begins at off+19 and is NUL-terminated within the record.
            let name_start = off + 19;
            let mut name_end = name_start;
            while name_end < off + reclen && buf[name_end] != 0 {
                name_end += 1;
            }
            let name = &buf[name_start..name_end];
            if name != b"." && name != b".." && starts_with(name, prefix) {
                let is_dir = track_type && d_type == sotos_common::linux_abi::DT_DIR;
                cands.push(name, is_dir);
                if cands.count >= MAX_CANDIDATES { break; }
            }
            off += reclen;
        }
        if cands.count >= MAX_CANDIDATES { break; }
    }
    linux_close(fd as u64);
}

/// Insert a slice into `line_buf` at `*pos`, advancing `*pos` and echoing to
/// the terminal. Bounds-checked; silently drops bytes that would overflow.
fn line_insert(line_buf: &mut [u8; 512], pos: &mut usize, data: &[u8]) {
    let room = line_buf.len().saturating_sub(*pos + 1);
    let n = data.len().min(room);
    if n == 0 { return; }
    line_buf[*pos..*pos + n].copy_from_slice(&data[..n]);
    *pos += n;
    linux_write(1, data.as_ptr(), n);
}

/// Act on collected candidates — zero/one/many.
/// `filter_prefix` is the substring the user already typed (the portion to
/// skip when writing the completion back into the line buffer).
fn finish_completion(
    cands: &Candidates,
    filter_prefix: &[u8],
    line_buf: &mut [u8; 512],
    pos: &mut usize,
    mode: CompletionMode,
) {
    match cands.count {
        0 => {
            print(b"\x07");
        }
        1 => {
            let full = cands.name(0);
            let suffix = &full[filter_prefix.len().min(full.len())..];
            line_insert(line_buf, pos, suffix);
            if cands.is_dir[0] {
                line_insert(line_buf, pos, b"/");
            } else if mode == CompletionMode::AppendSpace {
                line_insert(line_buf, pos, b" ");
            }
        }
        _ => {
            // Extend by common prefix first (saves a round trip), then draw a
            // 4-column grid and redraw the prompt so the user keeps editing.
            let common = common_prefix_len(cands);
            if common > filter_prefix.len() {
                let extra = &cands.names[0][filter_prefix.len()..common];
                line_insert(line_buf, pos, extra);
            }
            print_candidate_grid(cands);
            print(b"$ ");
            linux_write(1, line_buf.as_ptr(), *pos);
        }
    }
}

/// Longest byte-wise common prefix of all candidate names.
fn common_prefix_len(cands: &Candidates) -> usize {
    if cands.count == 0 { return 0; }
    let first = cands.name(0);
    let mut common = first.len();
    for i in 1..cands.count {
        let other = cands.name(i);
        let mut cl = 0usize;
        while cl < common && cl < other.len() && first[cl] == other[cl] {
            cl += 1;
        }
        common = cl;
        if common == 0 { break; }
    }
    common
}

/// Print candidates in a 4-column grid colored Tokyo-Night blue.
fn print_candidate_grid(cands: &Candidates) {
    const COLS: usize = 4;
    const COL_WIDTH: usize = 20;
    print(b"\n");
    print(TN_BLUE);
    for i in 0..cands.count {
        let name = cands.name(i);
        let nlen = name.len().min(COL_WIDTH - 1);
        linux_write(1, name.as_ptr(), nlen);
        // Pad with spaces to column width; last column ends with newline.
        let is_last_col = (i % COLS) == COLS - 1;
        let is_last_entry = i + 1 == cands.count;
        if is_last_col || is_last_entry {
            print(b"\n");
        } else {
            let pad = COL_WIDTH - nlen;
            for _ in 0..pad { print(b" "); }
        }
    }
    print(TN_RESET);
}
