use crate::syscall::*;
use crate::util::*;
use crate::history::*;
use crate::jobs::*;
use crate::parse::BUILTIN_NAMES;
use crate::env::env_for_each_name;

// ---------------------------------------------------------------------------
// Shell line editor
//
// A readline-style editor with:
//  - left/right arrows move the cursor inside the line (mid-line edit)
//  - up/down navigate history, saving the working line
//  - Home/End (Ctrl+A / Ctrl+E also) jump to line boundaries
//  - Alt+B / Alt+F (ESC-prefix `b` / `f`) move by word
//  - Ctrl+K / Ctrl+U / Ctrl+W cut to end / start / previous word
//  - Ctrl+Y yanks the last cut (kill ring of 1 entry)
//  - Ctrl+R enters an incremental reverse-i-search over history
//
// All buffers are fixed-size static; no heap.
// ---------------------------------------------------------------------------

/// Scratch for Ctrl+K/U/W/Y. One slot is enough for a shell.
const KILL_BUF_SIZE: usize = 512;
static mut KILL_BUF: [u8; KILL_BUF_SIZE] = [0u8; KILL_BUF_SIZE];
static mut KILL_LEN: usize = 0;

// --- terminal cursor helpers ---------------------------------------------

/// Erase the current line on terminal (move cursor back, overwrite, move back).
pub fn erase_line(len: usize) {
    for _ in 0..len {
        print(b"\x08 \x08");
    }
}

/// Move cursor `n` cells left with bare backspaces (no SGR dependency).
fn move_left(n: usize) {
    for _ in 0..n {
        print(b"\x08");
    }
}

/// Emit `n` space characters (used by reverse-i-search to blank its prompt).
fn print_spaces(n: usize) {
    for _ in 0..n {
        print(b" ");
    }
}

/// Redraw the tail of the line from `pos` then reposition the cursor at `pos`.
/// `old_len` is the previous line length (used to blank trailing chars when
/// the edit shortened the line). After the call, the logical cursor is at
/// `pos`.
fn redraw_tail(buf: &[u8], pos: usize, len: usize, old_len: usize) {
    // Write the tail chars so the terminal matches the buffer.
    if len > pos {
        linux_write(1, buf[pos..len].as_ptr(), len - pos);
    }
    // Blank any trailing chars that disappeared.
    if old_len > len {
        let extra = old_len - len;
        print_spaces(extra);
        // And step back over those blanks.
        move_left(extra);
    }
    // Move the cursor back from end-of-text to the desired `pos`.
    if len > pos {
        move_left(len - pos);
    }
}

// --- word boundary helpers ------------------------------------------------

fn prev_word_start(buf: &[u8], pos: usize) -> usize {
    let mut p = pos;
    // skip whitespace going left
    while p > 0 && buf[p - 1] == b' ' {
        p -= 1;
    }
    // skip the word itself
    while p > 0 && buf[p - 1] != b' ' {
        p -= 1;
    }
    p
}

fn next_word_end(buf: &[u8], pos: usize, len: usize) -> usize {
    let mut p = pos;
    // skip whitespace going right
    while p < len && buf[p] == b' ' {
        p += 1;
    }
    // skip the word itself
    while p < len && buf[p] != b' ' {
        p += 1;
    }
    p
}

// --- kill-ring helpers ----------------------------------------------------

fn kill_store(bytes: &[u8]) {
    unsafe {
        let n = bytes.len().min(KILL_BUF_SIZE);
        // Byte-by-byte copy through a raw pointer sidesteps the implicit-autoref
        // rule that fires on `&mut (*addr_of_mut!(STATIC))[..]`.
        let ptr = core::ptr::addr_of_mut!(KILL_BUF) as *mut u8;
        for i in 0..n {
            core::ptr::write(ptr.add(i), bytes[i]);
        }
        KILL_LEN = n;
    }
}

fn kill_slice() -> &'static [u8] {
    unsafe {
        let n = KILL_LEN;
        let ptr = core::ptr::addr_of!(KILL_BUF) as *const u8;
        core::slice::from_raw_parts(ptr, n)
    }
}

// --- main line reader -----------------------------------------------------

/// Read a line with history navigation, tab completion, word motion,
/// kill-ring, Home/End and reverse-i-search. Returns number of bytes read.
pub fn read_line(line_buf: &mut [u8; 512]) -> usize {
    // `pos` is the cursor column (0..=len). `len` is how many chars are live.
    let mut pos: usize = 0;
    let mut len: usize = 0;
    let mut hist_nav: isize = -1; // -1 = not navigating, 0..count-1 = history index
    let mut saved_line = [0u8; 512];
    let mut saved_len: usize = 0;
    // ESC state machine:
    //  0 = normal
    //  1 = saw ESC
    //  2 = saw ESC '[' (CSI)
    //  3 = saw ESC '[' <digit>, collecting digits for `~`-terminated CSI
    let mut esc_state: u8 = 0;
    let mut csi_param: u8 = 0;

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
            return 0;
        }
        if n <= 0 {
            continue;
        }
        let c = ch[0];

        // --- CSI / ESC-prefix state machine ---
        if esc_state == 1 {
            // Saw ESC; decide what follows.
            match c {
                b'[' => { esc_state = 2; continue; }
                b'b' => {
                    // Alt+B — word back
                    let target = prev_word_start(line_buf, pos);
                    if target < pos {
                        move_left(pos - target);
                        pos = target;
                    }
                    esc_state = 0;
                    continue;
                }
                b'f' => {
                    // Alt+F — word forward
                    let target = next_word_end(line_buf, pos, len);
                    if target > pos {
                        linux_write(1, line_buf[pos..target].as_ptr(), target - pos);
                        pos = target;
                    }
                    esc_state = 0;
                    continue;
                }
                _ => { esc_state = 0; /* drop unrecognised meta key */ continue; }
            }
        }
        if esc_state == 2 {
            match c {
                b'A' => {
                    // Up arrow — previous history
                    let count = history_count();
                    if count == 0 { esc_state = 0; continue; }
                    if hist_nav < 0 {
                        saved_line[..len].copy_from_slice(&line_buf[..len]);
                        saved_len = len;
                        hist_nav = (count as isize) - 1;
                    } else if hist_nav > 0 {
                        hist_nav -= 1;
                    } else {
                        esc_state = 0;
                        continue;
                    }
                    // Reposition at end of current line then erase it
                    if pos < len { linux_write(1, line_buf[pos..len].as_ptr(), len - pos); }
                    erase_line(len);
                    if let Some(entry) = history_get(hist_nav as usize) {
                        let l = entry.len().min(line_buf.len() - 1);
                        line_buf[..l].copy_from_slice(&entry[..l]);
                        len = l;
                        pos = l;
                        linux_write(1, line_buf[..len].as_ptr(), len);
                    }
                    esc_state = 0;
                    continue;
                }
                b'B' => {
                    // Down arrow — next history
                    if hist_nav < 0 { esc_state = 0; continue; }
                    let count = history_count();
                    if pos < len { linux_write(1, line_buf[pos..len].as_ptr(), len - pos); }
                    erase_line(len);
                    if (hist_nav as usize) < count - 1 {
                        hist_nav += 1;
                        if let Some(entry) = history_get(hist_nav as usize) {
                            let l = entry.len().min(line_buf.len() - 1);
                            line_buf[..l].copy_from_slice(&entry[..l]);
                            len = l;
                            pos = l;
                            linux_write(1, line_buf[..len].as_ptr(), len);
                        }
                    } else {
                        hist_nav = -1;
                        line_buf[..saved_len].copy_from_slice(&saved_line[..saved_len]);
                        len = saved_len;
                        pos = saved_len;
                        linux_write(1, line_buf[..len].as_ptr(), len);
                    }
                    esc_state = 0;
                    continue;
                }
                b'C' => {
                    // Right arrow
                    if pos < len {
                        linux_write(1, &line_buf[pos] as *const u8, 1);
                        pos += 1;
                    }
                    esc_state = 0;
                    continue;
                }
                b'D' => {
                    // Left arrow
                    if pos > 0 {
                        move_left(1);
                        pos -= 1;
                    }
                    esc_state = 0;
                    continue;
                }
                b'H' => {
                    // Home (xterm no-number form)
                    if pos > 0 { move_left(pos); pos = 0; }
                    esc_state = 0;
                    continue;
                }
                b'F' => {
                    // End (xterm no-number form)
                    if pos < len {
                        linux_write(1, line_buf[pos..len].as_ptr(), len - pos);
                        pos = len;
                    }
                    esc_state = 0;
                    continue;
                }
                b'0'..=b'9' => {
                    csi_param = c - b'0';
                    esc_state = 3;
                    continue;
                }
                _ => { esc_state = 0; continue; }
            }
        }
        if esc_state == 3 {
            match c {
                b'0'..=b'9' => {
                    csi_param = csi_param.saturating_mul(10).saturating_add(c - b'0');
                    continue;
                }
                b'~' => {
                    // `CSI n ~` — VT sequence. 1=Home, 4=End, 7=Home(rxvt), 8=End(rxvt), 3=Delete.
                    match csi_param {
                        1 | 7 => {
                            if pos > 0 { move_left(pos); pos = 0; }
                        }
                        4 | 8 => {
                            if pos < len {
                                linux_write(1, line_buf[pos..len].as_ptr(), len - pos);
                                pos = len;
                            }
                        }
                        3 => {
                            // Delete forward one char
                            if pos < len {
                                let old_len = len;
                                line_buf.copy_within(pos + 1..len, pos);
                                len -= 1;
                                redraw_tail(line_buf, pos, len, old_len);
                            }
                        }
                        _ => {}
                    }
                    esc_state = 0;
                    csi_param = 0;
                    continue;
                }
                _ => { esc_state = 0; csi_param = 0; continue; }
            }
        }

        match c {
            0x1B => {
                esc_state = 1;
            }
            // Enter
            b'\r' | b'\n' => {
                // Cursor may be mid-line; walk to end so the next \n is clean.
                if pos < len {
                    linux_write(1, line_buf[pos..len].as_ptr(), len - pos);
                }
                print(b"\n");
                let _ = hist_nav;
                return len;
            }
            // Backspace (0x08) or DEL (0x7F) — delete char left of cursor
            0x08 | 0x7F => {
                if pos > 0 {
                    let old_len = len;
                    pos -= 1;
                    line_buf.copy_within(pos + 1..len, pos);
                    len -= 1;
                    // step back, then redraw tail with blank for lost char
                    print(b"\x08");
                    redraw_tail(line_buf, pos, len, old_len);
                }
            }
            // Tab — completion (only when cursor at end-of-line to keep it simple)
            b'\t' => {
                if pos == len {
                    do_tab_completion(line_buf, &mut len);
                    pos = len;
                }
            }
            // Ctrl+A — move to line start
            0x01 => {
                if pos > 0 { move_left(pos); pos = 0; }
            }
            // Ctrl+E — move to line end
            0x05 => {
                if pos < len {
                    linux_write(1, line_buf[pos..len].as_ptr(), len - pos);
                    pos = len;
                }
            }
            // Ctrl+K — kill to end of line
            0x0B => {
                if pos < len {
                    let old_len = len;
                    kill_store(&line_buf[pos..len]);
                    len = pos;
                    redraw_tail(line_buf, pos, len, old_len);
                }
            }
            // Ctrl+U — kill from start to cursor
            0x15 => {
                if pos > 0 {
                    let old_len = len;
                    kill_store(&line_buf[..pos]);
                    line_buf.copy_within(pos..len, 0);
                    len -= pos;
                    move_left(pos);
                    pos = 0;
                    redraw_tail(line_buf, pos, len, old_len);
                }
            }
            // Ctrl+W — kill previous word
            0x17 => {
                if pos > 0 {
                    let word_start = prev_word_start(line_buf, pos);
                    let cut_len = pos - word_start;
                    if cut_len > 0 {
                        let old_len = len;
                        kill_store(&line_buf[word_start..pos]);
                        line_buf.copy_within(pos..len, word_start);
                        len -= cut_len;
                        move_left(cut_len);
                        pos = word_start;
                        redraw_tail(line_buf, pos, len, old_len);
                    }
                }
            }
            // Ctrl+Y — yank last kill at cursor
            0x19 => {
                let yank = kill_slice();
                let yank_len = yank.len();
                if yank_len > 0 && len + yank_len < line_buf.len() {
                    // Make room: shift tail right by yank_len.
                    line_buf.copy_within(pos..len, pos + yank_len);
                    for i in 0..yank_len {
                        line_buf[pos + i] = yank[i];
                    }
                    len += yank_len;
                    // Write inserted chars + tail, then step cursor back to
                    // just after the yanked text.
                    linux_write(1, line_buf[pos..len].as_ptr(), len - pos);
                    pos += yank_len;
                    if len > pos { move_left(len - pos); }
                }
            }
            // Ctrl+R — reverse-i-search
            0x12 => {
                let new_len = reverse_search(line_buf, len);
                len = new_len;
                pos = len;
            }
            // Ctrl+Z
            0x1A => {
                let fg = get_fg_pid();
                if fg != 0 {
                    linux_kill(fg, 20); // SIGTSTP
                    print(b"^Z\n");
                    let jid = job_add(fg, JOB_STOPPED, b"(stopped)");
                    if jid > 0 {
                        print(b"[");
                        print_u64(jid as u64);
                        print(b"]  Stopped\n");
                    }
                    set_fg_pid(0);
                    return 0;
                }
            }
            // Printable character — insert at cursor
            0x20..=0x7E => {
                if len < line_buf.len() - 1 {
                    if pos == len {
                        // Fast path: appending.
                        line_buf[pos] = c;
                        pos += 1;
                        len += 1;
                        linux_write(1, &c as *const u8, 1);
                    } else {
                        // Mid-line insert: shift tail right.
                        line_buf.copy_within(pos..len, pos + 1);
                        line_buf[pos] = c;
                        len += 1;
                        // Write from cursor to end, then reposition.
                        linux_write(1, line_buf[pos..len].as_ptr(), len - pos);
                        pos += 1;
                        move_left(len - pos);
                    }
                }
            }
            _ => {}
        }
    }
}

// ---------------------------------------------------------------------------
// Ctrl+R — incremental reverse search over history
// ---------------------------------------------------------------------------

/// Find the most recent history entry containing `query`, scanning backwards
/// starting at `start_idx` (inclusive). Returns the found index or None.
fn history_find_backward(query: &[u8], start_idx: isize) -> Option<usize> {
    if query.is_empty() { return None; }
    let mut i = start_idx;
    while i >= 0 {
        if let Some(entry) = history_get(i as usize) {
            if contains(entry, query) {
                return Some(i as usize);
            }
        }
        i -= 1;
    }
    None
}

/// Copy history entry `idx` into `dst`, returning its length. Zero on miss.
fn copy_history_entry(idx: usize, dst: &mut [u8]) -> usize {
    if let Some(e) = history_get(idx) {
        let l = e.len().min(dst.len());
        dst[..l].copy_from_slice(&e[..l]);
        l
    } else {
        0
    }
}

/// Blank `width` cells starting at the current cursor column, leaving the
/// cursor exactly where it started.
fn erase_width(width: usize) {
    if width == 0 { return; }
    move_left(width);
    print_spaces(width);
    move_left(width);
}

/// Draw the reverse-search prompt. The visible area is:
///     (reverse-i-search) `query`: match
/// The cursor is left at the end so the user can keep typing.
fn draw_rsearch(prev_total: usize, query: &[u8], matched: &[u8]) -> usize {
    // Erase the previous rendering first.
    erase_width(prev_total);
    const PROMPT_LEFT: &[u8] = b"(reverse-i-search) `";
    const PROMPT_RIGHT: &[u8] = b"': ";
    print(PROMPT_LEFT);
    linux_write(1, query.as_ptr(), query.len());
    print(PROMPT_RIGHT);
    linux_write(1, matched.as_ptr(), matched.len());
    PROMPT_LEFT.len() + query.len() + PROMPT_RIGHT.len() + matched.len()
}

/// Run the Ctrl+R loop. On Enter the matched line becomes the new line_buf
/// contents (and is returned via `len`). On Esc, the original line is
/// restored. Returns the new length; the caller places the cursor at the end.
fn reverse_search(line_buf: &mut [u8; 512], orig_len: usize) -> usize {
    // Stash the pre-search line so Esc can restore it.
    let mut orig = [0u8; 512];
    orig[..orig_len].copy_from_slice(&line_buf[..orig_len]);

    // Erase the current line (cursor may be at end — caller took care of that).
    erase_line(orig_len);

    let mut query = [0u8; 128];
    let mut qlen: usize = 0;
    let mut found_idx: isize = (history_count() as isize) - 1;
    let mut rendered: usize;
    let mut cur_match: [u8; 512] = [0u8; 512];
    let mut cur_match_len: usize = 0;

    // Initial render with empty query — shows prompt skeleton.
    rendered = draw_rsearch(0, &query[..qlen], &cur_match[..cur_match_len]);

    loop {
        let mut ch = [0u8; 1];
        let n = linux_read(0, ch.as_mut_ptr(), 1);
        if n <= 0 { continue; }
        let c = ch[0];
        match c {
            // Esc — cancel, restore original line
            0x1B => {
                erase_width(rendered);
                linux_write(1, orig[..orig_len].as_ptr(), orig_len);
                line_buf[..orig_len].copy_from_slice(&orig[..orig_len]);
                return orig_len;
            }
            // Enter — accept current match
            b'\r' | b'\n' => {
                erase_width(rendered);
                line_buf[..cur_match_len].copy_from_slice(&cur_match[..cur_match_len]);
                linux_write(1, line_buf[..cur_match_len].as_ptr(), cur_match_len);
                return cur_match_len;
            }
            // Backspace / DEL — trim query, re-search from newest.
            0x08 | 0x7F => {
                if qlen > 0 {
                    qlen -= 1;
                    found_idx = (history_count() as isize) - 1;
                    cur_match_len = 0;
                    if let Some(idx) = history_find_backward(&query[..qlen], found_idx) {
                        found_idx = idx as isize;
                        cur_match_len = copy_history_entry(idx, &mut cur_match);
                    }
                    rendered = draw_rsearch(rendered, &query[..qlen], &cur_match[..cur_match_len]);
                }
            }
            // Another Ctrl+R — step to previous match for the same query.
            0x12 => {
                if found_idx > 0 {
                    if let Some(idx) = history_find_backward(&query[..qlen], found_idx - 1) {
                        found_idx = idx as isize;
                        cur_match_len = copy_history_entry(idx, &mut cur_match);
                        rendered = draw_rsearch(rendered, &query[..qlen], &cur_match[..cur_match_len]);
                    }
                }
            }
            // Printable — extend query, re-search from newest.
            0x20..=0x7E => {
                if qlen < query.len() {
                    query[qlen] = c;
                    qlen += 1;
                    found_idx = (history_count() as isize) - 1;
                    cur_match_len = 0;
                    if let Some(idx) = history_find_backward(&query[..qlen], found_idx) {
                        found_idx = idx as isize;
                        cur_match_len = copy_history_entry(idx, &mut cur_match);
                    }
                    rendered = draw_rsearch(rendered, &query[..qlen], &cur_match[..cur_match_len]);
                }
            }
            // Any control char other than R/Backspace/Enter/Esc cancels.
            _ => {
                erase_width(rendered);
                linux_write(1, orig[..orig_len].as_ptr(), orig_len);
                line_buf[..orig_len].copy_from_slice(&orig[..orig_len]);
                return orig_len;
            }
        }
    }
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
