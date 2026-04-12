use crate::syscall::*;
use crate::util::*;
use crate::env::*;
use crate::builtins::*;
use crate::functions::*;
use crate::exec::cmd_exec;
use crate::net::cmd_wget;
use crate::lua::cmd_lua;
use crate::jobs::*;
use crate::history::cmd_history;
use crate::{err, usage, shell_trace};

// ---------------------------------------------------------------------------
// Last exit status ($?)
// ---------------------------------------------------------------------------

pub static mut LAST_EXIT_STATUS: i64 = 0;

pub fn set_exit_status(s: i64) { unsafe { LAST_EXIT_STATUS = s; } }
pub fn get_exit_status() -> i64 { unsafe { LAST_EXIT_STATUS } }

/// Canonical list of shell builtins, mirroring the dispatch table in
/// `dispatch_command`. Used by tab completion for command-name matching.
/// Keep sorted alphabetically so the completion list prints nicely.
pub const BUILTIN_NAMES: &[&[u8]] = &[
    b".", b"apt", b"bench", b"bg", b"break", b"caps", b"cat", b"cd",
    b"continue", b"curl", b"diff", b"echo", b"env", b"exec", b"exit",
    b"export", b"false", b"fg", b"fork", b"getpid", b"grep", b"head",
    b"help", b"hexdump", b"history", b"jobs", b"kill", b"ls", b"lua",
    b"meminfo", b"mkdir", b"netmirror", b"ping", b"pkg", b"ps", b"pwd",
    b"read", b"resolve", b"rm", b"rmdir", b"services", b"sleep", b"snap",
    b"snapshot", b"sort", b"source", b"stat", b"syslog", b"tail",
    b"threads", b"top", b"trace", b"traceroute", b"true", b"type",
    b"uname", b"uniq", b"unset", b"uptime", b"wc", b"wget", b"write",
];

// ---------------------------------------------------------------------------
// Redirect parsing and execution
// ---------------------------------------------------------------------------

pub struct Redirects {
    pub stdin_file: [u8; 64],
    pub stdin_file_len: usize,
    pub stdout_file: [u8; 64],
    pub stdout_file_len: usize,
    pub stdout_append: bool,
}

impl Redirects {
    pub const fn empty() -> Self {
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
pub fn parse_redirects<'a>(line: &'a [u8], redir: &mut Redirects, clean: &mut [u8; 256]) -> usize {
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
pub fn dispatch_with_redirects(line: &[u8]) {
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
            err!(b"redirect", b"cannot open input file:", &redir.stdin_file[..redir.stdin_file_len]);
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
            err!(b"redirect", b"cannot open output file:", &redir.stdout_file[..redir.stdout_file_len]);
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
// Semicolon command list: cmd1; cmd2; cmd3
// ---------------------------------------------------------------------------

/// Execute a semicolon-separated list of commands.
/// Each command goes through the full dispatch pipeline (&&/||, pipes, redirects).
pub fn execute_semicolon_list(line: &[u8]) {
    let mut remaining = line;
    while !remaining.is_empty() {
        let segment = match find_semicolon_unquoted(remaining) {
            Some(pos) => {
                let seg = trim(&remaining[..pos]);
                remaining = trim(&remaining[pos + 1..]);
                seg
            }
            None => {
                let seg = trim(remaining);
                remaining = b"";
                seg
            }
        };
        if segment.is_empty() { continue; }

        // Each segment gets full processing: &&/||, pipes, redirects
        if find_logical_op_unquoted(segment).is_some() {
            execute_logical_chain(segment);
        } else {
            dispatch_single_command(segment);
        }
    }
}

// ---------------------------------------------------------------------------
// Logical operators: && and ||
// ---------------------------------------------------------------------------

/// Execute a chain of commands connected by && and ||.
/// Left-to-right with equal precedence (standard shell behavior).
pub fn execute_logical_chain(line: &[u8]) {
    // Split into segments and operators: seg1 OP seg2 OP seg3 ...
    const MAX_SEGS: usize = 16;
    let mut seg_start: [usize; MAX_SEGS] = [0; MAX_SEGS];
    let mut seg_end: [usize; MAX_SEGS] = [0; MAX_SEGS];
    let mut seg_op_is_and: [bool; MAX_SEGS] = [false; MAX_SEGS]; // operator BEFORE this segment
    let mut seg_count: usize = 0;
    let mut remaining = line;

    // First segment has no preceding operator
    loop {
        match find_logical_op_unquoted(remaining) {
            Some((pos, is_and)) => {
                if seg_count < MAX_SEGS {
                    let base = remaining.as_ptr() as usize - line.as_ptr() as usize;
                    seg_start[seg_count] = base;
                    seg_end[seg_count] = base + pos;
                    seg_count += 1;
                    // The next segment's preceding operator
                    if seg_count < MAX_SEGS {
                        seg_op_is_and[seg_count] = is_and;
                    }
                }
                remaining = &remaining[pos + 2..];
            }
            None => {
                if seg_count < MAX_SEGS {
                    let base = remaining.as_ptr() as usize - line.as_ptr() as usize;
                    seg_start[seg_count] = base;
                    seg_end[seg_count] = base + remaining.len();
                    seg_count += 1;
                }
                break;
            }
        }
    }

    // Execute segments left-to-right
    for i in 0..seg_count {
        let seg = trim(&line[seg_start[i]..seg_end[i]]);
        if seg.is_empty() { continue; }

        if i == 0 {
            // Always execute first segment
            dispatch_single_command(seg);
        } else {
            let status = get_exit_status();
            if seg_op_is_and[i] {
                // && — only execute if previous succeeded
                if status == 0 {
                    dispatch_single_command(seg);
                }
            } else {
                // || — only execute if previous failed
                if status != 0 {
                    dispatch_single_command(seg);
                }
            }
        }
    }
}

/// Dispatch a single command segment (may contain pipes, redirects, etc.)
fn dispatch_single_command(segment: &[u8]) {
    // Check for pipes within this segment
    if let Some(pipe_pos) = find_pipe_unquoted(segment) {
        let left = trim(&segment[..pipe_pos]);
        let right = trim(&segment[pipe_pos + 1..]);
        if !left.is_empty() && !right.is_empty() {
            execute_pipe(left, right);
            return;
        }
    }
    dispatch_with_redirects(segment);
}

// ---------------------------------------------------------------------------
// Here-document support
// ---------------------------------------------------------------------------

pub fn execute_heredoc(cmd: &[u8], delim: &[u8], line_buf: &mut [u8; 512]) {
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
pub fn dispatch_command_with_stdin(cmd: &[u8], stdin_data: &[u8]) {
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
// Pipe execution
// ---------------------------------------------------------------------------

/// Execute a pipe: capture output of left command, feed as input to right command.
pub fn execute_pipe(left: &[u8], right: &[u8]) {
    shell_trace!(Debug, PROCESS, {
        crate::trace::trace_write(b"pipe: ");
        crate::trace::trace_write(left);
        crate::trace::trace_write(b" | ");
        crate::trace::trace_write(right);
    });
    if starts_with(right, b"grep ") {
        let pattern = trim(&right[5..]);
        let mut capture = [0u8; 4096];
        let cap_len = capture_command(left, &mut capture);
        if cap_len > 0 {
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

// ---------------------------------------------------------------------------
// Multi-line block accumulation
// ---------------------------------------------------------------------------

/// Check if a control block is complete (has its closing keyword).
fn block_is_complete(line: &[u8]) -> bool {
    if starts_with(line, b"if ") {
        return find_substr(line, b"fi").is_some();
    }
    if starts_with(line, b"for ") || starts_with(line, b"while ") || starts_with(line, b"until ") {
        return find_substr(line, b"done").is_some();
    }
    true
}

/// If the line starts a control block but is incomplete, accumulate additional lines
/// from stdin until the closing keyword is found. Returns the complete block in buf.
/// Lines are joined with "; " separators to match the single-line parser format.
pub fn accumulate_block(first_line: &[u8], line_buf: &mut [u8; 512], buf: &mut [u8; 2048]) -> usize {
    let mut pos = first_line.len().min(buf.len() - 1);
    buf[..pos].copy_from_slice(&first_line[..pos]);

    if block_is_complete(&buf[..pos]) {
        return pos;
    }

    // Need more lines
    loop {
        print(b"> ");
        let n = read_simple_line(line_buf);
        let input_line = trim(&line_buf[..n]);
        if input_line.is_empty() { continue; }

        // Append "; " separator and the new line
        if pos + 2 + input_line.len() < buf.len() {
            buf[pos] = b';';
            buf[pos + 1] = b' ';
            pos += 2;
            buf[pos..pos + input_line.len()].copy_from_slice(input_line);
            pos += input_line.len();
        }

        // Check if block is now complete
        if block_is_complete(&buf[..pos]) {
            break;
        }
    }
    pos
}

// ---------------------------------------------------------------------------
// Shell scripting: if/then/fi and for/do/done
// ---------------------------------------------------------------------------

/// Basic if/then/fi scripting.
/// Format: if CONDITION; then COMMAND; fi
pub fn execute_if_block(line: &[u8], _line_buf: &mut [u8; 512]) {
    let after_if = trim(&line[3..]);
    let then_pos = find_substr(after_if, b"; then ");
    if then_pos.is_none() { err!(b"if", b"syntax error: expected '; then'"); return; }
    let then_pos = then_pos.unwrap();
    let condition = trim(&after_if[..then_pos]);
    let after_then = &after_if[then_pos + 7..];
    let fi_pos = find_substr(after_then, b"; fi");
    if fi_pos.is_none() { err!(b"if", b"syntax error: expected '; fi'"); return; }
    let fi_pos = fi_pos.unwrap();
    let command = trim(&after_then[..fi_pos]);

    if evaluate_condition(condition) {
        dispatch_command(command);
    }
}

/// Basic for loop.
/// Format: for VAR in A B C; do CMD; done
pub fn execute_for_block(line: &[u8], _line_buf: &mut [u8; 512]) {
    let after_for = trim(&line[4..]);
    if let Some(in_pos) = find_substr(after_for, b" in ") {
        let var_name = trim(&after_for[..in_pos]);
        let after_in = &after_for[in_pos + 4..];
        if let Some(do_pos) = find_substr(after_in, b"; do ") {
            let raw_items = trim(&after_in[..do_pos]);
            // Expand the items list once (for things like: for x in $LIST)
            let mut items_exp = [0u8; 512];
            let items_len = expand_vars(raw_items, &mut items_exp);
            let items_str = trim(&items_exp[..items_len]);
            let after_do = &after_in[do_pos + 5..];
            if let Some(done_pos) = find_substr(after_do, b"; done") {
                let command_template = trim(&after_do[..done_pos]);
                let mut pos = 0;
                while pos < items_str.len() {
                    while pos < items_str.len() && items_str[pos] == b' ' { pos += 1; }
                    let start = pos;
                    while pos < items_str.len() && items_str[pos] != b' ' { pos += 1; }
                    if start < pos {
                        let item = &items_str[start..pos];
                        env_set(var_name, item);
                        let mut cmd_buf = [0u8; 512];
                        let cmd_len = expand_vars(command_template, &mut cmd_buf);
                        execute_body_commands(trim(&cmd_buf[..cmd_len]));
                        if get_loop_break() { set_loop_break(false); return; }
                        if get_loop_continue() { set_loop_continue(false); }
                    }
                }
                return;
            }
        }
    }
    usage!(b"for", b"for VAR in ITEMS; do CMD; done");
}

// ---------------------------------------------------------------------------
// Loop control: break / continue
// ---------------------------------------------------------------------------

pub static mut LOOP_BREAK: bool = false;
pub static mut LOOP_CONTINUE: bool = false;

pub fn get_loop_break() -> bool { unsafe { LOOP_BREAK } }
pub fn set_loop_break(v: bool) { unsafe { LOOP_BREAK = v; } }
pub fn get_loop_continue() -> bool { unsafe { LOOP_CONTINUE } }
pub fn set_loop_continue(v: bool) { unsafe { LOOP_CONTINUE = v; } }

/// while CONDITION; do CMD1; CMD2; ...; done
pub fn execute_while_block(line: &[u8], _line_buf: &mut [u8; 512]) {
    execute_while_inner(line, false);
}

/// until CONDITION; do CMD1; CMD2; ...; done
pub fn execute_until_block(line: &[u8], _line_buf: &mut [u8; 512]) {
    execute_while_inner(line, true);
}

fn execute_while_inner(line: &[u8], invert: bool) {
    // Parse: "while COND; do BODY; done" or "until COND; do BODY; done"
    let keyword_len = if invert { 6 } else { 6 }; // "while " or "until " = 6
    let after_kw = trim(&line[keyword_len..]);

    let do_pos = match find_substr(after_kw, b"; do ") {
        Some(p) => p,
        None => {
            // Also try "; do\n" or just "; do;" pattern
            match find_substr(after_kw, b";do ") {
                Some(p) => p,
                None => {
                    let cmd: &[u8] = if invert { b"until" } else { b"while" };
                    err!(cmd, b"syntax error: expected '; do'");
                    return;
                }
            }
        }
    };
    let condition = trim(&after_kw[..do_pos]);
    let after_do = &after_kw[do_pos + 4..]; // skip "; do "

    let done_pos = match find_substr(after_do, b"; done") {
        Some(p) => p,
        None => {
            match find_substr(after_do, b";done") {
                Some(p) => p,
                None => {
                    let cmd: &[u8] = if invert { b"until" } else { b"while" };
                    err!(cmd, b"syntax error: expected '; done'");
                    return;
                }
            }
        }
    };
    let body = trim(&after_do[..done_pos]);

    // Copy condition and body templates (unexpanded) for re-expansion each iteration
    let mut cond_template = [0u8; 256];
    let cl = condition.len().min(255);
    cond_template[..cl].copy_from_slice(&condition[..cl]);
    let mut body_template = [0u8; 1024];
    let bl = body.len().min(1023);
    body_template[..bl].copy_from_slice(&body[..bl]);

    // Execute loop
    let mut iterations: usize = 0;
    const MAX_ITERATIONS: usize = 10000;

    loop {
        if iterations >= MAX_ITERATIONS {
            let cmd: &[u8] = if invert { b"until" } else { b"while" };
            err!(cmd, b"max iterations reached");
            break;
        }
        iterations += 1;

        // Re-expand condition variables each iteration
        let mut cond_exp = [0u8; 256];
        let cond_len = expand_vars(&cond_template[..cl], &mut cond_exp);
        let cond_result = evaluate_condition(trim(&cond_exp[..cond_len]));
        let should_run = if invert { !cond_result } else { cond_result };
        if !should_run { break; }

        // Re-expand body variables each iteration
        let mut body_exp = [0u8; 1024];
        let body_len = expand_vars(&body_template[..bl], &mut body_exp);
        execute_body_commands(trim(&body_exp[..body_len]));

        if get_loop_break() {
            set_loop_break(false);
            break;
        }
        if get_loop_continue() {
            set_loop_continue(false);
        }
    }
}

/// Execute a semicolon-separated list of commands (loop/function body).
fn execute_body_commands(body: &[u8]) {
    let mut pos: usize = 0;
    while pos < body.len() {
        // Find next "; " separator
        let start = pos;
        while pos < body.len() {
            if body[pos] == b';' && pos + 1 < body.len() && body[pos + 1] == b' ' {
                break;
            }
            pos += 1;
        }
        let cmd = trim(&body[start..pos]);
        if !cmd.is_empty() {
            dispatch_or_call_func(cmd);
            if get_loop_break() || get_loop_continue() { return; }
        }
        if pos < body.len() { pos += 2; } // skip "; "
    }
}

fn evaluate_condition(cond: &[u8]) -> bool {
    // Support [ ... ] as alias for test ...
    let test_expr = if cond.len() >= 2 && cond[0] == b'[' && cond[cond.len() - 1] == b']' {
        trim(&cond[1..cond.len() - 1])
    } else if starts_with(cond, b"test ") {
        trim(&cond[5..])
    } else {
        return false;
    };

    // Negation: ! EXPR
    if starts_with(test_expr, b"! ") {
        return !evaluate_test_expr(trim(&test_expr[2..]));
    }
    evaluate_test_expr(test_expr)
}

fn evaluate_test_expr(expr: &[u8]) -> bool {
    // Unary file tests
    if starts_with(expr, b"-f ") {
        let name = trim(&expr[3..]);
        let mut path_buf = [0u8; 64];
        let path = null_terminate(name, &mut path_buf);
        let mut stat_buf = [0u8; 144];
        return linux_stat(path, stat_buf.as_mut_ptr()) >= 0;
    }
    if starts_with(expr, b"-d ") {
        let name = trim(&expr[3..]);
        let mut path_buf = [0u8; 64];
        let path = null_terminate(name, &mut path_buf);
        let mut stat_buf = [0u8; 144];
        if linux_stat(path, stat_buf.as_mut_ptr()) < 0 { return false; }
        let mode = u32::from_le_bytes([stat_buf[24], stat_buf[25], stat_buf[26], stat_buf[27]]);
        return mode & 0o170000 == 0o40000;
    }
    if starts_with(expr, b"-e ") {
        let name = trim(&expr[3..]);
        let mut path_buf = [0u8; 64];
        let path = null_terminate(name, &mut path_buf);
        let mut stat_buf = [0u8; 144];
        return linux_stat(path, stat_buf.as_mut_ptr()) >= 0;
    }
    // -n STR — string is non-empty
    if starts_with(expr, b"-n ") {
        return !trim(&expr[3..]).is_empty();
    }
    // -z STR — string is empty
    if starts_with(expr, b"-z ") {
        return trim(&expr[3..]).is_empty();
    }
    // Binary operators: find the operator
    // String: = !=
    if let Some(pos) = find_substr(expr, b" != ") {
        let left = trim(&expr[..pos]);
        let right = trim(&expr[pos + 4..]);
        return !eq(left, right);
    }
    if let Some(pos) = find_substr(expr, b" = ") {
        let left = trim(&expr[..pos]);
        let right = trim(&expr[pos + 3..]);
        return eq(left, right);
    }
    // Integer: -eq -ne -gt -lt -ge -le
    if let Some(pos) = find_substr(expr, b" -eq ") {
        let a = parse_i64(trim(&expr[..pos]));
        let b = parse_i64(trim(&expr[pos + 5..]));
        return a == b;
    }
    if let Some(pos) = find_substr(expr, b" -ne ") {
        let a = parse_i64(trim(&expr[..pos]));
        let b = parse_i64(trim(&expr[pos + 5..]));
        return a != b;
    }
    if let Some(pos) = find_substr(expr, b" -gt ") {
        let a = parse_i64(trim(&expr[..pos]));
        let b = parse_i64(trim(&expr[pos + 5..]));
        return a > b;
    }
    if let Some(pos) = find_substr(expr, b" -lt ") {
        let a = parse_i64(trim(&expr[..pos]));
        let b = parse_i64(trim(&expr[pos + 5..]));
        return a < b;
    }
    if let Some(pos) = find_substr(expr, b" -ge ") {
        let a = parse_i64(trim(&expr[..pos]));
        let b = parse_i64(trim(&expr[pos + 5..]));
        return a >= b;
    }
    if let Some(pos) = find_substr(expr, b" -le ") {
        let a = parse_i64(trim(&expr[..pos]));
        let b = parse_i64(trim(&expr[pos + 5..]));
        return a <= b;
    }
    // Bare string — true if non-empty
    !expr.is_empty()
}

/// Parse an i64 from byte slice (handles negative numbers).
fn parse_i64(s: &[u8]) -> i64 {
    if s.is_empty() { return 0; }
    let (neg, start) = if s[0] == b'-' { (true, 1) } else { (false, 0) };
    let val = parse_u64_simple(&s[start..]) as i64;
    if neg { -val } else { val }
}

// ---------------------------------------------------------------------------
// Command dispatch
// ---------------------------------------------------------------------------

/// Dispatch a command, trying functions first, then builtins.
pub fn dispatch_or_call_func(line: &[u8]) {
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

pub fn dispatch_command(line: &[u8]) {
        shell_trace!(Trace, SYSCALL, {
            crate::trace::trace_write(b"dispatch: ");
            crate::trace::trace_write(line);
        });

        // Default: command succeeds. Builtins that fail override this.
        set_exit_status(0);

        // Intercept `<cmd> --help` before running the real handler.
        if let Some(sp) = find_space(line) {
            let args_tail = trim(&line[sp + 1..]);
            if crate::help::is_help_flag(args_tail) {
                crate::help::print_command_doc(&line[..sp]);
                return;
            }
        }

        // --- Command dispatch ---
        if eq(line, b"help") {
            crate::help::print_all_categorized();
        } else if starts_with(line, b"help ") {
            let topic = trim(&line[5..]);
            crate::help::print_command_doc(topic);
        } else if eq(line, b"man") {
            print(b"usage: man <command>\n");
        } else if starts_with(line, b"man ") {
            let topic = trim(&line[4..]);
            crate::help::print_command_doc(topic);
        } else if eq(line, b"uname") {
            print(b"sotOS 0.1.0 x86_64 LUCAS\n");
        } else if eq(line, b"uptime") {
            cmd_uptime();
        } else if eq(line, b"ps") {
            cmd_ps();
        } else if starts_with(line, b"kill ") {
            let args = trim(&line[5..]);
            if args.is_empty() {
                usage!(b"kill", b"kill <pid> [signal]");
            } else {
                cmd_kill(args);
            }
        } else if eq(line, b"caps") {
            cmd_caps();
        } else if eq(line, b"services") {
            cmd_services();
        } else if eq(line, b"threads") {
            cmd_threads();
        } else if eq(line, b"meminfo") {
            cmd_meminfo();
        } else if eq(line, b"bench") {
            cmd_bench();
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
                usage!(b"cat", b"cat <file>");
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
                    usage!(b"write", b"write <file> <text>");
                }
            }
        } else if starts_with(line, b"rm ") {
            let name = trim(&line[3..]);
            if name.is_empty() {
                usage!(b"rm", b"rm <file>");
            } else {
                cmd_rm(name);
            }
        } else if starts_with(line, b"stat ") {
            let name = trim(&line[5..]);
            if name.is_empty() {
                usage!(b"stat", b"stat <file>");
            } else {
                cmd_stat(name);
            }
        } else if eq(line, b"stat") {
            cmd_stat(b".");
        } else if starts_with(line, b"hexdump ") {
            let name = trim(&line[8..]);
            if name.is_empty() {
                usage!(b"hexdump", b"hexdump <file>");
            } else {
                cmd_hexdump(name);
            }
        } else if starts_with(line, b"mkdir ") {
            let name = trim(&line[6..]);
            if name.is_empty() {
                usage!(b"mkdir", b"mkdir <dir>");
            } else {
                cmd_mkdir(name);
            }
        } else if starts_with(line, b"rmdir ") {
            let name = trim(&line[6..]);
            if name.is_empty() {
                usage!(b"rmdir", b"rmdir <dir>");
            } else {
                cmd_rmdir(name);
            }
        } else if starts_with(line, b"cd ") {
            let name = trim(&line[3..]);
            if name.is_empty() {
                usage!(b"cd", b"cd <dir>");
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
                usage!(b"exec", b"exec <program>");
            } else {
                cmd_exec(name);
            }
        } else if starts_with(line, b"resolve ") {
            let name = trim(&line[8..]);
            if name.is_empty() {
                usage!(b"resolve", b"resolve <hostname>");
            } else {
                crate::net::cmd_resolve(name);
            }
        } else if eq(line, b"ping") {
            usage!(b"ping", b"ping <host|ip>");
        } else if starts_with(line, b"ping ") {
            let host = trim(&line[5..]);
            if host.is_empty() {
                usage!(b"ping", b"ping <host|ip>");
            } else {
                crate::net::cmd_ping(host);
            }
        } else if eq(line, b"traceroute") {
            usage!(b"traceroute", b"traceroute <host|ip>");
        } else if starts_with(line, b"traceroute ") {
            let host = trim(&line[11..]);
            if host.is_empty() {
                usage!(b"traceroute", b"traceroute <host|ip>");
            } else {
                crate::net::cmd_traceroute(host);
            }
        } else if eq(line, b"wget") || eq(line, b"curl") {
            usage!(b"wget", b"wget [-O file] [-q] <url>");
        } else if starts_with(line, b"curl ") {
            let args = trim(&line[5..]);
            if args.is_empty() {
                usage!(b"curl", b"wget [-O file] [-q] <url>");
            } else {
                cmd_wget(args);
            }
        } else if starts_with(line, b"wget ") {
            let args = trim(&line[5..]);
            if args.is_empty() {
                usage!(b"wget", b"wget [-O file] [-q] <url>");
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
                usage!(b"export", b"export KEY=VALUE");
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
            usage!(b"sort", b"sort <file>");
        } else if starts_with(line, b"uniq ") {
            let name = trim(&line[5..]);
            cmd_uniq(name);
        } else if eq(line, b"uniq") {
            usage!(b"uniq", b"uniq <file>");
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
            usage!(b"netmirror", b"netmirror on|off");
        } else if starts_with(line, b"snapshot ") {
            let arg = trim(&line[9..]);
            cmd_snap(arg);
        } else if eq(line, b"snapshot") {
            cmd_snap(b"list");
        } else if starts_with(line, b"lua ") {
            let code = trim(&line[4..]);
            cmd_lua(code);
        } else if eq(line, b"lua") {
            usage!(b"lua", b"lua <code>  (example: lua print(1+2))");
        } else if starts_with(line, b"apt ") {
            let args = trim(&line[4..]);
            cmd_apt(args);
        } else if eq(line, b"apt") {
            cmd_apt(b"help");
        } else if starts_with(line, b"pkg ") {
            let args = trim(&line[4..]);
            cmd_pkg(args);
        } else if eq(line, b"pkg") {
            cmd_pkg(b"help");
        } else if starts_with(line, b"source ") {
            let name = trim(&line[7..]);
            if name.is_empty() { usage!(b"source", b"source <file>"); }
            else { cmd_source(name); }
        } else if starts_with(line, b". ") {
            let name = trim(&line[2..]);
            if name.is_empty() { usage!(b".", b". <file>"); }
            else { cmd_source(name); }
        } else if starts_with(line, b"read ") {
            let args = trim(&line[5..]);
            cmd_read(args);
        } else if eq(line, b"read") {
            cmd_read(b"");
        } else if eq(line, b"true") {
            set_exit_status(0);
        } else if eq(line, b"false") {
            set_exit_status(1);
        } else if starts_with(line, b"sleep ") {
            let arg = trim(&line[6..]);
            cmd_sleep(arg);
        } else if eq(line, b"sleep") {
            usage!(b"sleep", b"sleep <seconds>");
        } else if starts_with(line, b"type ") {
            let name = trim(&line[5..]);
            cmd_type(name);
        } else if eq(line, b"break") {
            set_loop_break(true);
        } else if eq(line, b"continue") {
            set_loop_continue(true);
        } else if eq(line, b"exit") {
            print(b"bye!\n");
            linux_exit(0);
        } else if starts_with(line, b"trace ") {
            let args = trim(&line[6..]);
            cmd_trace(args);
        } else if eq(line, b"trace") {
            cmd_trace(b"status");
        } else {
            // Try auto-exec: treat first word as initrd binary name
            cmd_exec(line);
        }
}
