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
use crate::shell_trace;

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

pub fn execute_heredoc(cmd: &[u8], delim: &[u8], line_buf: &mut [u8; 256]) {
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
// Shell scripting: if/then/fi and for/do/done
// ---------------------------------------------------------------------------

/// Basic if/then/fi scripting.
/// Format: if CONDITION; then COMMAND; fi
pub fn execute_if_block(line: &[u8], _line_buf: &mut [u8; 256]) {
    let after_if = trim(&line[3..]);
    let then_pos = find_substr(after_if, b"; then ");
    if then_pos.is_none() { print(b"syntax error: expected '; then'\n"); return; }
    let then_pos = then_pos.unwrap();
    let condition = trim(&after_if[..then_pos]);
    let after_then = &after_if[then_pos + 7..];
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
pub fn execute_for_block(line: &[u8], _line_buf: &mut [u8; 256]) {
    let after_for = trim(&line[4..]);
    if let Some(in_pos) = find_substr(after_for, b" in ") {
        let var_name = trim(&after_for[..in_pos]);
        let after_in = &after_for[in_pos + 4..];
        if let Some(do_pos) = find_substr(after_in, b"; do ") {
            let items_str = trim(&after_in[..do_pos]);
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
                crate::net::cmd_resolve(name);
            }
        } else if eq(line, b"ping") {
            print(b"usage: ping <host|ip>\n");
        } else if starts_with(line, b"ping ") {
            let host = trim(&line[5..]);
            if host.is_empty() {
                print(b"usage: ping <host|ip>\n");
            } else {
                crate::net::cmd_ping(host);
            }
        } else if eq(line, b"traceroute") {
            print(b"usage: traceroute <host|ip>\n");
        } else if starts_with(line, b"traceroute ") {
            let host = trim(&line[11..]);
            if host.is_empty() {
                print(b"usage: traceroute <host|ip>\n");
            } else {
                crate::net::cmd_traceroute(host);
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
