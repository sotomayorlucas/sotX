use crate::syscall::*;
use crate::env::env_slice;
use crate::shell_trace;

// ---------------------------------------------------------------------------
// Exec: fork + execve
// ---------------------------------------------------------------------------

/// Buffer for passing exec path to child_exec_main.
pub static mut EXEC_NAME_BUF: [u8; 128] = [0u8; 128];
pub static mut EXEC_NAME_LEN: usize = 0;
/// Argv string storage (null-separated).
pub static mut EXEC_ARGV_STRS: [u8; 1024] = [0u8; 1024];
/// Argv pointer array (u64 pointers + NULL terminator).
pub static mut EXEC_ARGV_PTRS: [u64; 17] = [0u64; 17];
/// Envp string storage (null-separated).
pub static mut EXEC_ENVP_STRS: [u8; 2048] = [0u8; 2048];
/// Envp pointer array (u64 pointers + NULL terminator).
pub static mut EXEC_ENVP_PTRS: [u64; 33] = [0u64; 33];

/// Child function that immediately calls execve with the name in EXEC_NAME_BUF.
pub extern "C" fn child_exec_main() -> ! {
    let name = unsafe { &EXEC_NAME_BUF[..EXEC_NAME_LEN + 1] }; // includes NUL
    let argv = unsafe { EXEC_ARGV_PTRS.as_ptr() };
    let envp = unsafe { EXEC_ENVP_PTRS.as_ptr() };
    let ret = linux_execve(name.as_ptr(), argv, envp);
    // execve failed — print error and exit
    shell_trace!(Error, PROCESS, {
        crate::trace::trace_write(b"execve failed errno=");
        crate::trace::trace_write_u64((-ret) as u64);
    });
    print(b"exec: not found\n");
    linux_exit(127);
}

/// Check if a word looks like VAR=value (contains '=' and starts with a letter/underscore).
fn is_env_assignment(word: &[u8]) -> bool {
    if word.is_empty() { return false; }
    let c = word[0];
    if !((c >= b'A' && c <= b'Z') || (c >= b'a' && c <= b'z') || c == b'_') { return false; }
    for i in 1..word.len() {
        if word[i] == b'=' { return true; }
        if word[i] == b' ' { return false; }
    }
    false
}

/// Try to stat a path. Returns true if file exists.
fn file_exists(path: &[u8]) -> bool {
    let mut buf = [0u8; 130];
    let len = path.len().min(128);
    buf[..len].copy_from_slice(&path[..len]);
    buf[len] = 0;
    let mut stat_buf = [0u8; 144];
    linux_stat(buf.as_ptr(), stat_buf.as_mut_ptr()) >= 0
}

/// Resolve a command name to a full path using $PATH.
/// Returns the length written to out_buf, or 0 if not found.
pub fn resolve_command(name: &[u8], out_buf: &mut [u8; 128]) -> usize {
    // Absolute or relative path → use as-is
    if !name.is_empty() && (name[0] == b'/' || name[0] == b'.') {
        let len = name.len().min(127);
        out_buf[..len].copy_from_slice(&name[..len]);
        out_buf[len] = 0;
        return len;
    }

    // Search $PATH directories
    let default_path = b"/bin:/usr/bin:/sbin:/usr/sbin" as &[u8];
    let path_val = crate::env::env_get(b"PATH").unwrap_or(default_path);

    let mut pos = 0;
    while pos <= path_val.len() {
        // Extract next directory from colon-separated PATH
        let start = pos;
        while pos < path_val.len() && path_val[pos] != b':' { pos += 1; }
        let dir = &path_val[start..pos];
        pos += 1; // skip ':'

        if dir.is_empty() { continue; }

        // Build candidate: dir/name
        let total = dir.len() + 1 + name.len();
        if total >= 127 { continue; }

        out_buf[..dir.len()].copy_from_slice(dir);
        out_buf[dir.len()] = b'/';
        out_buf[dir.len() + 1..dir.len() + 1 + name.len()].copy_from_slice(name);
        out_buf[total] = 0;

        if file_exists(&out_buf[..total]) {
            return total;
        }
    }

    // Fallback: try /bin/name (for initrd binaries that may not stat but can exec)
    let total = 5 + name.len();
    if total < 127 {
        out_buf[..5].copy_from_slice(b"/bin/");
        out_buf[5..5 + name.len()].copy_from_slice(name);
        out_buf[total] = 0;
        return total;
    }

    0
}

/// Build envp from shell environment + inline overrides.
/// Inline overrides (VAR=val from command line) take priority.
unsafe fn build_envp(_inline_strs: &[u8], inline_count: usize, inline_ptrs: &[u64]) {
    let mut epos: usize = 0;
    let mut envc: usize = 0;

    // First, add shell environment variables
    for e in env_slice() {
        if !e.active || envc >= 32 { continue; }

        // Skip if this key is overridden by inline env
        let mut overridden = false;
        for oi in 0..inline_count {
            let optr = inline_ptrs[oi] as *const u8;
            // Find '=' in the inline var
            let mut ok = 0;
            while ok < 128 {
                let ch = *optr.add(ok);
                if ch == b'=' || ch == 0 { break; }
                ok += 1;
            }
            if ok == e.key_len {
                let mut matches = true;
                for ki in 0..ok {
                    if *optr.add(ki) != e.key[ki] { matches = false; break; }
                }
                if matches { overridden = true; break; }
            }
        }
        if overridden { continue; }

        // Format: KEY=VALUE\0
        let entry_len = e.key_len + 1 + e.val_len;
        if epos + entry_len + 1 >= EXEC_ENVP_STRS.len() { break; }

        EXEC_ENVP_PTRS[envc] = EXEC_ENVP_STRS.as_ptr().add(epos) as u64;
        EXEC_ENVP_STRS[epos..epos + e.key_len].copy_from_slice(&e.key[..e.key_len]);
        epos += e.key_len;
        EXEC_ENVP_STRS[epos] = b'=';
        epos += 1;
        EXEC_ENVP_STRS[epos..epos + e.val_len].copy_from_slice(&e.val[..e.val_len]);
        epos += e.val_len;
        EXEC_ENVP_STRS[epos] = 0;
        epos += 1;
        envc += 1;
    }

    // Then add inline overrides
    for oi in 0..inline_count {
        if envc >= 32 { break; }
        // Copy from inline storage: find length of the null-terminated string
        let src = inline_ptrs[oi] as *const u8;
        let mut slen = 0;
        while slen < 256 && *src.add(slen) != 0 { slen += 1; }
        if epos + slen + 1 >= EXEC_ENVP_STRS.len() { break; }

        EXEC_ENVP_PTRS[envc] = EXEC_ENVP_STRS.as_ptr().add(epos) as u64;
        for si in 0..slen {
            EXEC_ENVP_STRS[epos + si] = *src.add(si);
        }
        epos += slen;
        EXEC_ENVP_STRS[epos] = 0;
        epos += 1;
        envc += 1;
    }

    EXEC_ENVP_PTRS[envc] = 0; // NULL terminator
}

pub fn cmd_exec(line: &[u8]) {
    shell_trace!(Info, PROCESS, {
        crate::trace::trace_write(b"exec: ");
        crate::trace::trace_write(line);
    });

    let mut pos: usize = 0;

    unsafe {
        // Parse inline envp: leading VAR=value words (stored temporarily)
        let mut inline_strs = [0u8; 512];
        let mut inline_ptrs = [0u64; 16];
        let mut inline_pos: usize = 0;
        let mut inline_count: usize = 0;

        loop {
            while pos < line.len() && line[pos] == b' ' { pos += 1; }
            if pos >= line.len() { break; }

            let word_start = pos;
            while pos < line.len() && line[pos] != b' ' { pos += 1; }
            let word = &line[word_start..pos];

            if is_env_assignment(word) && inline_count < 16 {
                inline_ptrs[inline_count] = inline_strs.as_ptr().add(inline_pos) as u64;
                if inline_pos + word.len() < 511 {
                    inline_strs[inline_pos..inline_pos + word.len()].copy_from_slice(word);
                    inline_pos += word.len();
                    inline_strs[inline_pos] = 0;
                    inline_pos += 1;
                }
                inline_count += 1;
            } else {
                pos = word_start;
                break;
            }
        }

        // Build full envp: shell env + inline overrides
        build_envp(&inline_strs, inline_count, &inline_ptrs);

        // Remaining line is the actual command + args
        let cmd_line = &line[pos..];

        // Parse: first word = program name
        let mut prog_end = cmd_line.len();
        for i in 0..cmd_line.len() {
            if cmd_line[i] == b' ' { prog_end = i; break; }
        }
        let prog_name = &cmd_line[..prog_end];
        if prog_name.is_empty() {
            return;
        }

        // Resolve command via PATH
        let resolved_len = resolve_command(prog_name, &mut EXEC_NAME_BUF);
        if resolved_len == 0 {
            print(prog_name);
            print(b": command not found\n");
            crate::parse::set_exit_status(127);
            return;
        }
        EXEC_NAME_LEN = resolved_len;

        // Build argv
        let mut spos: usize = 0;
        let mut argc: usize = 0;

        // argv[0] = program name (as user typed it)
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
                while i < args.len() && args[i] == b' ' { i += 1; }
                if i >= args.len() { break; }

                let arg_start = spos;
                EXEC_ARGV_PTRS[argc] = EXEC_ARGV_STRS.as_ptr().add(spos) as u64;

                if args[i] == b'\'' || args[i] == b'"' {
                    let quote = args[i];
                    i += 1;
                    while i < args.len() && args[i] != quote {
                        if spos < 1023 {
                            EXEC_ARGV_STRS[spos] = args[i];
                            spos += 1;
                        }
                        i += 1;
                    }
                    if i < args.len() { i += 1; }
                } else {
                    while i < args.len() && args[i] != b' ' {
                        if spos < 1023 {
                            EXEC_ARGV_STRS[spos] = args[i];
                            spos += 1;
                        }
                        i += 1;
                    }
                }

                if spos == arg_start { continue; }
                EXEC_ARGV_STRS[spos] = 0;
                spos += 1;
                argc += 1;
            }
        }
        EXEC_ARGV_PTRS[argc] = 0;
    }

    // Fork child, which immediately does execve
    shell_trace!(Debug, PROCESS, {
        crate::trace::trace_write(b"fork for exec");
    });
    let child_pid = linux_clone(child_exec_main as *const () as u64);
    if child_pid < 0 {
        shell_trace!(Error, PROCESS, {
            crate::trace::trace_write(b"fork failed");
        });
        print(b"exec: fork failed\n");
        crate::parse::set_exit_status(1);
        return;
    }

    // Wait for child to complete and capture exit status
    let mut wstatus: u32 = 0;
    let ret = linux_waitpid_status(child_pid as u64, &mut wstatus as *mut u32, 0);
    if ret > 0 {
        let exit_code = ((wstatus >> 8) & 0xFF) as i64;
        crate::parse::set_exit_status(exit_code);
    } else {
        crate::parse::set_exit_status(1);
    }
}

/// Child shell main — used for fork and background jobs.
#[unsafe(no_mangle)]
pub extern "C" fn child_shell_main() -> ! {
    let pid = linux_getpid();
    print(b"[child shell pid=");
    print_u64(pid as u64);
    print(b"]\n");
    crate::shell_loop();
    linux_exit(0);
}
