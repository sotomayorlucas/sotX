use crate::syscall::*;
use crate::shell_trace;

// ---------------------------------------------------------------------------
// Exec: fork + execve
// ---------------------------------------------------------------------------

/// Buffer for passing exec path to child_exec_main.
pub static mut EXEC_NAME_BUF: [u8; 64] = [0u8; 64];
pub static mut EXEC_NAME_LEN: usize = 0;
/// Argv string storage (null-separated).
pub static mut EXEC_ARGV_STRS: [u8; 512] = [0u8; 512];
/// Argv pointer array (u64 pointers + NULL terminator).
pub static mut EXEC_ARGV_PTRS: [u64; 17] = [0u64; 17];
/// Envp string storage (null-separated).
pub static mut EXEC_ENVP_STRS: [u8; 512] = [0u8; 512];
/// Envp pointer array (u64 pointers + NULL terminator).
pub static mut EXEC_ENVP_PTRS: [u64; 17] = [0u64; 17];

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
    print(b"exec: failed (errno=");
    print_u64((-ret) as u64);
    print(b")\n");
    linux_exit(1);
}

/// Check if a word looks like VAR=value (contains '=' and starts with a letter/underscore).
fn is_env_assignment(word: &[u8]) -> bool {
    if word.is_empty() { return false; }
    // Must start with letter or underscore
    let c = word[0];
    if !((c >= b'A' && c <= b'Z') || (c >= b'a' && c <= b'z') || c == b'_') { return false; }
    // Must contain '=' before any space
    for i in 1..word.len() {
        if word[i] == b'=' { return true; }
        if word[i] == b' ' { return false; }
    }
    false
}

pub fn cmd_exec(line: &[u8]) {
    shell_trace!(Info, PROCESS, {
        crate::trace::trace_write(b"exec: ");
        crate::trace::trace_write(line);
    });

    // Parse leading VAR=value tokens, then command + arguments.
    // e.g., "HOME=/tmp PATH=/bin git init" -> envp=["HOME=/tmp","PATH=/bin"], prog="git", argv=["git","init"]
    let mut pos: usize = 0;

    unsafe {
        // Parse envp: leading VAR=value words
        let mut epos: usize = 0; // position in EXEC_ENVP_STRS
        let mut envc: usize = 0;
        loop {
            // Skip whitespace
            while pos < line.len() && line[pos] == b' ' { pos += 1; }
            if pos >= line.len() { break; }

            // Find end of this word
            let word_start = pos;
            while pos < line.len() && line[pos] != b' ' { pos += 1; }
            let word = &line[word_start..pos];

            if is_env_assignment(word) && envc < 16 {
                // Store as env var
                EXEC_ENVP_PTRS[envc] = EXEC_ENVP_STRS.as_ptr().add(epos) as u64;
                if epos + word.len() < 511 {
                    EXEC_ENVP_STRS[epos..epos + word.len()].copy_from_slice(word);
                    epos += word.len();
                    EXEC_ENVP_STRS[epos] = 0;
                    epos += 1;
                }
                envc += 1;
            } else {
                // Not an env assignment — this is the command. Rewind.
                pos = word_start;
                break;
            }
        }
        EXEC_ENVP_PTRS[envc] = 0; // NULL terminator

        // Remaining line is the actual command + args
        let cmd_line = &line[pos..];

        // Parse: first word = program name
        let mut prog_end = cmd_line.len();
        for i in 0..cmd_line.len() {
            if cmd_line[i] == b' ' { prog_end = i; break; }
        }
        let prog_name = &cmd_line[..prog_end];
        if prog_name.is_empty() {
            // Only env assignments, no command — nothing to exec
            return;
        }

        // Build path into EXEC_NAME_BUF: absolute paths pass through, relative get /bin/ prefix
        let is_absolute = prog_name[0] == b'/';
        let total = if is_absolute { prog_name.len() } else { 5 + prog_name.len() };
        if total >= 63 {
            print(b"exec: name too long\n");
            return;
        }
        if is_absolute {
            EXEC_NAME_BUF[..prog_name.len()].copy_from_slice(prog_name);
        } else {
            EXEC_NAME_BUF[..5].copy_from_slice(b"/bin/");
            EXEC_NAME_BUF[5..total].copy_from_slice(prog_name);
        }
        EXEC_NAME_BUF[total] = 0;
        EXEC_NAME_LEN = total;

        // Build argv: split remaining line on spaces
        let mut spos: usize = 0;
        let mut argc: usize = 0;

        // argv[0] = program name (what the binary sees as its own name)
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
                // Skip whitespace
                while i < args.len() && args[i] == b' ' { i += 1; }
                if i >= args.len() { break; }

                // Parse one argument, stripping quotes
                let arg_start = spos;
                EXEC_ARGV_PTRS[argc] = EXEC_ARGV_STRS.as_ptr().add(spos) as u64;

                if args[i] == b'\'' || args[i] == b'"' {
                    // Quoted argument: collect until matching close quote
                    let quote = args[i];
                    i += 1; // skip opening quote
                    while i < args.len() && args[i] != quote {
                        if spos < 511 {
                            EXEC_ARGV_STRS[spos] = args[i];
                            spos += 1;
                        }
                        i += 1;
                    }
                    if i < args.len() { i += 1; } // skip closing quote
                } else {
                    // Unquoted argument: collect until space
                    while i < args.len() && args[i] != b' ' {
                        if spos < 511 {
                            EXEC_ARGV_STRS[spos] = args[i];
                            spos += 1;
                        }
                        i += 1;
                    }
                }

                if spos == arg_start { continue; } // empty arg, skip
                EXEC_ARGV_STRS[spos] = 0;
                spos += 1;
                argc += 1;
            }
        }
        EXEC_ARGV_PTRS[argc] = 0; // NULL terminator
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
        return;
    }

    // Wait for child to complete
    let status = linux_waitpid(child_pid as u64);
    let _ = status;
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
