#![no_std]
#![no_main]

pub mod syscall;
pub mod util;
pub mod env;
pub mod jobs;
pub mod history;
pub mod functions;
pub mod line;
pub mod parse;
pub mod builtins;
pub mod exec;
pub mod net;
pub mod lua;
pub mod trace;

use syscall::*;
use util::*;
use env::env_set;
use jobs::*;
use history::{history_add, load_from_vfs};
use functions::*;
use line::read_line;
use parse::*;

// ---------------------------------------------------------------------------
// Stack canary support
// ---------------------------------------------------------------------------

#[used]
#[no_mangle]
static mut __stack_chk_guard: u64 = 0x00000aff0a0d0000;

#[no_mangle]
pub extern "C" fn __stack_chk_fail() -> ! {
    let msg = b"!!! STACK SMASH DETECTED (shell) !!!\n";
    linux_write(1, msg.as_ptr(), msg.len());
    linux_exit(137);
}

// ---------------------------------------------------------------------------
// Shell main loop
// ---------------------------------------------------------------------------

pub fn shell_loop() {
    let mut line_buf = [0u8; 512];

    // Set default env vars.
    env_set(b"SHELL", b"lucas");
    env_set(b"OS", b"sotOS");
    env_set(b"VERSION", b"0.1.0");
    env_set(b"PATH", b"/bin:/usr/bin:/sbin:/usr/sbin");
    env_set(b"HOME", b"/root");
    env_set(b"TERM", b"xterm");
    env_set(b"USER", b"root");

    loop {
        // Reap finished background jobs
        reap_done_jobs();

        // Prompt
        print(b"$ ");

        // Read line with history navigation and tab completion
        let pos = read_line(&mut line_buf);

        // Copy raw line into its own buffer to avoid borrow conflicts
        let mut raw_copy = [0u8; 512];
        let raw_trimmed = trim(&line_buf[..pos]);
        if raw_trimmed.is_empty() {
            continue;
        }
        let raw_len = raw_trimmed.len();
        raw_copy[..raw_len].copy_from_slice(raw_trimmed);
        let raw_line = &raw_copy[..raw_len];

        // Add to history
        history_add(raw_line);

        // Check for function definition: "function NAME() {"
        if starts_with(raw_line, b"function ") {
            read_function_def(raw_line, &mut line_buf);
            continue;
        }

        // --- Control structures: detect BEFORE variable expansion ---
        // while/until/for need raw (unexpanded) text so loop bodies
        // can re-expand $VAR on each iteration.
        if starts_with(raw_line, b"while ") || starts_with(raw_line, b"until ")
            || starts_with(raw_line, b"for ") || starts_with(raw_line, b"if ")
        {
            let mut block_buf = [0u8; 2048];
            let block_len = accumulate_block(raw_line, &mut line_buf, &mut block_buf);
            let block = trim(&block_buf[..block_len]);
            if !block.is_empty() {
                if starts_with(block, b"if ") {
                    // if blocks: expand once (condition + body are one-shot)
                    let mut exp = [0u8; 2048];
                    let elen = expand_vars(block, &mut exp);
                    let eblock = trim(&exp[..elen]);
                    execute_if_block(eblock, &mut line_buf);
                } else if starts_with(block, b"for ") {
                    execute_for_block(block, &mut line_buf);
                } else if starts_with(block, b"while ") {
                    execute_while_block(block, &mut line_buf);
                } else if starts_with(block, b"until ") {
                    execute_until_block(block, &mut line_buf);
                }
            }
            continue;
        }

        // Expand environment variables ($VAR).
        let mut expanded = [0u8; 512];
        let exp_len = expand_vars(raw_line, &mut expanded);
        let line = trim(&expanded[..exp_len]);
        if line.is_empty() {
            continue;
        }

        // Semicolon command separator: cmd1; cmd2; cmd3
        if find_semicolon_unquoted(line).is_some() {
            execute_semicolon_list(line);
            continue;
        }

        // Check for here-document (<<DELIM).
        if let Some(heredoc_pos) = find_substr(line, b"<<") {
            let cmd_part = trim(&line[..heredoc_pos]);
            let delim = trim(&line[heredoc_pos + 2..]);
            if !delim.is_empty() && !cmd_part.is_empty() {
                execute_heredoc(cmd_part, delim, &mut line_buf);
                continue;
            }
        }

        // Check for && / || conditional operators (lower precedence than pipes).
        if find_logical_op_unquoted(line).is_some() {
            execute_logical_chain(line);
            continue;
        }

        // Check for pipe operator (respects quotes).
        if let Some(pipe_pos) = find_pipe_unquoted(line) {
            let left = trim(&line[..pipe_pos]);
            let right = trim(&line[pipe_pos + 1..]);
            if !left.is_empty() && !right.is_empty() {
                execute_pipe(left, right);
                continue;
            }
        }

        // Check for background execution (&).
        let (line, background) = if line.len() > 0 && line[line.len() - 1] == b'&' {
            (trim(&line[..line.len() - 1]), true)
        } else {
            (line, false)
        };

        if background {
            let child_fn = exec::child_shell_main as *const () as u64;
            let pid = linux_clone(child_fn);
            if pid > 0 {
                let jid = job_add(pid as u64, JOB_RUNNING, line);
                print(b"[");
                print_u64(jid as u64);
                print(b"] ");
                print_u64(pid as u64);
                print(b"\n");
            }
            continue;
        }

        // Parse and handle redirects, then dispatch
        dispatch_with_redirects(line);
    }
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    print(b"sotOS LUCAS shell v0.3\n");
    // Load persistent history (silently no-ops on first run).
    load_from_vfs();
    shell_loop();
    linux_exit(0);
}

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    print(b"PANIC in lucas-shell\n");
    linux_exit(1);
}
