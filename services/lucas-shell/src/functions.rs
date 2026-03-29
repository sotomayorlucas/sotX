use crate::syscall::*;
use crate::util::*;
use crate::env::env_get;
use crate::parse::dispatch_or_call_func;

// ---------------------------------------------------------------------------
// Shell functions
// ---------------------------------------------------------------------------

pub const MAX_FUNCTIONS: usize = 16;
pub const MAX_FUNC_NAME: usize = 32;
pub const MAX_FUNC_BODY: usize = 1024;

pub struct ShellFunction {
    pub active: bool,
    pub name: [u8; MAX_FUNC_NAME],
    pub name_len: usize,
    pub body: [u8; MAX_FUNC_BODY],
    pub body_len: usize,
}

impl ShellFunction {
    pub const fn empty() -> Self {
        Self {
            active: false,
            name: [0; MAX_FUNC_NAME],
            name_len: 0,
            body: [0; MAX_FUNC_BODY],
            body_len: 0,
        }
    }
}

pub static mut FUNCTIONS: [ShellFunction; MAX_FUNCTIONS] = {
    const INIT: ShellFunction = ShellFunction::empty();
    [INIT; MAX_FUNCTIONS]
};

pub fn funcs_slice() -> &'static [ShellFunction] {
    unsafe { core::slice::from_raw_parts(core::ptr::addr_of!(FUNCTIONS) as *const ShellFunction, MAX_FUNCTIONS) }
}

pub fn funcs_slice_mut() -> &'static mut [ShellFunction] {
    unsafe { core::slice::from_raw_parts_mut(core::ptr::addr_of_mut!(FUNCTIONS) as *mut ShellFunction, MAX_FUNCTIONS) }
}

pub fn func_define(name: &[u8], body: &[u8]) {
    // Update existing
    for f in funcs_slice_mut().iter_mut() {
        if f.active && f.name_len == name.len() && f.name[..f.name_len] == *name {
            let bl = body.len().min(MAX_FUNC_BODY);
            f.body[..bl].copy_from_slice(&body[..bl]);
            f.body_len = bl;
            return;
        }
    }
    // Insert new
    for f in funcs_slice_mut().iter_mut() {
        if !f.active {
            let nl = name.len().min(MAX_FUNC_NAME);
            f.name[..nl].copy_from_slice(&name[..nl]);
            f.name_len = nl;
            let bl = body.len().min(MAX_FUNC_BODY);
            f.body[..bl].copy_from_slice(&body[..bl]);
            f.body_len = bl;
            f.active = true;
            return;
        }
    }
    print(b"error: too many functions defined\n");
}

pub fn func_find(name: &[u8]) -> Option<usize> {
    for (i, f) in funcs_slice().iter().enumerate() {
        if f.active && f.name_len == name.len() && f.name[..f.name_len] == *name {
            return Some(i);
        }
    }
    None
}

/// Positional args for the currently executing function ($1, $2, ...).
pub const MAX_FUNC_ARGS: usize = 8;
pub static mut FUNC_ARGS: [[u8; 128]; MAX_FUNC_ARGS] = [[0; 128]; MAX_FUNC_ARGS];
pub static mut FUNC_ARG_LENS: [usize; MAX_FUNC_ARGS] = [0; MAX_FUNC_ARGS];
pub static mut FUNC_ARG_COUNT: usize = 0;

/// Expand $VAR references (and $1-$8 positional args) in a command line.
pub fn expand_vars(input: &[u8], output: &mut [u8]) -> usize {
    let mut out_pos = 0;
    let mut i = 0;
    while i < input.len() && out_pos < output.len() - 1 {
        if input[i] == b'$' && i + 1 < input.len() && input[i + 1] != b' ' {
            // $((expr)) — arithmetic expansion
            if i + 2 < input.len() && input[i + 1] == b'(' && input[i + 2] == b'(' {
                // Find matching ))
                let start = i + 3;
                let mut depth = 2;
                let mut end = start;
                while end < input.len() && depth > 0 {
                    if input[end] == b'(' { depth += 1; }
                    if input[end] == b')' { depth -= 1; }
                    if depth > 0 { end += 1; }
                }
                if depth == 0 {
                    let expr = &input[start..end - 1]; // exclude the inner )
                    // Expand variables inside the expression first
                    let mut expr_buf = [0u8; 128];
                    let expr_len = expand_vars(expr, &mut expr_buf);
                    let val = eval_arithmetic(&expr_buf[..expr_len]);
                    // Write result
                    let neg = val < 0;
                    let abs_val = if neg { (-val) as u64 } else { val as u64 };
                    if neg && out_pos < output.len() - 1 { output[out_pos] = b'-'; out_pos += 1; }
                    let mut tmp = [0u8; 20];
                    let mut tl = 0;
                    if abs_val == 0 { tmp[0] = b'0'; tl = 1; } else {
                        let mut v = abs_val;
                        while v > 0 { tmp[tl] = b'0' + (v % 10) as u8; v /= 10; tl += 1; }
                    }
                    let mut j = tl;
                    while j > 0 && out_pos < output.len() - 1 { j -= 1; output[out_pos] = tmp[j]; out_pos += 1; }
                    i = end + 1; // skip past ))
                    continue;
                }
            }
            // $(cmd) — command substitution
            if input[i + 1] == b'(' {
                let start = i + 2;
                let mut depth: u32 = 1;
                let mut end = start;
                while end < input.len() && depth > 0 {
                    if input[end] == b'(' { depth += 1; }
                    if input[end] == b')' { depth -= 1; }
                    end += 1;
                }
                if depth == 0 {
                    let cmd = &input[start..end - 1];
                    let mut cap_buf = [0u8; 4096];
                    let cap_len = crate::builtins::capture_command(cmd, &mut cap_buf);
                    // If capture_command returned nothing, try capture_command_extended approach
                    let actual_len = if cap_len == 0 {
                        // Also try via dispatch for non-capturable commands
                        // For now, only capture_command is supported
                        0
                    } else {
                        cap_len
                    };
                    // Strip trailing newlines
                    let mut out_len = actual_len;
                    while out_len > 0 && (cap_buf[out_len - 1] == b'\n' || cap_buf[out_len - 1] == b'\r') {
                        out_len -= 1;
                    }
                    let copy_len = out_len.min(output.len() - 1 - out_pos);
                    output[out_pos..out_pos + copy_len].copy_from_slice(&cap_buf[..copy_len]);
                    out_pos += copy_len;
                    i = end;
                    continue;
                }
            }
            // `cmd` — backtick command substitution
            if input[i + 1] == b'`' {
                // Actually this doesn't start with $, handle backticks separately below
            }
            // $$ — current PID
            if input[i + 1] == b'$' {
                let pid = crate::syscall::linux_getpid() as u64;
                let mut tmp = [0u8; 20];
                let mut tl = 0;
                if pid == 0 { tmp[0] = b'0'; tl = 1; } else {
                    let mut v = pid;
                    while v > 0 { tmp[tl] = b'0' + (v % 10) as u8; v /= 10; tl += 1; }
                }
                let mut j = tl;
                while j > 0 && out_pos < output.len() - 1 { j -= 1; output[out_pos] = tmp[j]; out_pos += 1; }
                i += 2;
                continue;
            }
            // $# — number of positional args
            if input[i + 1] == b'#' {
                let count = unsafe { FUNC_ARG_COUNT as u64 };
                let mut tmp = [0u8; 20];
                let mut tl = 0;
                if count == 0 { tmp[0] = b'0'; tl = 1; } else {
                    let mut v = count;
                    while v > 0 { tmp[tl] = b'0' + (v % 10) as u8; v /= 10; tl += 1; }
                }
                let mut j = tl;
                while j > 0 && out_pos < output.len() - 1 { j -= 1; output[out_pos] = tmp[j]; out_pos += 1; }
                i += 2;
                continue;
            }
            // $0 — shell name
            if input[i + 1] == b'0' {
                let name = b"lucas";
                let copy_len = name.len().min(output.len() - 1 - out_pos);
                output[out_pos..out_pos + copy_len].copy_from_slice(&name[..copy_len]);
                out_pos += copy_len;
                i += 2;
                continue;
            }
            // $@ and $* — all positional args joined with spaces
            if input[i + 1] == b'@' || input[i + 1] == b'*' {
                unsafe {
                    for a in 0..FUNC_ARG_COUNT {
                        if a > 0 && out_pos < output.len() - 1 {
                            output[out_pos] = b' ';
                            out_pos += 1;
                        }
                        let arg_len = FUNC_ARG_LENS[a];
                        let copy_len = arg_len.min(output.len() - 1 - out_pos);
                        output[out_pos..out_pos + copy_len].copy_from_slice(&FUNC_ARGS[a][..copy_len]);
                        out_pos += copy_len;
                    }
                }
                i += 2;
                continue;
            }
            // $? — last exit status
            if input[i + 1] == b'?' {
                let status = crate::parse::get_exit_status();
                let val = if status < 0 { (-status) as u64 } else { status as u64 };
                let mut tmp = [0u8; 20];
                let mut tl = 0;
                if status < 0 && out_pos < output.len() - 1 {
                    output[out_pos] = b'-';
                    out_pos += 1;
                }
                if val == 0 {
                    tmp[0] = b'0';
                    tl = 1;
                } else {
                    let mut v = val;
                    while v > 0 {
                        tmp[tl] = b'0' + (v % 10) as u8;
                        v /= 10;
                        tl += 1;
                    }
                }
                let mut j = tl;
                while j > 0 && out_pos < output.len() - 1 {
                    j -= 1;
                    output[out_pos] = tmp[j];
                    out_pos += 1;
                }
                i += 2;
                continue;
            }
            // Check for positional argument $1-$8
            let next = input[i + 1];
            if next >= b'1' && next <= b'8' {
                let arg_idx = (next - b'1') as usize;
                unsafe {
                    if arg_idx < FUNC_ARG_COUNT {
                        let arg_len = FUNC_ARG_LENS[arg_idx];
                        let copy_len = arg_len.min(output.len() - 1 - out_pos);
                        output[out_pos..out_pos + copy_len].copy_from_slice(&FUNC_ARGS[arg_idx][..copy_len]);
                        out_pos += copy_len;
                    }
                }
                i += 2;
                continue;
            }
            // Extract variable name.
            let start = i + 1;
            let mut end = start;
            while end < input.len() && (input[end].is_ascii_alphanumeric() || input[end] == b'_') {
                end += 1;
            }
            if end > start {
                if let Some(val) = env_get(&input[start..end]) {
                    let copy_len = val.len().min(output.len() - 1 - out_pos);
                    output[out_pos..out_pos + copy_len].copy_from_slice(&val[..copy_len]);
                    out_pos += copy_len;
                }
                i = end;
            } else {
                output[out_pos] = input[i];
                out_pos += 1;
                i += 1;
            }
        } else if input[i] == b'`' {
            // Backtick command substitution: `cmd`
            let start = i + 1;
            let mut end = start;
            while end < input.len() && input[end] != b'`' { end += 1; }
            if end < input.len() {
                let cmd = &input[start..end];
                let mut cap_buf = [0u8; 4096];
                let cap_len = crate::builtins::capture_command(cmd, &mut cap_buf);
                let mut out_len = cap_len;
                while out_len > 0 && (cap_buf[out_len - 1] == b'\n' || cap_buf[out_len - 1] == b'\r') {
                    out_len -= 1;
                }
                let copy_len = out_len.min(output.len() - 1 - out_pos);
                output[out_pos..out_pos + copy_len].copy_from_slice(&cap_buf[..copy_len]);
                out_pos += copy_len;
                i = end + 1;
            } else {
                output[out_pos] = input[i];
                out_pos += 1;
                i += 1;
            }
        } else {
            output[out_pos] = input[i];
            out_pos += 1;
            i += 1;
        }
    }
    out_pos
}

// ---------------------------------------------------------------------------
// Arithmetic evaluation for $(( expr ))
// ---------------------------------------------------------------------------

/// Evaluate a simple integer arithmetic expression.
/// Supports: +, -, *, /, %, parentheses, decimal integers, negative numbers.
pub fn eval_arithmetic(expr: &[u8]) -> i64 {
    let mut pos = 0;
    let result = arith_expr(expr, &mut pos);
    result
}

fn arith_skip_spaces(expr: &[u8], pos: &mut usize) {
    while *pos < expr.len() && (expr[*pos] == b' ' || expr[*pos] == b'\t') { *pos += 1; }
}

/// expr = term (('+' | '-') term)*
fn arith_expr(expr: &[u8], pos: &mut usize) -> i64 {
    let mut val = arith_term(expr, pos);
    loop {
        arith_skip_spaces(expr, pos);
        if *pos >= expr.len() { break; }
        match expr[*pos] {
            b'+' => { *pos += 1; val += arith_term(expr, pos); }
            b'-' => { *pos += 1; val -= arith_term(expr, pos); }
            _ => break,
        }
    }
    val
}

/// term = factor (('*' | '/' | '%') factor)*
fn arith_term(expr: &[u8], pos: &mut usize) -> i64 {
    let mut val = arith_factor(expr, pos);
    loop {
        arith_skip_spaces(expr, pos);
        if *pos >= expr.len() { break; }
        match expr[*pos] {
            b'*' => { *pos += 1; val *= arith_factor(expr, pos); }
            b'/' => {
                *pos += 1;
                let d = arith_factor(expr, pos);
                val = if d != 0 { val / d } else { 0 };
            }
            b'%' => {
                *pos += 1;
                let d = arith_factor(expr, pos);
                val = if d != 0 { val % d } else { 0 };
            }
            _ => break,
        }
    }
    val
}

/// factor = '-' factor | '(' expr ')' | number
fn arith_factor(expr: &[u8], pos: &mut usize) -> i64 {
    arith_skip_spaces(expr, pos);
    if *pos >= expr.len() { return 0; }

    // Unary minus
    if expr[*pos] == b'-' {
        *pos += 1;
        return -arith_factor(expr, pos);
    }
    // Parenthesized expression
    if expr[*pos] == b'(' {
        *pos += 1;
        let val = arith_expr(expr, pos);
        arith_skip_spaces(expr, pos);
        if *pos < expr.len() && expr[*pos] == b')' { *pos += 1; }
        return val;
    }
    // Number
    let mut val: i64 = 0;
    let mut found = false;
    while *pos < expr.len() && expr[*pos] >= b'0' && expr[*pos] <= b'9' {
        val = val * 10 + (expr[*pos] - b'0') as i64;
        *pos += 1;
        found = true;
    }
    if !found { return 0; }
    val
}

// ---------------------------------------------------------------------------
// Function definition and invocation
// ---------------------------------------------------------------------------

pub fn read_function_def(first_line: &[u8], line_buf: &mut [u8; 512]) {
    // Parse "function NAME() {" or "function NAME {"
    let after_func = trim(&first_line[9..]);

    // Extract function name
    let mut name_end: usize = 0;
    while name_end < after_func.len()
        && after_func[name_end] != b'('
        && after_func[name_end] != b' '
        && after_func[name_end] != b'{'
    {
        name_end += 1;
    }
    let func_name = &after_func[..name_end];
    if func_name.is_empty() {
        print(b"syntax error: function name expected\n");
        return;
    }

    // Check if first line contains '{' — if not, it's an error
    let has_brace = find_byte(after_func, b'{').is_some();
    if !has_brace {
        print(b"syntax error: expected '{'\n");
        return;
    }

    // Read body lines until we see "}"
    let mut body = [0u8; MAX_FUNC_BODY];
    let mut body_len: usize = 0;

    loop {
        print(b"> ");
        let pos = read_simple_line(line_buf);
        let input_line = trim(&line_buf[..pos]);
        if eq(input_line, b"}") {
            break;
        }
        // Append line to body with newline separator
        if body_len + input_line.len() + 1 < MAX_FUNC_BODY {
            body[body_len..body_len + input_line.len()].copy_from_slice(input_line);
            body_len += input_line.len();
            body[body_len] = b'\n';
            body_len += 1;
        }
    }

    func_define(func_name, &body[..body_len]);
}

/// Try to call a shell function. Returns true if found and called.
pub fn call_function(name: &[u8], args: &[u8]) -> bool {
    let idx = match func_find(name) {
        Some(i) => i,
        None => return false,
    };

    // Save old positional args
    let mut old_args: [[u8; 128]; MAX_FUNC_ARGS] = [[0; 128]; MAX_FUNC_ARGS];
    let mut old_arg_lens: [usize; MAX_FUNC_ARGS] = [0; MAX_FUNC_ARGS];
    let old_count: usize;
    unsafe {
        old_count = FUNC_ARG_COUNT;
        for i in 0..MAX_FUNC_ARGS {
            old_arg_lens[i] = FUNC_ARG_LENS[i];
            old_args[i][..old_arg_lens[i]].copy_from_slice(&FUNC_ARGS[i][..old_arg_lens[i]]);
        }
    }

    // Parse new positional args from args string
    unsafe {
        FUNC_ARG_COUNT = 0;
        let mut pos: usize = 0;
        while pos < args.len() && FUNC_ARG_COUNT < MAX_FUNC_ARGS {
            while pos < args.len() && args[pos] == b' ' { pos += 1; }
            let start = pos;
            while pos < args.len() && args[pos] != b' ' { pos += 1; }
            if start < pos {
                let l = (pos - start).min(128);
                FUNC_ARGS[FUNC_ARG_COUNT][..l].copy_from_slice(&args[start..start + l]);
                FUNC_ARG_LENS[FUNC_ARG_COUNT] = l;
                FUNC_ARG_COUNT += 1;
            }
        }
    }

    // Copy the body before execution (func_define might modify FUNCTIONS)
    let mut body_copy = [0u8; MAX_FUNC_BODY];
    let body_len;
    {
        let f = &funcs_slice()[idx];
        body_len = f.body_len;
        body_copy[..body_len].copy_from_slice(&f.body[..body_len]);
    }

    // Execute each line in the body
    let mut line_start: usize = 0;
    let mut i: usize = 0;
    while i <= body_len {
        if i == body_len || body_copy[i] == b'\n' {
            let func_line = trim(&body_copy[line_start..i]);
            if !func_line.is_empty() {
                if eq(func_line, b"return") {
                    break; // early return
                }
                if starts_with(func_line, b"return ") {
                    break; // return with value (just exit)
                }
                // Expand variables (including $1, $2, etc.)
                let mut exp_buf = [0u8; 256];
                let exp_len = expand_vars(func_line, &mut exp_buf);
                let expanded = trim(&exp_buf[..exp_len]);
                if !expanded.is_empty() {
                    dispatch_or_call_func(expanded);
                }
            }
            line_start = i + 1;
        }
        i += 1;
    }

    // Restore old positional args
    unsafe {
        FUNC_ARG_COUNT = old_count;
        for i in 0..MAX_FUNC_ARGS {
            FUNC_ARG_LENS[i] = old_arg_lens[i];
            FUNC_ARGS[i][..old_arg_lens[i]].copy_from_slice(&old_args[i][..old_arg_lens[i]]);
        }
    }

    true
}
