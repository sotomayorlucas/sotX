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
        } else {
            output[out_pos] = input[i];
            out_pos += 1;
            i += 1;
        }
    }
    out_pos
}

// ---------------------------------------------------------------------------
// Function definition and invocation
// ---------------------------------------------------------------------------

pub fn read_function_def(first_line: &[u8], line_buf: &mut [u8; 256]) {
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
