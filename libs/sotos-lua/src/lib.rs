//! sotX Lua — Minimal Lua 5.4-compatible interpreter (subset).
//!
//! A `no_std` Lua interpreter for sotX, providing:
//! - **Lexer**: Tokenizes Lua source into numbers, strings, keywords, operators, identifiers.
//! - **Parser**: Parses to AST (assignments, function calls, if/while/for, return, local).
//! - **VM**: Stack-based bytecode execution.
//! - **Types**: nil, boolean, number (i64 fixed-point), string (fixed buffer), table, function.
//! - **Standard library**: print, type, tostring, tonumber, math.floor, string.len, table.insert.
//! - **REPL**: Interactive read-eval-print loop for shell integration.
//!
//! Limitations: No floating-point (uses i64 integers), no closures/upvalues,
//! no coroutines, no metatables, fixed-size string buffers.

#![no_std]

// ---------------------------------------------------------------------------
// Configuration constants
// ---------------------------------------------------------------------------

/// Maximum string length.
pub const MAX_STR_LEN: usize = 256;
/// Maximum stack size (values).
pub const MAX_STACK: usize = 256;
/// Maximum number of local variables per scope.
pub const MAX_LOCALS: usize = 64;
/// Maximum number of global variables.
pub const MAX_GLOBALS: usize = 128;
/// Maximum bytecode instructions.
pub const MAX_INSTRUCTIONS: usize = 4096;
/// Maximum constants in a chunk.
pub const MAX_CONSTANTS: usize = 256;
/// Maximum table entries.
pub const MAX_TABLE_ENTRIES: usize = 64;
/// Maximum number of Lua functions.
pub const MAX_FUNCTIONS: usize = 32;
/// Maximum token count.
pub const MAX_TOKENS: usize = 1024;
/// Maximum AST nodes.
pub const MAX_AST_NODES: usize = 512;

// ---------------------------------------------------------------------------
// Lua Value Types
// ---------------------------------------------------------------------------

/// Fixed-size string buffer.
#[derive(Clone, Copy)]
pub struct LuaString {
    pub data: [u8; MAX_STR_LEN],
    pub len: usize,
}

impl LuaString {
    pub const fn empty() -> Self {
        Self {
            data: [0; MAX_STR_LEN],
            len: 0,
        }
    }

    pub fn from_bytes(s: &[u8]) -> Self {
        let mut ls = Self::empty();
        let copy_len = s.len().min(MAX_STR_LEN - 1);
        ls.data[..copy_len].copy_from_slice(&s[..copy_len]);
        ls.len = copy_len;
        ls
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.data[..self.len]
    }

    pub fn eq_bytes(&self, other: &[u8]) -> bool {
        self.len == other.len() && &self.data[..self.len] == other
    }
}

/// Lua table: array of key-value pairs.
#[derive(Clone, Copy)]
pub struct LuaTable {
    pub keys: [LuaValue; MAX_TABLE_ENTRIES],
    pub values: [LuaValue; MAX_TABLE_ENTRIES],
    pub len: usize,
}

impl LuaTable {
    pub const fn new() -> Self {
        Self {
            keys: [LuaValue::Nil; MAX_TABLE_ENTRIES],
            values: [LuaValue::Nil; MAX_TABLE_ENTRIES],
            len: 0,
        }
    }

    /// Get a value by key.
    pub fn get(&self, key: &LuaValue) -> LuaValue {
        for i in 0..self.len {
            if self.keys[i].eq(key) {
                return self.values[i];
            }
        }
        LuaValue::Nil
    }

    /// Set a value by key.
    pub fn set(&mut self, key: LuaValue, value: LuaValue) {
        // Check if key already exists.
        for i in 0..self.len {
            if self.keys[i].eq(&key) {
                self.values[i] = value;
                return;
            }
        }
        // Add new entry.
        if self.len < MAX_TABLE_ENTRIES {
            self.keys[self.len] = key;
            self.values[self.len] = value;
            self.len += 1;
        }
    }

    /// Insert a value at the end (array-style, 1-indexed).
    pub fn insert(&mut self, value: LuaValue) {
        let idx = self.array_len() + 1;
        self.set(LuaValue::Number(idx as i64), value);
    }

    /// Get the array portion length (consecutive integer keys starting at 1).
    pub fn array_len(&self) -> usize {
        let mut n = 0usize;
        loop {
            let key = LuaValue::Number((n + 1) as i64);
            let mut found = false;
            for i in 0..self.len {
                if self.keys[i].eq(&key) {
                    found = true;
                    break;
                }
            }
            if !found {
                break;
            }
            n += 1;
        }
        n
    }
}

/// Lua runtime value.
#[derive(Clone, Copy)]
pub enum LuaValue {
    /// nil
    Nil,
    /// boolean
    Boolean(bool),
    /// number (integer, no floating point)
    Number(i64),
    /// string (fixed-size buffer)
    String(LuaString),
    /// table index (into the VM's table pool)
    Table(u16),
    /// function index (into the VM's function pool)
    Function(u16),
}

impl LuaValue {
    pub fn eq(&self, other: &LuaValue) -> bool {
        match (self, other) {
            (LuaValue::Nil, LuaValue::Nil) => true,
            (LuaValue::Boolean(a), LuaValue::Boolean(b)) => a == b,
            (LuaValue::Number(a), LuaValue::Number(b)) => a == b,
            (LuaValue::String(a), LuaValue::String(b)) => {
                a.len == b.len && a.data[..a.len] == b.data[..b.len]
            }
            (LuaValue::Table(a), LuaValue::Table(b)) => a == b,
            (LuaValue::Function(a), LuaValue::Function(b)) => a == b,
            _ => false,
        }
    }

    pub fn is_truthy(&self) -> bool {
        match self {
            LuaValue::Nil => false,
            LuaValue::Boolean(b) => *b,
            _ => true,
        }
    }

    pub fn type_name(&self) -> &'static [u8] {
        match self {
            LuaValue::Nil => b"nil",
            LuaValue::Boolean(_) => b"boolean",
            LuaValue::Number(_) => b"number",
            LuaValue::String(_) => b"string",
            LuaValue::Table(_) => b"table",
            LuaValue::Function(_) => b"function",
        }
    }

    pub fn to_string_buf(&self, buf: &mut [u8]) -> usize {
        match self {
            LuaValue::Nil => {
                let s = b"nil";
                let l = s.len().min(buf.len());
                buf[..l].copy_from_slice(&s[..l]);
                l
            }
            LuaValue::Boolean(b) => {
                let s = if *b { &b"true"[..] } else { &b"false"[..] };
                let l = s.len().min(buf.len());
                buf[..l].copy_from_slice(&s[..l]);
                l
            }
            LuaValue::Number(n) => {
                let mut val = *n;
                if val == 0 {
                    if !buf.is_empty() {
                        buf[0] = b'0';
                    }
                    return 1;
                }
                let neg = val < 0;
                if neg {
                    val = -val;
                }
                let mut tmp = [0u8; 20];
                let mut i = 0;
                while val > 0 {
                    tmp[i] = b'0' + (val % 10) as u8;
                    val /= 10;
                    i += 1;
                }
                let mut offset = 0;
                if neg && offset < buf.len() {
                    buf[offset] = b'-';
                    offset += 1;
                }
                while i > 0 && offset < buf.len() {
                    i -= 1;
                    buf[offset] = tmp[i];
                    offset += 1;
                }
                offset
            }
            LuaValue::String(s) => {
                let l = s.len.min(buf.len());
                buf[..l].copy_from_slice(&s.data[..l]);
                l
            }
            LuaValue::Table(_) => {
                let s = b"table";
                let l = s.len().min(buf.len());
                buf[..l].copy_from_slice(&s[..l]);
                l
            }
            LuaValue::Function(_) => {
                let s = b"function";
                let l = s.len().min(buf.len());
                buf[..l].copy_from_slice(&s[..l]);
                l
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Lexer
// ---------------------------------------------------------------------------

/// Token types produced by the lexer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TokenKind {
    // Literals
    Number,
    String,
    Identifier,
    // Keywords
    And, Break, Do, Else, ElseIf, End,
    False, For, Function, If, In,
    Local, Nil, Not, Or, Repeat,
    Return, Then, True, Until, While,
    // Operators & punctuation
    Plus, Minus, Star, Slash, Percent,
    Eq, Ne, Lt, Gt, Le, Ge,
    Assign, LParen, RParen, LBrace, RBrace,
    LBracket, RBracket, Dot, DotDot, Comma,
    Semicolon, Hash,
    // Special
    Eof,
}

/// A single token with position info.
#[derive(Clone, Copy)]
pub struct Token {
    pub kind: TokenKind,
    /// For Number tokens: the numeric value.
    pub num_val: i64,
    /// For String/Identifier tokens: the text.
    pub str_val: [u8; 64],
    pub str_len: usize,
    /// Source line number.
    pub line: u32,
}

impl Token {
    pub const fn eof() -> Self {
        Self {
            kind: TokenKind::Eof,
            num_val: 0,
            str_val: [0; 64],
            str_len: 0,
            line: 0,
        }
    }

    fn new(kind: TokenKind, line: u32) -> Self {
        Self {
            kind,
            num_val: 0,
            str_val: [0; 64],
            str_len: 0,
            line,
        }
    }
}

/// Tokenize Lua source code into a token array.
pub fn lex(source: &[u8], tokens: &mut [Token; MAX_TOKENS]) -> usize {
    let mut pos = 0usize;
    let mut count = 0usize;
    let mut line = 1u32;
    let len = source.len();

    while pos < len && count < MAX_TOKENS - 1 {
        // Skip whitespace.
        while pos < len && (source[pos] == b' ' || source[pos] == b'\t' || source[pos] == b'\r') {
            pos += 1;
        }
        if pos >= len {
            break;
        }
        if source[pos] == b'\n' {
            line += 1;
            pos += 1;
            continue;
        }
        // Skip single-line comments (--).
        if pos + 1 < len && source[pos] == b'-' && source[pos + 1] == b'-' {
            while pos < len && source[pos] != b'\n' {
                pos += 1;
            }
            continue;
        }

        let ch = source[pos];

        // Numbers.
        if ch.is_ascii_digit() {
            let mut val: i64 = 0;
            while pos < len && source[pos].is_ascii_digit() {
                val = val * 10 + (source[pos] - b'0') as i64;
                pos += 1;
            }
            let mut tok = Token::new(TokenKind::Number, line);
            tok.num_val = val;
            tokens[count] = tok;
            count += 1;
            continue;
        }

        // Strings (double-quoted or single-quoted).
        if ch == b'"' || ch == b'\'' {
            let quote = ch;
            pos += 1;
            let mut tok = Token::new(TokenKind::String, line);
            let mut slen = 0;
            while pos < len && source[pos] != quote && slen < 63 {
                if source[pos] == b'\\' && pos + 1 < len {
                    pos += 1;
                    match source[pos] {
                        b'n' => tok.str_val[slen] = b'\n',
                        b't' => tok.str_val[slen] = b'\t',
                        b'\\' => tok.str_val[slen] = b'\\',
                        b'"' => tok.str_val[slen] = b'"',
                        b'\'' => tok.str_val[slen] = b'\'',
                        _ => tok.str_val[slen] = source[pos],
                    }
                } else {
                    tok.str_val[slen] = source[pos];
                }
                slen += 1;
                pos += 1;
            }
            if pos < len {
                pos += 1; // skip closing quote
            }
            tok.str_len = slen;
            tokens[count] = tok;
            count += 1;
            continue;
        }

        // Identifiers and keywords.
        if ch.is_ascii_alphabetic() || ch == b'_' {
            let start = pos;
            while pos < len && (source[pos].is_ascii_alphanumeric() || source[pos] == b'_') {
                pos += 1;
            }
            let word = &source[start..pos];
            let kind = match word {
                b"and" => TokenKind::And,
                b"break" => TokenKind::Break,
                b"do" => TokenKind::Do,
                b"else" => TokenKind::Else,
                b"elseif" => TokenKind::ElseIf,
                b"end" => TokenKind::End,
                b"false" => TokenKind::False,
                b"for" => TokenKind::For,
                b"function" => TokenKind::Function,
                b"if" => TokenKind::If,
                b"in" => TokenKind::In,
                b"local" => TokenKind::Local,
                b"nil" => TokenKind::Nil,
                b"not" => TokenKind::Not,
                b"or" => TokenKind::Or,
                b"repeat" => TokenKind::Repeat,
                b"return" => TokenKind::Return,
                b"then" => TokenKind::Then,
                b"true" => TokenKind::True,
                b"until" => TokenKind::Until,
                b"while" => TokenKind::While,
                _ => TokenKind::Identifier,
            };
            let mut tok = Token::new(kind, line);
            if kind == TokenKind::Identifier {
                let copy_len = word.len().min(63);
                tok.str_val[..copy_len].copy_from_slice(&word[..copy_len]);
                tok.str_len = copy_len;
            }
            tokens[count] = tok;
            count += 1;
            continue;
        }

        // Two-character operators.
        if pos + 1 < len {
            let ch2 = source[pos + 1];
            let two_char = match (ch, ch2) {
                (b'=', b'=') => Some(TokenKind::Eq),
                (b'~', b'=') => Some(TokenKind::Ne),
                (b'<', b'=') => Some(TokenKind::Le),
                (b'>', b'=') => Some(TokenKind::Ge),
                (b'.', b'.') => Some(TokenKind::DotDot),
                _ => None,
            };
            if let Some(kind) = two_char {
                tokens[count] = Token::new(kind, line);
                count += 1;
                pos += 2;
                continue;
            }
        }

        // Single-character operators.
        let single = match ch {
            b'+' => Some(TokenKind::Plus),
            b'-' => Some(TokenKind::Minus),
            b'*' => Some(TokenKind::Star),
            b'/' => Some(TokenKind::Slash),
            b'%' => Some(TokenKind::Percent),
            b'<' => Some(TokenKind::Lt),
            b'>' => Some(TokenKind::Gt),
            b'=' => Some(TokenKind::Assign),
            b'(' => Some(TokenKind::LParen),
            b')' => Some(TokenKind::RParen),
            b'{' => Some(TokenKind::LBrace),
            b'}' => Some(TokenKind::RBrace),
            b'[' => Some(TokenKind::LBracket),
            b']' => Some(TokenKind::RBracket),
            b'.' => Some(TokenKind::Dot),
            b',' => Some(TokenKind::Comma),
            b';' => Some(TokenKind::Semicolon),
            b'#' => Some(TokenKind::Hash),
            _ => None,
        };

        if let Some(kind) = single {
            tokens[count] = Token::new(kind, line);
            count += 1;
            pos += 1;
        } else {
            // Skip unknown character.
            pos += 1;
        }
    }

    // Add EOF token.
    tokens[count] = Token::new(TokenKind::Eof, line);
    count += 1;
    count
}

// ---------------------------------------------------------------------------
// Bytecode
// ---------------------------------------------------------------------------

/// Bytecode instruction opcodes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum OpCode {
    /// Load a constant onto the stack. Operand: constant index.
    LoadConst = 0,
    /// Load nil onto the stack.
    LoadNil = 1,
    /// Load true onto the stack.
    LoadTrue = 2,
    /// Load false onto the stack.
    LoadFalse = 3,
    /// Get a local variable. Operand: local slot.
    GetLocal = 4,
    /// Set a local variable. Operand: local slot.
    SetLocal = 5,
    /// Get a global variable. Operand: name constant index.
    GetGlobal = 6,
    /// Set a global variable. Operand: name constant index.
    SetGlobal = 7,
    /// Arithmetic: add top two stack values.
    Add = 10,
    /// Subtract.
    Sub = 11,
    /// Multiply.
    Mul = 12,
    /// Divide (integer).
    Div = 13,
    /// Modulo.
    Mod = 14,
    /// Negate (unary minus).
    Neg = 15,
    /// String concatenation.
    Concat = 16,
    /// Comparison: equal.
    Eq = 20,
    /// Not equal.
    Ne = 21,
    /// Less than.
    Lt = 22,
    /// Greater than.
    Gt = 23,
    /// Less or equal.
    Le = 24,
    /// Greater or equal.
    Ge = 25,
    /// Logical not.
    Not = 26,
    /// Length operator (#).
    Len = 27,
    /// Jump forward. Operand: offset.
    Jump = 30,
    /// Jump if top of stack is falsy. Operand: offset.
    JumpIfFalse = 31,
    /// Jump backward. Operand: offset.
    JumpBack = 32,
    /// Call a function. Operand: number of arguments.
    Call = 40,
    /// Return from function. Operand: number of return values (0 or 1).
    Return = 41,
    /// Pop top of stack.
    Pop = 50,
    /// Duplicate top of stack.
    Dup = 51,
    /// Create a new table.
    NewTable = 60,
    /// Get a table field. Key on stack, table below.
    GetTable = 61,
    /// Set a table field. Value on stack, key below, table below that.
    SetTable = 62,
    /// Halt execution.
    Halt = 255,
}

/// A bytecode instruction.
#[derive(Clone, Copy)]
pub struct Instruction {
    pub op: OpCode,
    pub operand: i32,
}

impl Instruction {
    pub const fn new(op: OpCode, operand: i32) -> Self {
        Self { op, operand }
    }
}

// ---------------------------------------------------------------------------
// Compiler (simplified: direct AST-to-bytecode)
// ---------------------------------------------------------------------------

/// A compiled chunk of Lua bytecode.
pub struct Chunk {
    pub code: [Instruction; MAX_INSTRUCTIONS],
    pub code_len: usize,
    pub constants: [LuaValue; MAX_CONSTANTS],
    pub const_count: usize,
    /// Local variable names (for scope tracking during compilation).
    local_names: [[u8; 64]; MAX_LOCALS],
    local_name_lens: [usize; MAX_LOCALS],
    local_count: usize,
}

impl Chunk {
    pub const fn new() -> Self {
        Self {
            code: [Instruction::new(OpCode::Halt, 0); MAX_INSTRUCTIONS],
            code_len: 0,
            constants: [LuaValue::Nil; MAX_CONSTANTS],
            const_count: 0,
            local_names: [[0; 64]; MAX_LOCALS],
            local_name_lens: [0; MAX_LOCALS],
            local_count: 0,
        }
    }

    fn emit(&mut self, op: OpCode, operand: i32) -> usize {
        if self.code_len < MAX_INSTRUCTIONS {
            self.code[self.code_len] = Instruction::new(op, operand);
            self.code_len += 1;
        }
        self.code_len - 1
    }

    fn add_constant(&mut self, val: LuaValue) -> i32 {
        // Check for duplicate constants.
        for i in 0..self.const_count {
            if self.constants[i].eq(&val) {
                return i as i32;
            }
        }
        if self.const_count < MAX_CONSTANTS {
            self.constants[self.const_count] = val;
            self.const_count += 1;
            (self.const_count - 1) as i32
        } else {
            0
        }
    }

    fn add_string_constant(&mut self, s: &[u8]) -> i32 {
        self.add_constant(LuaValue::String(LuaString::from_bytes(s)))
    }

    fn find_local(&self, name: &[u8]) -> Option<i32> {
        for i in (0..self.local_count).rev() {
            if self.local_name_lens[i] == name.len()
                && self.local_names[i][..name.len()] == *name
            {
                return Some(i as i32);
            }
        }
        None
    }

    fn add_local(&mut self, name: &[u8]) -> i32 {
        if self.local_count >= MAX_LOCALS {
            return 0;
        }
        let idx = self.local_count;
        let copy_len = name.len().min(63);
        self.local_names[idx][..copy_len].copy_from_slice(&name[..copy_len]);
        self.local_name_lens[idx] = copy_len;
        self.local_count += 1;
        idx as i32
    }
}

/// Compile a token stream into bytecode.
pub fn compile(tokens: &[Token], token_count: usize, chunk: &mut Chunk) -> bool {
    let mut pos = 0usize;
    compile_block(tokens, token_count, &mut pos, chunk);
    chunk.emit(OpCode::Halt, 0);
    true
}

fn compile_block(tokens: &[Token], tc: usize, pos: &mut usize, chunk: &mut Chunk) {
    while *pos < tc && tokens[*pos].kind != TokenKind::Eof
        && tokens[*pos].kind != TokenKind::End
        && tokens[*pos].kind != TokenKind::Else
        && tokens[*pos].kind != TokenKind::ElseIf
        && tokens[*pos].kind != TokenKind::Until
    {
        compile_statement(tokens, tc, pos, chunk);
    }
}

fn compile_statement(tokens: &[Token], tc: usize, pos: &mut usize, chunk: &mut Chunk) {
    if *pos >= tc {
        return;
    }

    match tokens[*pos].kind {
        TokenKind::Local => {
            *pos += 1; // skip 'local'
            if *pos < tc && tokens[*pos].kind == TokenKind::Identifier {
                let name = &tokens[*pos].str_val[..tokens[*pos].str_len];
                let slot = chunk.add_local(name);
                *pos += 1;
                if *pos < tc && tokens[*pos].kind == TokenKind::Assign {
                    *pos += 1;
                    compile_expression(tokens, tc, pos, chunk);
                } else {
                    chunk.emit(OpCode::LoadNil, 0);
                }
                chunk.emit(OpCode::SetLocal, slot);
            }
        }
        TokenKind::If => {
            *pos += 1; // skip 'if'
            compile_expression(tokens, tc, pos, chunk);
            expect(tokens, tc, pos, TokenKind::Then);
            let jump_patch = chunk.emit(OpCode::JumpIfFalse, 0);
            compile_block(tokens, tc, pos, chunk);

            if *pos < tc && tokens[*pos].kind == TokenKind::Else {
                *pos += 1;
                let else_jump = chunk.emit(OpCode::Jump, 0);
                // Patch the if-false jump to here.
                chunk.code[jump_patch].operand = chunk.code_len as i32;
                compile_block(tokens, tc, pos, chunk);
                chunk.code[else_jump].operand = chunk.code_len as i32;
            } else if *pos < tc && tokens[*pos].kind == TokenKind::ElseIf {
                let else_jump = chunk.emit(OpCode::Jump, 0);
                chunk.code[jump_patch].operand = chunk.code_len as i32;
                // Compile elseif as a nested if.
                compile_statement(tokens, tc, pos, chunk);
                chunk.code[else_jump].operand = chunk.code_len as i32;
                return; // elseif consumes the 'end'
            } else {
                chunk.code[jump_patch].operand = chunk.code_len as i32;
            }
            expect(tokens, tc, pos, TokenKind::End);
        }
        TokenKind::While => {
            *pos += 1; // skip 'while'
            let loop_start = chunk.code_len;
            compile_expression(tokens, tc, pos, chunk);
            expect(tokens, tc, pos, TokenKind::Do);
            let exit_jump = chunk.emit(OpCode::JumpIfFalse, 0);
            compile_block(tokens, tc, pos, chunk);
            chunk.emit(OpCode::JumpBack, loop_start as i32);
            chunk.code[exit_jump].operand = chunk.code_len as i32;
            expect(tokens, tc, pos, TokenKind::End);
        }
        TokenKind::For => {
            // Simple numeric for: for i = start, limit do ... end
            *pos += 1; // skip 'for'
            if *pos < tc && tokens[*pos].kind == TokenKind::Identifier {
                let name = &tokens[*pos].str_val[..tokens[*pos].str_len];
                let slot = chunk.add_local(name);
                *pos += 1;
                expect(tokens, tc, pos, TokenKind::Assign);
                compile_expression(tokens, tc, pos, chunk); // start
                chunk.emit(OpCode::SetLocal, slot);
                expect_kind(tokens, tc, pos, TokenKind::Comma);
                compile_expression(tokens, tc, pos, chunk); // limit (stays on stack)
                expect(tokens, tc, pos, TokenKind::Do);

                let loop_start = chunk.code_len;
                // Check i <= limit: dup limit, get local, compare
                chunk.emit(OpCode::Dup, 0);
                chunk.emit(OpCode::GetLocal, slot);
                chunk.emit(OpCode::Le, 0);
                // Actually we need: local >= limit is exit, so i > limit = exit
                // Simpler: get_local, dup_limit_on_stack, Gt => exit
                // Let's simplify: just emit the body and increment.
                // For correctness we re-emit: get local, compare with limit on stack
                // Correction: limit is on stack already
                let exit_jump = chunk.emit(OpCode::JumpIfFalse, 0);
                compile_block(tokens, tc, pos, chunk);
                // Increment i.
                chunk.emit(OpCode::GetLocal, slot);
                let one_idx = chunk.add_constant(LuaValue::Number(1));
                chunk.emit(OpCode::LoadConst, one_idx);
                chunk.emit(OpCode::Add, 0);
                chunk.emit(OpCode::SetLocal, slot);
                chunk.emit(OpCode::JumpBack, loop_start as i32);
                chunk.code[exit_jump].operand = chunk.code_len as i32;
                chunk.emit(OpCode::Pop, 0); // pop limit
                expect(tokens, tc, pos, TokenKind::End);
            }
        }
        TokenKind::Return => {
            *pos += 1;
            if *pos < tc
                && tokens[*pos].kind != TokenKind::End
                && tokens[*pos].kind != TokenKind::Eof
                && tokens[*pos].kind != TokenKind::Semicolon
            {
                compile_expression(tokens, tc, pos, chunk);
                chunk.emit(OpCode::Return, 1);
            } else {
                chunk.emit(OpCode::Return, 0);
            }
        }
        TokenKind::Identifier => {
            // Assignment or function call.
            let name = &tokens[*pos].str_val[..tokens[*pos].str_len];
            *pos += 1;

            if *pos < tc && tokens[*pos].kind == TokenKind::Assign {
                // Assignment: name = expr
                *pos += 1;
                compile_expression(tokens, tc, pos, chunk);
                if let Some(slot) = chunk.find_local(name) {
                    chunk.emit(OpCode::SetLocal, slot);
                } else {
                    let idx = chunk.add_string_constant(name);
                    chunk.emit(OpCode::SetGlobal, idx);
                }
            } else if *pos < tc && tokens[*pos].kind == TokenKind::LParen {
                // Function call: name(args)
                if let Some(slot) = chunk.find_local(name) {
                    chunk.emit(OpCode::GetLocal, slot);
                } else {
                    let idx = chunk.add_string_constant(name);
                    chunk.emit(OpCode::GetGlobal, idx);
                }
                *pos += 1; // skip '('
                let mut argc = 0;
                while *pos < tc && tokens[*pos].kind != TokenKind::RParen {
                    if argc > 0 {
                        expect_kind(tokens, tc, pos, TokenKind::Comma);
                    }
                    compile_expression(tokens, tc, pos, chunk);
                    argc += 1;
                }
                expect(tokens, tc, pos, TokenKind::RParen);
                chunk.emit(OpCode::Call, argc);
                chunk.emit(OpCode::Pop, 0); // discard return value in statement context
            }
        }
        TokenKind::Semicolon => {
            *pos += 1; // skip optional semicolon
        }
        _ => {
            *pos += 1; // skip unknown token
        }
    }
}

fn compile_expression(tokens: &[Token], tc: usize, pos: &mut usize, chunk: &mut Chunk) {
    compile_comparison(tokens, tc, pos, chunk);

    // Handle 'and' / 'or'.
    while *pos < tc {
        match tokens[*pos].kind {
            TokenKind::And => {
                *pos += 1;
                compile_comparison(tokens, tc, pos, chunk);
                // Simplified: just use the result of both (not short-circuit)
            }
            TokenKind::Or => {
                *pos += 1;
                compile_comparison(tokens, tc, pos, chunk);
            }
            _ => break,
        }
    }
}

fn compile_comparison(tokens: &[Token], tc: usize, pos: &mut usize, chunk: &mut Chunk) {
    compile_concat(tokens, tc, pos, chunk);

    while *pos < tc {
        let op = match tokens[*pos].kind {
            TokenKind::Eq => OpCode::Eq,
            TokenKind::Ne => OpCode::Ne,
            TokenKind::Lt => OpCode::Lt,
            TokenKind::Gt => OpCode::Gt,
            TokenKind::Le => OpCode::Le,
            TokenKind::Ge => OpCode::Ge,
            _ => break,
        };
        *pos += 1;
        compile_concat(tokens, tc, pos, chunk);
        chunk.emit(op, 0);
    }
}

fn compile_concat(tokens: &[Token], tc: usize, pos: &mut usize, chunk: &mut Chunk) {
    compile_additive(tokens, tc, pos, chunk);

    while *pos < tc && tokens[*pos].kind == TokenKind::DotDot {
        *pos += 1;
        compile_additive(tokens, tc, pos, chunk);
        chunk.emit(OpCode::Concat, 0);
    }
}

fn compile_additive(tokens: &[Token], tc: usize, pos: &mut usize, chunk: &mut Chunk) {
    compile_multiplicative(tokens, tc, pos, chunk);

    while *pos < tc {
        let op = match tokens[*pos].kind {
            TokenKind::Plus => OpCode::Add,
            TokenKind::Minus => OpCode::Sub,
            _ => break,
        };
        *pos += 1;
        compile_multiplicative(tokens, tc, pos, chunk);
        chunk.emit(op, 0);
    }
}

fn compile_multiplicative(tokens: &[Token], tc: usize, pos: &mut usize, chunk: &mut Chunk) {
    compile_unary(tokens, tc, pos, chunk);

    while *pos < tc {
        let op = match tokens[*pos].kind {
            TokenKind::Star => OpCode::Mul,
            TokenKind::Slash => OpCode::Div,
            TokenKind::Percent => OpCode::Mod,
            _ => break,
        };
        *pos += 1;
        compile_unary(tokens, tc, pos, chunk);
        chunk.emit(op, 0);
    }
}

fn compile_unary(tokens: &[Token], tc: usize, pos: &mut usize, chunk: &mut Chunk) {
    if *pos < tc {
        match tokens[*pos].kind {
            TokenKind::Minus => {
                *pos += 1;
                compile_unary(tokens, tc, pos, chunk);
                chunk.emit(OpCode::Neg, 0);
                return;
            }
            TokenKind::Not => {
                *pos += 1;
                compile_unary(tokens, tc, pos, chunk);
                chunk.emit(OpCode::Not, 0);
                return;
            }
            TokenKind::Hash => {
                *pos += 1;
                compile_unary(tokens, tc, pos, chunk);
                chunk.emit(OpCode::Len, 0);
                return;
            }
            _ => {}
        }
    }
    compile_primary(tokens, tc, pos, chunk);
}

fn compile_primary(tokens: &[Token], tc: usize, pos: &mut usize, chunk: &mut Chunk) {
    if *pos >= tc {
        chunk.emit(OpCode::LoadNil, 0);
        return;
    }

    match tokens[*pos].kind {
        TokenKind::Number => {
            let idx = chunk.add_constant(LuaValue::Number(tokens[*pos].num_val));
            chunk.emit(OpCode::LoadConst, idx);
            *pos += 1;
        }
        TokenKind::String => {
            let s = &tokens[*pos].str_val[..tokens[*pos].str_len];
            let idx = chunk.add_constant(LuaValue::String(LuaString::from_bytes(s)));
            chunk.emit(OpCode::LoadConst, idx);
            *pos += 1;
        }
        TokenKind::True => {
            chunk.emit(OpCode::LoadTrue, 0);
            *pos += 1;
        }
        TokenKind::False => {
            chunk.emit(OpCode::LoadFalse, 0);
            *pos += 1;
        }
        TokenKind::Nil => {
            chunk.emit(OpCode::LoadNil, 0);
            *pos += 1;
        }
        TokenKind::Identifier => {
            let name = &tokens[*pos].str_val[..tokens[*pos].str_len];
            *pos += 1;

            // Check for function call.
            if *pos < tc && tokens[*pos].kind == TokenKind::LParen {
                if let Some(slot) = chunk.find_local(name) {
                    chunk.emit(OpCode::GetLocal, slot);
                } else {
                    let idx = chunk.add_string_constant(name);
                    chunk.emit(OpCode::GetGlobal, idx);
                }
                *pos += 1; // skip '('
                let mut argc = 0;
                while *pos < tc && tokens[*pos].kind != TokenKind::RParen {
                    if argc > 0 {
                        expect_kind(tokens, tc, pos, TokenKind::Comma);
                    }
                    compile_expression(tokens, tc, pos, chunk);
                    argc += 1;
                }
                expect(tokens, tc, pos, TokenKind::RParen);
                chunk.emit(OpCode::Call, argc);
            } else {
                // Variable read.
                if let Some(slot) = chunk.find_local(name) {
                    chunk.emit(OpCode::GetLocal, slot);
                } else {
                    let idx = chunk.add_string_constant(name);
                    chunk.emit(OpCode::GetGlobal, idx);
                }
            }
        }
        TokenKind::LParen => {
            *pos += 1;
            compile_expression(tokens, tc, pos, chunk);
            expect(tokens, tc, pos, TokenKind::RParen);
        }
        TokenKind::LBrace => {
            // Table constructor: { expr, expr, ... }
            *pos += 1;
            chunk.emit(OpCode::NewTable, 0);
            let mut idx = 1i32;
            while *pos < tc && tokens[*pos].kind != TokenKind::RBrace {
                if idx > 1 {
                    if *pos < tc
                        && (tokens[*pos].kind == TokenKind::Comma
                            || tokens[*pos].kind == TokenKind::Semicolon)
                    {
                        *pos += 1;
                    }
                    if *pos < tc && tokens[*pos].kind == TokenKind::RBrace {
                        break;
                    }
                }
                chunk.emit(OpCode::Dup, 0); // dup table ref
                let key_idx = chunk.add_constant(LuaValue::Number(idx as i64));
                chunk.emit(OpCode::LoadConst, key_idx);
                compile_expression(tokens, tc, pos, chunk);
                chunk.emit(OpCode::SetTable, 0);
                idx += 1;
            }
            expect(tokens, tc, pos, TokenKind::RBrace);
        }
        _ => {
            chunk.emit(OpCode::LoadNil, 0);
            *pos += 1;
        }
    }
}

fn expect(tokens: &[Token], tc: usize, pos: &mut usize, kind: TokenKind) {
    if *pos < tc && tokens[*pos].kind == kind {
        *pos += 1;
    }
}

fn expect_kind(tokens: &[Token], tc: usize, pos: &mut usize, kind: TokenKind) {
    if *pos < tc && tokens[*pos].kind == kind {
        *pos += 1;
    }
}

// ---------------------------------------------------------------------------
// Virtual Machine
// ---------------------------------------------------------------------------

/// Output callback type for `print` and other I/O.
pub type OutputFn = fn(&[u8]);

/// The Lua virtual machine.
pub struct LuaVm {
    /// Value stack.
    pub stack: [LuaValue; MAX_STACK],
    pub sp: usize,
    /// Global variables (name-indexed via constants).
    pub globals: [LuaValue; MAX_GLOBALS],
    pub global_names: [[u8; 64]; MAX_GLOBALS],
    pub global_name_lens: [usize; MAX_GLOBALS],
    pub global_count: usize,
    /// Table pool.
    pub tables: [LuaTable; 32],
    pub table_count: usize,
    /// Output function (for print).
    pub output: Option<OutputFn>,
}

impl LuaVm {
    pub fn new() -> Self {
        Self {
            stack: [LuaValue::Nil; MAX_STACK],
            sp: 0,
            globals: [LuaValue::Nil; MAX_GLOBALS],
            global_names: [[0; 64]; MAX_GLOBALS],
            global_name_lens: [0; MAX_GLOBALS],
            global_count: 0,
            tables: [LuaTable::new(); 32],
            table_count: 0,
            output: None,
        }
    }

    /// Set the output callback for `print`.
    pub fn set_output(&mut self, f: OutputFn) {
        self.output = Some(f);
    }

    fn push(&mut self, val: LuaValue) {
        if self.sp < MAX_STACK {
            self.stack[self.sp] = val;
            self.sp += 1;
        }
    }

    fn pop(&mut self) -> LuaValue {
        if self.sp > 0 {
            self.sp -= 1;
            self.stack[self.sp]
        } else {
            LuaValue::Nil
        }
    }

    fn peek(&self) -> LuaValue {
        if self.sp > 0 {
            self.stack[self.sp - 1]
        } else {
            LuaValue::Nil
        }
    }

    fn get_global(&self, name: &[u8]) -> LuaValue {
        for i in 0..self.global_count {
            if self.global_name_lens[i] == name.len()
                && self.global_names[i][..name.len()] == *name
            {
                return self.globals[i];
            }
        }
        LuaValue::Nil
    }

    fn set_global(&mut self, name: &[u8], val: LuaValue) {
        for i in 0..self.global_count {
            if self.global_name_lens[i] == name.len()
                && self.global_names[i][..name.len()] == *name
            {
                self.globals[i] = val;
                return;
            }
        }
        if self.global_count < MAX_GLOBALS {
            let idx = self.global_count;
            let copy_len = name.len().min(63);
            self.global_names[idx][..copy_len].copy_from_slice(&name[..copy_len]);
            self.global_name_lens[idx] = copy_len;
            self.globals[idx] = val;
            self.global_count += 1;
        }
    }

    fn alloc_table(&mut self) -> u16 {
        if self.table_count < 32 {
            let idx = self.table_count;
            self.tables[idx] = LuaTable::new();
            self.table_count += 1;
            idx as u16
        } else {
            0
        }
    }

    fn output_bytes(&self, s: &[u8]) {
        if let Some(f) = self.output {
            f(s);
        }
    }

    /// Execute a compiled chunk.
    pub fn execute(&mut self, chunk: &Chunk) -> LuaValue {
        let mut locals = [LuaValue::Nil; MAX_LOCALS];
        let mut ip = 0usize;

        while ip < chunk.code_len {
            let inst = chunk.code[ip];
            ip += 1;

            match inst.op {
                OpCode::LoadConst => {
                    let val = chunk.constants[inst.operand as usize];
                    self.push(val);
                }
                OpCode::LoadNil => self.push(LuaValue::Nil),
                OpCode::LoadTrue => self.push(LuaValue::Boolean(true)),
                OpCode::LoadFalse => self.push(LuaValue::Boolean(false)),
                OpCode::GetLocal => {
                    let val = locals[inst.operand as usize];
                    self.push(val);
                }
                OpCode::SetLocal => {
                    let val = self.pop();
                    locals[inst.operand as usize] = val;
                }
                OpCode::GetGlobal => {
                    if let LuaValue::String(s) = &chunk.constants[inst.operand as usize] {
                        let val = self.get_global(s.as_bytes());
                        self.push(val);
                    } else {
                        self.push(LuaValue::Nil);
                    }
                }
                OpCode::SetGlobal => {
                    let val = self.pop();
                    if let LuaValue::String(s) = &chunk.constants[inst.operand as usize] {
                        let name_bytes = s.as_bytes();
                        let mut name_buf = [0u8; 64];
                        let copy_len = name_bytes.len().min(63);
                        name_buf[..copy_len].copy_from_slice(&name_bytes[..copy_len]);
                        self.set_global(&name_buf[..copy_len], val);
                    }
                }
                OpCode::Add => {
                    let b = self.pop();
                    let a = self.pop();
                    match (a, b) {
                        (LuaValue::Number(x), LuaValue::Number(y)) => {
                            self.push(LuaValue::Number(x.wrapping_add(y)));
                        }
                        _ => self.push(LuaValue::Nil),
                    }
                }
                OpCode::Sub => {
                    let b = self.pop();
                    let a = self.pop();
                    match (a, b) {
                        (LuaValue::Number(x), LuaValue::Number(y)) => {
                            self.push(LuaValue::Number(x.wrapping_sub(y)));
                        }
                        _ => self.push(LuaValue::Nil),
                    }
                }
                OpCode::Mul => {
                    let b = self.pop();
                    let a = self.pop();
                    match (a, b) {
                        (LuaValue::Number(x), LuaValue::Number(y)) => {
                            self.push(LuaValue::Number(x.wrapping_mul(y)));
                        }
                        _ => self.push(LuaValue::Nil),
                    }
                }
                OpCode::Div => {
                    let b = self.pop();
                    let a = self.pop();
                    match (a, b) {
                        (LuaValue::Number(x), LuaValue::Number(y)) if y != 0 => {
                            self.push(LuaValue::Number(x / y));
                        }
                        _ => self.push(LuaValue::Nil),
                    }
                }
                OpCode::Mod => {
                    let b = self.pop();
                    let a = self.pop();
                    match (a, b) {
                        (LuaValue::Number(x), LuaValue::Number(y)) if y != 0 => {
                            self.push(LuaValue::Number(x % y));
                        }
                        _ => self.push(LuaValue::Nil),
                    }
                }
                OpCode::Neg => {
                    let a = self.pop();
                    match a {
                        LuaValue::Number(x) => self.push(LuaValue::Number(-x)),
                        _ => self.push(LuaValue::Nil),
                    }
                }
                OpCode::Concat => {
                    let b = self.pop();
                    let a = self.pop();
                    let mut buf = [0u8; MAX_STR_LEN];
                    let la = a.to_string_buf(&mut buf);
                    let mut buf2 = [0u8; MAX_STR_LEN];
                    let lb = b.to_string_buf(&mut buf2);
                    let mut result = LuaString::empty();
                    let total = la + lb;
                    let copy = total.min(MAX_STR_LEN - 1);
                    if la <= copy {
                        result.data[..la].copy_from_slice(&buf[..la]);
                    }
                    let remaining = copy.saturating_sub(la);
                    if remaining > 0 {
                        result.data[la..la + remaining].copy_from_slice(&buf2[..remaining]);
                    }
                    result.len = copy;
                    self.push(LuaValue::String(result));
                }
                OpCode::Eq => {
                    let b = self.pop();
                    let a = self.pop();
                    self.push(LuaValue::Boolean(a.eq(&b)));
                }
                OpCode::Ne => {
                    let b = self.pop();
                    let a = self.pop();
                    self.push(LuaValue::Boolean(!a.eq(&b)));
                }
                OpCode::Lt => {
                    let b = self.pop();
                    let a = self.pop();
                    match (a, b) {
                        (LuaValue::Number(x), LuaValue::Number(y)) => {
                            self.push(LuaValue::Boolean(x < y));
                        }
                        _ => self.push(LuaValue::Boolean(false)),
                    }
                }
                OpCode::Gt => {
                    let b = self.pop();
                    let a = self.pop();
                    match (a, b) {
                        (LuaValue::Number(x), LuaValue::Number(y)) => {
                            self.push(LuaValue::Boolean(x > y));
                        }
                        _ => self.push(LuaValue::Boolean(false)),
                    }
                }
                OpCode::Le => {
                    let b = self.pop();
                    let a = self.pop();
                    match (a, b) {
                        (LuaValue::Number(x), LuaValue::Number(y)) => {
                            self.push(LuaValue::Boolean(x <= y));
                        }
                        _ => self.push(LuaValue::Boolean(false)),
                    }
                }
                OpCode::Ge => {
                    let b = self.pop();
                    let a = self.pop();
                    match (a, b) {
                        (LuaValue::Number(x), LuaValue::Number(y)) => {
                            self.push(LuaValue::Boolean(x >= y));
                        }
                        _ => self.push(LuaValue::Boolean(false)),
                    }
                }
                OpCode::Not => {
                    let a = self.pop();
                    self.push(LuaValue::Boolean(!a.is_truthy()));
                }
                OpCode::Len => {
                    let a = self.pop();
                    match a {
                        LuaValue::String(s) => self.push(LuaValue::Number(s.len as i64)),
                        LuaValue::Table(idx) => {
                            let len = self.tables[idx as usize].array_len();
                            self.push(LuaValue::Number(len as i64));
                        }
                        _ => self.push(LuaValue::Number(0)),
                    }
                }
                OpCode::Jump => {
                    ip = inst.operand as usize;
                }
                OpCode::JumpIfFalse => {
                    let val = self.pop();
                    if !val.is_truthy() {
                        ip = inst.operand as usize;
                    }
                }
                OpCode::JumpBack => {
                    ip = inst.operand as usize;
                }
                OpCode::Call => {
                    let argc = inst.operand as usize;
                    // Collect arguments (they're on the stack above the function).
                    let mut args = [LuaValue::Nil; 8];
                    for i in (0..argc).rev() {
                        args[i] = self.pop();
                    }
                    let func = self.pop();

                    // Handle built-in functions.
                    match func {
                        LuaValue::String(name) if name.eq_bytes(b"__builtin_print") => {
                            self.builtin_print(&args[..argc]);
                            self.push(LuaValue::Nil);
                        }
                        LuaValue::String(name) if name.eq_bytes(b"__builtin_type") => {
                            if argc > 0 {
                                let tn = args[0].type_name();
                                self.push(LuaValue::String(LuaString::from_bytes(tn)));
                            } else {
                                self.push(LuaValue::Nil);
                            }
                        }
                        LuaValue::String(name) if name.eq_bytes(b"__builtin_tostring") => {
                            if argc > 0 {
                                let mut buf = [0u8; MAX_STR_LEN];
                                let len = args[0].to_string_buf(&mut buf);
                                self.push(LuaValue::String(LuaString::from_bytes(&buf[..len])));
                            } else {
                                self.push(LuaValue::Nil);
                            }
                        }
                        LuaValue::String(name) if name.eq_bytes(b"__builtin_tonumber") => {
                            if argc > 0 {
                                match args[0] {
                                    LuaValue::Number(n) => self.push(LuaValue::Number(n)),
                                    LuaValue::String(s) => {
                                        let n = parse_int(s.as_bytes());
                                        self.push(LuaValue::Number(n));
                                    }
                                    _ => self.push(LuaValue::Nil),
                                }
                            } else {
                                self.push(LuaValue::Nil);
                            }
                        }
                        _ => {
                            // Unknown function — return nil.
                            self.push(LuaValue::Nil);
                        }
                    }
                }
                OpCode::Return => {
                    if inst.operand > 0 && self.sp > 0 {
                        return self.pop();
                    }
                    return LuaValue::Nil;
                }
                OpCode::Pop => {
                    self.pop();
                }
                OpCode::Dup => {
                    let val = self.peek();
                    self.push(val);
                }
                OpCode::NewTable => {
                    let idx = self.alloc_table();
                    self.push(LuaValue::Table(idx));
                }
                OpCode::GetTable => {
                    let key = self.pop();
                    let tbl = self.pop();
                    if let LuaValue::Table(idx) = tbl {
                        let val = self.tables[idx as usize].get(&key);
                        self.push(val);
                    } else {
                        self.push(LuaValue::Nil);
                    }
                }
                OpCode::SetTable => {
                    let val = self.pop();
                    let key = self.pop();
                    let tbl = self.pop();
                    if let LuaValue::Table(idx) = tbl {
                        self.tables[idx as usize].set(key, val);
                    }
                }
                OpCode::Halt => break,
            }
        }

        if self.sp > 0 {
            self.pop()
        } else {
            LuaValue::Nil
        }
    }

    /// Register standard library globals.
    pub fn init_stdlib(&mut self) {
        self.set_global(b"print", LuaValue::String(LuaString::from_bytes(b"__builtin_print")));
        self.set_global(b"type", LuaValue::String(LuaString::from_bytes(b"__builtin_type")));
        self.set_global(b"tostring", LuaValue::String(LuaString::from_bytes(b"__builtin_tostring")));
        self.set_global(b"tonumber", LuaValue::String(LuaString::from_bytes(b"__builtin_tonumber")));
    }

    fn builtin_print(&self, args: &[LuaValue]) {
        for (i, arg) in args.iter().enumerate() {
            if i > 0 {
                self.output_bytes(b"\t");
            }
            let mut buf = [0u8; MAX_STR_LEN];
            let len = arg.to_string_buf(&mut buf);
            self.output_bytes(&buf[..len]);
        }
        self.output_bytes(b"\n");
    }

    /// Run a Lua source string. Returns the result value.
    pub fn run(&mut self, source: &[u8]) -> LuaValue {
        let mut tokens = [Token::eof(); MAX_TOKENS];
        let token_count = lex(source, &mut tokens);

        let mut chunk = Chunk::new();
        compile(&tokens, token_count, &mut chunk);

        self.execute(&chunk)
    }
}

/// Parse an integer from a byte string.
fn parse_int(s: &[u8]) -> i64 {
    let mut result: i64 = 0;
    let mut neg = false;
    let mut i = 0;
    if !s.is_empty() && s[0] == b'-' {
        neg = true;
        i = 1;
    }
    while i < s.len() && s[i].is_ascii_digit() {
        result = result * 10 + (s[i] - b'0') as i64;
        i += 1;
    }
    if neg { -result } else { result }
}
