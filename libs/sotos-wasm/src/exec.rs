//! WASM stack-based bytecode interpreter with SFI memory bounds checking.
//!
//! The execution engine maintains:
//! - An operand stack (values)
//! - A call stack (return addresses + frame bases)
//! - Linear memory (bounds-checked on every access)
//! - Local variables per call frame
//! - Global variables

use crate::decode::{self, op};
use crate::module::Module;
use crate::types::{ValType, Value};
use crate::{MAX_CALL_DEPTH, MAX_MEMORY_PAGES, MAX_STACK, WASM_PAGE_SIZE};

/// Runtime execution error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Trap {
    StackOverflow,
    StackUnderflow,
    CallStackOverflow,
    DivisionByZero,
    OutOfBoundsMemoryAccess,
    UndefinedFunction,
    TypeMismatch,
    Unreachable,
    InvalidOpcode(u8),
    MemoryGrowFailed,
}

/// A call frame on the call stack.
#[derive(Clone, Copy)]
struct CallFrame {
    /// Function index being executed.
    func_idx: u32,
    /// Instruction pointer (offset into module code buffer).
    ip: usize,
    /// End of this function's code.
    ip_end: usize,
    /// Base index into the value stack for this frame's locals.
    local_base: usize,
    /// Number of locals (params + declared locals).
    local_count: usize,
    /// Stack depth at frame entry (for cleanup on return).
    stack_base: usize,
    /// Whether this function has a return value.
    has_result: bool,
}

/// Block/loop label for branch targets.
#[derive(Clone, Copy)]
struct Label {
    /// Stack depth when the block was entered.
    stack_depth: usize,
    /// Instruction pointer to branch to.
    target_ip: usize,
    /// Whether this is a loop (branch target = start).
    is_loop: bool,
    /// Whether the block has a result value.
    has_result: bool,
}

/// Maximum number of nested blocks per function.
const MAX_LABELS: usize = 32;

/// Maximum locals per frame (params + locals).
const MAX_LOCALS_PER_FRAME: usize = 64;

/// WASM runtime instance.
pub struct Runtime {
    /// Operand stack.
    stack: [Value; MAX_STACK],
    sp: usize,

    /// Call stack.
    frames: [CallFrame; MAX_CALL_DEPTH],
    fp: usize,

    /// Local variable storage (flat array, indexed by frame.local_base + idx).
    locals: [Value; MAX_CALL_DEPTH * MAX_LOCALS_PER_FRAME],

    /// Linear memory (SFI-protected: every access bounds-checked).
    memory: [u8; MAX_MEMORY_PAGES * WASM_PAGE_SIZE],
    memory_size: usize, // current size in bytes

    /// Global variables.
    globals: [Value; 32],
    global_count: usize,
}

impl Runtime {
    /// Create a new runtime instance with the given module's memory and globals.
    pub fn new(module: &Module) -> Self {
        let mut rt = Runtime {
            stack: [Value::I32(0); MAX_STACK],
            sp: 0,
            frames: [CallFrame {
                func_idx: 0,
                ip: 0,
                ip_end: 0,
                local_base: 0,
                local_count: 0,
                stack_base: 0,
                has_result: false,
            }; MAX_CALL_DEPTH],
            fp: 0,
            locals: [Value::I32(0); MAX_CALL_DEPTH * MAX_LOCALS_PER_FRAME],
            memory: [0; MAX_MEMORY_PAGES * WASM_PAGE_SIZE],
            memory_size: module.memory_pages as usize * WASM_PAGE_SIZE,
            globals: [Value::I32(0); 32],
            global_count: module.global_count,
        };

        // Initialize globals from module.
        for i in 0..module.global_count {
            let g = &module.globals[i];
            rt.globals[i] = match g.val_type {
                ValType::I32 => Value::I32(g.init_i32),
                ValType::I64 => Value::I64(g.init_i64),
            };
        }

        rt
    }

    /// Call an exported function by index with the given arguments.
    /// Returns the result value (or None if void).
    pub fn call(&mut self, module: &Module, func_idx: u32, args: &[Value]) -> Result<Option<Value>, Trap> {
        if func_idx as usize >= module.func_count {
            return Err(Trap::UndefinedFunction);
        }

        let func = &module.functions[func_idx as usize];
        let ftype = &module.types[func.type_idx as usize];

        // Set up call frame.
        let local_base = 0; // First frame starts at 0.
        let total_locals = ftype.param_count + func.local_count;
        if total_locals > MAX_LOCALS_PER_FRAME {
            return Err(Trap::StackOverflow);
        }

        // Initialize locals: params from args, rest zero.
        for i in 0..ftype.param_count {
            if i < args.len() {
                self.locals[local_base + i] = args[i];
            }
        }
        for i in ftype.param_count..total_locals {
            self.locals[local_base + i] = match func.locals[i - ftype.param_count] {
                ValType::I32 => Value::I32(0),
                ValType::I64 => Value::I64(0),
            };
        }

        self.fp = 0;
        self.sp = 0;
        self.frames[0] = CallFrame {
            func_idx,
            ip: func.code_offset,
            ip_end: func.code_offset + func.code_len,
            local_base,
            local_count: total_locals,
            stack_base: 0,
            has_result: ftype.result.is_some(),
        };
        self.fp = 1;

        // Execute.
        self.execute(module)?;

        // Return value.
        if ftype.result.is_some() && self.sp > 0 {
            self.sp -= 1;
            Ok(Some(self.stack[self.sp]))
        } else {
            Ok(None)
        }
    }

    /// Main interpreter loop.
    fn execute(&mut self, module: &Module) -> Result<(), Trap> {
        // Label stack for block/loop/if control flow.
        let mut labels: [Label; MAX_LABELS] = [Label {
            stack_depth: 0,
            target_ip: 0,
            is_loop: false,
            has_result: false,
        }; MAX_LABELS];
        let mut label_sp: usize = 0;

        while self.fp > 0 {
            let frame_idx = self.fp - 1;
            let frame = self.frames[frame_idx];
            let mut ip = frame.ip;

            while ip < frame.ip_end {
                let opcode = module.code[ip];
                ip += 1;

                match opcode {
                    op::UNREACHABLE => return Err(Trap::Unreachable),

                    op::NOP => {}

                    op::BLOCK => {
                        let block_type = module.code[ip];
                        ip += 1;
                        let has_result = block_type != 0x40;
                        // Find matching end to compute branch target.
                        let end_ip = find_end(&module.code, ip, frame.ip_end);
                        if label_sp >= MAX_LABELS {
                            return Err(Trap::StackOverflow);
                        }
                        labels[label_sp] = Label {
                            stack_depth: self.sp,
                            target_ip: end_ip,
                            is_loop: false,
                            has_result,
                        };
                        label_sp += 1;
                    }

                    op::LOOP => {
                        let _block_type = module.code[ip];
                        ip += 1;
                        if label_sp >= MAX_LABELS {
                            return Err(Trap::StackOverflow);
                        }
                        labels[label_sp] = Label {
                            stack_depth: self.sp,
                            target_ip: ip, // Loop branches go back to start.
                            is_loop: true,
                            has_result: false,
                        };
                        label_sp += 1;
                    }

                    op::IF => {
                        let block_type = module.code[ip];
                        ip += 1;
                        let has_result = block_type != 0x40;
                        let cond = self.pop()?;
                        let else_ip = find_else(&module.code, ip, frame.ip_end);
                        let end_ip = find_end(&module.code, ip, frame.ip_end);

                        if label_sp >= MAX_LABELS {
                            return Err(Trap::StackOverflow);
                        }
                        labels[label_sp] = Label {
                            stack_depth: self.sp,
                            target_ip: end_ip,
                            is_loop: false,
                            has_result,
                        };
                        label_sp += 1;

                        if !cond.is_truthy() {
                            ip = if else_ip < end_ip { else_ip } else { end_ip };
                        }
                    }

                    op::ELSE => {
                        // Jump to end of if/else block.
                        if label_sp > 0 {
                            ip = labels[label_sp - 1].target_ip;
                        }
                    }

                    op::END => {
                        if label_sp > 0 {
                            label_sp -= 1;
                        } else {
                            // End of function.
                            break;
                        }
                    }

                    op::BR => {
                        let (depth, n) = decode::read_u32_leb128(&module.code[ip..])
                            .ok_or(Trap::InvalidOpcode(opcode))?;
                        ip += n;
                        if depth as usize >= label_sp {
                            break; // Branch out of function.
                        }
                        let target_label = &labels[label_sp - 1 - depth as usize];
                        ip = target_label.target_ip;
                        let target_depth = target_label.stack_depth;
                        let is_loop = target_label.is_loop;
                        // Unwind labels.
                        label_sp = label_sp.saturating_sub(depth as usize + if is_loop { 0 } else { 1 });
                        // Restore stack (keep result if any).
                        if self.sp > target_depth {
                            self.sp = target_depth;
                        }
                    }

                    op::BR_IF => {
                        let (depth, n) = decode::read_u32_leb128(&module.code[ip..])
                            .ok_or(Trap::InvalidOpcode(opcode))?;
                        ip += n;
                        let cond = self.pop()?;
                        if cond.is_truthy() {
                            if depth as usize >= label_sp {
                                break;
                            }
                            let target_label = &labels[label_sp - 1 - depth as usize];
                            ip = target_label.target_ip;
                            let target_depth = target_label.stack_depth;
                            let is_loop = target_label.is_loop;
                            label_sp = label_sp.saturating_sub(depth as usize + if is_loop { 0 } else { 1 });
                            if self.sp > target_depth {
                                self.sp = target_depth;
                            }
                        }
                    }

                    op::RETURN => {
                        // Return from current function.
                        let result = if frame.has_result && self.sp > frame.stack_base {
                            Some(self.stack[self.sp - 1])
                        } else {
                            None
                        };
                        self.sp = frame.stack_base;
                        if let Some(val) = result {
                            self.push(val)?;
                        }
                        self.fp -= 1;
                        // Update IP for the outer loop.
                        self.frames[frame_idx].ip = frame.ip_end;
                        return Ok(());
                    }

                    op::CALL => {
                        let (callee_idx, n) = decode::read_u32_leb128(&module.code[ip..])
                            .ok_or(Trap::InvalidOpcode(opcode))?;
                        ip += n;
                        // Save current IP.
                        self.frames[frame_idx].ip = ip;
                        // Set up new frame.
                        self.call_function(module, callee_idx)?;
                        // After return, restore execution.
                        ip = self.frames[frame_idx].ip;
                        // Recurse into execute for the callee.
                        self.execute(module)?;
                        // Continue from saved IP.
                        continue;
                    }

                    op::DROP => {
                        self.pop()?;
                    }

                    op::SELECT => {
                        let cond = self.pop()?;
                        let val2 = self.pop()?;
                        let val1 = self.pop()?;
                        self.push(if cond.is_truthy() { val1 } else { val2 })?;
                    }

                    op::LOCAL_GET => {
                        let (idx, n) = decode::read_u32_leb128(&module.code[ip..])
                            .ok_or(Trap::InvalidOpcode(opcode))?;
                        ip += n;
                        let val = self.locals[frame.local_base + idx as usize];
                        self.push(val)?;
                    }

                    op::LOCAL_SET => {
                        let (idx, n) = decode::read_u32_leb128(&module.code[ip..])
                            .ok_or(Trap::InvalidOpcode(opcode))?;
                        ip += n;
                        let val = self.pop()?;
                        self.locals[frame.local_base + idx as usize] = val;
                    }

                    op::LOCAL_TEE => {
                        let (idx, n) = decode::read_u32_leb128(&module.code[ip..])
                            .ok_or(Trap::InvalidOpcode(opcode))?;
                        ip += n;
                        let val = self.peek()?;
                        self.locals[frame.local_base + idx as usize] = val;
                    }

                    op::GLOBAL_GET => {
                        let (idx, n) = decode::read_u32_leb128(&module.code[ip..])
                            .ok_or(Trap::InvalidOpcode(opcode))?;
                        ip += n;
                        if idx as usize >= self.global_count {
                            return Err(Trap::OutOfBoundsMemoryAccess);
                        }
                        self.push(self.globals[idx as usize])?;
                    }

                    op::GLOBAL_SET => {
                        let (idx, n) = decode::read_u32_leb128(&module.code[ip..])
                            .ok_or(Trap::InvalidOpcode(opcode))?;
                        ip += n;
                        let val = self.pop()?;
                        if idx as usize >= self.global_count {
                            return Err(Trap::OutOfBoundsMemoryAccess);
                        }
                        self.globals[idx as usize] = val;
                    }

                    // --- Memory ---
                    op::I32_LOAD => {
                        let (_align, n) = decode::read_u32_leb128(&module.code[ip..])
                            .ok_or(Trap::InvalidOpcode(opcode))?;
                        ip += n;
                        let (offset, n) = decode::read_u32_leb128(&module.code[ip..])
                            .ok_or(Trap::InvalidOpcode(opcode))?;
                        ip += n;
                        let base = self.pop()?.as_u32();
                        let addr = base as usize + offset as usize;
                        let val = self.mem_load_i32(addr)?;
                        self.push(Value::I32(val))?;
                    }

                    op::I64_LOAD => {
                        let (_align, n) = decode::read_u32_leb128(&module.code[ip..])
                            .ok_or(Trap::InvalidOpcode(opcode))?;
                        ip += n;
                        let (offset, n) = decode::read_u32_leb128(&module.code[ip..])
                            .ok_or(Trap::InvalidOpcode(opcode))?;
                        ip += n;
                        let base = self.pop()?.as_u32();
                        let addr = base as usize + offset as usize;
                        let val = self.mem_load_i64(addr)?;
                        self.push(Value::I64(val))?;
                    }

                    op::I32_STORE => {
                        let (_align, n) = decode::read_u32_leb128(&module.code[ip..])
                            .ok_or(Trap::InvalidOpcode(opcode))?;
                        ip += n;
                        let (offset, n) = decode::read_u32_leb128(&module.code[ip..])
                            .ok_or(Trap::InvalidOpcode(opcode))?;
                        ip += n;
                        let val = self.pop()?.as_i32();
                        let base = self.pop()?.as_u32();
                        let addr = base as usize + offset as usize;
                        self.mem_store_i32(addr, val)?;
                    }

                    op::I64_STORE => {
                        let (_align, n) = decode::read_u32_leb128(&module.code[ip..])
                            .ok_or(Trap::InvalidOpcode(opcode))?;
                        ip += n;
                        let (offset, n) = decode::read_u32_leb128(&module.code[ip..])
                            .ok_or(Trap::InvalidOpcode(opcode))?;
                        ip += n;
                        let val = self.pop()?.as_i64();
                        let base = self.pop()?.as_u32();
                        let addr = base as usize + offset as usize;
                        self.mem_store_i64(addr, val)?;
                    }

                    op::MEMORY_SIZE => {
                        ip += 1; // skip 0x00 memory index
                        let pages = (self.memory_size / WASM_PAGE_SIZE) as i32;
                        self.push(Value::I32(pages))?;
                    }

                    op::MEMORY_GROW => {
                        ip += 1; // skip 0x00 memory index
                        let delta = self.pop()?.as_i32() as usize;
                        let old_pages = self.memory_size / WASM_PAGE_SIZE;
                        let new_pages = old_pages + delta;
                        if new_pages <= MAX_MEMORY_PAGES {
                            self.memory_size = new_pages * WASM_PAGE_SIZE;
                            self.push(Value::I32(old_pages as i32))?;
                        } else {
                            self.push(Value::I32(-1))?;
                        }
                    }

                    // --- Constants ---
                    op::I32_CONST => {
                        let (val, n) = decode::read_i32_leb128(&module.code[ip..])
                            .ok_or(Trap::InvalidOpcode(opcode))?;
                        ip += n;
                        self.push(Value::I32(val))?;
                    }

                    op::I64_CONST => {
                        let (val, n) = decode::read_i64_leb128(&module.code[ip..])
                            .ok_or(Trap::InvalidOpcode(opcode))?;
                        ip += n;
                        self.push(Value::I64(val))?;
                    }

                    // --- i32 comparisons ---
                    op::I32_EQZ => {
                        let a = self.pop()?.as_i32();
                        self.push(Value::I32(if a == 0 { 1 } else { 0 }))?;
                    }
                    op::I32_EQ => { let (b, a) = (self.pop()?.as_i32(), self.pop()?.as_i32()); self.push(Value::I32(if a == b { 1 } else { 0 }))?; }
                    op::I32_NE => { let (b, a) = (self.pop()?.as_i32(), self.pop()?.as_i32()); self.push(Value::I32(if a != b { 1 } else { 0 }))?; }
                    op::I32_LT_S => { let (b, a) = (self.pop()?.as_i32(), self.pop()?.as_i32()); self.push(Value::I32(if a < b { 1 } else { 0 }))?; }
                    op::I32_LT_U => { let (b, a) = (self.pop()?.as_u32(), self.pop()?.as_u32()); self.push(Value::I32(if a < b { 1 } else { 0 }))?; }
                    op::I32_GT_S => { let (b, a) = (self.pop()?.as_i32(), self.pop()?.as_i32()); self.push(Value::I32(if a > b { 1 } else { 0 }))?; }
                    op::I32_GT_U => { let (b, a) = (self.pop()?.as_u32(), self.pop()?.as_u32()); self.push(Value::I32(if a > b { 1 } else { 0 }))?; }
                    op::I32_LE_S => { let (b, a) = (self.pop()?.as_i32(), self.pop()?.as_i32()); self.push(Value::I32(if a <= b { 1 } else { 0 }))?; }
                    op::I32_LE_U => { let (b, a) = (self.pop()?.as_u32(), self.pop()?.as_u32()); self.push(Value::I32(if a <= b { 1 } else { 0 }))?; }
                    op::I32_GE_S => { let (b, a) = (self.pop()?.as_i32(), self.pop()?.as_i32()); self.push(Value::I32(if a >= b { 1 } else { 0 }))?; }
                    op::I32_GE_U => { let (b, a) = (self.pop()?.as_u32(), self.pop()?.as_u32()); self.push(Value::I32(if a >= b { 1 } else { 0 }))?; }

                    // --- i64 comparisons ---
                    op::I64_EQZ => { let a = self.pop()?.as_i64(); self.push(Value::I32(if a == 0 { 1 } else { 0 }))?; }
                    op::I64_EQ => { let (b, a) = (self.pop()?.as_i64(), self.pop()?.as_i64()); self.push(Value::I32(if a == b { 1 } else { 0 }))?; }
                    op::I64_NE => { let (b, a) = (self.pop()?.as_i64(), self.pop()?.as_i64()); self.push(Value::I32(if a != b { 1 } else { 0 }))?; }
                    op::I64_LT_S => { let (b, a) = (self.pop()?.as_i64(), self.pop()?.as_i64()); self.push(Value::I32(if a < b { 1 } else { 0 }))?; }
                    op::I64_GT_S => { let (b, a) = (self.pop()?.as_i64(), self.pop()?.as_i64()); self.push(Value::I32(if a > b { 1 } else { 0 }))?; }

                    // --- i32 arithmetic ---
                    op::I32_ADD => { let (b, a) = (self.pop()?.as_i32(), self.pop()?.as_i32()); self.push(Value::I32(a.wrapping_add(b)))?; }
                    op::I32_SUB => { let (b, a) = (self.pop()?.as_i32(), self.pop()?.as_i32()); self.push(Value::I32(a.wrapping_sub(b)))?; }
                    op::I32_MUL => { let (b, a) = (self.pop()?.as_i32(), self.pop()?.as_i32()); self.push(Value::I32(a.wrapping_mul(b)))?; }
                    op::I32_DIV_S => {
                        let b = self.pop()?.as_i32();
                        let a = self.pop()?.as_i32();
                        if b == 0 { return Err(Trap::DivisionByZero); }
                        self.push(Value::I32(a.wrapping_div(b)))?;
                    }
                    op::I32_DIV_U => {
                        let b = self.pop()?.as_u32();
                        let a = self.pop()?.as_u32();
                        if b == 0 { return Err(Trap::DivisionByZero); }
                        self.push(Value::I32((a / b) as i32))?;
                    }
                    op::I32_REM_S => {
                        let b = self.pop()?.as_i32();
                        let a = self.pop()?.as_i32();
                        if b == 0 { return Err(Trap::DivisionByZero); }
                        self.push(Value::I32(a.wrapping_rem(b)))?;
                    }
                    op::I32_REM_U => {
                        let b = self.pop()?.as_u32();
                        let a = self.pop()?.as_u32();
                        if b == 0 { return Err(Trap::DivisionByZero); }
                        self.push(Value::I32((a % b) as i32))?;
                    }
                    op::I32_AND => { let (b, a) = (self.pop()?.as_i32(), self.pop()?.as_i32()); self.push(Value::I32(a & b))?; }
                    op::I32_OR => { let (b, a) = (self.pop()?.as_i32(), self.pop()?.as_i32()); self.push(Value::I32(a | b))?; }
                    op::I32_XOR => { let (b, a) = (self.pop()?.as_i32(), self.pop()?.as_i32()); self.push(Value::I32(a ^ b))?; }
                    op::I32_SHL => { let (b, a) = (self.pop()?.as_u32(), self.pop()?.as_i32()); self.push(Value::I32(a.wrapping_shl(b & 31)))?; }
                    op::I32_SHR_S => { let (b, a) = (self.pop()?.as_u32(), self.pop()?.as_i32()); self.push(Value::I32(a.wrapping_shr(b & 31)))?; }
                    op::I32_SHR_U => { let (b, a) = (self.pop()?.as_u32(), self.pop()?.as_u32()); self.push(Value::I32((a.wrapping_shr(b & 31)) as i32))?; }

                    // --- i64 arithmetic ---
                    op::I64_ADD => { let (b, a) = (self.pop()?.as_i64(), self.pop()?.as_i64()); self.push(Value::I64(a.wrapping_add(b)))?; }
                    op::I64_SUB => { let (b, a) = (self.pop()?.as_i64(), self.pop()?.as_i64()); self.push(Value::I64(a.wrapping_sub(b)))?; }
                    op::I64_MUL => { let (b, a) = (self.pop()?.as_i64(), self.pop()?.as_i64()); self.push(Value::I64(a.wrapping_mul(b)))?; }
                    op::I64_DIV_S => {
                        let b = self.pop()?.as_i64();
                        let a = self.pop()?.as_i64();
                        if b == 0 { return Err(Trap::DivisionByZero); }
                        self.push(Value::I64(a.wrapping_div(b)))?;
                    }
                    op::I64_AND => { let (b, a) = (self.pop()?.as_i64(), self.pop()?.as_i64()); self.push(Value::I64(a & b))?; }
                    op::I64_OR => { let (b, a) = (self.pop()?.as_i64(), self.pop()?.as_i64()); self.push(Value::I64(a | b))?; }
                    op::I64_XOR => { let (b, a) = (self.pop()?.as_i64(), self.pop()?.as_i64()); self.push(Value::I64(a ^ b))?; }
                    op::I64_SHL => { let (b, a) = (self.pop()?.as_i64(), self.pop()?.as_i64()); self.push(Value::I64(a.wrapping_shl((b & 63) as u32)))?; }
                    op::I64_SHR_S => { let (b, a) = (self.pop()?.as_i64(), self.pop()?.as_i64()); self.push(Value::I64(a.wrapping_shr((b & 63) as u32)))?; }
                    op::I64_SHR_U => {
                        let b = self.pop()?.as_i64();
                        let a = self.pop()?.as_i64();
                        self.push(Value::I64(((a as u64).wrapping_shr((b & 63) as u32)) as i64))?;
                    }

                    // --- Conversions ---
                    op::I32_WRAP_I64 => {
                        let a = self.pop()?.as_i64();
                        self.push(Value::I32(a as i32))?;
                    }
                    op::I64_EXTEND_I32_S => {
                        let a = self.pop()?.as_i32();
                        self.push(Value::I64(a as i64))?;
                    }
                    op::I64_EXTEND_I32_U => {
                        let a = self.pop()?.as_u32();
                        self.push(Value::I64(a as i64))?;
                    }

                    _ => return Err(Trap::InvalidOpcode(opcode)),
                }
            }

            // Function ended (reached end of code).
            self.fp -= 1;
            if self.fp > 0 {
                // Return to caller — update IP already saved.
                break;
            }
        }

        Ok(())
    }

    /// Push a value onto the operand stack.
    fn push(&mut self, val: Value) -> Result<(), Trap> {
        if self.sp >= MAX_STACK {
            return Err(Trap::StackOverflow);
        }
        self.stack[self.sp] = val;
        self.sp += 1;
        Ok(())
    }

    /// Pop a value from the operand stack.
    fn pop(&mut self) -> Result<Value, Trap> {
        if self.sp == 0 {
            return Err(Trap::StackUnderflow);
        }
        self.sp -= 1;
        Ok(self.stack[self.sp])
    }

    /// Peek at the top of the stack without popping.
    fn peek(&self) -> Result<Value, Trap> {
        if self.sp == 0 {
            return Err(Trap::StackUnderflow);
        }
        Ok(self.stack[self.sp - 1])
    }

    /// Set up a new call frame for a function call.
    fn call_function(&mut self, module: &Module, func_idx: u32) -> Result<(), Trap> {
        if self.fp >= MAX_CALL_DEPTH {
            return Err(Trap::CallStackOverflow);
        }
        if func_idx as usize >= module.func_count {
            return Err(Trap::UndefinedFunction);
        }

        let func = &module.functions[func_idx as usize];
        let ftype = &module.types[func.type_idx as usize];
        let total_locals = ftype.param_count + func.local_count;
        let local_base = self.fp * MAX_LOCALS_PER_FRAME;

        // Pop arguments from stack into locals.
        for i in (0..ftype.param_count).rev() {
            self.locals[local_base + i] = self.pop()?;
        }
        // Initialize declared locals to zero.
        for i in ftype.param_count..total_locals {
            self.locals[local_base + i] = match func.locals[i - ftype.param_count] {
                ValType::I32 => Value::I32(0),
                ValType::I64 => Value::I64(0),
            };
        }

        self.frames[self.fp] = CallFrame {
            func_idx,
            ip: func.code_offset,
            ip_end: func.code_offset + func.code_len,
            local_base,
            local_count: total_locals,
            stack_base: self.sp,
            has_result: ftype.result.is_some(),
        };
        self.fp += 1;
        Ok(())
    }

    // --- SFI-protected memory access ---

    /// Load i32 from linear memory with bounds checking.
    fn mem_load_i32(&self, addr: usize) -> Result<i32, Trap> {
        if addr + 4 > self.memory_size {
            return Err(Trap::OutOfBoundsMemoryAccess);
        }
        let bytes = [
            self.memory[addr],
            self.memory[addr + 1],
            self.memory[addr + 2],
            self.memory[addr + 3],
        ];
        Ok(i32::from_le_bytes(bytes))
    }

    /// Load i64 from linear memory with bounds checking.
    fn mem_load_i64(&self, addr: usize) -> Result<i64, Trap> {
        if addr + 8 > self.memory_size {
            return Err(Trap::OutOfBoundsMemoryAccess);
        }
        let mut bytes = [0u8; 8];
        bytes.copy_from_slice(&self.memory[addr..addr + 8]);
        Ok(i64::from_le_bytes(bytes))
    }

    /// Store i32 to linear memory with bounds checking.
    fn mem_store_i32(&mut self, addr: usize, val: i32) -> Result<(), Trap> {
        if addr + 4 > self.memory_size {
            return Err(Trap::OutOfBoundsMemoryAccess);
        }
        let bytes = val.to_le_bytes();
        self.memory[addr..addr + 4].copy_from_slice(&bytes);
        Ok(())
    }

    /// Store i64 to linear memory with bounds checking.
    fn mem_store_i64(&mut self, addr: usize, val: i64) -> Result<(), Trap> {
        if addr + 8 > self.memory_size {
            return Err(Trap::OutOfBoundsMemoryAccess);
        }
        let bytes = val.to_le_bytes();
        self.memory[addr..addr + 8].copy_from_slice(&bytes);
        Ok(())
    }

    /// Read a byte from linear memory (for debugging / inspection).
    pub fn mem_read_byte(&self, addr: usize) -> Result<u8, Trap> {
        if addr >= self.memory_size {
            return Err(Trap::OutOfBoundsMemoryAccess);
        }
        Ok(self.memory[addr])
    }

    /// Write a byte to linear memory (for initialization).
    pub fn mem_write_byte(&mut self, addr: usize, val: u8) -> Result<(), Trap> {
        if addr >= self.memory_size {
            return Err(Trap::OutOfBoundsMemoryAccess);
        }
        self.memory[addr] = val;
        Ok(())
    }
}

/// Find the matching `end` opcode for a block/loop/if, handling nesting.
fn find_end(code: &[u8], mut ip: usize, limit: usize) -> usize {
    let mut depth = 1u32;
    while ip < limit && depth > 0 {
        match code[ip] {
            op::BLOCK | op::LOOP | op::IF => depth += 1,
            op::END => depth -= 1,
            op::I32_CONST => { if let Some((_, n)) = decode::read_i32_leb128(&code[ip + 1..]) { ip += n; } }
            op::I64_CONST => { if let Some((_, n)) = decode::read_i64_leb128(&code[ip + 1..]) { ip += n; } }
            _ => {}
        }
        ip += 1;
    }
    ip
}

/// Find the matching `else` opcode for an `if` block, or return `limit` if no else.
fn find_else(code: &[u8], mut ip: usize, limit: usize) -> usize {
    let mut depth = 1u32;
    while ip < limit {
        match code[ip] {
            op::BLOCK | op::LOOP | op::IF => depth += 1,
            op::END => {
                depth -= 1;
                if depth == 0 { return ip + 1; }
            }
            op::ELSE if depth == 1 => return ip + 1,
            _ => {}
        }
        ip += 1;
    }
    limit
}
