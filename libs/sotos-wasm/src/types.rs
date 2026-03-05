//! WASM value types and runtime values.

/// WASM value types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ValType {
    I32,
    I64,
}

/// Runtime value on the operand stack.
#[derive(Debug, Clone, Copy)]
pub enum Value {
    I32(i32),
    I64(i64),
}

impl Value {
    pub fn as_i32(self) -> i32 {
        match self {
            Value::I32(v) => v,
            Value::I64(v) => v as i32,
        }
    }

    pub fn as_i64(self) -> i64 {
        match self {
            Value::I32(v) => v as i64,
            Value::I64(v) => v,
        }
    }

    pub fn as_u32(self) -> u32 {
        self.as_i32() as u32
    }

    pub fn val_type(&self) -> ValType {
        match self {
            Value::I32(_) => ValType::I32,
            Value::I64(_) => ValType::I64,
        }
    }

    pub fn is_truthy(&self) -> bool {
        match self {
            Value::I32(v) => *v != 0,
            Value::I64(v) => *v != 0,
        }
    }
}
