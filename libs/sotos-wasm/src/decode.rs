//! WASM binary format decoder (LEB128 encoding + section parsing).

/// Read an unsigned LEB128 integer from a byte slice.
/// Returns (value, bytes_consumed).
pub fn read_u32_leb128(data: &[u8]) -> Option<(u32, usize)> {
    let mut result: u32 = 0;
    let mut shift = 0;
    for (i, &byte) in data.iter().enumerate() {
        if i >= 5 {
            return None; // Too many bytes for u32
        }
        result |= ((byte & 0x7F) as u32) << shift;
        shift += 7;
        if byte & 0x80 == 0 {
            return Some((result, i + 1));
        }
    }
    None
}

/// Read a signed LEB128 i32 from a byte slice.
pub fn read_i32_leb128(data: &[u8]) -> Option<(i32, usize)> {
    let mut result: i32 = 0;
    let mut shift = 0;
    let mut byte = 0u8;
    let mut count = 0;
    for (i, &b) in data.iter().enumerate() {
        if i >= 5 {
            return None;
        }
        byte = b;
        result |= ((byte & 0x7F) as i32) << shift;
        shift += 7;
        count = i + 1;
        if byte & 0x80 == 0 {
            break;
        }
    }
    // Sign extend
    if shift < 32 && (byte & 0x40) != 0 {
        result |= !0i32 << shift;
    }
    Some((result, count))
}

/// Read a signed LEB128 i64 from a byte slice.
pub fn read_i64_leb128(data: &[u8]) -> Option<(i64, usize)> {
    let mut result: i64 = 0;
    let mut shift = 0;
    let mut byte = 0u8;
    let mut count = 0;
    for (i, &b) in data.iter().enumerate() {
        if i >= 10 {
            return None;
        }
        byte = b;
        result |= ((byte & 0x7F) as i64) << shift;
        shift += 7;
        count = i + 1;
        if byte & 0x80 == 0 {
            break;
        }
    }
    if shift < 64 && (byte & 0x40) != 0 {
        result |= !0i64 << shift;
    }
    Some((result, count))
}

/// WASM opcode constants.
pub mod op {
    // Control flow
    pub const UNREACHABLE: u8 = 0x00;
    pub const NOP: u8 = 0x01;
    pub const BLOCK: u8 = 0x02;
    pub const LOOP: u8 = 0x03;
    pub const IF: u8 = 0x04;
    pub const ELSE: u8 = 0x05;
    pub const END: u8 = 0x0B;
    pub const BR: u8 = 0x0C;
    pub const BR_IF: u8 = 0x0D;
    pub const RETURN: u8 = 0x0F;
    pub const CALL: u8 = 0x10;

    // Variable access
    pub const LOCAL_GET: u8 = 0x20;
    pub const LOCAL_SET: u8 = 0x21;
    pub const LOCAL_TEE: u8 = 0x22;
    pub const GLOBAL_GET: u8 = 0x23;
    pub const GLOBAL_SET: u8 = 0x24;

    // Memory
    pub const I32_LOAD: u8 = 0x28;
    pub const I64_LOAD: u8 = 0x29;
    pub const I32_STORE: u8 = 0x36;
    pub const I64_STORE: u8 = 0x37;
    pub const MEMORY_SIZE: u8 = 0x3F;
    pub const MEMORY_GROW: u8 = 0x40;

    // Constants
    pub const I32_CONST: u8 = 0x41;
    pub const I64_CONST: u8 = 0x42;

    // i32 comparison
    pub const I32_EQZ: u8 = 0x45;
    pub const I32_EQ: u8 = 0x46;
    pub const I32_NE: u8 = 0x47;
    pub const I32_LT_S: u8 = 0x48;
    pub const I32_LT_U: u8 = 0x49;
    pub const I32_GT_S: u8 = 0x4A;
    pub const I32_GT_U: u8 = 0x4B;
    pub const I32_LE_S: u8 = 0x4C;
    pub const I32_LE_U: u8 = 0x4D;
    pub const I32_GE_S: u8 = 0x4E;
    pub const I32_GE_U: u8 = 0x4F;

    // i64 comparison
    pub const I64_EQZ: u8 = 0x50;
    pub const I64_EQ: u8 = 0x51;
    pub const I64_NE: u8 = 0x52;
    pub const I64_LT_S: u8 = 0x53;
    pub const I64_GT_S: u8 = 0x55;

    // i32 arithmetic
    pub const I32_ADD: u8 = 0x6A;
    pub const I32_SUB: u8 = 0x6B;
    pub const I32_MUL: u8 = 0x6C;
    pub const I32_DIV_S: u8 = 0x6D;
    pub const I32_DIV_U: u8 = 0x6E;
    pub const I32_REM_S: u8 = 0x6F;
    pub const I32_REM_U: u8 = 0x70;
    pub const I32_AND: u8 = 0x71;
    pub const I32_OR: u8 = 0x72;
    pub const I32_XOR: u8 = 0x73;
    pub const I32_SHL: u8 = 0x74;
    pub const I32_SHR_S: u8 = 0x75;
    pub const I32_SHR_U: u8 = 0x76;

    // i64 arithmetic
    pub const I64_ADD: u8 = 0x7C;
    pub const I64_SUB: u8 = 0x7D;
    pub const I64_MUL: u8 = 0x7E;
    pub const I64_DIV_S: u8 = 0x7F;
    pub const I64_AND: u8 = 0x83;
    pub const I64_OR: u8 = 0x84;
    pub const I64_XOR: u8 = 0x85;
    pub const I64_SHL: u8 = 0x86;
    pub const I64_SHR_S: u8 = 0x87;
    pub const I64_SHR_U: u8 = 0x88;

    // Conversions
    pub const I32_WRAP_I64: u8 = 0xA7;
    pub const I64_EXTEND_I32_S: u8 = 0xAC;
    pub const I64_EXTEND_I32_U: u8 = 0xAD;

    // Drop / Select
    pub const DROP: u8 = 0x1A;
    pub const SELECT: u8 = 0x1B;
}

/// WASM section IDs.
pub mod section {
    pub const TYPE: u8 = 1;
    pub const FUNCTION: u8 = 3;
    pub const MEMORY: u8 = 5;
    pub const GLOBAL: u8 = 6;
    pub const EXPORT: u8 = 7;
    pub const CODE: u8 = 10;
}

/// WASM type encoding.
pub mod valtype {
    pub const I32: u8 = 0x7F;
    pub const I64: u8 = 0x7E;
    pub const FUNC: u8 = 0x60;
    pub const EMPTY: u8 = 0x40;
}
