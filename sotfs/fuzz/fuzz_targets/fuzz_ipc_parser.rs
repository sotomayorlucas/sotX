//! Fuzz target: IPC message parser from the bare-metal sotfs service.
//!
//! Feeds arbitrary (tag, regs[8]) tuples to the VfsOp dispatcher and
//! name extraction logic. Must never panic on malformed input.
//!
//! Run: cd sotfs/fuzz && cargo +nightly fuzz run fuzz_ipc_parser -- -runs=500000

#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

/// Replicated VfsOp::from_tag from services/sotfs/src/graph.rs
fn vfsop_from_tag(tag: u64) -> &'static str {
    match tag {
        1 => "Open",
        2 => "Close",
        3 => "Read",
        4 => "Write",
        5 => "Stat",
        6 => "Readdir",
        7 => "Mkdir",
        8 => "Rmdir",
        9 => "Unlink",
        10 => "Rename",
        12 => "Fstat",
        _ => "Unknown",
    }
}

/// Replicated extract_name from services/sotfs/src/main.rs
/// Extracts a null-terminated string from IPC register data.
fn extract_name(regs: &[u64]) -> String {
    let mut buf = Vec::new();
    for &r in regs {
        let bytes = r.to_le_bytes();
        for &b in &bytes {
            if b == 0 {
                return String::from_utf8_lossy(&buf).to_string();
            }
            buf.push(b);
        }
    }
    String::from_utf8_lossy(&buf).to_string()
}

use std::string::String;
use std::vec::Vec;

#[derive(Debug, Arbitrary)]
struct IpcMessage {
    tag: u64,
    regs: [u64; 8],
}

fuzz_target!(|msg: IpcMessage| {
    // VfsOp dispatch must never panic
    let _op = vfsop_from_tag(msg.tag);

    // Name extraction must never panic, even with garbage input
    let _name1 = extract_name(&msg.regs[1..]);
    let _name2 = extract_name(&msg.regs[2..5]);
    let _name3 = extract_name(&msg.regs[5..8]);
    let _name4 = extract_name(&msg.regs);

    // Numeric field extraction must never panic
    let _inode_id = msg.regs[0];
    let _offset = msg.regs[1];
    let _len = msg.regs[2] as usize;
    let _flags = msg.regs[3] as u32;
});
