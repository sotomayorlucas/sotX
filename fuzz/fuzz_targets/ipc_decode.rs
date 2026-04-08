//! Fuzz target: `sotos_common::IpcMsg::decode_from_bytes`.
//!
//! Userspace receivers parse IPC messages out of a kernel-filled ring as
//! raw byte slices (tag + 8 u64 regs, little-endian = 72 bytes). This
//! harness proves that decoding arbitrary bytes is total (never panics)
//! and that encode/decode round-trip as the identity.
//!
//! Invariants:
//!
//! 1. Any slice shorter than `WIRE_SIZE` returns `None` -- no panic.
//! 2. Any slice `>= WIRE_SIZE` returns `Some(msg)`.
//! 3. `encode_to_bytes(decode_from_bytes(bytes)) == bytes[..WIRE_SIZE]`
//!    for any accepted input (canonical form).
//! 4. Double round-trip is the identity on the struct.

#![no_main]

use libfuzzer_sys::fuzz_target;
use sotos_common::IpcMsg;

fuzz_target!(|data: &[u8]| {
    match IpcMsg::decode_from_bytes(data) {
        None => {
            // Must only happen for short inputs.
            assert!(data.len() < IpcMsg::WIRE_SIZE);
        }
        Some(msg) => {
            // Canonical round-trip.
            let re = msg.encode_to_bytes();
            assert_eq!(
                &re[..],
                &data[..IpcMsg::WIRE_SIZE],
                "encode/decode not round-trip identity"
            );

            // Double round-trip on the struct.
            let msg2 = IpcMsg::decode_from_bytes(&re).expect("re-decode must succeed");
            assert_eq!(msg.tag, msg2.tag);
            assert_eq!(msg.regs, msg2.regs);
        }
    }
});
