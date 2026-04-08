//! Fuzz target: `sotos_common::ProvenanceEntry::decode_from_bytes`.
//!
//! The kernel exposes its per-CPU provenance ring via syscall 260
//! (`SYS_PROVENANCE_DRAIN`), which memcpys 48-byte records into a
//! userspace buffer. Any userspace observer has to parse those records
//! out of raw bytes. This harness proves:
//!
//! 1. Decoding arbitrary bytes is total (never panics).
//! 2. Short input is rejected with `None` (exactly the `< 48` case).
//! 3. Long input is accepted and only reads the first 48 bytes.
//! 4. Encode round-trip is the canonical-form identity.
//! 5. The `is_valid_operation` predicate never panics and is a pure
//!    function of the `operation` field.

#![no_main]

use libfuzzer_sys::fuzz_target;
use sotos_common::{ProvenanceEntry, PROVENANCE_ENTRY_SIZE};

fuzz_target!(|data: &[u8]| {
    match ProvenanceEntry::decode_from_bytes(data) {
        None => {
            assert!(data.len() < PROVENANCE_ENTRY_SIZE);
        }
        Some(entry) => {
            // Round-trip: re-encoding must exactly match the first 48 bytes.
            let re = entry.encode_to_bytes();
            assert_eq!(
                &re[..],
                &data[..PROVENANCE_ENTRY_SIZE],
                "provenance encode/decode not round-trip identity"
            );

            // Double round-trip on the struct itself.
            let entry2 =
                ProvenanceEntry::decode_from_bytes(&re).expect("re-decode must succeed");
            assert_eq!(entry, entry2);

            // Validator is total and deterministic.
            let _ = entry.is_valid_operation();
            let _ = entry2.is_valid_operation();
            assert_eq!(entry.is_valid_operation(), entry2.is_valid_operation());
        }
    }
});
