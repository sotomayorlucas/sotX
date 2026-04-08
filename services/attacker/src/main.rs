//! Tier 3 demo "attacker" — a userspace process that emits realistic
//! provenance entries onto the kernel SOT ring so the deception
//! pipeline runs against live data instead of a synthetic trace.
//!
//! It impersonates `domain 7` (the value `deception_demo` migrates) and
//! drives the canonical CredentialTheftAfterBackdoor sequence:
//!
//!   1. Backdoor a system binary: emit one
//!      `(Operation::Write, SoType::SystemBinary, /sbin/sshd)` event.
//!   2. Read /etc/shadow: emit one
//!      `(Operation::Read,  SoType::Credential,  /etc/shadow)` event.
//!   3. Read /proc/version: emit one informational
//!      `(Operation::Read,  SoType::ConfigFile,  /proc/version)` event
//!      so the post-migration interposition lookup has a meaningful
//!      target visible in the ring.
//!
//! All entries land in the per-CPU provenance ring via `SYS_PROVENANCE_EMIT`
//! and are later drained by `init`'s deception_demo. Because the entries
//! carry the proper `Operation` + `SoType` tags, the GraphHunter
//! `match_credential_theft` rule fires on real drained data instead of
//! the synthetic fallback trace.
//!
//! No real files are touched -- this is pure provenance signalling.

#![no_std]
#![no_main]

use sotos_common::sys;

const ATTACKER_DOMAIN: u32 = 7;

// Match `sotos_provenance::Operation` (u16).
const OP_READ: u16 = 1;
const OP_WRITE: u16 = 2;

// Match `sotos_provenance::SoType` (u8).
const SOTYPE_SYSTEM_BINARY: u8 = 6;
const SOTYPE_CREDENTIAL: u8 = 7;
const SOTYPE_CONFIG_FILE: u8 = 8;

// Logical object ids that fall in the deception detector's known ranges
// (`personality/common/deception/src/anomaly.rs::is_system_binary` etc.)
// AND happen to be the same constants the userspace deception_demo uses
// when looking up the fake /proc/version in the Ubuntu profile.
const OBJ_SBIN_SSHD: u64 = 0xA0_05;
const OBJ_ETC_SHADOW: u64 = 0xF001;
const OBJ_PROC_VERSION: u64 = 0x1_0001;

fn print(s: &[u8]) {
    for &b in s {
        sys::debug_print(b);
    }
}

fn print_u64(mut n: u64) {
    if n == 0 {
        sys::debug_print(b'0');
        return;
    }
    let mut buf = [0u8; 20];
    let mut i = 0;
    while n > 0 {
        buf[i] = b'0' + (n % 10) as u8;
        n /= 10;
        i += 1;
    }
    while i > 0 {
        i -= 1;
        sys::debug_print(buf[i]);
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    print(b"ATTACKER: domain=");
    print_u64(ATTACKER_DOMAIN as u64);
    print(b", emitting provenance for CredentialTheftAfterBackdoor\n");

    // Step 1: backdoor /sbin/sshd
    sys::provenance_emit(OP_WRITE, SOTYPE_SYSTEM_BINARY, OBJ_SBIN_SSHD, ATTACKER_DOMAIN);
    print(b"ATTACKER: 1) Write SystemBinary /sbin/sshd\n");

    // Step 2: read /etc/shadow
    sys::provenance_emit(OP_READ, SOTYPE_CREDENTIAL, OBJ_ETC_SHADOW, ATTACKER_DOMAIN);
    print(b"ATTACKER: 2) Read  Credential   /etc/shadow\n");

    // Step 3: read /proc/version (the file the attacker will see spoofed
    // after migration). Marked as ConfigFile so it shows up in the ring
    // without tripping the credential rule a second time.
    sys::provenance_emit(OP_READ, SOTYPE_CONFIG_FILE, OBJ_PROC_VERSION, ATTACKER_DOMAIN);
    print(b"ATTACKER: 3) Read  ConfigFile   /proc/version\n");

    print(b"ATTACKER: emitted 3 provenance events; exiting cleanly\n");
    sys::thread_exit();
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    print(b"ATTACKER: PANIC!\n");
    loop { sys::yield_now(); }
}
