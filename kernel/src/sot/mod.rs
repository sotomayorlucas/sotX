//! SOT security primitives -- adapted from OpenBSD.
//!
//! This module provides cryptographic and security primitives for the
//! SOT microkernel, ported from well-audited OpenBSD sources:
//!
//! - `crypto` — ChaCha20-based CSPRNG (from OpenBSD arc4random)
//! - `secure_string` — Safe string ops + explicit_bzero (from OpenBSD strlcpy/strlcat)
//! - `wx_enforce` — W^X enforcement per domain (inspired by OpenBSD W^X policy)
//! - `aslr` — Address space layout randomization (inspired by OpenBSD KARL)

pub mod aslr;
pub mod crypto;
pub mod secure_string;
pub mod wx_enforce;
