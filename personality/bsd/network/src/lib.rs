//! BSD network stack domain for sotOS Project STYX.
//!
//! Implements the BSD socket model where every socket is a SecureObject
//! governed by capabilities. The network domain owns protocol processing
//! (TCP/UDP/ICMP), interface abstraction (ifnet), and a PF firewall that
//! acts as a capability interposer between client domains and the real
//! network.

#![no_std]

extern crate alloc;

pub mod ifnet;
pub mod pf;
pub mod protocol;
pub mod socket;
