//! Network protocol stack for sotOS.
//!
//! Pure protocol logic (Ethernet, ARP, IPv4, ICMP, UDP, TCP).
//! No device I/O — works with raw byte buffers.

#![no_std]

pub mod checksum;
pub mod eth;
pub mod arp;
pub mod ip;
pub mod icmp;
pub mod udp;
pub mod tcp;
pub mod dns;
pub mod dhcp;
