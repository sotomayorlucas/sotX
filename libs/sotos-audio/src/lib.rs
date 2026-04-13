//! AC'97 audio driver library for sotX.
//!
//! Implements the Intel AC'97 (Audio Codec '97) specification for PCM audio
//! playback through the ICH-compatible Audio Controller. Uses PIO registers
//! (NABM + Mixer) and a Buffer Descriptor List (BDL) for DMA transfers.

#![no_std]

pub mod regs;
pub mod bdl;
pub mod mixer;
pub mod controller;
pub mod playback;
