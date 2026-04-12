//! sotOS Theme — canonical Tokyo Night palette, geometry, and ANSI helpers.
//!
//! `#![no_std]`, zero dependencies. Every color, layout constant, and ANSI
//! escape sequence used across the sotOS UI lives here so that the five+
//! consumer crates (compositor, sotos-gui, init framebuffer, sot-statusbar,
//! hello-gui) share a single source of truth instead of drifting copies.

#![no_std]

pub mod palette;
pub mod geometry;
pub mod ansi;

// Re-export the main palette instance at the crate root for convenience.
pub use palette::{Palette, TOKYO_NIGHT, ANSI_16, rgb_components};
pub use geometry::*;
