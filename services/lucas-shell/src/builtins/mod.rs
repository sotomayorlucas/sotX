//! Built-in shell commands for lucas-shell.
pub mod text;
pub mod files;
pub mod system;
pub mod apt;
pub mod util;
pub use text::*;
pub use files::*;
pub use system::*;
pub use apt::*;
pub use util::*;
