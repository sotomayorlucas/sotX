//! Built-in deception profiles.
//!
//! Each submodule exports a `PROFILE` constant containing a complete
//! `DeceptionProfile` ready to apply via `ProfileRegistry::with_builtins()`.

pub mod centos_database;
pub mod iot_device;
pub mod ubuntu_webserver;
pub mod windows_workstation;
