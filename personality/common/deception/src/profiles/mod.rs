//! Built-in deception profiles.
//!
//! Each submodule defines the body of a deception profile (fake files,
//! fake services, etc). The runtime list of builtin profile *names* +
//! their `active` bit lives in `crate::profile::ProfileRegistry`
//! (construct with `ProfileRegistry::with_builtins()`); that registry
//! is what init's `"deception"` IPC service advertises to sotsh. This
//! module does not itself declare submodules yet — they depend on
//! extension types (`NetworkDeceptionConfig`, fake_net, etc.) that
//! have not landed yet — but the registry already knows their canonical
//! names (`ubuntu_webserver`, `centos_database`, `iot_device`,
//! `windows_workstation`).
