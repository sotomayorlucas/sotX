//! Built-in: `arm` — list active deception profiles.
//!
//! TODO: once sotsh runs under sotOS, replace hardcoded profile list with
//! IPC call to sotos-init (which hosts sotos-deception at
//! `personality/common/deception/`). Runtime state — which arms are
//! currently *active* vs just defined — will come from that IPC. Until
//! then, return the static list of profiles from sotos-deception.
//! Source: `personality/common/deception/src/profile.rs` and
//! `services/init/src/deception_demo.rs`.
//!
//! Required capabilities: `deception:read` (see [`super::required_caps`]).

use crate::context::Context;
use crate::error::Error;
use crate::value::{Row, Value};

const PROFILES: &[&str] = &[
    "ubuntu_webserver",
    "centos_database",
    "iot_device",
    "windows_workstation",
];

pub fn run(_args: &[Value], _ctx: &mut Context) -> Result<Value, Error> {
    let rows = PROFILES
        .iter()
        .map(|name| {
            Row::new()
                .with("name", Value::Str((*name).into()))
                .with("kind", Value::Str("profile".into()))
        })
        .collect();
    Ok(Value::Table(rows))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn returns_four_profiles() {
        let mut ctx = Context::new().unwrap();
        let v = run(&[], &mut ctx).unwrap();
        let Value::Table(rows) = v else {
            panic!("expected Table");
        };
        assert_eq!(rows.len(), 4);
    }

    #[test]
    fn contains_ubuntu_webserver() {
        let mut ctx = Context::new().unwrap();
        let Value::Table(rows) = run(&[], &mut ctx).unwrap() else {
            panic!("expected Table");
        };
        let found = rows.iter().any(|row| {
            row.cells.iter().any(|(k, v)| {
                k == "name" && matches!(v, Value::Str(s) if s == "ubuntu_webserver")
            })
        });
        assert!(found, "ubuntu_webserver profile not found");
    }
}
