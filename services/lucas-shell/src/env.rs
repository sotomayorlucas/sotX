use crate::syscall::*;

// ---------------------------------------------------------------------------
// Environment variables
// ---------------------------------------------------------------------------

pub const MAX_ENV_VARS: usize = 32;
pub const MAX_KEY_LEN: usize = 32;
pub const MAX_VAL_LEN: usize = 128;

pub struct EnvVar {
    pub key: [u8; MAX_KEY_LEN],
    pub key_len: usize,
    pub val: [u8; MAX_VAL_LEN],
    pub val_len: usize,
    pub active: bool,
}

impl EnvVar {
    pub const fn empty() -> Self {
        Self { key: [0; MAX_KEY_LEN], key_len: 0, val: [0; MAX_VAL_LEN], val_len: 0, active: false }
    }
}

pub static mut ENV: [EnvVar; MAX_ENV_VARS] = {
    const INIT: EnvVar = EnvVar::empty();
    [INIT; MAX_ENV_VARS]
};

pub fn env_slice() -> &'static [EnvVar] {
    unsafe { core::slice::from_raw_parts(core::ptr::addr_of!(ENV) as *const EnvVar, MAX_ENV_VARS) }
}

pub fn env_slice_mut() -> &'static mut [EnvVar] {
    unsafe { core::slice::from_raw_parts_mut(core::ptr::addr_of_mut!(ENV) as *mut EnvVar, MAX_ENV_VARS) }
}

pub fn env_set(key: &[u8], val: &[u8]) {
    // Update existing.
    for e in env_slice_mut().iter_mut() {
        if e.active && e.key_len == key.len() && e.key[..e.key_len] == *key {
            let vl = val.len().min(MAX_VAL_LEN);
            e.val[..vl].copy_from_slice(&val[..vl]);
            e.val_len = vl;
            return;
        }
    }
    // Insert new.
    for e in env_slice_mut().iter_mut() {
        if !e.active {
            let kl = key.len().min(MAX_KEY_LEN);
            let vl = val.len().min(MAX_VAL_LEN);
            e.key[..kl].copy_from_slice(&key[..kl]);
            e.key_len = kl;
            e.val[..vl].copy_from_slice(&val[..vl]);
            e.val_len = vl;
            e.active = true;
            return;
        }
    }
}

pub fn env_get(key: &[u8]) -> Option<&'static [u8]> {
    for e in env_slice() {
        if e.active && e.key_len == key.len() && e.key[..e.key_len] == *key {
            return Some(&e.val[..e.val_len]);
        }
    }
    None
}

pub fn env_unset(key: &[u8]) {
    for e in env_slice_mut().iter_mut() {
        if e.active && e.key_len == key.len() && e.key[..e.key_len] == *key {
            e.active = false;
            return;
        }
    }
}

pub fn cmd_env() {
    for e in env_slice() {
        if e.active {
            print(&e.key[..e.key_len]);
            print(b"=");
            print(&e.val[..e.val_len]);
            print(b"\n");
        }
    }
}
