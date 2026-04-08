//! Kernel-side service registry.
//!
//! Maps service names to IPC endpoint capabilities. Avoids the
//! chicken-and-egg problem of a userspace nameserver: processes
//! can register and look up services without needing IPC first.

use sotos_common::SysError;
use spin::Mutex;

const MAX_SERVICES: usize = 32;
const MAX_NAME_LEN: usize = 31;

/// A registered service entry.
struct ServiceEntry {
    name: [u8; MAX_NAME_LEN],
    name_len: u8,
    /// Raw endpoint pool handle ID (from CapObject::Endpoint { id }).
    ep_id: u32,
    active: bool,
}

impl ServiceEntry {
    const fn empty() -> Self {
        Self {
            name: [0; MAX_NAME_LEN],
            name_len: 0,
            ep_id: 0,
            active: false,
        }
    }
}

struct Registry {
    entries: [ServiceEntry; MAX_SERVICES],
    count: usize,
}

impl Registry {
    const fn new() -> Self {
        Self {
            entries: [const { ServiceEntry::empty() }; MAX_SERVICES],
            count: 0,
        }
    }

    fn register(&mut self, name: &[u8], ep_id: u32) -> Result<(), SysError> {
        if name.is_empty() || name.len() > MAX_NAME_LEN {
            return Err(SysError::InvalidArg);
        }

        // Check for duplicate name.
        for entry in self.entries.iter() {
            if entry.active
                && entry.name_len as usize == name.len()
                && &entry.name[..name.len()] == name
            {
                return Err(SysError::InvalidArg);
            }
        }

        // Find a free slot.
        for entry in self.entries.iter_mut() {
            if !entry.active {
                entry.name[..name.len()].copy_from_slice(name);
                entry.name_len = name.len() as u8;
                entry.ep_id = ep_id;
                entry.active = true;
                self.count += 1;
                return Ok(());
            }
        }

        Err(SysError::OutOfResources)
    }

    fn lookup(&self, name: &[u8]) -> Result<u32, SysError> {
        if name.is_empty() || name.len() > MAX_NAME_LEN {
            return Err(SysError::InvalidArg);
        }

        for entry in self.entries.iter() {
            if entry.active
                && entry.name_len as usize == name.len()
                && &entry.name[..name.len()] == name
            {
                return Ok(entry.ep_id);
            }
        }

        Err(SysError::NotFound)
    }
}

static REGISTRY: Mutex<Registry> = Mutex::new(Registry::new());

/// Register a service name → endpoint mapping.
/// The caller must have already validated the endpoint capability.
pub fn register(name: &[u8], ep_id: u32) -> Result<(), SysError> {
    REGISTRY.lock().register(name, ep_id)
}

/// Look up a service by name. Returns the endpoint pool handle ID.
pub fn lookup(name: &[u8]) -> Result<u32, SysError> {
    REGISTRY.lock().lookup(name)
}
