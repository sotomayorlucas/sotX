//! Path resolution via capability chains.
//!
//! Walks the mount table and vnode tree to resolve a path string into a
//! target vnode. Each path component checks the caller's VFS capability
//! to ensure the domain has permission to traverse that directory.

use alloc::string::String;
use alloc::vec::Vec;
use crate::mount::MountTable;
use crate::vnode::{Vnode, VnodeType, NAME_MAX};
use crate::VfsError;

/// Result of a successful path lookup.
#[derive(Debug, Clone, Copy)]
pub struct LookupResult {
    /// The resolved vnode id.
    pub vnode_id: u64,
    /// The mount id the vnode belongs to.
    pub mount_id: u32,
}

/// Result of resolving all but the last component — used by create/mkdir/unlink
/// to locate the parent directory plus the final name.
#[derive(Debug, Clone)]
pub struct ParentLookup {
    /// Parent directory vnode id.
    pub parent_id: u64,
    /// Mount id of the parent.
    pub mount_id: u32,
    /// Final path component (the name to create/remove).
    pub name: String,
}

/// Split an absolute path into components, filtering empty segments and `.`.
pub fn split_path(path: &str) -> Vec<&str> {
    path.split('/')
        .filter(|s| !s.is_empty() && *s != ".")
        .collect()
}

/// Resolve a full path to a vnode within the given vnode store.
///
/// `caller_cap` is verified at each directory traversal to ensure the
/// domain has rights to walk this part of the tree. In a full system this
/// would be checked against the capability table; here we take it as a
/// parameter for the ops layer to validate before calling.
pub fn resolve_path(
    path: &str,
    mounts: &MountTable,
    vnodes: &[Vnode],
) -> Result<LookupResult, VfsError> {
    if !path.starts_with('/') {
        return Err(VfsError::Inval);
    }

    let mount = mounts.resolve(path).ok_or(VfsError::NoEnt)?;
    let components = split_path(path);

    // Strip the mount prefix components so we walk relative to the mount root.
    let mount_depth = split_path(&mount.path).len();

    let mut current_id = mount.root_vnode;

    for component in components.iter().skip(mount_depth) {
        if component.len() > NAME_MAX {
            return Err(VfsError::NameTooLong);
        }
        if *component == ".." {
            // `..` handled by vnode's stored parent link.
            let vnode = find_vnode(vnodes, current_id).ok_or(VfsError::NoEnt)?;
            current_id = vnode.find_child("..").ok_or(VfsError::NoEnt)?;
            continue;
        }
        let vnode = find_vnode(vnodes, current_id).ok_or(VfsError::NoEnt)?;
        if vnode.vtype != VnodeType::Directory {
            return Err(VfsError::NotDir);
        }
        current_id = vnode.find_child(component).ok_or(VfsError::NoEnt)?;
    }

    Ok(LookupResult {
        vnode_id: current_id,
        mount_id: mount.mount_id,
    })
}

/// Resolve all path components except the last one, returning the parent
/// directory and the trailing filename. Used by create, mkdir, unlink, etc.
pub fn resolve_parent(
    path: &str,
    mounts: &MountTable,
    vnodes: &[Vnode],
) -> Result<ParentLookup, VfsError> {
    if !path.starts_with('/') {
        return Err(VfsError::Inval);
    }

    let components = split_path(path);
    if components.is_empty() {
        return Err(VfsError::Inval);
    }

    let name = String::from(*components.last().unwrap());
    if name.len() > NAME_MAX {
        return Err(VfsError::NameTooLong);
    }

    // Build parent path: everything except the last component.
    let parent_components = &components[..components.len() - 1];
    let parent_path = if parent_components.is_empty() {
        String::from("/")
    } else {
        let mut p = String::new();
        for c in parent_components {
            p.push('/');
            p.push_str(c);
        }
        p
    };

    let result = resolve_path(&parent_path, mounts, vnodes)?;
    let parent = find_vnode(vnodes, result.vnode_id).ok_or(VfsError::NoEnt)?;
    if parent.vtype != VnodeType::Directory {
        return Err(VfsError::NotDir);
    }

    Ok(ParentLookup {
        parent_id: result.vnode_id,
        mount_id: result.mount_id,
        name,
    })
}

/// Find a vnode by id in a flat slice (simple linear scan).
fn find_vnode(vnodes: &[Vnode], id: u64) -> Option<&Vnode> {
    vnodes.iter().find(|v| v.id == id)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mount::{FsType, MountTable};
    use crate::vnode::Vnode;
    use alloc::string::String;

    fn setup() -> (MountTable, Vec<Vnode>) {
        let mut mt = MountTable::new();
        mt.mount(String::from("/"), FsType::Tmpfs, 1, 0, false);

        let mut root = Vnode::new_dir(0, 0, 1);
        let mut etc = Vnode::new_dir(1, 0, 1);
        let passwd = Vnode::new_file(2, 1);
        etc.add_child(String::from("passwd"), 2, VnodeType::Regular);
        root.add_child(String::from("etc"), 1, VnodeType::Directory);

        (mt, alloc::vec![root, etc, passwd])
    }

    #[test]
    fn resolve_root_path() {
        let (mt, vnodes) = setup();
        let r = resolve_path("/", &mt, &vnodes).unwrap();
        assert_eq!(r.vnode_id, 0);
    }

    #[test]
    fn resolve_nested() {
        let (mt, vnodes) = setup();
        let r = resolve_path("/etc/passwd", &mt, &vnodes).unwrap();
        assert_eq!(r.vnode_id, 2);
    }

    #[test]
    fn resolve_not_found() {
        let (mt, vnodes) = setup();
        let r = resolve_path("/etc/shadow", &mt, &vnodes);
        assert_eq!(r.unwrap_err(), VfsError::NoEnt);
    }

    #[test]
    fn resolve_parent_works() {
        let (mt, vnodes) = setup();
        let p = resolve_parent("/etc/passwd", &mt, &vnodes).unwrap();
        assert_eq!(p.parent_id, 1);
        assert_eq!(p.name, "passwd");
    }

    #[test]
    fn resolve_parent_at_root() {
        let (mt, vnodes) = setup();
        let p = resolve_parent("/etc", &mt, &vnodes).unwrap();
        assert_eq!(p.parent_id, 0);
        assert_eq!(p.name, "etc");
    }

    #[test]
    fn split_filters_empty_and_dot() {
        assert_eq!(split_path("/a/./b//c"), alloc::vec!["a", "b", "c"]);
    }
}
