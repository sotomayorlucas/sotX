//! sotX Package Manager — package registry and dependency management.
//!
//! Provides a minimal package management system for sotX:
//! - Package registration with name, version, description, dependencies
//! - Dependency checking (are all deps installed?)
//! - Install/uninstall (marks packages; actual binary loading uses initrd)
//! - Package listing and lookup
//! - SHA-256 checksum for integrity verification
//!
//! All data structures are fixed-size, no_std, no heap.

#![no_std]

/// Maximum number of packages in the registry.
pub const MAX_PACKAGES: usize = 64;
/// Maximum dependencies per package.
pub const MAX_DEPS: usize = 4;
/// Maximum name length.
pub const PKG_NAME_LEN: usize = 32;
/// Maximum version string length.
pub const PKG_VERSION_LEN: usize = 16;
/// Maximum description length.
pub const PKG_DESC_LEN: usize = 128;
/// Maximum install directory length.
pub const PKG_DIR_LEN: usize = 64;

/// A package entry in the registry.
#[derive(Clone, Copy)]
pub struct Package {
    /// Package name (null-terminated).
    pub name: [u8; PKG_NAME_LEN],
    /// Version string (semver, null-terminated, e.g. "1.2.3").
    pub version: [u8; PKG_VERSION_LEN],
    /// Human-readable description.
    pub description: [u8; PKG_DESC_LEN],
    /// Package size in bytes (of the binary/archive).
    pub size: u32,
    /// SHA-256 checksum of the package contents.
    pub checksum: [u8; 32],
    /// Whether this package is currently installed.
    pub installed: bool,
    /// Dependency names (up to MAX_DEPS).
    pub deps: [[u8; PKG_NAME_LEN]; MAX_DEPS],
    /// Number of dependencies.
    pub dep_count: u8,
}

impl Package {
    pub const fn empty() -> Self {
        Self {
            name: [0; PKG_NAME_LEN],
            version: [0; PKG_VERSION_LEN],
            description: [0; PKG_DESC_LEN],
            size: 0,
            checksum: [0; 32],
            installed: false,
            deps: [[0; PKG_NAME_LEN]; MAX_DEPS],
            dep_count: 0,
        }
    }

    /// Get the name as a byte slice.
    pub fn name_str(&self) -> &[u8] {
        let len = self.name.iter().position(|&b| b == 0).unwrap_or(PKG_NAME_LEN);
        &self.name[..len]
    }

    /// Get the version as a byte slice.
    pub fn version_str(&self) -> &[u8] {
        let len = self
            .version
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(PKG_VERSION_LEN);
        &self.version[..len]
    }

    /// Get the description as a byte slice.
    pub fn description_str(&self) -> &[u8] {
        let len = self
            .description
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(PKG_DESC_LEN);
        &self.description[..len]
    }

    /// Get the name of dependency at index `i`.
    pub fn dep_name(&self, i: usize) -> &[u8] {
        if i >= self.dep_count as usize {
            return &[];
        }
        let len = self.deps[i]
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(PKG_NAME_LEN);
        &self.deps[i][..len]
    }
}

/// Create a package with the given metadata.
pub fn make_package(
    name: &[u8],
    version: &[u8],
    description: &[u8],
    size: u32,
    checksum: [u8; 32],
) -> Package {
    let mut pkg = Package::empty();
    let name_len = name.len().min(PKG_NAME_LEN - 1);
    pkg.name[..name_len].copy_from_slice(&name[..name_len]);
    let ver_len = version.len().min(PKG_VERSION_LEN - 1);
    pkg.version[..ver_len].copy_from_slice(&version[..ver_len]);
    let desc_len = description.len().min(PKG_DESC_LEN - 1);
    pkg.description[..desc_len].copy_from_slice(&description[..desc_len]);
    pkg.size = size;
    pkg.checksum = checksum;
    pkg
}

/// Add a dependency to a package.
pub fn add_dep(pkg: &mut Package, dep_name: &[u8]) -> bool {
    if pkg.dep_count as usize >= MAX_DEPS {
        return false;
    }
    let idx = pkg.dep_count as usize;
    let copy_len = dep_name.len().min(PKG_NAME_LEN - 1);
    pkg.deps[idx][..copy_len].copy_from_slice(&dep_name[..copy_len]);
    pkg.dep_count += 1;
    true
}

/// The package registry.
pub struct PackageRegistry {
    /// Package slots.
    pub packages: [Package; MAX_PACKAGES],
    /// Number of registered packages.
    pub pkg_count: usize,
    /// Installation directory path.
    pub install_dir: [u8; PKG_DIR_LEN],
}

impl PackageRegistry {
    /// Create a new empty registry.
    pub const fn new() -> Self {
        Self {
            packages: [Package::empty(); MAX_PACKAGES],
            pkg_count: 0,
            install_dir: [0; PKG_DIR_LEN],
        }
    }

    /// Create a new registry with a custom install directory.
    pub fn with_install_dir(dir: &[u8]) -> Self {
        let mut reg = Self::new();
        let copy_len = dir.len().min(PKG_DIR_LEN - 1);
        reg.install_dir[..copy_len].copy_from_slice(&dir[..copy_len]);
        reg
    }

    /// Register a package in the registry.
    ///
    /// If a package with the same name already exists, it is updated.
    /// Returns `true` if the package was registered, `false` if the registry is full.
    pub fn register(&mut self, pkg: Package) -> bool {
        // Check for existing package with same name.
        let pkg_name = pkg.name_str();
        for i in 0..self.pkg_count {
            let existing_name = self.packages[i].name_str();
            if existing_name.len() == pkg_name.len() && existing_name == pkg_name {
                // Update existing.
                let was_installed = self.packages[i].installed;
                self.packages[i] = pkg;
                self.packages[i].installed = was_installed;
                return true;
            }
        }

        if self.pkg_count >= MAX_PACKAGES {
            return false;
        }

        self.packages[self.pkg_count] = pkg;
        self.pkg_count += 1;
        true
    }

    /// Look up a package by name.
    pub fn lookup(&self, name: &[u8]) -> Option<&Package> {
        for i in 0..self.pkg_count {
            let pkg_name = self.packages[i].name_str();
            if pkg_name.len() == name.len() && pkg_name == name {
                return Some(&self.packages[i]);
            }
        }
        None
    }

    /// Look up a package by name (mutable).
    pub fn lookup_mut(&mut self, name: &[u8]) -> Option<&mut Package> {
        for i in 0..self.pkg_count {
            let pkg_name_len = self.packages[i].name_str().len();
            if pkg_name_len == name.len() && self.packages[i].name[..name.len()] == *name {
                return Some(&mut self.packages[i]);
            }
        }
        None
    }

    /// Check if all dependencies for a package are installed.
    ///
    /// Returns `true` if all dependencies are satisfied.
    pub fn check_deps(&self, name: &[u8]) -> bool {
        let pkg = match self.lookup(name) {
            Some(p) => p,
            None => return false,
        };

        for i in 0..pkg.dep_count as usize {
            let dep_name = pkg.dep_name(i);
            if dep_name.is_empty() {
                continue;
            }

            match self.lookup(dep_name) {
                Some(dep) if dep.installed => {}
                _ => return false, // Dependency not found or not installed
            }
        }

        true
    }

    /// Install a package by name.
    ///
    /// Marks the package as installed. Returns `false` if the package
    /// is not found or dependencies are not satisfied.
    ///
    /// Note: Actual binary loading would be done separately (e.g., from initrd).
    pub fn install(&mut self, name: &[u8]) -> bool {
        // First check dependencies.
        if !self.check_deps(name) {
            return false;
        }

        match self.lookup_mut(name) {
            Some(pkg) => {
                pkg.installed = true;
                true
            }
            None => false,
        }
    }

    /// Uninstall a package by name.
    ///
    /// Marks the package as not installed. Checks that no other installed
    /// package depends on this one.
    pub fn uninstall(&mut self, name: &[u8]) -> bool {
        // Check that no installed package depends on this one.
        for i in 0..self.pkg_count {
            if !self.packages[i].installed {
                continue;
            }
            for j in 0..self.packages[i].dep_count as usize {
                let dep_name = self.packages[i].dep_name(j);
                if dep_name.len() == name.len() && dep_name == name {
                    return false; // Another package depends on this
                }
            }
        }

        match self.lookup_mut(name) {
            Some(pkg) => {
                pkg.installed = false;
                true
            }
            None => false,
        }
    }

    /// Count installed packages.
    pub fn installed_count(&self) -> usize {
        let mut count = 0;
        for i in 0..self.pkg_count {
            if self.packages[i].installed {
                count += 1;
            }
        }
        count
    }

    /// Iterate over installed packages.
    ///
    /// Calls `callback` for each installed package. The callback receives
    /// a reference to the package. Returns the number of installed packages.
    pub fn for_each_installed<F>(&self, mut callback: F) -> usize
    where
        F: FnMut(&Package),
    {
        let mut count = 0;
        for i in 0..self.pkg_count {
            if self.packages[i].installed {
                callback(&self.packages[i]);
                count += 1;
            }
        }
        count
    }

    /// List all installed packages into a name buffer.
    ///
    /// Writes installed package names into `names_buf` (separated by newlines).
    /// Returns the number of bytes written.
    pub fn list_installed(&self, names_buf: &mut [u8]) -> usize {
        let mut offset = 0;
        for i in 0..self.pkg_count {
            if !self.packages[i].installed {
                continue;
            }
            let name = self.packages[i].name_str();
            let version = self.packages[i].version_str();
            let needed = name.len() + 1 + version.len() + 1; // "name version\n"
            if offset + needed > names_buf.len() {
                break;
            }
            names_buf[offset..offset + name.len()].copy_from_slice(name);
            offset += name.len();
            names_buf[offset] = b' ';
            offset += 1;
            names_buf[offset..offset + version.len()].copy_from_slice(version);
            offset += version.len();
            names_buf[offset] = b'\n';
            offset += 1;
        }
        offset
    }

    /// Remove a package from the registry entirely (not just uninstall).
    pub fn remove(&mut self, name: &[u8]) -> bool {
        let mut found = usize::MAX;
        for i in 0..self.pkg_count {
            let pkg_name = self.packages[i].name_str();
            if pkg_name.len() == name.len() && pkg_name == name {
                found = i;
                break;
            }
        }
        if found == usize::MAX {
            return false;
        }

        // Shift remaining packages.
        for i in found..self.pkg_count - 1 {
            self.packages[i] = self.packages[i + 1];
        }
        self.packages[self.pkg_count - 1] = Package::empty();
        self.pkg_count -= 1;
        true
    }
}
