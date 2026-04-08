//! Multiuser support — user account management and authentication.
//!
//! Provides a simple user account system with:
//! - User registration with name, UID, GID, password hash
//! - Password authentication (SHA-256 hash comparison)
//! - Current user context tracking (uid/gid)
//! - Default root user (uid=0, gid=0)
//!
//! The password hashing uses a simple built-in SHA-256 implementation
//! (no external dependencies). For a production system, this should
//! use a proper key derivation function (PBKDF2, scrypt, argon2).

use spin::Mutex;

/// Maximum number of user accounts.
const MAX_USERS: usize = 32;

/// A user account entry.
#[derive(Clone, Copy)]
pub struct UserAccount {
    /// User ID.
    pub uid: u16,
    /// Group ID.
    pub gid: u16,
    /// User name (null-terminated).
    pub name: [u8; 32],
    /// Password hash (SHA-256 of password).
    pub password_hash: [u8; 32],
    /// Home directory path.
    pub home_dir: [u8; 64],
    /// Default shell path.
    pub shell: [u8; 32],
    /// Whether this account is active.
    pub active: bool,
}

impl UserAccount {
    const fn empty() -> Self {
        Self {
            uid: 0,
            gid: 0,
            name: [0; 32],
            password_hash: [0; 32],
            home_dir: [0; 64],
            shell: [0; 32],
            active: false,
        }
    }

    /// Get the name as a byte slice.
    pub fn name_str(&self) -> &[u8] {
        let len = self.name.iter().position(|&b| b == 0).unwrap_or(32);
        &self.name[..len]
    }

    /// Get the home directory as a byte slice.
    pub fn home_str(&self) -> &[u8] {
        let len = self.home_dir.iter().position(|&b| b == 0).unwrap_or(64);
        &self.home_dir[..len]
    }

    /// Get the shell as a byte slice.
    pub fn shell_str(&self) -> &[u8] {
        let len = self.shell.iter().position(|&b| b == 0).unwrap_or(32);
        &self.shell[..len]
    }
}

/// The global user table.
pub struct UserTable {
    /// User account slots.
    pub users: [UserAccount; MAX_USERS],
    /// Number of registered users.
    pub user_count: usize,
    /// Currently active user ID.
    pub current_uid: u16,
    /// Currently active group ID.
    pub current_gid: u16,
}

impl UserTable {
    const fn new() -> Self {
        Self {
            users: [UserAccount::empty(); MAX_USERS],
            user_count: 0,
            current_uid: 0,
            current_gid: 0,
        }
    }

    /// Register a new user account.
    ///
    /// Returns `true` if the user was added, `false` if the table is full
    /// or a user with the same UID already exists.
    pub fn add_user(&mut self, name: &[u8], password: &[u8], uid: u16, gid: u16) -> bool {
        // Check for duplicate UID.
        for i in 0..self.user_count {
            if self.users[i].uid == uid && self.users[i].active {
                return false;
            }
        }

        if self.user_count >= MAX_USERS {
            return false;
        }

        let idx = self.user_count;
        let user = &mut self.users[idx];
        user.uid = uid;
        user.gid = gid;
        user.active = true;

        // Copy name.
        let name_len = name.len().min(31);
        user.name[..name_len].copy_from_slice(&name[..name_len]);

        // Hash password and store.
        user.password_hash = sha256(password);

        // Set default home directory: /home/<name>
        let prefix = b"/home/";
        let prefix_len = prefix.len();
        if prefix_len + name_len < 64 {
            user.home_dir[..prefix_len].copy_from_slice(prefix);
            user.home_dir[prefix_len..prefix_len + name_len].copy_from_slice(&name[..name_len]);
        }

        // Set default shell.
        let shell = b"/bin/sh";
        let shell_len = shell.len().min(31);
        user.shell[..shell_len].copy_from_slice(&shell[..shell_len]);

        self.user_count += 1;
        true
    }

    /// Authenticate a user by name and password.
    ///
    /// Returns the UID if authentication succeeds, or `None` if the
    /// user doesn't exist or the password is wrong.
    pub fn authenticate(&self, name: &[u8], password: &[u8]) -> Option<u16> {
        let hash = sha256(password);

        for i in 0..self.user_count {
            let user = &self.users[i];
            if !user.active {
                continue;
            }
            let user_name = user.name_str();
            if user_name.len() == name.len() && user_name == name {
                // Compare password hashes (constant-time comparison).
                if constant_time_eq(&user.password_hash, &hash) {
                    return Some(user.uid);
                } else {
                    return None; // Wrong password
                }
            }
        }
        None // User not found
    }

    /// Switch the current user context to the given UID.
    ///
    /// Returns `true` if the user exists and is active.
    pub fn switch_user(&mut self, uid: u16) -> bool {
        for i in 0..self.user_count {
            if self.users[i].uid == uid && self.users[i].active {
                self.current_uid = uid;
                self.current_gid = self.users[i].gid;
                return true;
            }
        }
        false
    }

    /// Get the current user ID.
    pub fn get_current_uid(&self) -> u16 {
        self.current_uid
    }

    /// Get the current group ID.
    pub fn get_current_gid(&self) -> u16 {
        self.current_gid
    }

    /// Find a user by UID.
    pub fn find_by_uid(&self, uid: u16) -> Option<&UserAccount> {
        for i in 0..self.user_count {
            if self.users[i].uid == uid && self.users[i].active {
                return Some(&self.users[i]);
            }
        }
        None
    }

    /// Find a user by name.
    pub fn find_by_name(&self, name: &[u8]) -> Option<&UserAccount> {
        for i in 0..self.user_count {
            if !self.users[i].active {
                continue;
            }
            let user_name = self.users[i].name_str();
            if user_name.len() == name.len() && user_name == name {
                return Some(&self.users[i]);
            }
        }
        None
    }

    /// Deactivate a user account by UID (cannot deactivate root).
    pub fn deactivate_user(&mut self, uid: u16) -> bool {
        if uid == 0 {
            return false; // Cannot deactivate root
        }
        for i in 0..self.user_count {
            if self.users[i].uid == uid && self.users[i].active {
                self.users[i].active = false;
                return true;
            }
        }
        false
    }

    /// Change a user's password.
    pub fn change_password(&mut self, uid: u16, new_password: &[u8]) -> bool {
        for i in 0..self.user_count {
            if self.users[i].uid == uid && self.users[i].active {
                self.users[i].password_hash = sha256(new_password);
                return true;
            }
        }
        false
    }

    /// Count active users.
    pub fn active_count(&self) -> usize {
        let mut count = 0;
        for i in 0..self.user_count {
            if self.users[i].active {
                count += 1;
            }
        }
        count
    }
}

/// Global user table, protected by a mutex.
pub static USER_TABLE: Mutex<UserTable> = Mutex::new(UserTable::new());

/// Initialize the user system with a default root account.
pub fn init() {
    let mut table = USER_TABLE.lock();
    table.add_user(b"root", b"root", 0, 0);
    // Set root as current user.
    table.current_uid = 0;
    table.current_gid = 0;
}

// ---------------------------------------------------------------------------
// SHA-256 implementation (minimal, no_std, no alloc)
// ---------------------------------------------------------------------------

/// SHA-256 initial hash values (first 32 bits of fractional parts of sqrt(2..19)).
const H_INIT: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

/// SHA-256 round constants (first 32 bits of fractional parts of cube roots of primes 2..311).
const K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

/// Compute SHA-256 hash of the input data.
pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut h = H_INIT;

    // Pre-processing: pad the message.
    // Length in bits.
    let bit_len = (data.len() as u64) * 8;

    // We need to process in 64-byte (512-bit) blocks.
    // Padding: append 1 bit (0x80), then zeros, then 8-byte big-endian length.
    let mut padded = [0u8; 128]; // max 2 blocks for small inputs
    let data_len = data.len().min(padded.len());
    padded[..data_len].copy_from_slice(&data[..data_len]);
    padded[data_len] = 0x80;

    // Calculate total padded length (must be multiple of 64).
    let padded_len = if data_len + 9 <= 64 { 64 } else { 128 };

    // Append length in big-endian at the end.
    padded[padded_len - 8..padded_len].copy_from_slice(&bit_len.to_be_bytes());

    // Process each 64-byte block.
    let mut offset = 0;
    while offset < padded_len {
        let block = &padded[offset..offset + 64];
        sha256_block(&mut h, block);
        offset += 64;
    }

    // Produce final hash.
    let mut result = [0u8; 32];
    for i in 0..8 {
        result[i * 4..i * 4 + 4].copy_from_slice(&h[i].to_be_bytes());
    }
    result
}

/// Process a single 512-bit (64-byte) block.
fn sha256_block(h: &mut [u32; 8], block: &[u8]) {
    // Prepare message schedule.
    let mut w = [0u32; 64];
    for i in 0..16 {
        w[i] = u32::from_be_bytes([
            block[i * 4],
            block[i * 4 + 1],
            block[i * 4 + 2],
            block[i * 4 + 3],
        ]);
    }
    for i in 16..64 {
        let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
        let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16]
            .wrapping_add(s0)
            .wrapping_add(w[i - 7])
            .wrapping_add(s1);
    }

    // Initialize working variables.
    let mut a = h[0];
    let mut b = h[1];
    let mut c = h[2];
    let mut d = h[3];
    let mut e = h[4];
    let mut f = h[5];
    let mut g = h[6];
    let mut hh = h[7];

    // Compression loop.
    for i in 0..64 {
        let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
        let ch = (e & f) ^ ((!e) & g);
        let temp1 = hh
            .wrapping_add(s1)
            .wrapping_add(ch)
            .wrapping_add(K[i])
            .wrapping_add(w[i]);
        let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
        let maj = (a & b) ^ (a & c) ^ (b & c);
        let temp2 = s0.wrapping_add(maj);

        hh = g;
        g = f;
        f = e;
        e = d.wrapping_add(temp1);
        d = c;
        c = b;
        b = a;
        a = temp1.wrapping_add(temp2);
    }

    h[0] = h[0].wrapping_add(a);
    h[1] = h[1].wrapping_add(b);
    h[2] = h[2].wrapping_add(c);
    h[3] = h[3].wrapping_add(d);
    h[4] = h[4].wrapping_add(e);
    h[5] = h[5].wrapping_add(f);
    h[6] = h[6].wrapping_add(g);
    h[7] = h[7].wrapping_add(hh);
}

/// Constant-time comparison of two 32-byte arrays.
fn constant_time_eq(a: &[u8; 32], b: &[u8; 32]) -> bool {
    let mut diff = 0u8;
    for i in 0..32 {
        diff |= a[i] ^ b[i];
    }
    diff == 0
}
