//! Package-management built-ins: cmd_apt + apt_*, cmd_pkg + pkg_*.

use crate::syscall::*;
use crate::util::*;

// ---------------------------------------------------------------------------
// pkg -package management
// ---------------------------------------------------------------------------

/// pkg list | info <name> | which <name> | count
pub fn cmd_pkg(args: &[u8]) {
    if args.is_empty() || eq(args, b"help") {
        print(b"usage: pkg list           -list available executables\n");
        print(b"       pkg info <name>    -show binary info\n");
        print(b"       pkg which <name>   -show full path\n");
        print(b"       pkg count          -count executables\n");
        return;
    }

    if eq(args, b"list") {
        pkg_list();
    } else if eq(args, b"count") {
        pkg_count();
    } else if starts_with(args, b"info ") {
        let name = trim(&args[5..]);
        if !name.is_empty() { pkg_info(name); }
        else { print(b"usage: pkg info <name>\n"); }
    } else if starts_with(args, b"which ") {
        let name = trim(&args[6..]);
        if !name.is_empty() { pkg_which(name); }
        else { print(b"usage: pkg which <name>\n"); }
    } else {
        print(b"pkg: unknown subcommand. Try 'pkg help'\n");
        crate::parse::set_exit_status(1);
    }
}

fn pkg_list() {
    // List /bin/ contents
    print(b"--- /bin/ ---\n");
    pkg_list_dir(b"/bin");
    // List /usr/bin/ contents
    print(b"--- /usr/bin/ ---\n");
    pkg_list_dir(b"/usr/bin");
}

fn pkg_list_dir(dir: &[u8]) {
    let mut path_buf = [0u8; 64];
    let path = null_terminate(dir, &mut path_buf);
    let fd = linux_open(path, 0); // O_RDONLY
    if fd < 0 {
        print(b"  (empty)\n");
        return;
    }
    let mut listing = [0u8; 4096];
    let total = read_all(fd as u64, &mut listing);
    linux_close(fd as u64);

    if total == 0 {
        print(b"  (empty)\n");
        return;
    }

    // Parse listing: one entry per line
    let mut count = 0u64;
    let mut line_start = 0;
    let mut i = 0;
    while i <= total {
        if i == total || listing[i] == b'\n' {
            let entry = trim(&listing[line_start..i]);
            if !entry.is_empty() {
                // Extract just the name (before any whitespace metadata)
                let name_end = find_space(entry).unwrap_or(entry.len());
                let name = &entry[..name_end];
                if !name.is_empty() {
                    print(b"  ");
                    print(name);
                    print(b"\n");
                    count += 1;
                }
            }
            line_start = i + 1;
        }
        i += 1;
    }
    if count == 0 { print(b"  (empty)\n"); }
}

fn pkg_count() {
    let mut total = 0u64;
    for dir in &[b"/bin" as &[u8], b"/usr/bin"] {
        let mut path_buf = [0u8; 64];
        let path = null_terminate(dir, &mut path_buf);
        let fd = linux_open(path, 0);
        if fd < 0 { continue; }
        let mut listing = [0u8; 4096];
        let n = read_all(fd as u64, &mut listing);
        linux_close(fd as u64);
        for j in 0..n {
            if listing[j] == b'\n' { total += 1; }
        }
    }
    print_u64(total);
    print(b" executables available\n");
}

fn pkg_info(name: &[u8]) {
    // Try to stat the binary
    let mut resolved = [0u8; 128];
    let len = crate::exec::resolve_command(name, &mut resolved);
    if len == 0 {
        print(name);
        print(b": not found\n");
        crate::parse::set_exit_status(1);
        return;
    }

    let path = &resolved[..len];
    print(b"Name:    ");
    print(name);
    print(b"\n");
    print(b"Path:    ");
    print(path);
    print(b"\n");

    // Stat for size
    let mut stat_buf_nul = [0u8; 130];
    stat_buf_nul[..len].copy_from_slice(path);
    stat_buf_nul[len] = 0;
    let mut stat_buf = [0u8; 144];
    if linux_stat(stat_buf_nul.as_ptr(), stat_buf.as_mut_ptr()) >= 0 {
        let size = u64::from_le_bytes([stat_buf[48], stat_buf[49], stat_buf[50], stat_buf[51],
                                       stat_buf[52], stat_buf[53], stat_buf[54], stat_buf[55]]);
        print(b"Size:    ");
        print_u64(size);
        print(b" bytes\n");

        let mode = u32::from_le_bytes([stat_buf[24], stat_buf[25], stat_buf[26], stat_buf[27]]);
        print(b"Mode:    0o");
        // Print octal
        let mut oct_buf = [0u8; 8];
        let mut oct_len = 0;
        let mut m = mode & 0o7777;
        if m == 0 { oct_buf[0] = b'0'; oct_len = 1; }
        else {
            while m > 0 { oct_buf[oct_len] = b'0' + (m & 7) as u8; m >>= 3; oct_len += 1; }
        }
        let mut j = oct_len;
        while j > 0 { j -= 1; linux_write(1, &oct_buf[j] as *const u8, 1); }
        print(b"\n");
    }

    // Try to read ELF header to detect type
    let fd = linux_open(stat_buf_nul.as_ptr(), 0);
    if fd >= 0 {
        let mut hdr = [0u8; 64];
        let n = linux_read(fd as u64, hdr.as_mut_ptr(), 64);
        linux_close(fd as u64);
        if n >= 20 && hdr[0] == 0x7F && hdr[1] == b'E' && hdr[2] == b'L' && hdr[3] == b'F' {
            print(b"Type:    ELF ");
            // e_type at offset 16 (2 bytes LE)
            let etype = u16::from_le_bytes([hdr[16], hdr[17]]);
            match etype {
                2 => print(b"executable (ET_EXEC)"),
                3 => print(b"shared object/PIE (ET_DYN)"),
                _ => { print(b"type="); print_u64(etype as u64); }
            }
            print(b"\n");
            // Check for PT_INTERP to detect static vs dynamic
            if n >= 64 {
                let phoff = u64::from_le_bytes([hdr[32], hdr[33], hdr[34], hdr[35], hdr[36], hdr[37], hdr[38], hdr[39]]);
                let phnum = u16::from_le_bytes([hdr[56], hdr[57]]);
                if phoff > 0 && phnum > 0 {
                    print(b"Linking: ");
                    // We can't easily check PT_INTERP without reading more, so just report phnum
                    if phnum > 4 {
                        print(b"dynamic (");
                    } else {
                        print(b"static (");
                    }
                    print_u64(phnum as u64);
                    print(b" program headers)\n");
                }
            }
        } else {
            print(b"Type:    script/data\n");
        }
    }
}

fn pkg_which(name: &[u8]) {
    let mut resolved = [0u8; 128];
    let len = crate::exec::resolve_command(name, &mut resolved);
    if len > 0 {
        print(&resolved[..len]);
        print(b"\n");
    } else {
        print(name);
        print(b": not found\n");
        crate::parse::set_exit_status(1);
    }
}

// ---------------------------------------------------------------------------
// apt -sotOS package manager
// ---------------------------------------------------------------------------

/// Package registry: tracks up to 64 packages (name, installed flag)
static mut APT_PKG_NAMES: [[u8; 32]; 64] = [[0u8; 32]; 64];
static mut APT_PKG_LENS: [u8; 64] = [0u8; 64];
static mut APT_PKG_INSTALLED: [bool; 64] = [false; 64];
static mut APT_PKG_COUNT: usize = 0;
static mut APT_INITIALIZED: bool = false;

/// Scan /bin/ and /pkg/ to discover available packages.
fn apt_init() {
    unsafe {
        if APT_INITIALIZED { return; }
        APT_INITIALIZED = true;
        APT_PKG_COUNT = 0;
    }
    apt_scan_dir(b"/bin", true);
    apt_scan_dir(b"/pkg", false);
}

fn apt_scan_dir(dir: &[u8], mark_installed: bool) {
    let mut path_buf = [0u8; 64];
    let path = null_terminate(dir, &mut path_buf);
    let fd = linux_open(path, 0);
    if fd < 0 { return; }
    let mut listing = [0u8; 4096];
    let total = read_all(fd as u64, &mut listing);
    linux_close(fd as u64);

    let mut line_start = 0;
    let mut i = 0;
    while i <= total {
        if i == total || listing[i] == b'\n' {
            let entry = trim(&listing[line_start..i]);
            let name_end = find_space(entry).unwrap_or(entry.len());
            let name = &entry[..name_end];
            if !name.is_empty() && name[0] != b'.' {
                apt_register(name, mark_installed);
            }
            line_start = i + 1;
        }
        i += 1;
    }
}

fn apt_register(name: &[u8], installed: bool) {
    unsafe {
        for j in 0..APT_PKG_COUNT {
            let plen = APT_PKG_LENS[j] as usize;
            if plen == name.len() && APT_PKG_NAMES[j][..plen] == *name {
                if installed { APT_PKG_INSTALLED[j] = true; }
                return;
            }
        }
        if APT_PKG_COUNT >= 64 { return; }
        let idx = APT_PKG_COUNT;
        let nl = name.len().min(31);
        APT_PKG_NAMES[idx][..nl].copy_from_slice(&name[..nl]);
        APT_PKG_LENS[idx] = nl as u8;
        APT_PKG_INSTALLED[idx] = installed;
        APT_PKG_COUNT += 1;
    }
}

pub fn cmd_apt(args: &[u8]) {
    apt_init();

    if args.is_empty() || eq(args, b"help") || eq(args, b"--help") {
        print(b"sotOS package manager\n");
        print(b"usage: apt install <pkg>    install package from /pkg/ to /bin/\n");
        print(b"       apt remove <pkg>     remove package from /bin/\n");
        print(b"       apt list             list all packages\n");
        print(b"       apt list --installed list installed packages\n");
        print(b"       apt search <term>    search packages by name\n");
        print(b"       apt update           rescan package directories\n");
        print(b"       apt fetch <url>      download package via HTTP\n");
        return;
    }

    if eq(args, b"update") {
        unsafe { APT_INITIALIZED = false; }
        apt_init();
        unsafe {
            print_u64(APT_PKG_COUNT as u64);
        }
        print(b" packages scanned\n");
    } else if eq(args, b"list") {
        apt_list(false);
    } else if eq(args, b"list --installed") {
        apt_list(true);
    } else if starts_with(args, b"install ") {
        let name = trim(&args[8..]);
        if !name.is_empty() { apt_install(name); }
        else { print(b"usage: apt install <pkg>\n"); }
    } else if starts_with(args, b"remove ") {
        let name = trim(&args[7..]);
        if !name.is_empty() { apt_remove(name); }
        else { print(b"usage: apt remove <pkg>\n"); }
    } else if starts_with(args, b"search ") {
        let term = trim(&args[7..]);
        if !term.is_empty() { apt_search(term); }
        else { print(b"usage: apt search <term>\n"); }
    } else if starts_with(args, b"fetch ") {
        let url = trim(&args[6..]);
        if !url.is_empty() { apt_fetch(url); }
        else { print(b"usage: apt fetch <url>\n"); }
    } else {
        print(b"apt: unknown command. Try 'apt help'\n");
        crate::parse::set_exit_status(1);
    }
}

fn apt_list(installed_only: bool) {
    unsafe {
        let mut count = 0u64;
        for i in 0..APT_PKG_COUNT {
            if installed_only && !APT_PKG_INSTALLED[i] { continue; }
            let plen = APT_PKG_LENS[i] as usize;
            print(&APT_PKG_NAMES[i][..plen]);
            if APT_PKG_INSTALLED[i] {
                print(b" [installed]");
            } else {
                print(b" [available]");
            }
            print(b"\n");
            count += 1;
        }
        if count == 0 { print(b"No packages found\n"); }
    }
}

fn apt_search(term: &[u8]) {
    unsafe {
        let mut found = false;
        for i in 0..APT_PKG_COUNT {
            let plen = APT_PKG_LENS[i] as usize;
            let name = &APT_PKG_NAMES[i][..plen];
            if contains(name, term) {
                print(name);
                if APT_PKG_INSTALLED[i] { print(b" [installed]"); }
                else { print(b" [available]"); }
                print(b"\n");
                found = true;
            }
        }
        if !found {
            print(b"No packages matching '");
            print(term);
            print(b"'\n");
        }
    }
}

fn apt_install(name: &[u8]) {
    // Check if already in /bin/
    let mut bin_path = [0u8; 70];
    bin_path[..5].copy_from_slice(b"/bin/");
    let nl = name.len().min(63);
    bin_path[5..5 + nl].copy_from_slice(&name[..nl]);
    bin_path[5 + nl] = 0;
    let mut stat_buf = [0u8; 144];
    if linux_stat(bin_path.as_ptr(), stat_buf.as_mut_ptr()) >= 0 {
        print(name);
        print(b" is already installed\n");
        return;
    }

    // Try /pkg/<name>
    let mut pkg_path = [0u8; 70];
    pkg_path[..5].copy_from_slice(b"/pkg/");
    pkg_path[5..5 + nl].copy_from_slice(&name[..nl]);
    pkg_path[5 + nl] = 0;

    if linux_stat(pkg_path.as_ptr(), stat_buf.as_mut_ptr()) < 0 {
        print(b"E: Unable to locate package ");
        print(name);
        print(b"\n");
        print(b"   Put packages in /pkg/ or use: apt fetch <url>\n");
        crate::parse::set_exit_status(100);
        return;
    }

    // Copy /pkg/<name> -> /bin/<name>
    let src_fd = linux_open(pkg_path.as_ptr(), 0);
    if src_fd < 0 {
        print(b"E: Failed to read /pkg/");
        print(name);
        print(b"\n");
        crate::parse::set_exit_status(1);
        return;
    }
    let mut data = [0u8; 4096];
    let mut total = 0usize;
    loop {
        let n = linux_read(src_fd as u64, data[total..].as_mut_ptr(), data.len() - total);
        if n <= 0 { break; }
        total += n as usize;
        if total >= data.len() { break; }
    }
    linux_close(src_fd as u64);

    let dst_fd = linux_open(bin_path.as_ptr(), 0x41); // O_WRONLY | O_CREAT
    if dst_fd < 0 {
        print(b"E: Failed to write /bin/");
        print(name);
        print(b"\n");
        crate::parse::set_exit_status(1);
        return;
    }
    if total > 0 {
        linux_write(dst_fd as u64, data.as_ptr(), total);
    }
    linux_close(dst_fd as u64);

    apt_register(name, true);
    print(b"Installing ");
    print(name);
    print(b" ... done (");
    print_u64(total as u64);
    print(b" bytes)\n");
}

fn apt_remove(name: &[u8]) {
    let mut bin_path = [0u8; 70];
    bin_path[..5].copy_from_slice(b"/bin/");
    let nl = name.len().min(63);
    bin_path[5..5 + nl].copy_from_slice(&name[..nl]);
    bin_path[5 + nl] = 0;

    let ret = linux_unlink(bin_path.as_ptr());
    if ret < 0 {
        print(b"E: ");
        print(name);
        print(b" is not installed\n");
        crate::parse::set_exit_status(1);
        return;
    }

    unsafe {
        for i in 0..APT_PKG_COUNT {
            let plen = APT_PKG_LENS[i] as usize;
            if plen == name.len() && APT_PKG_NAMES[i][..plen] == *name {
                APT_PKG_INSTALLED[i] = false;
            }
        }
    }
    print(b"Removing ");
    print(name);
    print(b" ... done\n");
}

fn apt_fetch(url: &[u8]) {
    let mut last_slash = 0;
    for i in 0..url.len() {
        if url[i] == b'/' { last_slash = i; }
    }
    if last_slash == 0 || last_slash + 1 >= url.len() {
        print(b"E: Cannot determine filename from URL\n");
        crate::parse::set_exit_status(1);
        return;
    }
    let filename = &url[last_slash + 1..];

    print(b"Fetching ");
    print(filename);
    print(b" ...\n");

    // Build wget command: wget -O /pkg/<filename> <url>
    let mut cmd = [0u8; 512];
    let mut pos = 0;
    let prefix = b"wget -O /pkg/";
    cmd[..prefix.len()].copy_from_slice(prefix);
    pos += prefix.len();
    let fl = filename.len().min(64);
    cmd[pos..pos + fl].copy_from_slice(&filename[..fl]);
    pos += fl;
    cmd[pos] = b' ';
    pos += 1;
    let ul = url.len().min(400);
    cmd[pos..pos + ul].copy_from_slice(&url[..ul]);
    pos += ul;

    crate::parse::dispatch_command(trim(&cmd[..pos]));

    if crate::parse::get_exit_status() == 0 {
        apt_register(filename, false);
        print(b"Done. Run: apt install ");
        print(filename);
        print(b"\n");
    }
}
