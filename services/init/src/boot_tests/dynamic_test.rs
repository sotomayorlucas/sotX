//! Dynamically-linked musl binary (hello_dynamic) boot test.
#![allow(unused_imports)]

use sotos_common::sys;
use sotos_common::linux_abi::*;
use core::sync::atomic::Ordering;
use crate::framebuffer::{print, print_u64, fb_putchar};
use crate::exec::{reply_val, exec_from_initrd, EXEC_LOCK, MAP_WRITABLE, copy_guest_path};
use crate::process::*;
use crate::fd::*;

/// Run a dynamically-linked musl binary (hello_dynamic) via LUCAS.
/// Tests the dynamic linker loading infrastructure: PT_INTERP, file-backed mmap, etc.
pub(crate) fn run_dynamic_test() {
    print(b"DYNAMIC-TEST: loading hello_dynamic...\n");

    while EXEC_LOCK.compare_exchange(0, 1, Ordering::AcqRel, Ordering::Relaxed).is_err() {
        sys::yield_now();
    }

    let ep_cap = match exec_from_initrd(b"hello_dynamic") {
        Ok((ep, _tc)) => {
            EXEC_LOCK.store(0, Ordering::Release);
            ep
        }
        Err(e) => {
            EXEC_LOCK.store(0, Ordering::Release);
            print(b"DYNAMIC-TEST: failed to load (errno=");
            print_u64((-e) as u64);
            print(b")\n");
            return;
        }
    };

    print(b"DYNAMIC-TEST: running dynamic binary...\n");

    // Re-use child brk/mmap for this test — use a dedicated region
    let mut current_brk: u64 = 0x9000000;
    let mut mmap_next: u64 = 0x9100000;

    // Initrd file tracking
    const DYN_MAX_FDS: usize = 32;
    let mut child_fds = [0u8; DYN_MAX_FDS];
    child_fds[0] = 1; // stdin
    child_fds[1] = 2; // stdout
    child_fds[2] = 2; // stderr

    const DYN_MAX_INITRD_FILES: usize = 8;
    let mut initrd_files: [[u64; 4]; DYN_MAX_INITRD_FILES] = [[0; 4]; DYN_MAX_INITRD_FILES];
    let initrd_file_buf_base: u64 = 0x9200000;

    loop {
        let msg = match sys::recv(ep_cap) {
            Ok(m) => m,
            Err(_) => break,
        };

        let nr = msg.tag;
        match nr {
            // write(fd, buf, len)
            1 => {
                let buf_ptr = msg.regs[1];
                let len = msg.regs[2] as usize;
                if len > 0 && buf_ptr != 0 && buf_ptr < 0x0000_8000_0000_0000 {
                    let data = unsafe { core::slice::from_raw_parts(buf_ptr as *const u8, len) };
                    for &b in data { sys::debug_print(b); unsafe { fb_putchar(b); } }
                }
                reply_val(ep_cap, len as i64);
            }
            // read(fd, buf, len)
            0 => {
                let fd = msg.regs[0] as usize;
                if fd < DYN_MAX_FDS && child_fds[fd] == 12 {
                    // Initrd file read
                    let buf_ptr = msg.regs[1];
                    let len = msg.regs[2] as usize;
                    let mut found = false;
                    for s in 0..DYN_MAX_INITRD_FILES {
                        if initrd_files[s][3] == fd as u64 && initrd_files[s][0] != 0 {
                            let data_base = initrd_files[s][0];
                            let file_size = initrd_files[s][1];
                            let pos = initrd_files[s][2];
                            let avail = if pos < file_size { file_size - pos } else { 0 };
                            let to_read = (len as u64).min(avail) as usize;
                            if to_read > 0 {
                                unsafe {
                                    core::ptr::copy_nonoverlapping(
                                        (data_base + pos) as *const u8,
                                        buf_ptr as *mut u8,
                                        to_read,
                                    );
                                }
                                initrd_files[s][2] = pos + to_read as u64;
                            }
                            reply_val(ep_cap, to_read as i64);
                            found = true;
                            break;
                        }
                    }
                    if !found { reply_val(ep_cap, 0); }
                } else {
                    reply_val(ep_cap, 0); // EOF
                }
            }
            // open(path, flags, mode) — musl dynamic linker uses SYS_open
            2 => {
                let path_ptr = msg.regs[0];
                let mut path = [0u8; 128];
                let path_len = copy_guest_path(path_ptr, &mut path);
                let name = &path[..path_len];

                // Try initrd by basename
                let mut basename_start = 0usize;
                for idx in 0..path_len {
                    if name[idx] == b'/' { basename_start = idx + 1; }
                }
                let basename = &name[basename_start..];

                let mut slot = None;
                for s in 0..DYN_MAX_INITRD_FILES {
                    if initrd_files[s][0] == 0 { slot = Some(s); break; }
                }

                if basename.is_empty() || slot.is_none() {
                    reply_val(ep_cap, -ENOENT);
                    continue;
                }
                let slot = slot.unwrap();

                let file_buf = initrd_file_buf_base + (slot as u64) * 0x100000;
                const FILE_BUF_PAGES_DYN: u64 = 256;
                let mut buf_ok = true;
                for p in 0..FILE_BUF_PAGES_DYN {
                    if let Ok(f) = sys::frame_alloc() {
                        if sys::map(file_buf + p * 0x1000, f, MAP_WRITABLE).is_err() {
                            buf_ok = false; break;
                        }
                    } else { buf_ok = false; break; }
                }
                if !buf_ok { reply_val(ep_cap, -ENOMEM); continue; }

                match sys::initrd_read(
                    basename.as_ptr() as u64,
                    basename.len() as u64,
                    file_buf,
                    FILE_BUF_PAGES_DYN * 0x1000,
                ) {
                    Ok(sz) => {
                        let mut fd = None;
                        for i in 3..DYN_MAX_FDS { if child_fds[i] == 0 { fd = Some(i); break; } }
                        if let Some(f) = fd {
                            child_fds[f] = 12;
                            initrd_files[slot] = [file_buf, sz, 0, f as u64];
                            print(b"DYNAMIC: open(");
                            for &b in basename { sys::debug_print(b); unsafe { fb_putchar(b); } }
                            print(b") = fd ");
                            print_u64(f as u64);
                            print(b" size=");
                            print_u64(sz);
                            print(b"\n");
                            reply_val(ep_cap, f as i64);
                        } else {
                            for p in 0..FILE_BUF_PAGES_DYN { let _ = sys::unmap_free(file_buf + p * 0x1000); }
                            reply_val(ep_cap, -EMFILE);
                        }
                    }
                    Err(_) => {
                        for p in 0..FILE_BUF_PAGES_DYN { let _ = sys::unmap_free(file_buf + p * 0x1000); }
                        reply_val(ep_cap, -ENOENT);
                    }
                }
            }
            // close
            3 => {
                let fd = msg.regs[0] as usize;
                if fd < DYN_MAX_FDS && child_fds[fd] == 12 {
                    for s in 0..DYN_MAX_INITRD_FILES {
                        if initrd_files[s][3] == fd as u64 {
                            initrd_files[s][3] = u64::MAX;
                            break;
                        }
                    }
                }
                if fd < DYN_MAX_FDS { child_fds[fd] = 0; }
                reply_val(ep_cap, 0);
            }
            // fstat
            5 => {
                let fd = msg.regs[0] as usize;
                let stat_ptr = msg.regs[1];
                if fd < DYN_MAX_FDS && child_fds[fd] == 12 {
                    let mut size = 0u64;
                    for s in 0..DYN_MAX_INITRD_FILES {
                        if initrd_files[s][3] == fd as u64 && initrd_files[s][0] != 0 {
                            size = initrd_files[s][1];
                            break;
                        }
                    }
                    write_linux_stat(stat_ptr, fd as u64, size, false);
                } else {
                    write_linux_stat(stat_ptr, fd as u64, 0, false);
                }
                reply_val(ep_cap, 0);
            }
            // poll
            7 => reply_val(ep_cap, 0),
            // mmap(addr, len, prot, flags, fd, offset)
            9 => {
                let req_addr = msg.regs[0];
                let len = msg.regs[1];
                let flags = msg.regs[3] as u32;
                let fd = msg.regs[4] as i64;
                let offset = msg.regs[5];

                let map_fixed = MFlags::from_bits_truncate(flags).contains(MFlags::FIXED);
                let pages = ((len + 0xFFF) & !0xFFF) / 0x1000;

                let base = if map_fixed && req_addr != 0 {
                    for p in 0..pages { let _ = sys::unmap_free(req_addr + p * 0x1000); }
                    req_addr
                } else {
                    let b = mmap_next;
                    mmap_next += pages * 0x1000;
                    b
                };

                // Allocate pages
                let mut ok = true;
                for p in 0..pages {
                    if let Ok(f) = sys::frame_alloc() {
                        if sys::map(base + p * 0x1000, f, MAP_WRITABLE).is_err() { ok = false; break; }
                    } else { ok = false; break; }
                }
                if !ok { reply_val(ep_cap, -ENOMEM); continue; }

                // Zero the region
                unsafe { core::ptr::write_bytes(base as *mut u8, 0, (pages * 0x1000) as usize); }

                // If file-backed, copy data from initrd file
                if fd >= 0 {
                    let fdu = fd as usize;
                    let mut file_data: u64 = 0;
                    let mut file_size: u64 = 0;
                    for s in 0..DYN_MAX_INITRD_FILES {
                        if initrd_files[s][0] != 0 && (initrd_files[s][3] == fdu as u64 || initrd_files[s][3] == u64::MAX) {
                            if initrd_files[s][3] == fdu as u64 {
                                file_data = initrd_files[s][0];
                                file_size = initrd_files[s][1];
                                break;
                            }
                        }
                    }
                    if file_data != 0 {
                        let file_off = offset as usize;
                        let avail = if file_off < file_size as usize { file_size as usize - file_off } else { 0 };
                        let to_copy = ((pages * 0x1000) as usize).min(avail);
                        if to_copy > 0 {
                            unsafe {
                                core::ptr::copy_nonoverlapping(
                                    (file_data + file_off as u64) as *const u8,
                                    base as *mut u8,
                                    to_copy,
                                );
                            }
                        }
                    }
                }

                reply_val(ep_cap, base as i64);
            }
            // mprotect
            10 => reply_val(ep_cap, 0),
            // munmap
            11 => {
                let addr = msg.regs[0];
                let len = msg.regs[1];
                let pages = ((len + 0xFFF) & !0xFFF) / 0x1000;
                for p in 0..pages { let _ = sys::unmap_free(addr + p * 0x1000); }
                reply_val(ep_cap, 0);
            }
            // brk
            12 => {
                let addr = msg.regs[0];
                if addr == 0 || addr <= current_brk {
                    reply_val(ep_cap, current_brk as i64);
                } else {
                    let new_brk = (addr + 0xFFF) & !0xFFF;
                    let mut pg = (current_brk + 0xFFF) & !0xFFF;
                    let mut ok = true;
                    while pg < new_brk {
                        if let Ok(f) = sys::frame_alloc() {
                            if sys::map(pg, f, MAP_WRITABLE).is_err() { ok = false; break; }
                        } else { ok = false; break; }
                        pg += 0x1000;
                    }
                    if ok { current_brk = new_brk; }
                    reply_val(ep_cap, current_brk as i64);
                }
            }
            // rt_sigaction
            13 => reply_val(ep_cap, 0),
            // rt_sigprocmask
            14 => reply_val(ep_cap, 0),
            // fcntl
            72 => reply_val(ep_cap, 0),
            // getpid
            39 => reply_val(ep_cap, 999),
            // arch_prctl — kernel intercepts, shouldn't reach
            158 => reply_val(ep_cap, 0),
            // set_tid_address
            218 => reply_val(ep_cap, 999),
            // exit / exit_group
            60 | 231 => {
                let status = msg.regs[0] as i64;
                print(b"DYNAMIC-TEST: exited with status ");
                print_u64(status as u64);
                print(b"\n");
                if status == 0 {
                    print(b"DYNAMIC-TEST: SUCCESS -- dynamically-linked musl binary ran under LUCAS!\n");
                } else {
                    print(b"DYNAMIC-TEST: FAILED\n");
                }
                break;
            }
            // Unknown
            _ => {
                print(b"DYNAMIC: unhandled syscall ");
                print_u64(nr);
                print(b"\n");
                reply_val(ep_cap, -ENOSYS);
            }
        }
    }

    print(b"DYNAMIC-TEST: complete\n");
}
