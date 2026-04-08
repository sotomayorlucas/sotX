//! VFS delete operations: unlink, unlinkat.

use sotos_common::sys;
use sotos_common::linux_abi::*;
use sotos_common::IpcMsg;
use crate::exec::reply_val;
use crate::fd::*;
use crate::{vfs_lock, vfs_unlock, shared_store};
use crate::framebuffer::{print, print_u64};
use crate::syscalls::context::SyscallContext;

/// SYS_UNLINK (87).
pub(crate) fn sys_unlink(ctx: &mut SyscallContext, msg: &IpcMsg) {
    let path_ptr = msg.regs[0];
    let mut path = [0u8; 128];
    let plen = ctx.guest_copy_path(path_ptr, &mut path);
    let mut abs = [0u8; 256];
    let alen = resolve_with_cwd(ctx.cwd, &path[..plen], &mut abs);
    let abs_name = &abs[..alen];
    trace!(Debug, FS, {
        print(b"UNLINK P"); print_u64(ctx.pid as u64);
        print(b" ["); for &b in abs_name { if b == 0 { break; } sys::debug_print(b); } print(b"]");
    });
    // Unix semantics: unlink removes the name but data stays alive while
    // any fd references the OID. For Wine's tmpmap pattern (create → write →
    // unlink → mmap → share fd via SCM_RIGHTS), we must keep data accessible.
    // Stub: return success without deleting — data preserved for open fds.
    vfs_lock();
    let found = unsafe { shared_store() }.and_then(|store| {
        use sotos_objstore::ROOT_OID;
        store.resolve_path(abs_name, ROOT_OID).ok()
    });
    vfs_unlock();
    reply_val(ctx.ep_cap, if found.is_some() { 0 } else { -ENOENT });
}

/// SYS_UNLINKAT (263).
pub(crate) fn sys_unlinkat(ctx: &mut SyscallContext, msg: &IpcMsg) {
    let path_ptr = msg.regs[1];
    let flags = msg.regs[2] as u32;
    let mut path = [0u8; 128];
    let plen = ctx.guest_copy_path(path_ptr, &mut path);
    let (path, plen) = if plen > 0 && path[0] != b'/' {
        let mut abs = [0u8; 256];
        let alen = resolve_with_cwd(ctx.cwd, &path[..plen], &mut abs);
        let mut resolved = [0u8; 128];
        let rlen = alen.min(127);
        resolved[..rlen].copy_from_slice(&abs[..rlen]);
        (resolved, rlen)
    } else {
        (path, plen)
    };
    let name = &path[..plen];
    trace!(Debug, FS, {
        print(b"UNLINKAT P"); print_u64(ctx.pid as u64);
        print(b" fl=0x"); crate::framebuffer::print_hex64(flags as u64);
        print(b" ["); for &b in name { if b == 0 { break; } sys::debug_print(b); } print(b"]");
    });
    if flags & 0x200 != 0 {
        reply_val(ctx.ep_cap, 0);
    } else {
        // Stub: preserve data for open fds (Wine tmpmap pattern)
        vfs_lock();
        let found = unsafe { shared_store() }.and_then(|store| {
            use sotos_objstore::ROOT_OID;
            store.resolve_path(name, ROOT_OID).ok()
        });
        vfs_unlock();
        reply_val(ctx.ep_cap, if found.is_some() { 0 } else { -ENOENT });
    }
}

