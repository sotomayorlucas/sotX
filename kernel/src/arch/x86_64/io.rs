//! x86 port I/O helpers.

/// Write a byte to an I/O port.
#[inline]
pub unsafe fn outb(port: u16, val: u8) {
    // SAFETY: `out` is a single x86 instruction with nomem/nostack/preserves_flags;
    // the caller vouches that writing `val` to `port` is safe for the device on
    // the other end (chipset spec) and that the port is not aliased to a driver
    // that requires exclusive access.
    unsafe {
        core::arch::asm!("out dx, al", in("dx") port, in("al") val, options(nomem, nostack, preserves_flags));
    }
}

/// Read a byte from an I/O port.
#[inline]
pub unsafe fn inb(port: u16) -> u8 {
    let val: u8;
    // SAFETY: `in` is a single x86 instruction with nomem/nostack/preserves_flags;
    // the caller guarantees the port is a readable device register with no
    // side effects that would violate Rust aliasing rules.
    unsafe {
        core::arch::asm!("in al, dx", in("dx") port, out("al") val, options(nomem, nostack, preserves_flags));
    }
    val
}

/// Write a 16-bit word to an I/O port.
#[inline]
pub unsafe fn outw(port: u16, val: u16) {
    // SAFETY: caller guarantees `port` accepts a 16-bit write per the chipset
    // spec; the asm touches no memory and preserves flags.
    unsafe {
        core::arch::asm!("out dx, ax", in("dx") port, in("ax") val, options(nomem, nostack, preserves_flags));
    }
}

/// Read a 16-bit word from an I/O port.
#[inline]
pub unsafe fn inw(port: u16) -> u16 {
    let val: u16;
    // SAFETY: caller guarantees `port` is a readable 16-bit device register;
    // the asm only reads from the port and writes `ax`, no memory access.
    unsafe {
        core::arch::asm!("in ax, dx", in("dx") port, out("ax") val, options(nomem, nostack, preserves_flags));
    }
    val
}

/// Write a 32-bit dword to an I/O port.
#[inline]
pub unsafe fn outl(port: u16, val: u32) {
    // SAFETY: caller guarantees `port` accepts a 32-bit write per the chipset
    // spec; the asm touches no memory and preserves flags.
    unsafe {
        core::arch::asm!("out dx, eax", in("dx") port, in("eax") val, options(nomem, nostack, preserves_flags));
    }
}

/// Read a 32-bit dword from an I/O port.
#[inline]
pub unsafe fn inl(port: u16) -> u32 {
    let val: u32;
    // SAFETY: caller guarantees `port` is a readable 32-bit device register;
    // the asm only reads from the port and writes `eax`, no memory access.
    unsafe {
        core::arch::asm!("in eax, dx", in("dx") port, out("eax") val, options(nomem, nostack, preserves_flags));
    }
    val
}
