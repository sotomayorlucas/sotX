//! Linux-to-BSD signal number translation, ported from FreeBSD.
//!
//! FreeBSD source: `sys/compat/linux/linux_signal.c` + `linux.h` (BSD-2-Clause)
//!
//! Linux and BSD share POSIX signal semantics but disagree on the numbering
//! of signals above SIGABRT (6). The translation tables below are the
//! canonical FreeBSD Linuxulator mappings.

// ---------------------------------------------------------------------------
// Linux signal constants (include/uapi/asm-generic/signal.h)
// ---------------------------------------------------------------------------

pub const LINUX_SIGHUP: i32 = 1;
pub const LINUX_SIGINT: i32 = 2;
pub const LINUX_SIGQUIT: i32 = 3;
pub const LINUX_SIGILL: i32 = 4;
pub const LINUX_SIGTRAP: i32 = 5;
pub const LINUX_SIGABRT: i32 = 6;
pub const LINUX_SIGBUS: i32 = 7;
pub const LINUX_SIGFPE: i32 = 8;
pub const LINUX_SIGKILL: i32 = 9;
pub const LINUX_SIGUSR1: i32 = 10;
pub const LINUX_SIGSEGV: i32 = 11;
pub const LINUX_SIGUSR2: i32 = 12;
pub const LINUX_SIGPIPE: i32 = 13;
pub const LINUX_SIGALRM: i32 = 14;
pub const LINUX_SIGTERM: i32 = 15;
pub const LINUX_SIGSTKFLT: i32 = 16;
pub const LINUX_SIGCHLD: i32 = 17;
pub const LINUX_SIGCONT: i32 = 18;
pub const LINUX_SIGSTOP: i32 = 19;
pub const LINUX_SIGTSTP: i32 = 20;
pub const LINUX_SIGTTIN: i32 = 21;
pub const LINUX_SIGTTOU: i32 = 22;
pub const LINUX_SIGURG: i32 = 23;
pub const LINUX_SIGXCPU: i32 = 24;
pub const LINUX_SIGXFSZ: i32 = 25;
pub const LINUX_SIGVTALRM: i32 = 26;
pub const LINUX_SIGPROF: i32 = 27;
pub const LINUX_SIGWINCH: i32 = 28;
pub const LINUX_SIGIO: i32 = 29;
pub const LINUX_SIGPWR: i32 = 30;
pub const LINUX_SIGSYS: i32 = 31;
pub const LINUX_SIGRTMIN: i32 = 32;
/// Number of standard (non-RT) signals.
pub const LINUX_NSIG: i32 = 32;

// ---------------------------------------------------------------------------
// BSD signal constants (sys/sys/signal.h)
// ---------------------------------------------------------------------------

pub const BSD_SIGHUP: i32 = 1;
pub const BSD_SIGINT: i32 = 2;
pub const BSD_SIGQUIT: i32 = 3;
pub const BSD_SIGILL: i32 = 4;
pub const BSD_SIGTRAP: i32 = 5;
pub const BSD_SIGABRT: i32 = 6;
pub const BSD_SIGEMT: i32 = 7;
pub const BSD_SIGFPE: i32 = 8;
pub const BSD_SIGKILL: i32 = 9;
pub const BSD_SIGBUS: i32 = 10;
pub const BSD_SIGSEGV: i32 = 11;
pub const BSD_SIGSYS: i32 = 12;
pub const BSD_SIGPIPE: i32 = 13;
pub const BSD_SIGALRM: i32 = 14;
pub const BSD_SIGTERM: i32 = 15;
pub const BSD_SIGURG: i32 = 16;
pub const BSD_SIGSTOP: i32 = 17;
pub const BSD_SIGTSTP: i32 = 18;
pub const BSD_SIGCONT: i32 = 19;
pub const BSD_SIGCHLD: i32 = 20;
pub const BSD_SIGTTIN: i32 = 21;
pub const BSD_SIGTTOU: i32 = 22;
pub const BSD_SIGIO: i32 = 23;
pub const BSD_SIGXCPU: i32 = 24;
pub const BSD_SIGXFSZ: i32 = 25;
pub const BSD_SIGVTALRM: i32 = 26;
pub const BSD_SIGPROF: i32 = 27;
pub const BSD_SIGWINCH: i32 = 28;
pub const BSD_SIGINFO: i32 = 29;
pub const BSD_SIGUSR1: i32 = 30;
pub const BSD_SIGUSR2: i32 = 31;
/// Total standard signal count (including 0).
pub const BSD_NSIG: i32 = 32;

// ---------------------------------------------------------------------------
// Linux -> BSD signal mapping (from FreeBSD linux_to_bsd_signal[])
//
// Index = Linux signal number, value = BSD signal number.
// Signals 1-6 are identical. Above that, the numbering diverges.
// Linux SIGSTKFLT (16) has no BSD equivalent -- mapped to SIGBUS.
// Linux SIGPWR (30) has no BSD equivalent -- mapped to SIGINFO.
// ---------------------------------------------------------------------------

const LINUX_TO_BSD: [i32; 33] = {
    let mut t = [0i32; 33];
    t[0] = 0;
    t[1] = BSD_SIGHUP;     // LINUX_SIGHUP
    t[2] = BSD_SIGINT;     // LINUX_SIGINT
    t[3] = BSD_SIGQUIT;    // LINUX_SIGQUIT
    t[4] = BSD_SIGILL;     // LINUX_SIGILL
    t[5] = BSD_SIGTRAP;    // LINUX_SIGTRAP
    t[6] = BSD_SIGABRT;    // LINUX_SIGABRT
    t[7] = BSD_SIGBUS;     // LINUX_SIGBUS
    t[8] = BSD_SIGFPE;     // LINUX_SIGFPE
    t[9] = BSD_SIGKILL;    // LINUX_SIGKILL
    t[10] = BSD_SIGUSR1;   // LINUX_SIGUSR1
    t[11] = BSD_SIGSEGV;   // LINUX_SIGSEGV
    t[12] = BSD_SIGUSR2;   // LINUX_SIGUSR2
    t[13] = BSD_SIGPIPE;   // LINUX_SIGPIPE
    t[14] = BSD_SIGALRM;   // LINUX_SIGALRM
    t[15] = BSD_SIGTERM;   // LINUX_SIGTERM
    t[16] = BSD_SIGBUS;    // LINUX_SIGSTKFLT -> SIGBUS (no BSD equivalent)
    t[17] = BSD_SIGCHLD;   // LINUX_SIGCHLD
    t[18] = BSD_SIGCONT;   // LINUX_SIGCONT
    t[19] = BSD_SIGSTOP;   // LINUX_SIGSTOP
    t[20] = BSD_SIGTSTP;   // LINUX_SIGTSTP
    t[21] = BSD_SIGTTIN;   // LINUX_SIGTTIN
    t[22] = BSD_SIGTTOU;   // LINUX_SIGTTOU
    t[23] = BSD_SIGURG;    // LINUX_SIGURG
    t[24] = BSD_SIGXCPU;   // LINUX_SIGXCPU
    t[25] = BSD_SIGXFSZ;   // LINUX_SIGXFSZ
    t[26] = BSD_SIGVTALRM; // LINUX_SIGVTALRM
    t[27] = BSD_SIGPROF;   // LINUX_SIGPROF
    t[28] = BSD_SIGWINCH;  // LINUX_SIGWINCH
    t[29] = BSD_SIGIO;     // LINUX_SIGIO
    t[30] = BSD_SIGINFO;   // LINUX_SIGPWR -> SIGINFO (closest BSD equivalent)
    t[31] = BSD_SIGSYS;    // LINUX_SIGSYS
    t[32] = 0;             // LINUX_SIGRTMIN (RT signals passed through 1:1)
    t
};

// ---------------------------------------------------------------------------
// BSD -> Linux signal mapping (from FreeBSD bsd_to_linux_signal[])
// ---------------------------------------------------------------------------

const BSD_TO_LINUX: [i32; 33] = {
    let mut t = [0i32; 33];
    t[0] = 0;
    t[1] = LINUX_SIGHUP;     // BSD_SIGHUP
    t[2] = LINUX_SIGINT;     // BSD_SIGINT
    t[3] = LINUX_SIGQUIT;    // BSD_SIGQUIT
    t[4] = LINUX_SIGILL;     // BSD_SIGILL
    t[5] = LINUX_SIGTRAP;    // BSD_SIGTRAP
    t[6] = LINUX_SIGABRT;    // BSD_SIGABRT
    t[7] = LINUX_SIGBUS;     // BSD_SIGEMT -> SIGBUS (no Linux equivalent for EMT)
    t[8] = LINUX_SIGFPE;     // BSD_SIGFPE
    t[9] = LINUX_SIGKILL;    // BSD_SIGKILL
    t[10] = LINUX_SIGBUS;    // BSD_SIGBUS
    t[11] = LINUX_SIGSEGV;   // BSD_SIGSEGV
    t[12] = LINUX_SIGSYS;    // BSD_SIGSYS
    t[13] = LINUX_SIGPIPE;   // BSD_SIGPIPE
    t[14] = LINUX_SIGALRM;   // BSD_SIGALRM
    t[15] = LINUX_SIGTERM;   // BSD_SIGTERM
    t[16] = LINUX_SIGURG;    // BSD_SIGURG
    t[17] = LINUX_SIGSTOP;   // BSD_SIGSTOP
    t[18] = LINUX_SIGTSTP;   // BSD_SIGTSTP
    t[19] = LINUX_SIGCONT;   // BSD_SIGCONT
    t[20] = LINUX_SIGCHLD;   // BSD_SIGCHLD
    t[21] = LINUX_SIGTTIN;   // BSD_SIGTTIN
    t[22] = LINUX_SIGTTOU;   // BSD_SIGTTOU
    t[23] = LINUX_SIGIO;     // BSD_SIGIO
    t[24] = LINUX_SIGXCPU;   // BSD_SIGXCPU
    t[25] = LINUX_SIGXFSZ;   // BSD_SIGXFSZ
    t[26] = LINUX_SIGVTALRM; // BSD_SIGVTALRM
    t[27] = LINUX_SIGPROF;   // BSD_SIGPROF
    t[28] = LINUX_SIGWINCH;  // BSD_SIGWINCH
    t[29] = LINUX_SIGPWR;    // BSD_SIGINFO -> SIGPWR (closest Linux equivalent)
    t[30] = LINUX_SIGUSR1;   // BSD_SIGUSR1
    t[31] = LINUX_SIGUSR2;   // BSD_SIGUSR2
    t[32] = 0;
    t
};

/// Map a Linux signal number to the corresponding BSD signal number.
///
/// Standard signals (1..31) are translated via the FreeBSD mapping table.
/// Real-time signals (>= SIGRTMIN) are passed through unchanged since both
/// Linux and BSD use the same RT signal offset scheme.
///
/// Returns 0 for signal 0 (null signal for kill() permission check) and
/// for out-of-range values.
pub const fn linux_to_bsd_signal(linux_sig: i32) -> i32 {
    if linux_sig <= 0 || linux_sig >= LINUX_SIGRTMIN {
        // Signal 0 or RT signals: pass through.
        linux_sig
    } else {
        LINUX_TO_BSD[linux_sig as usize]
    }
}

/// Map a BSD signal number to the corresponding Linux signal number.
///
/// Standard signals (1..31) are translated via the FreeBSD mapping table.
/// Real-time signals are passed through unchanged.
///
/// Returns 0 for signal 0 and for out-of-range values.
pub const fn bsd_to_linux_signal(bsd_sig: i32) -> i32 {
    if bsd_sig <= 0 || bsd_sig >= BSD_NSIG {
        // Signal 0 or RT signals: pass through.
        bsd_sig
    } else {
        BSD_TO_LINUX[bsd_sig as usize]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identical_low_signals() {
        // Signals 1-6 are the same on both Linux and BSD.
        for i in 1..=6 {
            assert_eq!(linux_to_bsd_signal(i), i, "signal {i} should be identical");
            assert_eq!(bsd_to_linux_signal(i), i, "signal {i} should be identical");
        }
    }

    #[test]
    fn divergent_signals() {
        // SIGBUS: Linux 7, BSD 10
        assert_eq!(linux_to_bsd_signal(LINUX_SIGBUS), BSD_SIGBUS);
        assert_eq!(bsd_to_linux_signal(BSD_SIGBUS), LINUX_SIGBUS);

        // SIGCHLD: Linux 17, BSD 20
        assert_eq!(linux_to_bsd_signal(LINUX_SIGCHLD), BSD_SIGCHLD);
        assert_eq!(bsd_to_linux_signal(BSD_SIGCHLD), LINUX_SIGCHLD);

        // SIGUSR1: Linux 10, BSD 30
        assert_eq!(linux_to_bsd_signal(LINUX_SIGUSR1), BSD_SIGUSR1);
        assert_eq!(bsd_to_linux_signal(BSD_SIGUSR1), LINUX_SIGUSR1);
    }

    #[test]
    fn no_equivalent_signals() {
        // Linux SIGSTKFLT (16) -> BSD SIGBUS (10).
        assert_eq!(linux_to_bsd_signal(LINUX_SIGSTKFLT), BSD_SIGBUS);
        // BSD SIGEMT (7) -> Linux SIGBUS (7).
        assert_eq!(bsd_to_linux_signal(BSD_SIGEMT), LINUX_SIGBUS);
        // Linux SIGPWR (30) -> BSD SIGINFO (29).
        assert_eq!(linux_to_bsd_signal(LINUX_SIGPWR), BSD_SIGINFO);
    }

    #[test]
    fn null_and_kill() {
        assert_eq!(linux_to_bsd_signal(0), 0);
        assert_eq!(bsd_to_linux_signal(0), 0);
        // SIGKILL is 9 on both.
        assert_eq!(linux_to_bsd_signal(9), 9);
        assert_eq!(bsd_to_linux_signal(9), 9);
    }

    #[test]
    fn rt_signals_passthrough() {
        // RT signals >= 32 should pass through unchanged.
        assert_eq!(linux_to_bsd_signal(32), 32);
        assert_eq!(linux_to_bsd_signal(64), 64);
    }
}
