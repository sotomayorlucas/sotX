//! Signals as IPC messages over signal channels.
//!
//! In SOT, signals are not magic kernel state mutations. Each domain has a
//! signal channel; delivering a signal means sending an IPC message on that
//! channel. The recipient's signal handler (registered via sigaction) reads
//! the message and dispatches accordingly.
//!
//! SIGKILL is special: it bypasses the channel and directly invokes
//! `domain_destroy`, but only if the sender holds the KILL capability
//! for the target domain.

use crate::posix::{Cap, SotOp, ChannelMode};

/// Standard POSIX signal numbers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum Signal {
    SIGHUP = 1,
    SIGINT = 2,
    SIGQUIT = 3,
    SIGILL = 4,
    SIGTRAP = 5,
    SIGABRT = 6,
    SIGBUS = 7,
    SIGFPE = 8,
    SIGKILL = 9,
    SIGUSR1 = 10,
    SIGPIPE = 13,
    SIGALRM = 14,
    SIGTERM = 15,
    SIGCHLD = 17,
    SIGCONT = 18,
    SIGSTOP = 19,
    SIGTSTP = 20,
    SIGTTIN = 21,
    SIGTTOU = 22,
    SIGURG = 23,
    SIGXCPU = 24,
    SIGUSR2 = 31,
}

impl Signal {
    /// Convert from raw signal number.
    pub fn from_raw(num: u8) -> Option<Self> {
        match num {
            1 => Some(Self::SIGHUP),
            2 => Some(Self::SIGINT),
            3 => Some(Self::SIGQUIT),
            4 => Some(Self::SIGILL),
            5 => Some(Self::SIGTRAP),
            6 => Some(Self::SIGABRT),
            7 => Some(Self::SIGBUS),
            8 => Some(Self::SIGFPE),
            9 => Some(Self::SIGKILL),
            10 => Some(Self::SIGUSR1),
            13 => Some(Self::SIGPIPE),
            14 => Some(Self::SIGALRM),
            15 => Some(Self::SIGTERM),
            17 => Some(Self::SIGCHLD),
            18 => Some(Self::SIGCONT),
            19 => Some(Self::SIGSTOP),
            20 => Some(Self::SIGTSTP),
            21 => Some(Self::SIGTTIN),
            22 => Some(Self::SIGTTOU),
            23 => Some(Self::SIGURG),
            24 => Some(Self::SIGXCPU),
            31 => Some(Self::SIGUSR2),
            _ => None,
        }
    }

    /// Whether this signal cannot be caught or ignored.
    pub fn is_uncatchable(self) -> bool {
        matches!(self, Signal::SIGKILL | Signal::SIGSTOP)
    }
}

/// A bitmask of pending signals.
#[derive(Debug, Clone, Copy, Default)]
pub struct SignalSet(u64);

impl SignalSet {
    pub const fn empty() -> Self {
        Self(0)
    }

    pub fn add(&mut self, sig: Signal) {
        self.0 |= 1 << (sig as u8);
    }

    pub fn remove(&mut self, sig: Signal) {
        self.0 &= !(1 << (sig as u8));
    }

    pub fn contains(self, sig: Signal) -> bool {
        (self.0 & (1 << (sig as u8))) != 0
    }

    pub fn is_empty(self) -> bool {
        self.0 == 0
    }

    /// Return and clear the lowest pending signal.
    pub fn pop_lowest(&mut self) -> Option<Signal> {
        if self.0 == 0 {
            return None;
        }
        let bit = self.0.trailing_zeros() as u8;
        self.0 &= !(1u64 << bit);
        Signal::from_raw(bit)
    }
}

/// What to do when a signal arrives.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignalAction {
    /// Perform the default action (terminate, stop, ignore, etc.).
    Default,
    /// Ignore the signal entirely.
    Ignore,
    /// Invoke a handler (the cap points to the handler's entry address).
    Handle { handler: u64, flags: SigActionFlags },
}

/// Flags for signal actions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SigActionFlags(pub u32);

impl SigActionFlags {
    /// Restart interrupted syscalls after the handler returns.
    pub const SA_RESTART: Self = Self(1 << 0);
    /// Reset the action to Default after the handler runs once.
    pub const SA_RESETHAND: Self = Self(1 << 1);
    /// Do not generate SIGCHLD when children stop.
    pub const SA_NOCLDSTOP: Self = Self(1 << 2);

    pub const fn empty() -> Self {
        Self(0)
    }

    pub const fn contains(self, other: Self) -> bool {
        (self.0 & other.0) == other.0
    }
}

/// Per-signal disposition table (one per process).
pub struct SignalTable {
    actions: [SignalAction; 32],
}

impl SignalTable {
    pub fn new() -> Self {
        Self {
            actions: [SignalAction::Default; 32],
        }
    }

    /// Register a handler for a signal. Returns error for SIGKILL/SIGSTOP.
    pub fn set_action(&mut self, sig: Signal, action: SignalAction) -> Result<(), ()> {
        if sig.is_uncatchable() && !matches!(action, SignalAction::Default) {
            return Err(()); // EINVAL: cannot catch or ignore SIGKILL/SIGSTOP
        }
        self.actions[sig as usize] = action;
        Ok(())
    }

    pub fn get_action(&self, sig: Signal) -> SignalAction {
        self.actions[sig as usize]
    }

    /// Reset all handlers to Default (called during exec).
    pub fn reset_on_exec(&mut self) {
        for action in self.actions.iter_mut() {
            if matches!(action, SignalAction::Handle { .. }) {
                *action = SignalAction::Default;
            }
        }
    }
}

/// Translate signal delivery into SOT operations.
///
/// SIGKILL: directly destroys the target domain (requires KILL cap).
/// All others: send an IPC message on the target's signal channel.
pub fn deliver_signal(sig: Signal, target_domain: Cap, signal_channel: Cap) -> SotOp {
    if sig == Signal::SIGKILL {
        // SIGKILL bypasses the channel -- immediate domain destruction.
        SotOp::DomainDestroy {
            domain: target_domain,
        }
    } else {
        // All other signals are delivered as IPC messages.
        SotOp::ChannelSend {
            channel: signal_channel,
            data: alloc::vec![sig as u8],
        }
    }
}

/// Create a signal channel for a new process.
pub fn create_signal_channel() -> SotOp {
    SotOp::ChannelCreate {
        mode: ChannelMode::Message,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signal_set_add_remove() {
        let mut set = SignalSet::empty();
        assert!(set.is_empty());
        set.add(Signal::SIGINT);
        assert!(set.contains(Signal::SIGINT));
        assert!(!set.contains(Signal::SIGTERM));
        set.remove(Signal::SIGINT);
        assert!(!set.contains(Signal::SIGINT));
    }

    #[test]
    fn signal_set_pop_lowest() {
        let mut set = SignalSet::empty();
        set.add(Signal::SIGTERM); // 15
        set.add(Signal::SIGINT);  // 2
        let first = set.pop_lowest().unwrap();
        assert_eq!(first, Signal::SIGINT); // lowest bit
    }

    #[test]
    fn cannot_catch_sigkill() {
        let mut table = SignalTable::new();
        let result = table.set_action(
            Signal::SIGKILL,
            SignalAction::Ignore,
        );
        assert!(result.is_err());
    }

    #[test]
    fn handler_resets_on_exec() {
        let mut table = SignalTable::new();
        table
            .set_action(
                Signal::SIGINT,
                SignalAction::Handle {
                    handler: 0x1000,
                    flags: SigActionFlags::empty(),
                },
            )
            .unwrap();
        table.set_action(Signal::SIGPIPE, SignalAction::Ignore).unwrap();
        table.reset_on_exec();
        assert_eq!(table.get_action(Signal::SIGINT), SignalAction::Default);
        // Ignored signals survive exec
        assert_eq!(table.get_action(Signal::SIGPIPE), SignalAction::Ignore);
    }

    #[test]
    fn sigkill_delivers_domain_destroy() {
        let op = deliver_signal(Signal::SIGKILL, 42, 100);
        assert!(matches!(op, SotOp::DomainDestroy { domain: 42 }));
    }

    #[test]
    fn normal_signal_delivers_ipc() {
        let op = deliver_signal(Signal::SIGTERM, 42, 100);
        match op {
            SotOp::ChannelSend { channel: 100, data } => {
                assert_eq!(data, alloc::vec![Signal::SIGTERM as u8]);
            }
            _ => panic!("expected ChannelSend"),
        }
    }
}
