//! POSIX signal tests.
//!
//! LTP categories: syscalls/sigaction, syscalls/kill, syscalls/sigprocmask

#[cfg(test)]
mod tests {
    /// sigaction() installs a signal handler.
    /// LTP: sigaction01
    #[test]
    fn sigaction_installs_handler() {
        // TODO: Install SIGUSR1 handler via rt_sigaction.
        // Raise SIGUSR1. Verify handler was called.
    }

    /// kill() delivers a signal to a process.
    /// LTP: kill01
    #[test]
    fn kill_delivers_signal() {
        // TODO: Fork. Parent sends SIGUSR1 to child.
        // Child has a handler that sets a flag. Verify flag set.
    }

    /// SIGKILL terminates a process unconditionally.
    /// LTP: kill02
    #[test]
    fn sigkill_terminates() {
        // TODO: Fork. Parent sends SIGKILL to child.
        // waitpid() should report child killed by SIGKILL.
    }

    /// sigprocmask() blocks signal delivery.
    /// LTP: sigprocmask01
    #[test]
    fn sigprocmask_blocks_delivery() {
        // TODO: Block SIGUSR1. Raise SIGUSR1. Verify handler NOT called.
        // Unblock. Verify handler IS called (pending signal delivered).
    }

    /// SIGCHLD is delivered when a child exits.
    /// LTP: sigchld01
    #[test]
    fn sigchld_on_child_exit() {
        // TODO: Install SIGCHLD handler. Fork. Child exits.
        // Verify SIGCHLD handler was called in parent.
    }

    /// sigaltstack() sets alternate signal stack.
    /// LTP: sigaltstack01
    #[test]
    fn sigaltstack_alternate() {
        // TODO: Allocate alternate stack. sigaltstack().
        // Raise signal. Verify handler runs on alternate stack
        // (RSP within the alternate stack region).
    }

    /// rt_sigreturn restores context after signal handler.
    /// LTP: rt_sigreturn01
    #[test]
    fn rt_sigreturn_restores_context() {
        // TODO: Install handler for SIGUSR1. Raise in middle of
        // computation. Verify computation resumes correctly after
        // handler returns (via rt_sigreturn).
    }
}
