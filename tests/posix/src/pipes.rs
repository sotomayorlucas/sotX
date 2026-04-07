//! POSIX pipe tests.
//!
//! LTP categories: syscalls/pipe, syscalls/dup, syscalls/select

#[cfg(test)]
mod tests {
    /// pipe() creates a unidirectional byte stream.
    /// LTP: pipe01
    #[test]
    fn pipe_creates_pair() {
        // TODO: pipe(fds). write(fds[1], "hello"). read(fds[0], buf).
        // Verify buf == "hello".
    }

    /// pipe() read returns 0 (EOF) when all write ends are closed.
    /// LTP: pipe02
    #[test]
    fn pipe_eof_on_close() {
        // TODO: pipe(fds). close(fds[1]). read(fds[0]).
        // Verify read returns 0.
    }

    /// write() to a pipe with no readers returns EPIPE.
    /// LTP: pipe03
    #[test]
    fn pipe_epipe_no_reader() {
        // TODO: pipe(fds). close(fds[0]). write(fds[1], "data").
        // Verify returns EPIPE (or SIGPIPE).
    }

    /// dup() duplicates a file descriptor.
    /// LTP: dup01
    #[test]
    fn dup_duplicates_fd() {
        // TODO: open file, dup(fd). Write via dup'd fd.
        // Read via original fd. Verify data matches.
    }

    /// dup2() duplicates to a specific fd number.
    /// LTP: dup201
    #[test]
    fn dup2_specific_fd() {
        // TODO: dup2(old_fd, 10). Verify fd 10 refers to same file.
    }

    /// pipe + fork: parent writes, child reads.
    /// LTP: pipe04
    #[test]
    fn pipe_across_fork() {
        // TODO: pipe(fds). fork(). Parent closes read end, writes.
        // Child closes write end, reads. Verify data transfer.
    }

    /// poll() detects readability on pipe.
    /// LTP: poll01
    #[test]
    fn poll_pipe_readable() {
        // TODO: pipe(fds). write to write end. poll(read end, POLLIN).
        // Verify POLLIN is set.
    }

    /// select() with timeout returns 0 on empty pipe.
    /// LTP: select01
    #[test]
    fn select_timeout_empty_pipe() {
        // TODO: pipe(fds). select(read end, timeout=10ms).
        // Verify returns 0 (timeout, no data).
    }
}
