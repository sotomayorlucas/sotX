use crate::syscall::*;

// ---------------------------------------------------------------------------
// Job control
// ---------------------------------------------------------------------------

pub const MAX_JOBS: usize = 16;
pub const MAX_JOB_CMD: usize = 128;

pub const JOB_NONE: u8 = 0;
pub const JOB_RUNNING: u8 = 1;
pub const JOB_STOPPED: u8 = 2;
pub const JOB_DONE: u8 = 3;

pub struct Job {
    pub active: bool,
    pub pid: u64,
    pub status: u8,
    pub cmd: [u8; MAX_JOB_CMD],
    pub cmd_len: usize,
}

impl Job {
    pub const fn empty() -> Self {
        Self { active: false, pid: 0, status: JOB_NONE, cmd: [0; MAX_JOB_CMD], cmd_len: 0 }
    }
}

pub static mut JOBS: [Job; MAX_JOBS] = {
    const INIT: Job = Job::empty();
    [INIT; MAX_JOBS]
};

pub fn jobs_slice() -> &'static [Job] {
    unsafe { core::slice::from_raw_parts(core::ptr::addr_of!(JOBS) as *const Job, MAX_JOBS) }
}

pub fn jobs_slice_mut() -> &'static mut [Job] {
    unsafe { core::slice::from_raw_parts_mut(core::ptr::addr_of_mut!(JOBS) as *mut Job, MAX_JOBS) }
}

pub fn job_add(pid: u64, status: u8, cmd: &[u8]) -> usize {
    for (i, j) in jobs_slice_mut().iter_mut().enumerate() {
        if !j.active {
            j.active = true;
            j.pid = pid;
            j.status = status;
            let cl = cmd.len().min(MAX_JOB_CMD);
            j.cmd[..cl].copy_from_slice(&cmd[..cl]);
            j.cmd_len = cl;
            return i + 1; // 1-based job IDs
        }
    }
    0 // no free slot
}

pub fn job_find_by_id(id: usize) -> Option<&'static mut Job> {
    if id == 0 || id > MAX_JOBS { return None; }
    let j = &mut jobs_slice_mut()[id - 1];
    if j.active { Some(j) } else { None }
}

/// Track the PID of the foreground child (0 = none).
pub static mut FG_PID: u64 = 0;

pub fn set_fg_pid(pid: u64) {
    unsafe { FG_PID = pid; }
}

pub fn get_fg_pid() -> u64 {
    unsafe { FG_PID }
}

/// Reap background jobs that have finished (non-blocking).
pub fn reap_done_jobs() {
    for (i, j) in jobs_slice_mut().iter_mut().enumerate() {
        if j.active && j.status == JOB_RUNNING {
            let ret = linux_waitpid_wnohang(j.pid);
            if ret > 0 {
                // Child exited
                j.status = JOB_DONE;
                print(b"[");
                print_u64((i + 1) as u64);
                print(b"]  Done       ");
                print(&j.cmd[..j.cmd_len]);
                print(b"\n");
            } else if ret < 0 {
                // Child gone (error)
                j.status = JOB_DONE;
            }
            // ret == 0 means still running, skip
        }
    }
}

// ---------------------------------------------------------------------------
// Job control commands
// ---------------------------------------------------------------------------

pub fn cmd_jobs() {
    for (i, j) in jobs_slice().iter().enumerate() {
        if j.active {
            print(b"[");
            print_u64((i + 1) as u64);
            print(b"]  ");
            match j.status {
                JOB_RUNNING => print(b"Running    "),
                JOB_STOPPED => print(b"Stopped    "),
                JOB_DONE    => print(b"Done       "),
                _           => print(b"Unknown    "),
            }
            print(&j.cmd[..j.cmd_len]);
            print(b"\n");
        }
    }
    // Clean up done jobs after listing
    for j in jobs_slice_mut().iter_mut() {
        if j.active && j.status == JOB_DONE {
            j.active = false;
        }
    }
}

pub fn cmd_fg(id: usize) {
    // If id==0, find most recent running/stopped job
    let job_id = if id == 0 {
        let mut last: usize = 0;
        for (i, j) in jobs_slice().iter().enumerate() {
            if j.active && (j.status == JOB_RUNNING || j.status == JOB_STOPPED) {
                last = i + 1;
            }
        }
        last
    } else {
        id
    };

    if let Some(j) = job_find_by_id(job_id) {
        let pid = j.pid;
        print(&j.cmd[..j.cmd_len]);
        print(b"\n");
        if j.status == JOB_STOPPED {
            // Resume the process
            linux_kill(pid, 18); // SIGCONT
            j.status = JOB_RUNNING;
        }
        // Wait for it
        set_fg_pid(pid);
        linux_waitpid(pid);
        set_fg_pid(0);
        j.status = JOB_DONE;
        j.active = false;
    } else {
        print(b"fg: no such job\n");
    }
}

pub fn cmd_bg(id: usize) {
    let job_id = if id == 0 {
        let mut last: usize = 0;
        for (i, j) in jobs_slice().iter().enumerate() {
            if j.active && j.status == JOB_STOPPED {
                last = i + 1;
            }
        }
        last
    } else {
        id
    };

    if let Some(j) = job_find_by_id(job_id) {
        if j.status == JOB_STOPPED {
            linux_kill(j.pid, 18); // SIGCONT
            j.status = JOB_RUNNING;
            print(b"[");
            print_u64(job_id as u64);
            print(b"]  ");
            print(&j.cmd[..j.cmd_len]);
            print(b" &\n");
        } else {
            print(b"bg: job not stopped\n");
        }
    } else {
        print(b"bg: no such job\n");
    }
}
