//! Cross-channel consistency tests.
//!
//! These tests verify that the deception engine maintains a coherent
//! view across all channels. Information obtained through different
//! syscalls and pseudo-files must agree.

#[cfg(test)]
mod tests {
    use crate::{TestProfile, verify_profile_consistency};

    /// Verify hostname consistency across uname, /etc/hostname, and gethostname.
    ///
    /// All three must return the same hostname. If any disagree, the
    /// adversary can detect the inconsistency.
    #[test]
    fn hostname_cross_channel() {
        let profile = TestProfile::ubuntu_2204();
        let errors = verify_profile_consistency(&profile);
        assert!(errors.is_empty(), "hostname inconsistency: {:?}", errors);

        // TODO: In a live test, additionally verify:
        // - uname().nodename == "test-host"
        // - read("/etc/hostname") == "test-host\n"
        // - gethostname() == "test-host"
    }

    /// Verify that /proc/uptime increases monotonically.
    ///
    /// Reading /proc/uptime twice should return increasing values.
    /// If uptime jumps backward or is constant, the illusion breaks.
    #[test]
    fn uptime_monotonic() {
        // TODO: Read /proc/uptime at T=0 and T=1s.
        // Verify uptime[1] > uptime[0].
        // Verify uptime[1] - uptime[0] is approximately 1 second.
    }

    /// Verify that /proc/meminfo values are plausible.
    ///
    /// MemFree should be less than MemTotal. Buffers + Cached should
    /// not exceed MemTotal. Values should fluctuate slightly between reads.
    #[test]
    fn meminfo_plausible() {
        // TODO: Read /proc/meminfo twice.
        // Verify MemFree < MemTotal.
        // Verify Buffers + Cached < MemTotal.
        // Verify values change slightly between reads.
    }

    /// Verify that /proc/<pid>/status is consistent with /proc/<pid>/cmdline.
    ///
    /// The Name field in status should match the first argument in cmdline.
    #[test]
    fn process_status_cmdline_consistent() {
        let profile = TestProfile::ubuntu_2204();
        for proc in &profile.processes {
            // The cmdline's first component should match the process name
            let cmdline_name = proc.cmdline.split_whitespace().next().unwrap_or("");
            assert!(
                cmdline_name.contains(&proc.name.split('/').last().unwrap_or("")),
                "pid {} cmdline '{}' inconsistent with name '{}'",
                proc.pid, proc.cmdline, proc.name
            );
        }
    }

    /// Verify that file sizes derived from content are positive.
    ///
    /// stat(file).st_size should equal the number of bytes returned by
    /// reading the entire file.
    #[test]
    fn stat_size_matches_read_count() {
        let profile = TestProfile::ubuntu_2204();
        for file in &profile.files {
            assert_eq!(
                file.size(),
                file.content.len() as u64,
                "{}: stat size {} != read count {}",
                file.path,
                file.size(),
                file.content.len()
            );
        }
    }

    /// Verify that clock_gettime is consistent with /proc/uptime.
    ///
    /// CLOCK_MONOTONIC should advance at approximately the same rate
    /// as /proc/uptime.
    #[test]
    fn clock_vs_uptime_consistent() {
        // TODO: Read clock_gettime(CLOCK_MONOTONIC) and /proc/uptime.
        // Verify they differ by less than 1 second.
    }

    /// Verify that /etc/passwd UIDs match getuid() results.
    ///
    /// If the profile claims the current user is uid 1000, then
    /// getuid() must return 1000 and /etc/passwd must have an entry.
    #[test]
    fn uid_consistency() {
        // TODO: Read getuid(). Find matching entry in /etc/passwd.
        // Verify username and UID match.
    }

    /// Verify network interface consistency.
    ///
    /// /proc/net/dev, /sys/class/net/*, and SIOCGIFADDR ioctl must
    /// all agree on interface names and addresses.
    #[test]
    fn network_interface_consistency() {
        // TODO: Read interface list from three sources. Verify agreement.
    }
}
