//! Live migration to deception mode.
//!
//! When the system detects an intrusion, it can atomically migrate a
//! compromised domain into a deception environment. All capabilities held
//! by the domain are interposed so the attacker sees synthetic data while
//! the real system continues undisturbed.

use alloc::vec::Vec;

use crate::fake_fs::FsOverlay;
use crate::fake_net::NetworkDeception;
use crate::fake_proc::FakeProcessList;
use crate::interpose::{InterpositionEngine, InterpositionPolicy, InterpositionRule};
use crate::profile::DeceptionProfile;
use crate::DeceptionError;

/// Snapshot of a domain's state at the moment of migration (for forensics).
pub struct DomainSnapshot {
    /// Domain ID that was migrated.
    pub domain_id: u32,
    /// Timestamp (TSC value) when the snapshot was taken.
    pub timestamp_tsc: u64,
    /// Capabilities the domain held at migration time.
    pub caps: Vec<u64>,
    /// Number of threads active in the domain.
    pub thread_count: u32,
}

/// Tracks the state of a deception migration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MigrationState {
    /// Not started.
    Idle,
    /// Profile created, preparing interposition.
    Preparing,
    /// Transaction open, interposing capabilities.
    Interposing,
    /// All capabilities interposed, ready to commit.
    ReadyToCommit,
    /// Migration committed -- domain is now in deception.
    Active,
    /// Migration rolled back.
    RolledBack,
}

/// Orchestrates live migration of a domain into deception mode.
///
/// The migration follows a transactional pattern:
/// 1. Build the deception environment (profile + overlays).
/// 2. Open a transaction (conceptually: Tier 2 tx_begin).
/// 3. Interpose every capability held by the target domain.
/// 4. Snapshot domain state for forensics.
/// 5. Commit -- all interpositions activate atomically.
///
/// On failure at any step, the migration is rolled back and the domain
/// continues with its real capabilities unchanged.
pub struct MigrationController {
    pub state: MigrationState,
    pub domain_id: u32,
    pub proxy_domain: u32,
    pub engine: InterpositionEngine,
    pub fs: FsOverlay,
    pub procs: FakeProcessList,
    pub net: NetworkDeception,
    interposed_caps: Vec<u64>,
}

impl MigrationController {
    /// Create a new controller targeting `domain_id`.
    /// `proxy_domain` is the deception proxy that handles intercepted operations.
    pub fn new(domain_id: u32, proxy_domain: u32) -> Self {
        Self {
            state: MigrationState::Idle,
            domain_id,
            proxy_domain,
            engine: InterpositionEngine::new(),
            fs: FsOverlay::new(),
            procs: FakeProcessList::new(),
            net: NetworkDeception::new(),
            interposed_caps: Vec::new(),
        }
    }

    /// Step 1: Apply a deception profile, building the fake environment.
    pub fn prepare(&mut self, profile: &DeceptionProfile) -> Result<(), DeceptionError> {
        if self.state != MigrationState::Idle {
            return Err(DeceptionError::MigrationFailed);
        }
        profile.apply(&mut self.fs, &mut self.procs, &mut self.net)?;
        self.state = MigrationState::Preparing;
        Ok(())
    }

    /// Step 2+3: Interpose every capability in `domain_caps` with Inspect policy.
    ///
    /// In a real system, this would be wrapped in a Tier 2 transaction
    /// (tx_begin / tx_commit) so all interpositions activate atomically.
    /// Here we model the logic; the kernel integration calls the actual
    /// transaction primitives.
    pub fn interpose_all(&mut self, domain_caps: &[u64]) -> Result<(), DeceptionError> {
        if self.state != MigrationState::Preparing {
            return Err(DeceptionError::MigrationFailed);
        }
        self.state = MigrationState::Interposing;

        for &cap in domain_caps {
            let rule = InterpositionRule {
                original_cap: cap,
                proxy_domain: self.proxy_domain,
                policy: InterpositionPolicy::Inspect,
                cache_decisions: true,
            };
            self.engine.add_rule(rule)?;
            self.interposed_caps.push(cap);
        }

        self.state = MigrationState::ReadyToCommit;
        Ok(())
    }

    /// Step 4: Snapshot the domain state for forensic analysis.
    pub fn snapshot(&self, thread_count: u32, timestamp_tsc: u64) -> DomainSnapshot {
        DomainSnapshot {
            domain_id: self.domain_id,
            timestamp_tsc,
            caps: self.interposed_caps.clone(),
            thread_count,
        }
    }

    /// Step 5: Commit the migration. Returns the number of interposed capabilities.
    ///
    /// After this call, every capability invocation by the target domain
    /// passes through the interposition engine.
    pub fn commit(&mut self) -> Result<usize, DeceptionError> {
        if self.state != MigrationState::ReadyToCommit {
            return Err(DeceptionError::MigrationFailed);
        }
        let count = self.engine.active_count();
        self.state = MigrationState::Active;
        Ok(count)
    }

    /// Roll back the migration, removing all interpositions.
    pub fn rollback(&mut self) {
        for &cap in &self.interposed_caps {
            let _ = self.engine.remove_rule_for_cap(cap);
        }
        self.interposed_caps.clear();
        self.state = MigrationState::RolledBack;
    }

    /// Convenience: execute the full migration sequence in one call.
    ///
    /// `domain_caps` are the capabilities held by the target domain.
    /// `thread_count` and `timestamp_tsc` are used for the forensic snapshot.
    pub fn migrate_to_deception(
        &mut self,
        profile: &DeceptionProfile,
        domain_caps: &[u64],
        thread_count: u32,
        timestamp_tsc: u64,
    ) -> Result<(usize, DomainSnapshot), DeceptionError> {
        self.prepare(profile)?;

        if let Err(e) = self.interpose_all(domain_caps) {
            self.rollback();
            return Err(e);
        }

        let snapshot = self.snapshot(thread_count, timestamp_tsc);

        match self.commit() {
            Ok(count) => Ok((count, snapshot)),
            Err(e) => {
                self.rollback();
                Err(e)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::profile::UBUNTU_WEBSERVER;

    #[test]
    fn full_migration_flow() {
        let caps = [100, 101, 102, 103, 104];
        let mut ctrl = MigrationController::new(42, 99);

        let (count, snapshot) = ctrl
            .migrate_to_deception(&UBUNTU_WEBSERVER, &caps, 3, 123_456_789)
            .unwrap();

        assert_eq!(count, 5);
        assert_eq!(ctrl.state, MigrationState::Active);
        assert_eq!(snapshot.domain_id, 42);
        assert_eq!(snapshot.caps.len(), 5);
        assert_eq!(snapshot.thread_count, 3);

        // Every cap is now interposed.
        for &cap in &caps {
            assert!(ctrl.engine.is_interposed(cap));
        }
    }

    #[test]
    fn rollback_on_state_error() {
        let mut ctrl = MigrationController::new(1, 2);
        // Try to interpose without preparing -- should fail.
        assert_eq!(
            ctrl.interpose_all(&[10, 20]),
            Err(DeceptionError::MigrationFailed)
        );
    }
}
