//! Migration orchestrator -- transparently moves a compromised domain
//! into a deception environment.
//!
//! The pipeline:
//! 1. Anomaly detector flags a domain.
//! 2. Orchestrator selects a deception profile.
//! 3. For each capability the domain holds, an interposition rule is
//!    created so future invocations route through the profile.
//! 4. A snapshot is recorded for forensic analysis.
//! 5. The domain continues running, unaware it now lives in a lie.

use crate::anomaly::AnomalyPattern;
use crate::interpose::{InterpositionAction, InterpositionEngine};
use crate::profile::DeceptionProfile;

/// Maximum concurrent migrations.
const MAX_ACTIVE: usize = 16;

/// Maximum completed migration records kept for forensics.
const MAX_HISTORY: usize = 64;

/// Maximum capabilities per domain that can be interposed.
const MAX_DOMAIN_CAPS: usize = 64;

/// Errors that can occur during migration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MigrationError {
    /// No free slot in the active migrations table.
    TableFull,
    /// Domain is already in a deception environment.
    AlreadyMigrated,
    /// Interposition engine is full; cannot add more rules.
    InterpositionFull,
    /// Domain has no capabilities to interpose (nothing to do).
    NoCaps,
    /// Internal error during swap phase.
    SwapFailed,
}

/// Phase of an active migration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MigrationPhase {
    /// Preparing deception profile.
    Preparing,
    /// Swapping capabilities atomically.
    Swapping,
    /// Migration complete -- domain is in deception.
    Active,
    /// Migration failed -- rolled back.
    Failed,
}

/// State of a migration that is currently in progress or active.
pub struct MigrationState {
    pub domain_id: u32,
    pub profile_name: [u8; 32],
    pub phase: MigrationPhase,
    pub caps_interposed: u32,
    pub caps_total: u32,
    pub started_at: u64,
    pub snapshot_id: u64,
}

impl MigrationState {
    const fn empty() -> Self {
        Self {
            domain_id: 0,
            profile_name: [0; 32],
            phase: MigrationPhase::Preparing,
            caps_interposed: 0,
            caps_total: 0,
            started_at: 0,
            snapshot_id: 0,
        }
    }
}

/// A completed migration record for forensic review.
pub struct MigrationRecord {
    pub domain_id: u32,
    pub trigger: AnomalyPattern,
    pub profile: [u8; 32],
    pub started_at: u64,
    pub completed_at: u64,
    pub caps_interposed: u32,
    /// How many operations the attacker performed while in deception.
    pub post_migration_ops: u64,
}

impl MigrationRecord {
    const fn empty() -> Self {
        Self {
            domain_id: 0,
            trigger: AnomalyPattern::Custom { pattern_id: 0 },
            profile: [0; 32],
            started_at: 0,
            completed_at: 0,
            caps_interposed: 0,
            post_migration_ops: 0,
        }
    }
}

/// Central orchestrator for live migration to deception.
pub struct MigrationOrchestrator {
    active: [Option<MigrationState>; MAX_ACTIVE],
    history: [Option<MigrationRecord>; MAX_HISTORY],
    history_count: usize,
    interpose: InterpositionEngine,
    next_snapshot_id: u64,
}

impl MigrationOrchestrator {
    pub const fn new() -> Self {
        Self {
            active: [const { None }; MAX_ACTIVE],
            history: [const { None }; MAX_HISTORY],
            history_count: 0,
            interpose: InterpositionEngine::new(),
            next_snapshot_id: 1,
        }
    }

    /// Migrate a domain into deception.
    ///
    /// `domain_caps` is the set of capability IDs currently held by
    /// the target domain. The orchestrator interposes each one according
    /// to the deception profile.
    pub fn migrate(
        &mut self,
        domain_id: u32,
        profile: &DeceptionProfile,
        trigger: AnomalyPattern,
        domain_caps: &[u32],
        now: u64,
    ) -> Result<u64, MigrationError> {
        // Check if already migrated.
        if self.is_migrated(domain_id) {
            return Err(MigrationError::AlreadyMigrated);
        }

        if domain_caps.is_empty() {
            return Err(MigrationError::NoCaps);
        }

        // Find a free active slot.
        let slot = self.find_free_slot().ok_or(MigrationError::TableFull)?;

        let snapshot_id = self.next_snapshot_id;
        self.next_snapshot_id += 1;

        let cap_count = core::cmp::min(domain_caps.len(), MAX_DOMAIN_CAPS);

        // Phase 1: Preparing -- build the migration state.
        let mut state = MigrationState::empty();
        state.domain_id = domain_id;
        state.started_at = now;
        state.snapshot_id = snapshot_id;
        state.caps_total = cap_count as u32;
        state.phase = MigrationPhase::Preparing;
        state.profile_name = profile.name;

        // Phase 2: Swapping -- create interposition rules for each cap.
        state.phase = MigrationPhase::Swapping;
        let mut interposed = 0u32;
        for i in 0..cap_count {
            let cap_id = domain_caps[i];
            let action = self.action_for_cap(profile, cap_id);
            match self
                .interpose
                .add_rule(cap_id, domain_id, action, snapshot_id)
            {
                Some(_) => interposed += 1,
                None => {
                    // Rollback: remove any rules we already added.
                    self.interpose.remove_domain_rules(domain_id);
                    state.phase = MigrationPhase::Failed;
                    self.active[slot] = Some(state);
                    return Err(MigrationError::InterpositionFull);
                }
            }
        }

        // Phase 3: Active -- all caps interposed, migration complete.
        state.caps_interposed = interposed;
        state.phase = MigrationPhase::Active;
        self.active[slot] = Some(state);

        // Record in history.
        self.record_history(domain_id, trigger, &profile.name, now, interposed);

        Ok(snapshot_id)
    }

    /// Rollback a migration: remove all interposition rules and deactivate.
    pub fn rollback(&mut self, domain_id: u32) -> bool {
        self.interpose.remove_domain_rules(domain_id);

        for entry in self.active.iter_mut() {
            if let Some(ref mut s) = entry {
                if s.domain_id == domain_id {
                    s.phase = MigrationPhase::Failed;
                    *entry = None;
                    return true;
                }
            }
        }
        false
    }

    /// Query the current migration state for a domain.
    pub fn status(&self, domain_id: u32) -> Option<&MigrationState> {
        for entry in &self.active {
            if let Some(ref s) = entry {
                if s.domain_id == domain_id && s.phase == MigrationPhase::Active {
                    return Some(s);
                }
            }
        }
        None
    }

    /// Look up the forensic record for a domain.
    pub fn forensic_report(&self, domain_id: u32) -> Option<&MigrationRecord> {
        for i in 0..self.history_count {
            if let Some(ref r) = self.history[i] {
                if r.domain_id == domain_id {
                    return Some(r);
                }
            }
        }
        None
    }

    /// Check whether an operation on a capability should be interposed.
    /// If so, returns the action and records a hit.
    pub fn check_interposition(
        &mut self,
        domain_id: u32,
        cap_id: u32,
    ) -> Option<InterpositionAction> {
        let action = self.interpose.lookup_and_hit(domain_id, cap_id)?;

        for i in 0..self.history_count {
            if let Some(ref mut r) = self.history[i] {
                if r.domain_id == domain_id {
                    r.post_migration_ops += 1;
                    break;
                }
            }
        }
        Some(action)
    }

    /// Is this domain currently in a deception environment?
    pub fn is_migrated(&self, domain_id: u32) -> bool {
        self.status(domain_id).is_some()
    }

    // -- Internal helpers ---------------------------------------------------

    fn find_free_slot(&self) -> Option<usize> {
        for (i, entry) in self.active.iter().enumerate() {
            if entry.is_none() {
                return Some(i);
            }
        }
        None
    }

    /// Determine the interposition action for a given capability based
    /// on the deception profile. This is where profile-specific logic
    /// would consult fake files, services, etc.
    fn action_for_cap(&self, profile: &DeceptionProfile, _cap_id: u32) -> InterpositionAction {
        // For now, use the profile's default action. A real implementation
        // would map specific cap types (FS, Net, etc.) to different actions.
        profile.default_action
    }

    fn record_history(
        &mut self,
        domain_id: u32,
        trigger: AnomalyPattern,
        profile_name: &[u8; 32],
        now: u64,
        caps: u32,
    ) {
        if self.history_count >= MAX_HISTORY {
            // Evict oldest.
            for i in 0..MAX_HISTORY - 1 {
                self.history[i] = self.history[i + 1].take();
            }
            self.history_count = MAX_HISTORY - 1;
        }

        let mut record = MigrationRecord::empty();
        record.domain_id = domain_id;
        record.trigger = trigger;
        record.profile = *profile_name;
        record.started_at = now;
        record.completed_at = now;
        record.caps_interposed = caps;
        self.history[self.history_count] = Some(record);
        self.history_count += 1;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_profile() -> DeceptionProfile {
        let mut p = DeceptionProfile::with_name(b"test-honeypot");
        p.default_action = InterpositionAction::FakeResponse;
        p.add_file(0xF001, b"fake:x:0:0:::\n", 0o640);
        p
    }

    #[test]
    fn migrate_and_status() {
        let mut orch = MigrationOrchestrator::new();
        let profile = test_profile();
        let caps = [10, 11, 12];

        let snap = orch
            .migrate(
                1,
                &profile,
                AnomalyPattern::CredentialTheftAfterBackdoor,
                &caps,
                1000,
            )
            .unwrap();

        assert!(snap > 0);
        assert!(orch.is_migrated(1));

        let state = orch.status(1).unwrap();
        assert_eq!(state.phase, MigrationPhase::Active);
        assert_eq!(state.caps_interposed, 3);
        assert_eq!(state.caps_total, 3);
    }

    #[test]
    fn double_migrate_rejected() {
        let mut orch = MigrationOrchestrator::new();
        let profile = test_profile();
        let caps = [10];
        orch.migrate(1, &profile, AnomalyPattern::StagedPayload, &caps, 1)
            .unwrap();

        let err = orch
            .migrate(1, &profile, AnomalyPattern::StagedPayload, &caps, 2)
            .unwrap_err();
        assert_eq!(err, MigrationError::AlreadyMigrated);
    }

    #[test]
    fn rollback_removes_migration() {
        let mut orch = MigrationOrchestrator::new();
        let profile = test_profile();
        let caps = [10, 11];
        orch.migrate(
            1,
            &profile,
            AnomalyPattern::ReconnaissanceSweep,
            &caps,
            1,
        )
        .unwrap();

        assert!(orch.rollback(1));
        assert!(!orch.is_migrated(1));
    }

    #[test]
    fn interposition_check_and_ops_count() {
        let mut orch = MigrationOrchestrator::new();
        let profile = test_profile();
        let caps = [42];
        orch.migrate(
            5,
            &profile,
            AnomalyPattern::DataExfiltration,
            &caps,
            100,
        )
        .unwrap();

        // Simulate attacker using cap 42 three times.
        assert_eq!(
            orch.check_interposition(5, 42),
            Some(InterpositionAction::FakeResponse)
        );
        assert_eq!(
            orch.check_interposition(5, 42),
            Some(InterpositionAction::FakeResponse)
        );
        assert_eq!(
            orch.check_interposition(5, 42),
            Some(InterpositionAction::FakeResponse)
        );

        // Non-interposed cap returns None.
        assert!(orch.check_interposition(5, 99).is_none());

        // Forensic report tracks ops.
        let report = orch.forensic_report(5).unwrap();
        assert_eq!(report.post_migration_ops, 3);
    }

    #[test]
    fn no_caps_rejected() {
        let mut orch = MigrationOrchestrator::new();
        let profile = test_profile();
        let err = orch
            .migrate(
                1,
                &profile,
                AnomalyPattern::StagedPayload,
                &[],
                1,
            )
            .unwrap_err();
        assert_eq!(err, MigrationError::NoCaps);
    }

    #[test]
    fn forensic_report_after_migration() {
        let mut orch = MigrationOrchestrator::new();
        let profile = test_profile();
        let caps = [1, 2, 3, 4, 5];
        orch.migrate(
            7,
            &profile,
            AnomalyPattern::PersistenceInstall,
            &caps,
            500,
        )
        .unwrap();

        let report = orch.forensic_report(7).unwrap();
        assert_eq!(report.domain_id, 7);
        assert_eq!(report.caps_interposed, 5);
        assert_eq!(report.started_at, 500);
    }
}
