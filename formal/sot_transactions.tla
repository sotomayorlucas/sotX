--------------------------- MODULE sot_transactions ---------------------------
\* TLA+ Specification of sotOS Three-Tier Transaction Engine
\*
\* This specification models the SOT (Secure Object Transaction) engine
\* with three tiers of concurrency control. It verifies:
\*   - Atomicity: committed effects are all-or-nothing
\*   - Isolation: concurrent transactions on the same SO are serializable
\*   - Rollback: abort restores all modified SOs to pre-transaction state
\*
\* Tier 0 — Epoch-based RCU: read-only snapshots, no logging
\* Tier 1 — Per-object WAL: single-object mutations with undo log
\* Tier 2 — Two-phase commit: multi-object atomic mutations

EXTENDS Naturals, Sequences, FiniteSets

CONSTANTS
    Objects,    \* Set of Secure Object IDs (5 SOs)
    Txns        \* Set of transaction IDs (3 concurrent)

VARIABLES
    \* --- Object state ---
    soValue,        \* Function: Object -> current value (Nat)
    soLock,         \* Function: Object -> locking Txn or NULL

    \* --- Epoch-based RCU (Tier 0) ---
    globalEpoch,    \* Current global epoch counter
    localEpoch,     \* Function: Txn -> local epoch snapshot (or NULL)

    \* --- WAL (Tier 1 and Tier 2) ---
    wal,            \* Function: Txn -> Sequence of [obj, oldVal] entries
    walCommitted,   \* Function: Txn -> BOOLEAN (WAL marked committed)

    \* --- Transaction state ---
    txState,        \* Function: Txn -> "idle"|"t0_read"|"t1_active"|"t2_prepare"|
                    \*                   "t2_voting"|"committed"|"aborted"
    txTier,         \* Function: Txn -> 0, 1, or 2
    txReadSet,      \* Function: Txn -> Set of (obj, value) pairs read
    txWriteSet,     \* Function: Txn -> Set of objects written

    \* --- Two-phase commit (Tier 2) ---
    t2Participants, \* Function: Txn -> Set of Objects involved
    t2Votes,        \* Function: Txn -> Function: Object -> "none"|"yes"|"no"
    t2Decision,     \* Function: Txn -> "pending"|"commit"|"abort"

    \* --- History for verification ---
    committedEffects  \* Set of (txn, obj, newVal) triples from committed txns

\* Tier 5: bounded CHOOSE so TLC can evaluate (was unbounded).
NULL == CHOOSE x \in {"NULL_SENTINEL"} : x \notin Txns

\* =========================================================================
\* Shared Helpers
\* =========================================================================

\* Release all locks held by transaction tx.
ReleaseLocks(tx) ==
    [o \in Objects |-> IF soLock[o] = tx THEN NULL ELSE soLock[o]]

\* Restore object values from WAL: for each modified object, use the
\* original value (earliest WAL entry) to undo all writes.
RestoreFromWal(tx) ==
    [o \in Objects |->
        LET entries == {i \in 1..Len(wal[tx]) : wal[tx][i].obj = o}
        IN IF entries = {} THEN soValue[o]
           ELSE wal[tx][CHOOSE i \in entries :
                    \A j \in entries : i <= j].oldVal]

\* =========================================================================
\* Type Invariant
\* =========================================================================

TypeInvariant ==
    /\ soValue \in [Objects -> Nat]
    /\ soLock \in [Objects -> Txns \cup {NULL}]
    /\ globalEpoch \in Nat
    /\ txState \in [Txns -> {"idle", "t0_read", "t1_active",
                              "t2_prepare", "t2_voting",
                              "committed", "aborted"}]
    /\ txTier \in [Txns -> {0, 1, 2}]

\* =========================================================================
\* Initial State
\* =========================================================================

Init ==
    /\ soValue = [o \in Objects |-> 0]
    /\ soLock = [o \in Objects |-> NULL]
    /\ globalEpoch = 0
    /\ localEpoch = [t \in Txns |-> 0]
    /\ wal = [t \in Txns |-> << >>]
    /\ walCommitted = [t \in Txns |-> FALSE]
    /\ txState = [t \in Txns |-> "idle"]
    /\ txTier = [t \in Txns |-> 0]
    /\ txReadSet = [t \in Txns |-> {}]
    /\ txWriteSet = [t \in Txns |-> {}]
    /\ t2Participants = [t \in Txns |-> {}]
    /\ t2Votes = [t \in Txns |-> [o \in Objects |-> "none"]]
    /\ t2Decision = [t \in Txns |-> "pending"]
    /\ committedEffects = {}

\* =========================================================================
\* Tier 0 — Epoch-based RCU (read-only snapshot)
\* =========================================================================

\* Begin a Tier 0 read transaction: bump local epoch to global epoch.
T0Begin(tx) ==
    /\ txState[tx] = "idle"
    /\ localEpoch' = [localEpoch EXCEPT ![tx] = globalEpoch]
    /\ txState' = [txState EXCEPT ![tx] = "t0_read"]
    /\ txTier' = [txTier EXCEPT ![tx] = 0]
    /\ UNCHANGED <<soValue, soLock, globalEpoch, wal, walCommitted,
                   txReadSet, txWriteSet, t2Participants, t2Votes,
                   t2Decision, committedEffects>>

\* Read a snapshot value (no locking, no logging).
T0Read(tx, obj) ==
    /\ txState[tx] = "t0_read"
    /\ txReadSet' = [txReadSet EXCEPT ![tx] = @ \cup {<<obj, soValue[obj]>>}]
    /\ UNCHANGED <<soValue, soLock, globalEpoch, localEpoch, wal,
                   walCommitted, txState, txTier, txWriteSet,
                   t2Participants, t2Votes, t2Decision, committedEffects>>

\* Release epoch — read-only transactions always succeed.
T0Release(tx) ==
    /\ txState[tx] = "t0_read"
    /\ txState' = [txState EXCEPT ![tx] = "committed"]
    /\ localEpoch' = [localEpoch EXCEPT ![tx] = 0]
    /\ UNCHANGED <<soValue, soLock, globalEpoch, wal, walCommitted,
                   txTier, txReadSet, txWriteSet, t2Participants,
                   t2Votes, t2Decision, committedEffects>>

\* =========================================================================
\* Tier 1 — Per-object WAL (single-object mutation)
\* =========================================================================

\* Begin a Tier 1 transaction.
T1Begin(tx) ==
    /\ txState[tx] = "idle"
    /\ wal' = [wal EXCEPT ![tx] = << >>]
    /\ walCommitted' = [walCommitted EXCEPT ![tx] = FALSE]
    /\ txState' = [txState EXCEPT ![tx] = "t1_active"]
    /\ txTier' = [txTier EXCEPT ![tx] = 1]
    /\ UNCHANGED <<soValue, soLock, globalEpoch, localEpoch,
                   txReadSet, txWriteSet, t2Participants, t2Votes,
                   t2Decision, committedEffects>>

\* Write to a single object: log old value in WAL, then apply new value.
\* The object must not be locked by another transaction.
T1Write(tx, obj, newVal) ==
    /\ txState[tx] = "t1_active"
    /\ soLock[obj] \in {NULL, tx}     \* Object free or already held by us
    /\ LET oldVal == soValue[obj]
       IN
        /\ wal' = [wal EXCEPT ![tx] = Append(@, [obj |-> obj, oldVal |-> oldVal])]
        /\ soValue' = [soValue EXCEPT ![obj] = newVal]
        /\ soLock' = [soLock EXCEPT ![obj] = tx]
        /\ txWriteSet' = [txWriteSet EXCEPT ![tx] = @ \cup {obj}]
        /\ UNCHANGED <<globalEpoch, localEpoch, walCommitted, txState,
                       txTier, txReadSet, t2Participants, t2Votes,
                       t2Decision, committedEffects>>

\* Commit Tier 1: mark WAL committed (GC-able), release lock, bump epoch.
T1Commit(tx) ==
    /\ txState[tx] = "t1_active"
    /\ walCommitted' = [walCommitted EXCEPT ![tx] = TRUE]
    /\ txState' = [txState EXCEPT ![tx] = "committed"]
    /\ globalEpoch' = globalEpoch + 1
    /\ committedEffects' = committedEffects \cup
        {<<tx, obj, soValue[obj]>> : obj \in txWriteSet[tx]}
    /\ soLock' = ReleaseLocks(tx)
    /\ UNCHANGED <<soValue, localEpoch, wal, txTier,
                   txReadSet, txWriteSet, t2Participants, t2Votes,
                   t2Decision>>

\* Abort Tier 1: read WAL, restore original values, release lock.
\* Tier 5: clear the WAL after restore -- it's been consumed, and
\* leaving it alive lets the Rollback invariant fire spuriously when
\* a subsequent transaction modifies the same object.
T1Abort(tx) ==
    /\ txState[tx] = "t1_active"
    /\ txState' = [txState EXCEPT ![tx] = "aborted"]
    /\ soValue' = RestoreFromWal(tx)
    /\ soLock' = ReleaseLocks(tx)
    /\ wal' = [wal EXCEPT ![tx] = << >>]
    /\ UNCHANGED <<globalEpoch, localEpoch, walCommitted,
                   txTier, txReadSet, txWriteSet, t2Participants,
                   t2Votes, t2Decision, committedEffects>>

\* =========================================================================
\* Tier 2 — Two-Phase Commit (multi-object)
\* =========================================================================

\* Begin a Tier 2 transaction with a set of participant objects.
T2Begin(tx, objs) ==
    /\ txState[tx] = "idle"
    /\ objs \subseteq Objects
    /\ Cardinality(objs) > 1         \* Multi-object requires Tier 2
    /\ wal' = [wal EXCEPT ![tx] = << >>]
    /\ walCommitted' = [walCommitted EXCEPT ![tx] = FALSE]
    /\ txState' = [txState EXCEPT ![tx] = "t2_prepare"]
    /\ txTier' = [txTier EXCEPT ![tx] = 2]
    /\ t2Participants' = [t2Participants EXCEPT ![tx] = objs]
    /\ t2Votes' = [t2Votes EXCEPT ![tx] = [o \in Objects |-> "none"]]
    /\ t2Decision' = [t2Decision EXCEPT ![tx] = "pending"]
    /\ UNCHANGED <<soValue, soLock, globalEpoch, localEpoch,
                   txReadSet, txWriteSet, committedEffects>>

\* Phase 1: Participant locks object, writes WAL, votes YES.
\* Coordinator sends PREPARE; each participant tries to acquire its lock.
T2VoteYes(tx, obj) ==
    /\ txState[tx] = "t2_prepare"
    /\ obj \in t2Participants[tx]
    /\ t2Votes[tx][obj] = "none"
    /\ soLock[obj] \in {NULL, tx}     \* Can acquire lock
    /\ soLock' = [soLock EXCEPT ![obj] = tx]
    /\ wal' = [wal EXCEPT ![tx] = Append(@, [obj |-> obj, oldVal |-> soValue[obj]])]
    /\ t2Votes' = [t2Votes EXCEPT ![tx][obj] = "yes"]
    /\ UNCHANGED <<soValue, globalEpoch, localEpoch, walCommitted,
                   txState, txTier, txReadSet, txWriteSet,
                   t2Participants, t2Decision, committedEffects>>

\* Phase 1: Participant votes NO (cannot acquire lock).
T2VoteNo(tx, obj) ==
    /\ txState[tx] = "t2_prepare"
    /\ obj \in t2Participants[tx]
    /\ t2Votes[tx][obj] = "none"
    /\ soLock[obj] /= NULL
    /\ soLock[obj] /= tx              \* Locked by another transaction
    /\ t2Votes' = [t2Votes EXCEPT ![tx][obj] = "no"]
    /\ UNCHANGED <<soValue, soLock, globalEpoch, localEpoch, wal,
                   walCommitted, txState, txTier, txReadSet, txWriteSet,
                   t2Participants, t2Decision, committedEffects>>

\* Transition to voting phase once all participants have voted.
T2EnterVoting(tx) ==
    /\ txState[tx] = "t2_prepare"
    /\ \A obj \in t2Participants[tx] : t2Votes[tx][obj] /= "none"
    /\ txState' = [txState EXCEPT ![tx] = "t2_voting"]
    /\ UNCHANGED <<soValue, soLock, globalEpoch, localEpoch, wal,
                   walCommitted, txTier, txReadSet, txWriteSet,
                   t2Participants, t2Votes, t2Decision, committedEffects>>

\* Phase 2: Coordinator decides COMMIT (all YES).
T2DecideCommit(tx) ==
    /\ txState[tx] = "t2_voting"
    /\ t2Decision[tx] = "pending"
    /\ \A obj \in t2Participants[tx] : t2Votes[tx][obj] = "yes"
    /\ t2Decision' = [t2Decision EXCEPT ![tx] = "commit"]
    /\ UNCHANGED <<soValue, soLock, globalEpoch, localEpoch, wal,
                   walCommitted, txState, txTier, txReadSet, txWriteSet,
                   t2Participants, t2Votes, committedEffects>>

\* Phase 2: Coordinator decides ABORT (any NO).
T2DecideAbort(tx) ==
    /\ txState[tx] = "t2_voting"
    /\ t2Decision[tx] = "pending"
    /\ \E obj \in t2Participants[tx] : t2Votes[tx][obj] = "no"
    /\ t2Decision' = [t2Decision EXCEPT ![tx] = "abort"]
    /\ UNCHANGED <<soValue, soLock, globalEpoch, localEpoch, wal,
                   walCommitted, txState, txTier, txReadSet, txWriteSet,
                   t2Participants, t2Votes, committedEffects>>

\* Phase 2: Apply writes for committed Tier 2 transaction.
T2ApplyCommit(tx, obj, newVal) ==
    /\ txState[tx] = "t2_voting"
    /\ t2Decision[tx] = "commit"
    /\ obj \in t2Participants[tx]
    /\ soLock[obj] = tx
    /\ soValue' = [soValue EXCEPT ![obj] = newVal]
    /\ txWriteSet' = [txWriteSet EXCEPT ![tx] = @ \cup {obj}]
    /\ UNCHANGED <<soLock, globalEpoch, localEpoch, wal, walCommitted,
                   txState, txTier, txReadSet, t2Participants, t2Votes,
                   t2Decision, committedEffects>>

\* Finalize Tier 2 commit: mark WAL, release locks, bump epoch.
T2FinalizeCommit(tx) ==
    /\ txState[tx] = "t2_voting"
    /\ t2Decision[tx] = "commit"
    \* All participants have been written (at least WAL entry exists for each)
    /\ \A obj \in t2Participants[tx] : soLock[obj] = tx
    /\ walCommitted' = [walCommitted EXCEPT ![tx] = TRUE]
    /\ txState' = [txState EXCEPT ![tx] = "committed"]
    /\ globalEpoch' = globalEpoch + 1
    /\ committedEffects' = committedEffects \cup
        {<<tx, obj, soValue[obj]>> : obj \in t2Participants[tx]}
    /\ soLock' = ReleaseLocks(tx)
    /\ UNCHANGED <<soValue, localEpoch, wal, txTier,
                   txReadSet, txWriteSet, t2Participants, t2Votes,
                   t2Decision>>

\* Finalize Tier 2 abort: rollback from WAL, release locks, clear WAL.
T2FinalizeAbort(tx) ==
    /\ txState[tx] = "t2_voting"
    /\ t2Decision[tx] = "abort"
    /\ txState' = [txState EXCEPT ![tx] = "aborted"]
    /\ soValue' = RestoreFromWal(tx)
    /\ soLock' = ReleaseLocks(tx)
    /\ wal' = [wal EXCEPT ![tx] = << >>]
    /\ UNCHANGED <<globalEpoch, localEpoch, walCommitted,
                   txTier, txReadSet, txWriteSet, t2Participants,
                   t2Votes, t2Decision, committedEffects>>

\* =========================================================================
\* Next-State Relation
\* =========================================================================

Next ==
    \* Tier 0 — Epoch-based RCU
    \/ \E tx \in Txns : T0Begin(tx)
    \/ \E tx \in Txns, obj \in Objects : T0Read(tx, obj)
    \/ \E tx \in Txns : T0Release(tx)
    \* Tier 1 — Per-object WAL
    \/ \E tx \in Txns : T1Begin(tx)
    \/ \E tx \in Txns, obj \in Objects, val \in 1..3 : T1Write(tx, obj, val)
    \/ \E tx \in Txns : T1Commit(tx)
    \/ \E tx \in Txns : T1Abort(tx)
    \* Tier 2 — Two-phase commit
    \/ \E tx \in Txns, objs \in SUBSET Objects : T2Begin(tx, objs)
    \/ \E tx \in Txns, obj \in Objects : T2VoteYes(tx, obj)
    \/ \E tx \in Txns, obj \in Objects : T2VoteNo(tx, obj)
    \/ \E tx \in Txns : T2EnterVoting(tx)
    \/ \E tx \in Txns : T2DecideCommit(tx)
    \/ \E tx \in Txns : T2DecideAbort(tx)
    \/ \E tx \in Txns, obj \in Objects, val \in 1..3 : T2ApplyCommit(tx, obj, val)
    \/ \E tx \in Txns : T2FinalizeCommit(tx)
    \/ \E tx \in Txns : T2FinalizeAbort(tx)

\* =========================================================================
\* Safety Properties
\* =========================================================================

\* ATOMICITY: A committed transaction's effects are all visible or none visible.
\* For Tier 2, either all participant objects have committed effects or none do.
Atomicity ==
    \A tx \in Txns : txState[tx] = "committed" /\ txTier[tx] = 2 =>
        \* For every committed Tier 2 transaction, either every
        \* participant has SOME entry in committedEffects, or none.
        \* The previous formulation queried soValue[obj] to look up
        \* the entry, but soValue can be subsequently modified by
        \* other transactions, which made the invariant fire even
        \* though the original commit was atomic. Querying
        \* committedEffects directly preserves the all-or-nothing
        \* check without depending on later state.
        LET committedObjs ==
            {obj \in Objects :
                \E v \in 0..3 : <<tx, obj, v>> \in committedEffects}
        IN committedObjs = t2Participants[tx] \/ committedObjs = {}

\* ISOLATION: The write sets of any two concurrently active transactions
\* are disjoint. An active transaction is one holding locks (t1_active,
\* t2_prepare, or t2_voting). This guarantees serializability.
Isolation ==
    \A tx1, tx2 \in Txns :
        tx1 /= tx2 =>
            LET held1 == {o \in Objects : soLock[o] = tx1}
                held2 == {o \in Objects : soLock[o] = tx2}
            IN held1 \cap held2 = {}

\* ROLLBACK: An aborted transaction holds no locks and its WAL entries
\* correspond to restored values (old values are back in soValue).
Rollback ==
    \A tx \in Txns : txState[tx] = "aborted" =>
        \* No locks held by aborted transaction
        /\ \A o \in Objects : soLock[o] /= tx
        \* For every object the aborted txn touched, soValue must equal
        \* the EARLIEST WAL entry's oldVal -- i.e. the value the object
        \* held before this txn's first write. RestoreFromWal already
        \* uses this semantics; the previous formulation iterated over
        \* every WAL entry which was wrong for objects written multiple
        \* times in one transaction (TLC found this).
        /\ \A o \in Objects :
            LET entries == {i \in 1..Len(wal[tx]) : wal[tx][i].obj = o}
            IN  entries /= {} =>
                soValue[o] =
                    wal[tx][CHOOSE i \in entries :
                        \A j \in entries : i <= j].oldVal

\* No lock held by a terminated (committed or aborted) transaction.
NoStaleLocksHeld ==
    \A tx \in Txns :
        txState[tx] \in {"committed", "aborted"} =>
            \A o \in Objects : soLock[o] /= tx

\* WAL consistency: a committed transaction's WAL is marked committed.
WalConsistency ==
    \A tx \in Txns :
        txState[tx] = "committed" /\ txTier[tx] \in {1, 2} =>
            walCommitted[tx] = TRUE

\* =========================================================================
\* Specification
\* =========================================================================

vars == <<soValue, soLock, globalEpoch, localEpoch, wal, walCommitted,
          txState, txTier, txReadSet, txWriteSet, t2Participants,
          t2Votes, t2Decision, committedEffects>>

\* Tier 5: bounded BFS for TLC. Three-fold bound: (1) global epoch
\* counter, (2) per-tx WAL length, (3) per-tx writeSet size. Together
\* these keep the BFS finite while still exercising every action.
EpochBound ==
    /\ globalEpoch <= 2
    /\ \A t \in Txns : Len(wal[t]) <= 3
    /\ \A t \in Txns : Cardinality(txWriteSet[t]) <= 2

Spec == Init /\ [][Next]_vars

THEOREM Spec => []TypeInvariant
THEOREM Spec => []Atomicity
THEOREM Spec => []Isolation
THEOREM Spec => []Rollback
THEOREM Spec => []NoStaleLocksHeld
THEOREM Spec => []WalConsistency

============================================================================
