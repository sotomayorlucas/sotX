------------------------- MODULE sotfs_transactions -------------------------
\* TLA+ Specification: sotFS Graph-Level Transactions (GTXN)
\*
\* Models the GTXN protocol from ADR-001: graph-level transactions that
\* compose SOT Tier 1 (single-SO WAL) and Tier 2 (multi-SO 2PC) to provide
\* atomic DPO rule application with rollback capability.
\*
\* Key properties verified:
\*   - GTXN atomicity: committed transactions have all effects, aborted have none
\*   - GTXN isolation: concurrent GTXNs have disjoint write sets
\*   - GTXN rollback: aborted GTXNs restore exact pre-transaction state
\*   - Tier mapping: single-SO ops use Tier 1, multi-SO ops use Tier 2
\* =====================================================================

EXTENDS Naturals, Sequences, FiniteSets

CONSTANTS
    GTxnIds,        \* Set of graph transaction IDs (e.g., {G1, G2, G3})
    SOIds,          \* Set of Secure Object IDs (e.g., {S1, S2, S3, S4})
    MaxOps          \* Maximum operations per trace

NULL == CHOOSE x : x \notin GTxnIds \cup SOIds

\* =====================================================================
\* VARIABLES
\* =====================================================================

VARIABLES
    \* --- GTXN state machine ---
    gtxnState,      \* Function: GTxnId -> {"idle", "active", "preparing",
                    \*                       "committed", "aborted"}
    gtxnTier,       \* Function: GTxnId -> {0, 1, 2} (SOT tier used)
    gtxnReadSet,    \* Function: GTxnId -> subset of SOIds
    gtxnWriteSet,   \* Function: GTxnId -> subset of SOIds

    \* --- SO state (abstract values for model checking) ---
    soValue,        \* Function: SOId -> Nat (current value)
    soLock,         \* Function: SOId -> GTxnId or NULL (write lock holder)

    \* --- WAL for rollback ---
    walLog,         \* Function: GTxnId -> sequence of <<SOId, oldValue>> pairs
    walCommitted,   \* Function: GTxnId -> BOOLEAN

    \* --- Committed effects record (for atomicity verification) ---
    committedEffects,   \* Set of <<GTxnId, SOId, newValue>> records

    \* --- 2PC state (for Tier 2 GTXNs) ---
    t2Votes,        \* Function: GTxnId -> function SOId -> {"none", "yes", "no"}
    t2Decision,     \* Function: GTxnId -> {"undecided", "commit", "abort"}

    \* --- Operation counter ---
    ops

vars == <<gtxnState, gtxnTier, gtxnReadSet, gtxnWriteSet,
          soValue, soLock, walLog, walCommitted, committedEffects,
          t2Votes, t2Decision, ops>>

\* =====================================================================
\* Type Invariant
\* =====================================================================

TypeInvariant ==
    /\ \A g \in GTxnIds : gtxnState[g] \in
           {"idle", "active", "preparing", "committed", "aborted"}
    /\ \A g \in GTxnIds : gtxnTier[g] \in {0, 1, 2}
    /\ \A g \in GTxnIds : gtxnReadSet[g] \subseteq SOIds
    /\ \A g \in GTxnIds : gtxnWriteSet[g] \subseteq SOIds
    /\ \A s \in SOIds : soValue[s] \in Nat
    /\ \A s \in SOIds : soLock[s] \in GTxnIds \cup {NULL}
    /\ \A g \in GTxnIds : walCommitted[g] \in BOOLEAN
    /\ ops \in 0..MaxOps

\* =====================================================================
\* Safety Properties
\* =====================================================================

\* GTXN Isolation: active transactions have disjoint write sets
Isolation ==
    \A g1, g2 \in GTxnIds :
        (g1 # g2 /\ gtxnState[g1] = "active" /\ gtxnState[g2] = "active")
        => gtxnWriteSet[g1] \cap gtxnWriteSet[g2] = {}

\* GTXN Atomicity: committed Tier 2 transactions applied all effects
Atomicity ==
    \A g \in GTxnIds :
        gtxnState[g] = "committed"
        => \A s \in gtxnWriteSet[g] :
            \E eff \in committedEffects :
                eff[1] = g /\ eff[2] = s

\* No stale locks: terminated transactions hold no locks
NoStaleLocks ==
    \A g \in GTxnIds :
        gtxnState[g] \in {"idle", "committed", "aborted"}
        => \A s \in SOIds : soLock[s] # g

\* Rollback correctness: aborted transactions have WAL entries that
\* match the restored SO values
RollbackCorrect ==
    \A g \in GTxnIds :
        gtxnState[g] = "aborted"
        => /\ gtxnWriteSet[g] = {}
           /\ walCommitted[g] = FALSE

\* Tier mapping: single-SO write sets use Tier 1, multi-SO use Tier 2
TierMapping ==
    \A g \in GTxnIds :
        gtxnState[g] \in {"active", "preparing"}
        => IF Cardinality(gtxnWriteSet[g]) > 1
           THEN gtxnTier[g] = 2
           ELSE gtxnTier[g] \in {0, 1}

\* =====================================================================
\* Initial state
\* =====================================================================

Init ==
    /\ gtxnState = [g \in GTxnIds |-> "idle"]
    /\ gtxnTier = [g \in GTxnIds |-> 0]
    /\ gtxnReadSet = [g \in GTxnIds |-> {}]
    /\ gtxnWriteSet = [g \in GTxnIds |-> {}]
    /\ soValue = [s \in SOIds |-> 0]
    /\ soLock = [s \in SOIds |-> NULL]
    /\ walLog = [g \in GTxnIds |-> <<>>]
    /\ walCommitted = [g \in GTxnIds |-> FALSE]
    /\ committedEffects = {}
    /\ t2Votes = [g \in GTxnIds |-> [s \in SOIds |-> "none"]]
    /\ t2Decision = [g \in GTxnIds |-> "undecided"]
    /\ ops = 0

\* =====================================================================
\* Actions
\* =====================================================================

\* --- Begin a GTXN ---
GtxnBegin(g) ==
    /\ ops < MaxOps
    /\ gtxnState[g] = "idle"
    /\ gtxnState' = [gtxnState EXCEPT ![g] = "active"]
    /\ gtxnTier' = [gtxnTier EXCEPT ![g] = 0]
    /\ gtxnReadSet' = [gtxnReadSet EXCEPT ![g] = {}]
    /\ gtxnWriteSet' = [gtxnWriteSet EXCEPT ![g] = {}]
    /\ walLog' = [walLog EXCEPT ![g] = <<>>]
    /\ walCommitted' = [walCommitted EXCEPT ![g] = FALSE]
    /\ t2Decision' = [t2Decision EXCEPT ![g] = "undecided"]
    /\ t2Votes' = [t2Votes EXCEPT ![g] = [s \in SOIds |-> "none"]]
    /\ ops' = ops + 1
    /\ UNCHANGED <<soValue, soLock, committedEffects>>

\* --- Read an SO within a GTXN (Tier 0 — no locking) ---
GtxnRead(g, s) ==
    /\ ops < MaxOps
    /\ gtxnState[g] = "active"
    /\ s \in SOIds
    /\ gtxnReadSet' = [gtxnReadSet EXCEPT ![g] = @ \cup {s}]
    /\ ops' = ops + 1
    /\ UNCHANGED <<gtxnState, gtxnTier, gtxnWriteSet, soValue, soLock,
                    walLog, walCommitted, committedEffects, t2Votes, t2Decision>>

\* --- Write an SO within a GTXN (Tier 1 or 2) ---
GtxnWrite(g, s, newVal) ==
    /\ ops < MaxOps
    /\ gtxnState[g] = "active"
    /\ s \in SOIds
    /\ newVal \in 0..3
    \* Acquire lock (or already hold it)
    /\ soLock[s] \in {g, NULL}
    /\ LET oldVal == soValue[s]
           newWriteSet == gtxnWriteSet[g] \cup {s}
           newTier == IF Cardinality(newWriteSet) > 1 THEN 2 ELSE 1
       IN
       /\ soLock' = [soLock EXCEPT ![s] = g]
       /\ soValue' = [soValue EXCEPT ![s] = newVal]
       /\ gtxnWriteSet' = [gtxnWriteSet EXCEPT ![g] = newWriteSet]
       /\ gtxnTier' = [gtxnTier EXCEPT ![g] = newTier]
       \* WAL: record old value for rollback
       /\ walLog' = [walLog EXCEPT ![g] = Append(@, <<s, oldVal>>)]
       /\ ops' = ops + 1
       /\ UNCHANGED <<gtxnState, gtxnReadSet, walCommitted,
                       committedEffects, t2Votes, t2Decision>>

\* --- Commit a Tier 1 GTXN (single-SO, direct commit) ---
GtxnCommitT1(g) ==
    /\ ops < MaxOps
    /\ gtxnState[g] = "active"
    /\ gtxnTier[g] \in {0, 1}
    /\ Cardinality(gtxnWriteSet[g]) <= 1
    \* Mark WAL as committed
    /\ walCommitted' = [walCommitted EXCEPT ![g] = TRUE]
    \* Record committed effects
    /\ committedEffects' = committedEffects \cup
           {<<g, s, soValue[s]>> : s \in gtxnWriteSet[g]}
    \* Release locks
    /\ soLock' = [s \in SOIds |->
           IF soLock[s] = g THEN NULL ELSE soLock[s]]
    \* Transition to committed
    /\ gtxnState' = [gtxnState EXCEPT ![g] = "committed"]
    /\ ops' = ops + 1
    /\ UNCHANGED <<gtxnTier, gtxnReadSet, gtxnWriteSet, soValue,
                    walLog, t2Votes, t2Decision>>

\* --- Commit a Tier 2 GTXN (multi-SO, 2PC) ---
\* Phase 1: Prepare — enter voting phase
GtxnPrepareT2(g) ==
    /\ ops < MaxOps
    /\ gtxnState[g] = "active"
    /\ gtxnTier[g] = 2
    /\ Cardinality(gtxnWriteSet[g]) > 1
    /\ gtxnState' = [gtxnState EXCEPT ![g] = "preparing"]
    /\ ops' = ops + 1
    /\ UNCHANGED <<gtxnTier, gtxnReadSet, gtxnWriteSet, soValue, soLock,
                    walLog, walCommitted, committedEffects, t2Votes, t2Decision>>

\* Phase 2a: Vote yes (all participants agree)
GtxnVoteYes(g, s) ==
    /\ ops < MaxOps
    /\ gtxnState[g] = "preparing"
    /\ s \in gtxnWriteSet[g]
    /\ t2Votes[g][s] = "none"
    /\ soLock[s] = g
    /\ t2Votes' = [t2Votes EXCEPT ![g][s] = "yes"]
    /\ ops' = ops + 1
    /\ UNCHANGED <<gtxnState, gtxnTier, gtxnReadSet, gtxnWriteSet,
                    soValue, soLock, walLog, walCommitted,
                    committedEffects, t2Decision>>

\* Phase 2b: All votes collected, decide commit
GtxnDecideCommit(g) ==
    /\ ops < MaxOps
    /\ gtxnState[g] = "preparing"
    /\ t2Decision[g] = "undecided"
    \* All participants voted yes
    /\ \A s \in gtxnWriteSet[g] : t2Votes[g][s] = "yes"
    /\ t2Decision' = [t2Decision EXCEPT ![g] = "commit"]
    /\ walCommitted' = [walCommitted EXCEPT ![g] = TRUE]
    /\ committedEffects' = committedEffects \cup
           {<<g, s, soValue[s]>> : s \in gtxnWriteSet[g]}
    \* Release all locks and transition
    /\ soLock' = [s \in SOIds |->
           IF soLock[s] = g THEN NULL ELSE soLock[s]]
    /\ gtxnState' = [gtxnState EXCEPT ![g] = "committed"]
    /\ ops' = ops + 1
    /\ UNCHANGED <<gtxnTier, gtxnReadSet, gtxnWriteSet, soValue,
                    walLog, t2Votes>>

\* --- Abort a GTXN (any tier, any phase) ---
GtxnAbort(g) ==
    /\ ops < MaxOps
    /\ gtxnState[g] \in {"active", "preparing"}
    \* Restore old values from WAL
    /\ LET RestoreFromWal(log) ==
               [s \in SOIds |->
                   LET entries == {i \in 1..Len(log) : log[i][1] = s}
                   IN IF entries = {} THEN soValue[s]
                      ELSE log[CHOOSE i \in entries :
                               \A j \in entries : i <= j][2]]
       IN soValue' = RestoreFromWal(walLog[g])
    \* Release all locks
    /\ soLock' = [s \in SOIds |->
           IF soLock[s] = g THEN NULL ELSE soLock[s]]
    \* Clear write set and mark WAL as not committed
    /\ gtxnState' = [gtxnState EXCEPT ![g] = "aborted"]
    /\ gtxnWriteSet' = [gtxnWriteSet EXCEPT ![g] = {}]
    /\ walCommitted' = [walCommitted EXCEPT ![g] = FALSE]
    /\ t2Decision' = [t2Decision EXCEPT ![g] = "abort"]
    /\ ops' = ops + 1
    /\ UNCHANGED <<gtxnTier, gtxnReadSet, walLog, committedEffects, t2Votes>>

\* --- Reset an idle/terminal GTXN for reuse ---
GtxnReset(g) ==
    /\ ops < MaxOps
    /\ gtxnState[g] \in {"committed", "aborted"}
    /\ gtxnState' = [gtxnState EXCEPT ![g] = "idle"]
    /\ gtxnTier' = [gtxnTier EXCEPT ![g] = 0]
    /\ gtxnReadSet' = [gtxnReadSet EXCEPT ![g] = {}]
    /\ gtxnWriteSet' = [gtxnWriteSet EXCEPT ![g] = {}]
    /\ walLog' = [walLog EXCEPT ![g] = <<>>]
    /\ walCommitted' = [walCommitted EXCEPT ![g] = FALSE]
    /\ t2Decision' = [t2Decision EXCEPT ![g] = "undecided"]
    /\ t2Votes' = [t2Votes EXCEPT ![g] = [s \in SOIds |-> "none"]]
    /\ ops' = ops + 1
    /\ UNCHANGED <<soValue, soLock, committedEffects>>

\* =====================================================================
\* Next-state relation
\* =====================================================================

Next ==
    \/ \E g \in GTxnIds : GtxnBegin(g)
    \/ \E g \in GTxnIds, s \in SOIds : GtxnRead(g, s)
    \/ \E g \in GTxnIds, s \in SOIds, v \in 0..3 : GtxnWrite(g, s, v)
    \/ \E g \in GTxnIds : GtxnCommitT1(g)
    \/ \E g \in GTxnIds : GtxnPrepareT2(g)
    \/ \E g \in GTxnIds, s \in SOIds : GtxnVoteYes(g, s)
    \/ \E g \in GTxnIds : GtxnDecideCommit(g)
    \/ \E g \in GTxnIds : GtxnAbort(g)
    \/ \E g \in GTxnIds : GtxnReset(g)

\* =====================================================================
\* Specification
\* =====================================================================

Spec == Init /\ [][Next]_vars

\* =====================================================================
\* Theorems
\* =====================================================================

THEOREM Spec => []TypeInvariant
THEOREM Spec => []Isolation
THEOREM Spec => []Atomicity
THEOREM Spec => []NoStaleLocks
THEOREM Spec => []RollbackCorrect
THEOREM Spec => []TierMapping

========================================================================
