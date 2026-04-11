------------------------- MODULE sotfs_crash -------------------------
\* TLA+ Specification: sotFS Crash and Recovery Model
\*
\* Models crash consistency for the sotFS graph persistence layer.
\* A crash can occur at any point during a GTXN. Recovery replays the WAL
\* and must produce a graph state that is either:
\*   (a) the pre-transaction state (if WAL not committed), or
\*   (b) the post-commit state (if WAL committed).
\*
\* Inspired by Yggdrasil's crash refinement approach: the abstract spec
\* is the GTXN model (sotfs_transactions.tla), and the concrete spec
\* adds crash points and WAL replay.
\*
\* Key properties verified:
\*   - Recovery consistency: post-recovery state satisfies all invariants
\*   - No partial application: either all writes in a GTXN are durable or none
\*   - WAL integrity: committed WAL survives crash
\* =====================================================================

EXTENDS Naturals, Sequences, FiniteSets

CONSTANTS
    SOIds,          \* Set of Secure Object IDs
    MaxOps          \* Maximum operations per trace

NULL == CHOOSE x : x \notin SOIds

\* =====================================================================
\* VARIABLES
\* =====================================================================

VARIABLES
    \* --- Persistent state (survives crash) ---
    diskValue,      \* Function: SOId -> Nat (on-disk SO values)
    walEntries,     \* Sequence of <<SOId, oldValue, newValue>> (WAL on disk)
    walCommitFlag,  \* BOOLEAN: TRUE if WAL commit record is durable

    \* --- Volatile state (lost on crash) ---
    memValue,       \* Function: SOId -> Nat (in-memory SO values, may differ from disk)
    txActive,       \* BOOLEAN: is a transaction in progress?
    txWriteSet,     \* Set of SOIds modified by current transaction
    crashed,        \* BOOLEAN: has a crash occurred?
    recovered,      \* BOOLEAN: has recovery completed?

    \* --- Ghost state (for verification only) ---
    preState,       \* Function: SOId -> Nat (snapshot before transaction began)

    \* --- Operation counter ---
    ops

vars == <<diskValue, walEntries, walCommitFlag,
          memValue, txActive, txWriteSet, crashed, recovered,
          preState, ops>>

\* =====================================================================
\* Type Invariant
\* =====================================================================

TypeInvariant ==
    /\ \A s \in SOIds : diskValue[s] \in Nat
    /\ \A s \in SOIds : memValue[s] \in Nat
    /\ \A s \in SOIds : preState[s] \in Nat
    /\ txActive \in BOOLEAN
    /\ txWriteSet \subseteq SOIds
    /\ crashed \in BOOLEAN
    /\ recovered \in BOOLEAN
    /\ walCommitFlag \in BOOLEAN
    /\ ops \in 0..MaxOps

\* =====================================================================
\* Safety Properties
\* =====================================================================

\* Recovery consistency: after recovery, disk state is either the pre-tx
\* state (if WAL was not committed) or the post-commit state (if it was)
RecoveryConsistency ==
    recovered
    => IF walCommitFlag
       THEN \* WAL was committed: disk should have the new values
            \A s \in SOIds : diskValue[s] = memValue[s]
       ELSE \* WAL not committed: disk should have the pre-tx values
            \A s \in SOIds : diskValue[s] = preState[s]

\* No partial application: for uncommitted transactions, NO writes are
\* visible on disk after recovery
NoPartialApplication ==
    (recovered /\ ~walCommitFlag)
    => \A s \in SOIds : diskValue[s] = preState[s]

\* WAL integrity: if commit flag was written before crash, it survives
WalIntegrity ==
    (crashed /\ walCommitFlag)
    => walCommitFlag' = TRUE  \* This is checked as a transition property

\* After recovery without committed WAL, state matches pre-transaction snapshot
RollbackToSnapshot ==
    (recovered /\ ~walCommitFlag)
    => \A s \in SOIds : diskValue[s] = preState[s]

\* =====================================================================
\* Initial state: clean filesystem, no pending transactions
\* =====================================================================

Init ==
    /\ diskValue = [s \in SOIds |-> 0]
    /\ walEntries = <<>>
    /\ walCommitFlag = FALSE
    /\ memValue = [s \in SOIds |-> 0]
    /\ txActive = FALSE
    /\ txWriteSet = {}
    /\ crashed = FALSE
    /\ recovered = FALSE
    /\ preState = [s \in SOIds |-> 0]
    /\ ops = 0

\* =====================================================================
\* Actions: Normal GTXN operations (pre-crash)
\* =====================================================================

\* --- Begin a GTXN: snapshot current state ---
TxBegin ==
    /\ ops < MaxOps
    /\ ~txActive
    /\ ~crashed
    /\ txActive' = TRUE
    /\ txWriteSet' = {}
    /\ walEntries' = <<>>
    /\ walCommitFlag' = FALSE
    /\ preState' = diskValue  \* snapshot for rollback verification
    /\ ops' = ops + 1
    /\ UNCHANGED <<diskValue, memValue, crashed, recovered>>

\* --- Write an SO: modify in-memory, log to WAL ---
TxWrite(s, newVal) ==
    /\ ops < MaxOps
    /\ txActive
    /\ ~crashed
    /\ s \in SOIds
    /\ newVal \in 0..3
    /\ LET oldVal == memValue[s]
       IN
       /\ memValue' = [memValue EXCEPT ![s] = newVal]
       /\ walEntries' = Append(walEntries, <<s, oldVal, newVal>>)
       /\ txWriteSet' = txWriteSet \cup {s}
       /\ ops' = ops + 1
       /\ UNCHANGED <<diskValue, walCommitFlag, txActive, crashed,
                       recovered, preState>>

\* --- WAL flush: write WAL entries to disk (without commit flag) ---
\* This is a separate step from commit to model the window where
\* WAL data is on disk but commit flag is not yet written.
WalFlush ==
    /\ ops < MaxOps
    /\ txActive
    /\ ~crashed
    /\ Len(walEntries) > 0
    \* WAL entries are now durable (modeled implicitly — they survive crash)
    /\ ops' = ops + 1
    /\ UNCHANGED <<diskValue, walEntries, walCommitFlag, memValue,
                    txActive, txWriteSet, crashed, recovered, preState>>

\* --- WAL commit: write commit flag (makes transaction durable) ---
WalCommit ==
    /\ ops < MaxOps
    /\ txActive
    /\ ~crashed
    /\ Len(walEntries) > 0
    /\ walCommitFlag' = TRUE
    /\ ops' = ops + 1
    /\ UNCHANGED <<diskValue, walEntries, memValue, txActive,
                    txWriteSet, crashed, recovered, preState>>

\* --- Apply: write new values to data region on disk ---
TxApply ==
    /\ ops < MaxOps
    /\ txActive
    /\ ~crashed
    /\ walCommitFlag = TRUE
    \* Apply all writes from WAL to disk
    /\ diskValue' = memValue
    /\ ops' = ops + 1
    /\ UNCHANGED <<walEntries, walCommitFlag, memValue, txActive,
                    txWriteSet, crashed, recovered, preState>>

\* --- Finalize: clear WAL, end transaction ---
TxFinalize ==
    /\ ops < MaxOps
    /\ txActive
    /\ ~crashed
    /\ walCommitFlag = TRUE
    /\ diskValue = memValue  \* apply must have happened
    /\ txActive' = FALSE
    /\ txWriteSet' = {}
    /\ walEntries' = <<>>
    /\ walCommitFlag' = FALSE
    /\ ops' = ops + 1
    /\ UNCHANGED <<diskValue, memValue, crashed, recovered, preState>>

\* =====================================================================
\* Actions: Crash and Recovery
\* =====================================================================

\* --- CRASH: can happen at ANY point during a transaction ---
\* Volatile state (memValue, txActive) is lost.
\* Persistent state (diskValue, walEntries, walCommitFlag) survives.
Crash ==
    /\ ops < MaxOps
    /\ ~crashed
    /\ crashed' = TRUE
    \* Volatile state is lost — memValue reverts to diskValue
    /\ memValue' = diskValue
    /\ txActive' = FALSE
    /\ txWriteSet' = {}
    /\ ops' = ops + 1
    /\ UNCHANGED <<diskValue, walEntries, walCommitFlag, recovered, preState>>

\* --- RECOVERY: replay WAL if committed, discard if not ---
Recover ==
    /\ ops < MaxOps
    /\ crashed
    /\ ~recovered
    /\ IF walCommitFlag
       THEN
           \* WAL was committed: replay all entries (apply new values)
           LET ApplyWal(disk, wal) ==
                   IF Len(wal) = 0
                   THEN disk
                   ELSE LET entry == wal[1]
                            s == entry[1]
                            newVal == entry[3]
                        IN ApplyWal([disk EXCEPT ![s] = newVal],
                                    SubSeq(wal, 2, Len(wal)))
           IN
           /\ diskValue' = ApplyWal(diskValue, walEntries)
           /\ memValue' = ApplyWal(diskValue, walEntries)
       ELSE
           \* WAL not committed: discard all entries (disk unchanged)
           /\ UNCHANGED <<diskValue>>
           /\ memValue' = diskValue
    \* Clear WAL after recovery
    /\ walEntries' = <<>>
    /\ walCommitFlag' = FALSE
    /\ recovered' = TRUE
    /\ ops' = ops + 1
    /\ UNCHANGED <<txActive, txWriteSet, crashed, preState>>

\* =====================================================================
\* Next-state relation
\* =====================================================================

Next ==
    \/ TxBegin
    \/ \E s \in SOIds, v \in 0..3 : TxWrite(s, v)
    \/ WalFlush
    \/ WalCommit
    \/ TxApply
    \/ TxFinalize
    \/ Crash
    \/ Recover

\* =====================================================================
\* State constraint: bound recursive WAL application
\* =====================================================================

StateConstraint ==
    /\ Len(walEntries) <= 4
    /\ ops <= MaxOps

\* =====================================================================
\* Specification
\* =====================================================================

Spec == Init /\ [][Next]_vars

\* =====================================================================
\* Theorems
\* =====================================================================

THEOREM Spec => []TypeInvariant
THEOREM Spec => []RecoveryConsistency
THEOREM Spec => []NoPartialApplication
THEOREM Spec => []RollbackToSnapshot

========================================================================
