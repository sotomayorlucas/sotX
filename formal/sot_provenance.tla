--------------------------- MODULE sot_provenance ---------------------------
\* TLA+ Specification of SOT Provenance Completeness
\*
\* This specification models the provenance ring buffer system used to
\* record every SO (Sovereign Object) operation. It verifies:
\*   - Completeness: every SO invocation produces exactly one provenance entry
\*   - Ordering: entries within a single CPU's ring are monotonically ordered by epoch
\*   - No silent loss: ring-full conditions increment a dropped counter
\*
\* The model covers 2 CPUs, each with a per-CPU SPSC ring buffer (capacity 8).
\* A kernel hot path producer appends entries; a provenance domain consumer drains them.

EXTENDS Naturals, Sequences, FiniteSets

CONSTANTS
    RingCap,        \* Ring buffer capacity per CPU (8 for model checking)
    Domains,        \* Set of domain IDs
    SoObjects,      \* Set of SO identifiers
    Operations      \* Set of operation types (e.g., "create", "read", "write", "delete")

CPUs == {0, 1}      \* 2 CPUs for model checking

VARIABLES
    ring,           \* Function: CPU -> Sequence of provenance entry records
    epoch,          \* Function: CPU -> monotonic epoch counter
    dropped,        \* Function: CPU -> count of entries dropped due to full ring
    invocationCount,\* Total number of SO invocations performed
    consumedCount,  \* Total number of entries drained by the consumer
    nextTxId        \* Global transaction ID counter

vars == <<ring, epoch, dropped, invocationCount, consumedCount, nextTxId>>

TypeInvariant ==
    /\ \A c \in CPUs : Len(ring[c]) <= RingCap
    /\ \A c \in CPUs : epoch[c] \in Nat
    /\ \A c \in CPUs : dropped[c] \in Nat
    /\ invocationCount \in Nat
    /\ consumedCount \in Nat
    /\ nextTxId \in Nat

Init ==
    /\ ring = [c \in CPUs |-> << >>]
    /\ epoch = [c \in CPUs |-> 0]
    /\ dropped = [c \in CPUs |-> 0]
    /\ invocationCount = 0
    /\ consumedCount = 0
    /\ nextTxId = 1

\* --- SoInvoke: a domain performs an operation on an SO, producing a provenance entry ---
\* Every invocation MUST produce exactly one provenance entry (appended to ring)
\* or exactly one dropped increment.
SoInvoke(cpu, domain, so, op) ==
    /\ LET e == epoch[cpu] + 1
           entry == [epoch     |-> e,
                     domain_id |-> domain,
                     operation |-> op,
                     so_id     |-> so,
                     version   |-> e,
                     tx_id     |-> nextTxId]
       IN
        /\ epoch' = [epoch EXCEPT ![cpu] = e]
        /\ nextTxId' = nextTxId + 1
        /\ invocationCount' = invocationCount + 1
        /\ IF Len(ring[cpu]) < RingCap THEN
            /\ ring' = [ring EXCEPT ![cpu] = Append(@, entry)]
            /\ UNCHANGED dropped
           ELSE
            /\ dropped' = [dropped EXCEPT ![cpu] = @ + 1]
            /\ UNCHANGED ring
        /\ UNCHANGED consumedCount

\* --- ConsumerDrain: pop one entry from a CPU's ring ---
ConsumerDrain(cpu) ==
    /\ Len(ring[cpu]) > 0
    /\ ring' = [ring EXCEPT ![cpu] = Tail(@)]
    /\ consumedCount' = consumedCount + 1
    /\ UNCHANGED <<epoch, dropped, invocationCount, nextTxId>>

\* --- Next-State Relation ---
Next ==
    \/ \E c \in CPUs, d \in Domains, s \in SoObjects, op \in Operations :
        SoInvoke(c, d, s, op)
    \/ \E c \in CPUs : ConsumerDrain(c)

\* --- Safety Properties ---

\* COMPLETENESS: invocations = entries still in rings + entries consumed + entries dropped.
Completeness ==
    invocationCount =
        Len(ring[0]) + Len(ring[1])
        + consumedCount
        + dropped[0] + dropped[1]

\* ORDERING: Within each CPU's ring, entries are monotonically ordered by epoch.
Ordering ==
    \A c \in CPUs :
        \A i \in 1..(Len(ring[c]) - 1) :
            ring[c][i].epoch < ring[c][i + 1].epoch

\* --- Liveness (optional) ---
\* If the consumer keeps draining, eventually the ring has space.
EventualSpace == \A c \in CPUs :
    Len(ring[c]) = RingCap ~> Len(ring[c]) < RingCap

\* --- Specification ---
Spec == Init /\ [][Next]_vars

FairSpec == Spec /\ \A c \in CPUs :
    WF_vars(ConsumerDrain(c))

THEOREM Spec => []TypeInvariant
THEOREM Spec => []Completeness
THEOREM Spec => []Ordering
THEOREM FairSpec => EventualSpace

============================================================================
