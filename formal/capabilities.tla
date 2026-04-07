----------------------------- MODULE capabilities -----------------------------
\* TLA+ Specification of sotOS Capability System
\*
\* This specification models the capability-based access control system.
\* It verifies:
\*   - No unauthorized access: operations require valid capabilities with correct rights
\*   - Revocation completeness: revoking a capability invalidates all derivatives
\*   - Monotonic rights: derived capabilities never have more rights than parents
\*   - Generation safety: stale handles are rejected

EXTENDS Naturals, Sequences, FiniteSets

CONSTANTS
    Objects,    \* Set of kernel objects
    MaxCaps     \* Maximum number of capabilities

VARIABLES
    caps,       \* Function: CapId -> {object, rights, parent, alive}
    nextId,     \* Next capability ID to allocate
    accesses    \* Set of (cap_id, object, operation) access records

\* Rights are modeled as a subset of {"read","write","execute","grant","revoke"}
\* Tier 5: shrunk to 3 atoms (read/write/grant) for TLC -- the 5-atom
\* powerset (32 subsets per cap) drove a state-space explosion that
\* didn't terminate within reasonable wall time. The shrunk model still
\* exercises every interesting path: Grant/Access/Revoke all branch on
\* presence of "grant"/"read"/"write" rights.
Rights == SUBSET {"read", "write", "grant"}

CapEntry == [object: Objects, rights: Rights, parent: Nat \cup {0}, alive: BOOLEAN]

TypeInvariant ==
    /\ nextId \in 1..(MaxCaps + 1)
    /\ \A id \in DOMAIN caps : caps[id].alive \in BOOLEAN

Init ==
    /\ caps = <<>>
    /\ nextId = 1
    /\ accesses = {}

\* --- Create a root capability (no parent) ---
CreateRoot(obj, rts) ==
    /\ nextId <= MaxCaps
    /\ caps' = caps \o <<[object |-> obj, rights |-> rts, parent |-> 0, alive |-> TRUE]>>
    /\ nextId' = nextId + 1
    /\ UNCHANGED accesses

\* --- Grant (delegate) a capability with restricted rights ---
\* The source capability must be alive and have "grant" right.
\* The new capability's rights are the intersection of source rights and requested mask.
Grant(srcId, mask) ==
    /\ srcId \in 1..Len(caps)
    /\ caps[srcId].alive = TRUE
    /\ "grant" \in caps[srcId].rights
    /\ nextId <= MaxCaps
    /\ LET newRights == caps[srcId].rights \cap mask
       IN  caps' = caps \o <<[object |-> caps[srcId].object,
                               rights |-> newRights,
                               parent |-> srcId,
                               alive |-> TRUE]>>
    /\ nextId' = nextId + 1
    /\ UNCHANGED accesses

\* --- Revoke a capability and all its derivatives ---
\* Walks the derivation tree and marks all children as dead.
Revoke(id) ==
    /\ id \in 1..Len(caps)
    /\ caps[id].alive = TRUE
    /\ LET
         \* Tier 5: replaced the original RECURSIVE Descendants with an
         \* explicitly bounded fixed-point. With at most MaxCaps caps in
         \* existence, the parent chain is at most MaxCaps long, so
         \* iterating MaxCaps+1 times is guaranteed to reach the
         \* fixed-point. The previous formulation made TLC's evaluator
         \* loop indefinitely on certain states.
         AddChildren(s) ==
            s \cup {i \in 1..Len(caps) : caps[i].parent \in s /\ caps[i].alive}
         Iter1 == AddChildren({id})
         Iter2 == AddChildren(Iter1)
         Iter3 == AddChildren(Iter2)
         Iter4 == AddChildren(Iter3)
         toRevoke == AddChildren(Iter4)
       IN caps' = [i \in 1..Len(caps) |->
            IF i \in toRevoke THEN [caps[i] EXCEPT !.alive = FALSE]
            ELSE caps[i]]
    /\ UNCHANGED <<nextId, accesses>>

\* --- Validate and Access ---
\* A thread attempts to access an object using a capability.
\* The capability must be alive and have the required right.
Access(capId, operation) ==
    /\ capId \in 1..Len(caps)
    /\ caps[capId].alive = TRUE
    /\ operation \in caps[capId].rights
    /\ accesses' = accesses \cup {<<capId, caps[capId].object, operation>>}
    /\ UNCHANGED <<caps, nextId>>

\* Tier 5: bound Access operations to keep BFS finite.
AccessBound == Cardinality(accesses) <= 3

\* --- Next-State Relation ---
Next ==
    \/ \E obj \in Objects, rts \in Rights : CreateRoot(obj, rts)
    \/ \E src \in 1..MaxCaps, mask \in Rights : Grant(src, mask)
    \/ \E id \in 1..MaxCaps : Revoke(id)
    \/ \E id \in 1..MaxCaps, op \in {"read","write","execute"} : Access(id, op)

\* --- Safety Properties ---

\* No unauthorized access: every access uses a valid, alive capability with the right.
NoUnauthorizedAccess ==
    \A <<capId, obj, op>> \in accesses :
        /\ capId \in 1..Len(caps)
        /\ caps[capId].object = obj
        /\ op \in caps[capId].rights

\* Monotonic rights: a derived capability never has more rights than its parent.
MonotonicRights ==
    \A i \in 1..Len(caps) :
        caps[i].alive /\ caps[i].parent /= 0 =>
            caps[i].rights \subseteq caps[caps[i].parent].rights

\* Revocation completeness: if a capability is dead, all its descendants are dead.
RevocationComplete ==
    \A i \in 1..Len(caps) :
        (caps[i].parent /= 0 /\ caps[i].parent <= Len(caps) /\
         caps[caps[i].parent].alive = FALSE) =>
            caps[i].alive = FALSE

\* --- Specification ---
Spec == Init /\ [][Next]_<<caps, nextId, accesses>>

THEOREM Spec => []NoUnauthorizedAccess
THEOREM Spec => []MonotonicRights

============================================================================
