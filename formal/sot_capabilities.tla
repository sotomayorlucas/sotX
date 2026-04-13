------------------------ MODULE sot_capabilities ------------------------
\* TLA+ Specification of SOT Capability Safety Properties
\*
\* This specification models the sotX capability system with epoch-based
\* revocation, rights attenuation, and capability interposition. It verifies
\* three safety properties:
\*   - NO_ESCALATION: no domain ever holds rights it was not explicitly granted
\*   - TRANSITIVE_REVOCATION: revoking a cap invalidates all descendants
\*   - ATTENUATION_ONLY: interposition cannot escalate rights
\*
\* Matches the kernel implementation in kernel/src/cap/ where Rights::restrict()
\* enforces monotonic attenuation, and CDT walk enforces transitive revocation.

EXTENDS Naturals, FiniteSets

CONSTANTS
    Domains,        \* Set of domain IDs (e.g. {D1, D2, D3})
    Caps,           \* Set of capability IDs (e.g. {C1, C2, C3, C4, C5})
    MaxOps          \* Maximum operations per trace (e.g. 10)

VARIABLES
    caps,           \* Set of active (live) capability IDs
    rights,         \* Function: Cap -> subset of AllRights
    parent,         \* Function: Cap -> Cap or NULL (derivation tree)
    epoch,          \* Global epoch counter
    capEpoch,       \* Function: Cap -> Nat (epoch at creation time)
    domains,        \* Function: Domain -> subset of Caps (held caps)
    interposed,     \* Function: Cap -> Cap or NULL (proxy mapping)
    ops             \* Operation counter (bounds trace length)

\* NULL is a sentinel "no cap" value. The bare CHOOSE form
\* `CHOOSE x : x \notin Caps` was unbounded -- TLC can't enumerate the
\* universe -- so we anchor it to a small disjoint set.
NULL == CHOOSE x \in {"NULL_SENTINEL"} : x \notin Caps

\* The set of all possible rights — mirrors kernel Rights bitmask.
AllRights == {"read", "write", "execute", "grant", "revoke"}

vars == <<caps, rights, parent, epoch, capEpoch, domains, interposed, ops>>

TypeInvariant ==
    /\ caps \subseteq Caps
    /\ epoch \in Nat
    /\ ops \in 0..MaxOps
    /\ \A c \in caps : rights[c] \subseteq AllRights
    /\ \A c \in caps : parent[c] \in Caps \cup {NULL}
    /\ \A c \in caps : capEpoch[c] \in Nat
    /\ \A c \in caps : interposed[c] \in Caps \cup {NULL}
    /\ \A d \in Domains : domains[d] \subseteq caps

\* --- Initial State ---
\* Each domain starts with one root capability holding ALL rights.
\* Remaining caps are unallocated (available for derivation).

Init ==
    \E rootCaps \in [Domains -> Caps] :
        \* Each domain gets a distinct root cap.
        /\ \A d1, d2 \in Domains : d1 /= d2 => rootCaps[d1] /= rootCaps[d2]
        /\ LET assigned == {rootCaps[d] : d \in Domains}
           IN
            /\ caps = assigned
            /\ rights = [c \in Caps |-> IF c \in assigned THEN AllRights ELSE {}]
            /\ parent = [c \in Caps |-> NULL]
            /\ epoch = 0
            /\ capEpoch = [c \in Caps |-> 0]
            /\ domains = [d \in Domains |-> {rootCaps[d]}]
            /\ interposed = [c \in Caps |-> NULL]
            /\ ops = 0

\* --- Helper: cap is live (active and epoch-valid) ---
IsLive(c) ==
    /\ c \in caps
    /\ capEpoch[c] >= epoch

\* --- Helper: descendants of a cap in the derivation tree ---
\* All caps whose parent chain leads back to root.
RECURSIVE DescendantsOf(_)
DescendantsOf(root) ==
    LET children == {c \in caps : parent[c] = root}
    IN children \cup UNION {DescendantsOf(c) : c \in children}

\* --- CreateCap: a domain creates a new root capability ---
CreateCap(d, c) ==
    /\ ops < MaxOps
    /\ c \notin caps
    /\ c \in Caps
    /\ caps' = caps \cup {c}
    /\ rights' = [rights EXCEPT ![c] = AllRights]
    /\ parent' = [parent EXCEPT ![c] = NULL]
    /\ capEpoch' = [capEpoch EXCEPT ![c] = epoch]
    /\ domains' = [domains EXCEPT ![d] = @ \cup {c}]
    /\ interposed' = [interposed EXCEPT ![c] = NULL]
    /\ ops' = ops + 1
    /\ UNCHANGED epoch

\* --- AttenuateCap: derive a new cap with reduced rights ---
\* Mirrors kernel Rights::restrict() — new rights = src.rights AND mask.
AttenuateCap(d, src, newCap, mask) ==
    /\ ops < MaxOps
    /\ src \in domains[d]
    /\ IsLive(src)
    /\ newCap \notin caps
    /\ newCap \in Caps
    /\ mask \subseteq AllRights
    /\ LET newRights == rights[src] \cap mask
       IN
        /\ caps' = caps \cup {newCap}
        /\ rights' = [rights EXCEPT ![newCap] = newRights]
        /\ parent' = [parent EXCEPT ![newCap] = src]
        /\ capEpoch' = [capEpoch EXCEPT ![newCap] = epoch]
        /\ domains' = [domains EXCEPT ![d] = @ \cup {newCap}]
        /\ interposed' = [interposed EXCEPT ![newCap] = NULL]
        /\ ops' = ops + 1
        /\ UNCHANGED epoch

\* --- InterposeCap: create a proxy cap for interposition ---
\* The proxy domain can observe invocations but CANNOT escalate rights.
\* The interposed cap's rights are bounded by the original.
InterposeCap(d, src, proxyCap) ==
    /\ ops < MaxOps
    /\ src \in domains[d]
    /\ IsLive(src)
    /\ proxyCap \notin caps
    /\ proxyCap \in Caps
    /\ caps' = caps \cup {proxyCap}
    /\ rights' = [rights EXCEPT ![proxyCap] = rights[src]]
    /\ parent' = [parent EXCEPT ![proxyCap] = src]
    /\ capEpoch' = [capEpoch EXCEPT ![proxyCap] = epoch]
    /\ interposed' = [interposed EXCEPT ![proxyCap] = src]
    /\ domains' = [domains EXCEPT ![d] = @ \cup {proxyCap}]
    /\ ops' = ops + 1
    /\ UNCHANGED epoch

\* --- InvokeCap: a domain uses a capability (requires it be live) ---
InvokeCap(d, c) ==
    /\ ops < MaxOps
    /\ c \in domains[d]
    /\ IsLive(c)
    /\ ops' = ops + 1
    /\ UNCHANGED <<caps, rights, parent, epoch, capEpoch, domains, interposed>>

\* --- RevokeCap: revoke a cap and all its descendants ---
\* Mirrors kernel CapabilityTable::revoke() CDT walk.
RevokeCap(d, c) ==
    /\ ops < MaxOps
    /\ c \in domains[d]
    /\ c \in caps
    /\ LET toRevoke == {c} \cup DescendantsOf(c)
       IN
        /\ caps' = caps \ toRevoke
        /\ domains' = [dd \in Domains |-> domains[dd] \ toRevoke]
        /\ ops' = ops + 1
        /\ UNCHANGED <<rights, parent, epoch, capEpoch, interposed>>

\* --- GrantCap: transfer a (possibly attenuated) cap to another domain ---
\* Source must hold "grant" right. New cap rights = src.rights AND mask.
GrantCap(srcDom, dstDom, src, newCap, mask) ==
    /\ ops < MaxOps
    /\ src \in domains[srcDom]
    /\ IsLive(src)
    /\ "grant" \in rights[src]
    /\ newCap \notin caps
    /\ newCap \in Caps
    /\ mask \subseteq AllRights
    /\ srcDom /= dstDom
    /\ LET newRights == rights[src] \cap mask
       IN
        /\ caps' = caps \cup {newCap}
        /\ rights' = [rights EXCEPT ![newCap] = newRights]
        /\ parent' = [parent EXCEPT ![newCap] = src]
        /\ capEpoch' = [capEpoch EXCEPT ![newCap] = epoch]
        /\ domains' = [domains EXCEPT ![dstDom] = @ \cup {newCap}]
        /\ interposed' = [interposed EXCEPT ![newCap] = NULL]
        /\ ops' = ops + 1
        /\ UNCHANGED epoch

\* --- AdvanceEpoch: bump the global epoch, invalidating old caps ---
\* All caps with capEpoch < new epoch become effectively dead.
AdvanceEpoch ==
    /\ ops < MaxOps
    /\ epoch' = epoch + 1
    /\ LET stale == {c \in caps : capEpoch[c] < epoch + 1}
       IN
        /\ caps' = caps \ stale
        /\ domains' = [d \in Domains |-> domains[d] \ stale]
    /\ ops' = ops + 1
    /\ UNCHANGED <<rights, parent, capEpoch, interposed>>

\* --- Next-State Relation ---
Next ==
    \/ \E d \in Domains, c \in Caps :
        CreateCap(d, c)
    \/ \E d \in Domains, src \in Caps, nc \in Caps, m \in SUBSET AllRights :
        AttenuateCap(d, src, nc, m)
    \/ \E d \in Domains, src \in Caps, pc \in Caps :
        InterposeCap(d, src, pc)
    \/ \E d \in Domains, c \in Caps :
        InvokeCap(d, c)
    \/ \E d \in Domains, c \in Caps :
        RevokeCap(d, c)
    \/ \E sd \in Domains, dd \in Domains, s \in Caps, nc \in Caps, m \in SUBSET AllRights :
        GrantCap(sd, dd, s, nc, m)
    \/ AdvanceEpoch

\* ======================================================================
\* SAFETY PROPERTIES
\* ======================================================================

\* NO_ESCALATION: A derived capability never has more rights than its parent.
\* This holds for both attenuated and granted caps.
\* Mirrors kernel: Rights::restrict(mask) = self.0 & mask.0
NoEscalation ==
    \A c \in caps :
        parent[c] /= NULL /\ parent[c] \in caps =>
            rights[c] \subseteq rights[parent[c]]

\* TRANSITIVE_REVOCATION: If a capability has been revoked (removed from caps),
\* then none of its descendants remain live.
\* Mirrors kernel: CapabilityTable::revoke() iteratively frees orphaned children.
TransitiveRevocation ==
    \A c \in Caps :
        c \notin caps /\ c /= NULL =>
            \A d \in caps :
                parent[d] /= c

\* ATTENUATION_ONLY: An interposed capability has at most the rights of
\* the original capability it proxies. Interposition cannot add rights.
AttenuationOnly ==
    \A c \in caps :
        interposed[c] /= NULL /\ interposed[c] \in caps =>
            rights[c] \subseteq rights[interposed[c]]

\* --- State-space bound for TLC model checking ---
\* Tier 5 follow-up: keep TLC's BFS finite by capping the operation
\* counter (the spec already increments `ops` on every action).
OpsBound == ops <= MaxOps

\* --- Specification ---
Spec == Init /\ [][Next]_vars

THEOREM Spec => []TypeInvariant
THEOREM Spec => []NoEscalation
THEOREM Spec => []TransitiveRevocation
THEOREM Spec => []AttenuationOnly

========================================================================
