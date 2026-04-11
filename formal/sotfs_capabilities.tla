------------------------- MODULE sotfs_capabilities -------------------------
\* TLA+ Specification: sotFS Capabilities as Graph Edges
\*
\* Models capabilities as nodes in the type graph with grants and delegates
\* edges. Verifies that DPO-style capability operations preserve:
\*   - Monotonic attenuation (derived rights <= parent rights)
\*   - Transitive revocation (revoking a cap invalidates all descendants)
\*   - No capability forgery (caps only created via Derive from existing cap)
\*   - Grants consistency (every cap has exactly one grants edge to an inode)
\*
\* Extends the existing sot_capabilities.tla model to the graph domain.
\* =====================================================================

EXTENDS Naturals, FiniteSets

CONSTANTS
    CapIds,         \* Set of capability identifiers (e.g., {C1, C2, C3, C4, C5})
    InodeIds,       \* Set of inode identifiers (e.g., {I1, I2, I3})
    DomainIds,      \* Set of domain identifiers (e.g., {D1, D2})
    MaxOps          \* Maximum operations per trace

\* Rights are modeled as subsets of this set
AllRights == {"read", "write", "execute", "grant", "revoke"}

NULL == CHOOSE x : x \notin CapIds \cup InodeIds \cup DomainIds

\* =====================================================================
\* VARIABLES
\* =====================================================================

VARIABLES
    \* --- Capability graph nodes ---
    caps,           \* Set of active (live) capability IDs
    capRights,      \* Function: CapId -> subset of AllRights
    capEpoch,       \* Function: CapId -> Nat (creation epoch)

    \* --- Edge: grants (Capability -> Inode) ---
    \* Modeled as a function: CapId -> InodeId
    grantsTarget,   \* Function: CapId -> InodeId (which inode this cap authorizes)

    \* --- Edge: delegates (Capability -> Capability, CDT parent-child) ---
    \* Modeled as a function: CapId -> CapId or NULL (parent in CDT)
    delegatesParent,

    \* --- Domain holdings ---
    domainCaps,     \* Function: DomainId -> subset of CapIds (held caps)

    \* --- Global epoch ---
    epoch,          \* Global epoch counter

    \* --- Inodes (simplified: just the set of valid targets) ---
    inodes,         \* Set of active inode IDs

    \* --- Access log (for forgery detection) ---
    accessLog,      \* Set of <<CapId, InodeId, right>> access records

    \* --- Operation counter ---
    ops

vars == <<caps, capRights, capEpoch, grantsTarget, delegatesParent,
          domainCaps, epoch, inodes, accessLog, ops>>

\* =====================================================================
\* Type Invariant
\* =====================================================================

TypeInvariant ==
    /\ caps \subseteq CapIds
    /\ \A c \in caps : capRights[c] \subseteq AllRights
    /\ \A c \in caps : capEpoch[c] \in Nat
    /\ \A c \in caps : grantsTarget[c] \in InodeIds
    /\ \A c \in caps : delegatesParent[c] \in CapIds \cup {NULL}
    /\ \A d \in DomainIds : domainCaps[d] \subseteq caps
    /\ epoch \in Nat
    /\ inodes \subseteq InodeIds
    /\ ops \in 0..MaxOps

\* =====================================================================
\* Safety Properties
\* =====================================================================

\* G4: Monotonic attenuation — derived cap's rights are subset of parent's
MonotonicAttenuation ==
    \A c \in caps :
        delegatesParent[c] # NULL
        => (delegatesParent[c] \in caps
            => capRights[c] \subseteq capRights[delegatesParent[c]])

\* I5: Every capability has exactly one grants target (enforced by
\* grantsTarget being a function, but we verify the target is valid)
GrantsConsistency ==
    \A c \in caps : grantsTarget[c] \in inodes

\* C4: Delegation subgraph is a forest (no cycles)
\* For bounded model checking: no cap is its own ancestor
RECURSIVE IsAncestor(_, _, _)
IsAncestor(c, target, visited) ==
    IF c = target /\ visited # {}
    THEN TRUE
    ELSE IF c \in visited \/ c = NULL \/ c \notin caps
    THEN FALSE
    ELSE IsAncestor(delegatesParent[c], target, visited \cup {c})

DelegationForest ==
    \A c \in caps : ~IsAncestor(c, c, {})

\* No capability forgery: every access used a valid, live capability
\* with the required right
NoForgery ==
    \A acc \in accessLog :
        /\ acc[1] \in caps
        /\ acc[3] \in capRights[acc[1]]
        /\ grantsTarget[acc[1]] = acc[2]

\* Transitive revocation: if a cap is dead, all its descendants are dead
\* (descendants = caps whose delegatesParent chain leads to the dead cap)
TransitiveRevocation ==
    \A c \in CapIds :
        c \notin caps
        => \A c2 \in caps : delegatesParent[c2] # c

\* =====================================================================
\* Initial state: one root capability with AllRights
\* =====================================================================

InitCap == CHOOSE c \in CapIds : TRUE
InitInode == CHOOSE i \in InodeIds : TRUE
InitDomain == CHOOSE d \in DomainIds : TRUE

Init ==
    LET c0 == InitCap
        i0 == InitInode
        d0 == InitDomain
    IN
    /\ caps = {c0}
    /\ capRights = [c \in CapIds |-> IF c = c0 THEN AllRights ELSE {}]
    /\ capEpoch = [c \in CapIds |-> 0]
    /\ grantsTarget = [c \in CapIds |-> IF c = c0 THEN i0 ELSE i0]
    /\ delegatesParent = [c \in CapIds |-> NULL]
    /\ domainCaps = [d \in DomainIds |->
                        IF d = d0 THEN {c0} ELSE {}]
    /\ epoch = 0
    /\ inodes = {i0}
    /\ accessLog = {}
    /\ ops = 0

\* =====================================================================
\* Actions (DPO rules for capability operations)
\* =====================================================================

\* --- DERIVE: Create a child capability with attenuated rights ---
\* DPO rule: L={c_parent}, K={c_parent}, R={c_parent, c_child, delegates edge}
Derive(domain, parentCap, mask, targetOverride) ==
    /\ ops < MaxOps
    /\ parentCap \in caps
    /\ parentCap \in domainCaps[domain]
    /\ "grant" \in capRights[parentCap]
    /\ mask \subseteq capRights[parentCap]
    \* Allocate fresh cap
    /\ \E newCap \in CapIds :
        /\ newCap \notin caps
        /\ caps' = caps \cup {newCap}
        /\ capRights' = [capRights EXCEPT ![newCap] = mask]
        /\ capEpoch' = [capEpoch EXCEPT ![newCap] = epoch]
        /\ grantsTarget' = [grantsTarget EXCEPT ![newCap] =
                               IF targetOverride \in inodes
                               THEN targetOverride
                               ELSE grantsTarget[parentCap]]
        /\ delegatesParent' = [delegatesParent EXCEPT ![newCap] = parentCap]
        /\ domainCaps' = [domainCaps EXCEPT ![domain] = @ \cup {newCap}]
        /\ ops' = ops + 1
        /\ UNCHANGED <<epoch, inodes, accessLog>>

\* --- GRANT: Transfer a capability to another domain ---
Grant(srcDomain, dstDomain, cap) ==
    /\ ops < MaxOps
    /\ cap \in caps
    /\ cap \in domainCaps[srcDomain]
    /\ "grant" \in capRights[cap]
    /\ srcDomain # dstDomain
    /\ domainCaps' = [domainCaps EXCEPT
           ![srcDomain] = @ \ {cap},
           ![dstDomain] = @ \cup {cap}]
    /\ ops' = ops + 1
    /\ UNCHANGED <<caps, capRights, capEpoch, grantsTarget,
                    delegatesParent, epoch, inodes, accessLog>>

\* --- REVOKE: Remove a capability and all its descendants ---
\* DPO rule: L={c, all descendants}, K={}, R={}
RECURSIVE DescendantsOf(_, _)
DescendantsOf(c, allCaps) ==
    LET children == {c2 \in allCaps : delegatesParent[c2] = c}
    IN children \cup UNION {DescendantsOf(c2, allCaps) : c2 \in children}

Revoke(domain, cap) ==
    /\ ops < MaxOps
    /\ cap \in caps
    /\ cap \in domainCaps[domain]
    /\ "revoke" \in capRights[cap]
    /\ LET toRemove == {cap} \cup DescendantsOf(cap, caps)
       IN
       /\ caps' = caps \ toRemove
       /\ domainCaps' = [d \in DomainIds |-> domainCaps[d] \ toRemove]
       /\ ops' = ops + 1
       /\ UNCHANGED <<capRights, capEpoch, grantsTarget, delegatesParent,
                       epoch, inodes, accessLog>>

\* --- ACCESS: Use a capability to access an inode ---
Access(domain, cap, right) ==
    /\ ops < MaxOps
    /\ cap \in caps
    /\ cap \in domainCaps[domain]
    /\ right \in capRights[cap]
    /\ grantsTarget[cap] \in inodes
    /\ accessLog' = accessLog \cup {<<cap, grantsTarget[cap], right>>}
    /\ ops' = ops + 1
    /\ UNCHANGED <<caps, capRights, capEpoch, grantsTarget, delegatesParent,
                    domainCaps, epoch, inodes>>

\* --- ADVANCE EPOCH: Invalidate stale capabilities ---
AdvanceEpoch ==
    /\ ops < MaxOps
    /\ epoch' = epoch + 1
    \* Remove caps with epoch < new epoch (simplified staleness check)
    /\ LET staleCaps == {c \in caps : capEpoch[c] < epoch}
       IN
       /\ caps' = caps \ staleCaps
       /\ domainCaps' = [d \in DomainIds |-> domainCaps[d] \ staleCaps]
    /\ ops' = ops + 1
    /\ UNCHANGED <<capRights, capEpoch, grantsTarget, delegatesParent,
                    inodes, accessLog>>

\* --- ADD INODE: Register a new inode as a valid grants target ---
AddInode(i) ==
    /\ ops < MaxOps
    /\ i \in InodeIds
    /\ i \notin inodes
    /\ inodes' = inodes \cup {i}
    /\ ops' = ops + 1
    /\ UNCHANGED <<caps, capRights, capEpoch, grantsTarget, delegatesParent,
                    domainCaps, epoch, accessLog>>

\* =====================================================================
\* Next-state relation
\* =====================================================================

Next ==
    \/ \E d \in DomainIds, c \in CapIds, m \in SUBSET AllRights, i \in InodeIds :
        Derive(d, c, m, i)
    \/ \E d1 \in DomainIds, d2 \in DomainIds, c \in CapIds :
        Grant(d1, d2, c)
    \/ \E d \in DomainIds, c \in CapIds :
        Revoke(d, c)
    \/ \E d \in DomainIds, c \in CapIds, r \in AllRights :
        Access(d, c, r)
    \/ AdvanceEpoch
    \/ \E i \in InodeIds : AddInode(i)

\* =====================================================================
\* Specification
\* =====================================================================

Spec == Init /\ [][Next]_vars

\* =====================================================================
\* Theorems
\* =====================================================================

THEOREM Spec => []TypeInvariant
THEOREM Spec => []MonotonicAttenuation
THEOREM Spec => []GrantsConsistency
THEOREM Spec => []DelegationForest
THEOREM Spec => []NoForgery
THEOREM Spec => []TransitiveRevocation

========================================================================
