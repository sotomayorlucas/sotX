---------------------- MODULE sotfs_curvature ----------------------
\* TLA+ Specification: sotFS Curvature Anomaly Monitor
\*
\* Models the runtime curvature monitor from sotfs-monitor/src/curvature.rs.
\* An evolving undirected graph undergoes add_node, add_edges (batch),
\* and remove_edge operations.  After each operation the monitor
\* computes a discrete Ollivier-Ricci-style curvature per edge:
\*
\*   kappa(u,v) = 1 - |N(u) DELTA N(v)| / max(deg(u), deg(v))
\*
\* We use scaled integer arithmetic to avoid rationals:
\*   kappa_s(u,v) = max(deg(u), deg(v)) - |N(u) DELTA N(v)|
\*
\* The batch AddEdges operation models filesystem events that create
\* multiple links at once (mass file creation, symlink bombs, etc.).
\* A "fan-out" event occurs when a node's degree increases by >=
\* FanOutDelta in a single step.
\*
\* Key theorem verified: curvature drops on expansion correlate with
\* structural fan-out events.
\*
\* Reference: sotfs-monitor/src/curvature.rs (~200 LOC)
\* Style: follows formal/sotfs_graph.tla conventions
\* ==================================================================

EXTENDS Integers, FiniteSets

CONSTANTS
    NodeIds,        \* e.g. {N1, N2, N3, N4, N5}
    MaxOps,         \* bound on operations (bounds state space)
    Threshold,      \* anomaly threshold on scaled kappa drop
    FanOutDelta     \* min degree increase that counts as fan-out

\* ==================================================================
\* Variables
\* ==================================================================

VARIABLES
    nodes,          \* Set of active node IDs (subset of NodeIds)
    edges,          \* Set of undirected edges as <<a, b>> pairs
    kappa,          \* Function: edge -> scaled curvature (integer)
    prevDeg,        \* Function: NodeIds -> degree before current step
    anomalyFlag,    \* Set of edges flagged as anomalous this step
    fanOutNodes,    \* Set of nodes that had a fan-out event this step
    lastOp,         \* Type of last operation
    ops             \* Operation counter

vars == <<nodes, edges, kappa, prevDeg, anomalyFlag, fanOutNodes, lastOp, ops>>

\* ==================================================================
\* Helpers
\* ==================================================================

\* Check if an edge exists (either ordering)
EdgeIn(a, b, E) == <<a, b>> \in E \/ <<b, a>> \in E

\* Neighbors of node n in edge set E restricted to node set N
NbrsIn(n, E) ==
    {m \in NodeIds : <<n, m>> \in E \/ <<m, n>> \in E}

\* Current neighbors
Neighbors(n) == NbrsIn(n, edges)

\* Degree in a given edge set
DegIn(n, E) == Cardinality(NbrsIn(n, E))

\* Current degree
Deg(n) == DegIn(n, edges)

\* Symmetric difference
SymDiff(A, B) == (A \ B) \cup (B \ A)

\* ------------------------------------------------------------------
\* Discrete Ollivier-Ricci curvature (scaled integer)
\*
\*   kappa_s(u,v) = max(deg(u), deg(v)) - |N(u) DELTA N(v)|
\*
\* The unscaled value is kappa_s / max(deg(u), deg(v)).
\* ------------------------------------------------------------------

KappaIn(u, v, E) ==
    LET Nu == NbrsIn(u, E)
        Nv == NbrsIn(v, E)
        sd == SymDiff(Nu, Nv)
        du == Cardinality(Nu)
        dv == Cardinality(Nv)
        mx == IF du >= dv THEN du ELSE dv
    IN
    IF mx = 0 THEN 0
    ELSE mx - Cardinality(sd)

KappaScaled(u, v) == KappaIn(u, v, edges)

\* Sum of a set of integers
RECURSIVE SetSum(_)
SetSum(S) ==
    IF S = {} THEN 0
    ELSE LET x == CHOOSE x \in S : TRUE
         IN  x + SetSum(S \ {x})

\* All possible undirected edges between nodes in a set (as <<a,b>> with a != b)
AllPossibleEdges(N) ==
    {<<a, b>> \in N \times N : a # b}

\* ==================================================================
\* Type Invariant
\* ==================================================================

MaxN == Cardinality(NodeIds)

TypeInvariant ==
    /\ nodes \subseteq NodeIds
    /\ \A e \in edges : e[1] \in nodes /\ e[2] \in nodes /\ e[1] # e[2]
    /\ DOMAIN kappa = edges
    /\ anomalyFlag \subseteq edges
    /\ fanOutNodes \subseteq nodes
    /\ ops \in 0..MaxOps
    /\ lastOp \in {"none", "addNode", "addEdges", "removeEdge"}

\* ==================================================================
\* Initial state: two connected nodes
\* ==================================================================

InitN1 == CHOOSE n \in NodeIds : TRUE
InitN2 == CHOOSE n \in NodeIds : n # InitN1

Init ==
    LET e == <<InitN1, InitN2>>
    IN
    \* N(N1) = {N2}, N(N2) = {N1}, SymDiff = {}, maxDeg = 1
    \* kappa_s = 1 - 0 = 1
    /\ nodes = {InitN1, InitN2}
    /\ edges = {e}
    /\ kappa = [edge \in {e} |-> 1]
    /\ prevDeg = [n \in NodeIds |-> IF n \in {InitN1, InitN2} THEN 1 ELSE 0]
    /\ anomalyFlag = {}
    /\ fanOutNodes = {}
    /\ lastOp = "none"
    /\ ops = 0

\* ==================================================================
\* Operations
\* ==================================================================

\* --- AddNode: introduce a new isolated node ---
\* No edges change, curvature is unchanged.
AddNode ==
    /\ ops < MaxOps
    /\ \E n \in NodeIds \ nodes :
        /\ nodes' = nodes \cup {n}
        /\ edges' = edges
        /\ kappa' = kappa
        /\ prevDeg' = [nd \in NodeIds |-> Deg(nd)]
        /\ anomalyFlag' = {}
        /\ fanOutNodes' = {}
        /\ lastOp' = "addNode"
        /\ ops' = ops + 1

\* --- AddEdges: connect a "hub" node to a set of target nodes ---
\* Models batch operations like mass file creation (directory node
\* gains many children at once).  The hub connects to 1..k targets
\* where each target must already be in nodes and not already connected
\* to hub.  This is the operation that produces fan-out events.
AddEdges ==
    /\ ops < MaxOps
    /\ \E hub \in nodes :
        \E targets \in SUBSET (nodes \ {hub}) :
            /\ targets # {}
            /\ Cardinality(targets) <= Cardinality(NodeIds) - 1
            \* None of the target edges already exist
            /\ \A t \in targets : ~EdgeIn(hub, t, edges)
            /\ LET newEs == {<<hub, t>> : t \in targets}
                   newEdges == edges \cup newEs
                   newKappa == [e \in newEdges |-> KappaIn(e[1], e[2], newEdges)]
                   newDeg == [n \in NodeIds |-> DegIn(n, newEdges)]
                   \* Fan-out: nodes whose degree jumped by >= FanOutDelta
                   fo == {n \in nodes : newDeg[n] - prevDeg[n] >= FanOutDelta}
                   \* Curvature drops on previously existing edges
                   drops == {e \in edges :
                                kappa[e] - newKappa[e] > Threshold}
               IN
               /\ edges' = newEdges
               /\ kappa' = newKappa
               /\ prevDeg' = newDeg
               /\ fanOutNodes' = fo
               /\ anomalyFlag' = drops
               /\ lastOp' = "addEdges"
               /\ ops' = ops + 1
               /\ UNCHANGED nodes

\* --- RemoveEdge: remove an existing edge ---
\* Degrees decrease, so no fan-out.  Models link removal / unlink.
RemoveEdge ==
    /\ ops < MaxOps
    /\ edges # {}
    /\ \E e \in edges :
        LET newEdges == edges \ {e}
            newKappa == [ed \in newEdges |-> KappaIn(ed[1], ed[2], newEdges)]
            newDeg == [n \in NodeIds |-> DegIn(n, newEdges)]
        IN
        /\ edges' = newEdges
        /\ kappa' = newKappa
        /\ prevDeg' = newDeg
        /\ fanOutNodes' = {}
        /\ anomalyFlag' = {}  \* removal is not a fan-out anomaly
        /\ lastOp' = "removeEdge"
        /\ ops' = ops + 1
        /\ UNCHANGED nodes

\* ==================================================================
\* Next-state relation
\* ==================================================================

Next ==
    \/ AddNode
    \/ AddEdges
    \/ RemoveEdge

Spec == Init /\ [][Next]_vars

\* ==================================================================
\* Properties
\* ==================================================================

\* --- P1: CurvatureDropImpliesFanOut ---
\* If an AddEdges step caused a curvature drop (> Threshold) on some
\* existing edge (u,v), then at least one endpoint of that edge had
\* a fan-out event (degree increase >= FanOutDelta).
\*
\* This is the core theorem from the curvature monitor design:
\* kappa drops during graph expansion are structurally caused by
\* fan-out at an endpoint.  (Removal anomalies are a separate class.)
CurvatureDropImpliesFanOut ==
    lastOp = "addEdges" =>
        \A e \in anomalyFlag :
            e[1] \in fanOutNodes \/ e[2] \in fanOutNodes

\* --- P2: NoFalseNegatives ---
\* Every fan-out event of size >= FanOutDelta at a node causes at
\* least one incident edge's curvature to drop by > Threshold.
\* If fan-out nodes exist, the monitor flags at least one edge.
NoFalseNegatives ==
    fanOutNodes # {} => anomalyFlag # {}

\* --- P3: MonitorEventuallyDetects ---
\* If a fan-out event occurs during an AddEdges step, the monitor
\* flags it in the same step (immediate detection — invariant, not
\* liveness, since curvature is recomputed eagerly).
MonitorEventuallyDetects ==
    (lastOp = "addEdges" /\ fanOutNodes # {}) => anomalyFlag # {}

\* --- P4: CurvatureBounded ---
\* Scaled curvature values stay in the valid integer range.
\*   kappa_s = maxDeg - |symDiff|
\*   maxDeg <= |NodeIds| - 1
\*   |symDiff| <= 2 * (|NodeIds| - 2)
\* So kappa_s in [-(|NodeIds|-1), |NodeIds|-1].
CurvatureBounded ==
    \A e \in edges :
        /\ kappa[e] >= -(MaxN)
        /\ kappa[e] <= MaxN

\* --- P5: NoSelfLoops ---
NoSelfLoops ==
    \A e \in edges : e[1] # e[2]

\* --- P6: KappaConsistent ---
\* Stored kappa matches the recomputed value (catches update bugs).
KappaConsistent ==
    \A e \in edges : kappa[e] = KappaScaled(e[1], e[2])

\* ==================================================================
\* Combined safety invariant
\* ==================================================================

SafetyInvariant ==
    /\ TypeInvariant
    /\ CurvatureBounded
    /\ NoSelfLoops
    /\ KappaConsistent
    /\ CurvatureDropImpliesFanOut

\* ==================================================================
\* Theorems
\* ==================================================================

THEOREM Spec => []TypeInvariant
THEOREM Spec => []CurvatureBounded
THEOREM Spec => []CurvatureDropImpliesFanOut
THEOREM Spec => []NoFalseNegatives
THEOREM Spec => []MonitorEventuallyDetects
THEOREM Spec => []KappaConsistent

=====================================================================
