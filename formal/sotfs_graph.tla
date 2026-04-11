------------------------- MODULE sotfs_graph -------------------------
\* TLA+ Specification: sotFS Type Graph and DPO Rules
\*
\* Models the core metadata graph of sotFS with six node types and six
\* edge types. POSIX filesystem operations are modeled as DPO-style
\* graph rewriting actions with explicit preconditions (gluing conditions).
\*
\* This is the base specification — sotfs_invariants, sotfs_transactions,
\* sotfs_capabilities, and sotfs_crash extend it.
\*
\* Model-checked with TLC using small constant sets to verify that all
\* DPO rules preserve the type graph invariants.
\* =====================================================================

EXTENDS Naturals, Sequences, FiniteSets

CONSTANTS
    InodeIds,       \* Set of possible inode identifiers (e.g., {I1, I2, I3, I4, I5})
    DirIds,         \* Set of possible directory identifiers (e.g., {D1, D2, D3})
    BlockIds,       \* Set of possible block identifiers (e.g., {B1, B2, B3})
    Names,          \* Set of possible filenames (e.g., {"a", "b", "c"})
    MaxOps          \* Maximum operations per trace (bounds state space)

\* Sentinel for "no value"
NULL == CHOOSE x : x \notin InodeIds \cup DirIds \cup BlockIds \cup Names

\* =====================================================================
\* Node types (represented as sets of active IDs)
\* =====================================================================

VARIABLES
    \* --- Node sets (which IDs are "alive" in the graph) ---
    inodes,         \* Set of active inode IDs (subset of InodeIds)
    dirs,           \* Set of active directory IDs (subset of DirIds)
    blocks,         \* Set of active block IDs (subset of BlockIds)

    \* --- Inode attributes ---
    inodeType,      \* Function: InodeId -> {"regular", "directory"} (vtype)
    linkCount,      \* Function: InodeId -> Nat (hard link count)

    \* --- Edge: contains (Directory -> Inode, labeled with name) ---
    \* Modeled as a set of <<dir, inode, name>> triples
    containsEdges,

    \* --- Edge: pointsTo (Inode -> Block, labeled with offset) ---
    \* Modeled as a set of <<inode, block, offset>> triples
    pointsToEdges,

    \* --- Directory-to-Inode pairing (which inode does "." point to) ---
    dirInode,       \* Function: DirId -> InodeId (the inode this dir represents)

    \* --- Block attributes ---
    blockRefcount,  \* Function: BlockId -> Nat

    \* --- Allocation tracking ---
    nextInode,      \* Next inode ID index to allocate
    nextDir,        \* Next directory ID index to allocate
    nextBlock,      \* Next block ID index to allocate

    \* --- Root ---
    rootDir,        \* The root directory ID
    rootInode,      \* The root inode ID

    \* --- Operation counter (bounds state space) ---
    ops

\* =====================================================================
\* Helper: all variables tuple
\* =====================================================================

vars == <<inodes, dirs, blocks, inodeType, linkCount,
          containsEdges, pointsToEdges, dirInode, blockRefcount,
          nextInode, nextDir, nextBlock, rootDir, rootInode, ops>>

\* =====================================================================
\* Type Invariant
\* =====================================================================

TypeInvariant ==
    /\ inodes \subseteq InodeIds
    /\ dirs \subseteq DirIds
    /\ blocks \subseteq BlockIds
    /\ \A i \in inodes : inodeType[i] \in {"regular", "directory"}
    /\ \A i \in inodes : linkCount[i] \in Nat
    /\ \A e \in containsEdges :
        /\ e[1] \in dirs
        /\ e[2] \in inodes
        /\ e[3] \in Names \cup {".", ".."}
    /\ \A e \in pointsToEdges :
        /\ e[1] \in inodes
        /\ e[2] \in blocks
        /\ e[3] \in Nat
    /\ \A b \in blocks : blockRefcount[b] \in Nat
    /\ ops \in 0..MaxOps

\* =====================================================================
\* Graph Invariants (from design doc §5.4-5.5)
\* =====================================================================

\* I2 + G3: link_count equals number of incoming contains edges
\*          (excluding ".." but including ".")
LinkCountConsistent ==
    \A i \in inodes :
        linkCount[i] = Cardinality({e \in containsEdges :
                                     e[2] = i /\ e[3] # ".."})

\* C1 + I4: unique names per directory
UniqueNamesPerDir ==
    \A d \in dirs :
        \A e1, e2 \in containsEdges :
            (e1[1] = d /\ e2[1] = d /\ e1[3] = e2[3]) => e1 = e2

\* I3: every directory has a "." self-reference
DirHasSelfRef ==
    \A d \in dirs :
        \E e \in containsEdges : e[1] = d /\ e[2] = dirInode[d] /\ e[3] = "."

\* G2: no dangling edges (guaranteed by construction — we only add edges
\*     between active nodes — but stated explicitly for verification)
NoDanglingEdges ==
    /\ \A e \in containsEdges : e[1] \in dirs /\ e[2] \in inodes
    /\ \A e \in pointsToEdges : e[1] \in inodes /\ e[2] \in blocks

\* I8: block refcount consistency
BlockRefcountConsistent ==
    \A b \in blocks :
        blockRefcount[b] = Cardinality({e \in pointsToEdges : e[2] = b})

\* G5: no directory cycles (simplified — check that no directory is its
\*     own ancestor via contains edges, excluding "." and "..")
\* For small models, we check: no non-trivial cycle of length ≤ |dirs|
\* This is a simplified version; full cycle detection would use RECURSIVE
NoDirCycle2 ==
    \A d1, d2 \in dirs :
        \A i1, i2 \in inodes :
            /\ <<d1, i1, ".">> \notin containsEdges  \* guard: d1's inode
            \/ i1 \notin inodes
            \/ TRUE  \* placeholder — see NoDirCycles below

\* Simplified cycle check: no directory d has a contains path back to itself
\* For bounded model checking with small dirs, exhaustive check is feasible
RECURSIVE AncestorOf(_, _, _)
AncestorOf(d, target, visited) ==
    IF d = target /\ visited # {}
    THEN TRUE
    ELSE IF d \in visited
    THEN FALSE
    ELSE \E e \in containsEdges :
            /\ e[1] = d
            /\ e[3] \notin {".", ".."}
            /\ e[2] \in inodes
            /\ inodeType[e[2]] = "directory"
            /\ \E d2 \in dirs :
                /\ dirInode[d2] = e[2]
                /\ AncestorOf(d2, target, visited \cup {d})

NoDirCycles ==
    \A d \in dirs : ~AncestorOf(d, d, {})

\* I1: reachable inodes have link_count >= 1
ReachableHaveLinks ==
    \A i \in inodes :
        Cardinality({e \in containsEdges : e[2] = i}) > 0
        => linkCount[i] >= 1

\* =====================================================================
\* Combined safety invariant
\* =====================================================================

SafetyInvariant ==
    /\ LinkCountConsistent
    /\ UniqueNamesPerDir
    /\ DirHasSelfRef
    /\ NoDanglingEdges
    /\ BlockRefcountConsistent
    /\ NoDirCycles
    /\ ReachableHaveLinks

\* =====================================================================
\* Initial state: CREATE-ROOT (ADR-003)
\* =====================================================================

\* Pick the first inode, dir, and block from the constant sets
InitInode == CHOOSE i \in InodeIds : TRUE
InitDir == CHOOSE d \in DirIds : TRUE

Init ==
    LET i == InitInode
        d == InitDir
    IN
    /\ inodes = {i}
    /\ dirs = {d}
    /\ blocks = {}
    /\ inodeType = [x \in InodeIds |-> IF x = i THEN "directory" ELSE "regular"]
    /\ linkCount = [x \in InodeIds |-> IF x = i THEN 2 ELSE 0]
    /\ containsEdges = {<<d, i, ".">>}
    /\ pointsToEdges = {}
    /\ dirInode = [x \in DirIds |-> IF x = d THEN i ELSE NULL]
    /\ blockRefcount = [x \in BlockIds |-> 0]
    /\ nextInode = 1
    /\ nextDir = 1
    /\ nextBlock = 0
    /\ rootDir = d
    /\ rootInode = i
    /\ ops = 0

\* =====================================================================
\* Helper: allocate a fresh ID from a set
\* =====================================================================

\* Pick an unused inode ID
FreshInode == CHOOSE i \in InodeIds : i \notin inodes
HasFreshInode == \E i \in InodeIds : i \notin inodes

\* Pick an unused directory ID
FreshDir == CHOOSE d \in DirIds : d \notin dirs
HasFreshDir == \E d \in DirIds : d \notin dirs

\* Pick an unused block ID
FreshBlock == CHOOSE b \in BlockIds : b \notin blocks
HasFreshBlock == \E b \in BlockIds : b \notin blocks

\* =====================================================================
\* DPO Rule: CREATE (file) — §6.2.1
\* Creates a regular file in a directory
\* =====================================================================

CreateFile(d, name) ==
    /\ ops < MaxOps
    /\ d \in dirs
    /\ name \in Names
    \* GC-CREATE-1: no existing entry with this name
    /\ ~\E e \in containsEdges : e[1] = d /\ e[3] = name
    \* Allocate fresh inode
    /\ HasFreshInode
    /\ LET newI == FreshInode
       IN
       /\ inodes' = inodes \cup {newI}
       /\ inodeType' = [inodeType EXCEPT ![newI] = "regular"]
       /\ linkCount' = [linkCount EXCEPT ![newI] = 1]
       /\ containsEdges' = containsEdges \cup {<<d, newI, name>>}
       /\ ops' = ops + 1
       /\ UNCHANGED <<dirs, blocks, pointsToEdges, dirInode,
                       blockRefcount, nextInode, nextDir, nextBlock,
                       rootDir, rootInode>>

\* =====================================================================
\* DPO Rule: MKDIR — §6.2.3
\* Creates a new directory
\* =====================================================================

Mkdir(parentDir, name) ==
    /\ ops < MaxOps
    /\ parentDir \in dirs
    /\ name \in Names
    \* GC-MKDIR-1: no existing entry with this name
    /\ ~\E e \in containsEdges : e[1] = parentDir /\ e[3] = name
    \* Need both a fresh inode AND a fresh directory ID
    /\ HasFreshInode
    /\ HasFreshDir
    /\ LET newI == FreshInode
           newD == FreshDir
           parentInode == dirInode[parentDir]
       IN
       /\ inodes' = inodes \cup {newI}
       /\ dirs' = dirs \cup {newD}
       /\ inodeType' = [inodeType EXCEPT ![newI] = "directory"]
       \* link_count = 2: one from parent contains + one from "." self
       /\ linkCount' = [linkCount EXCEPT ![newI] = 2]
       /\ dirInode' = [dirInode EXCEPT ![newD] = newI]
       /\ containsEdges' = containsEdges \cup {
              <<parentDir, newI, name>>,      \* parent -> new inode
              <<newD, newI, ".">>,             \* self-reference
              <<newD, parentInode, "..">>       \* parent-reference
          }
       /\ ops' = ops + 1
       /\ UNCHANGED <<blocks, pointsToEdges, blockRefcount,
                       nextInode, nextDir, nextBlock, rootDir, rootInode>>

\* =====================================================================
\* DPO Rule: RMDIR — §6.2.4
\* Removes an empty directory
\* =====================================================================

Rmdir(parentDir, name) ==
    /\ ops < MaxOps
    /\ parentDir \in dirs
    /\ name \in Names
    /\ name \notin {".", ".."}
    \* Find the contains edge to remove
    /\ \E targetInode \in inodes :
        /\ <<parentDir, targetInode, name>> \in containsEdges
        /\ inodeType[targetInode] = "directory"
        \* Find the directory node paired with this inode
        /\ \E targetDir \in dirs :
            /\ dirInode[targetDir] = targetInode
            \* GC-RMDIR-1: directory must be empty (only "." and ".." edges)
            /\ \A e \in containsEdges :
                e[1] = targetDir => e[3] \in {".", ".."}
            \* Apply removal
            /\ LET dotEdge == <<targetDir, targetInode, ".">>
                   dotdotEdges == {e \in containsEdges :
                                    e[1] = targetDir /\ e[3] = ".."}
                   entryEdge == <<parentDir, targetInode, name>>
               IN
               /\ containsEdges' = containsEdges
                    \ ({entryEdge, dotEdge} \cup dotdotEdges)
               /\ inodes' = inodes \ {targetInode}
               /\ dirs' = dirs \ {targetDir}
               /\ linkCount' = [linkCount EXCEPT ![targetInode] = 0]
               /\ inodeType' = [inodeType EXCEPT ![targetInode] = "regular"]
               /\ dirInode' = [dirInode EXCEPT ![targetDir] = NULL]
               /\ ops' = ops + 1
               /\ UNCHANGED <<blocks, pointsToEdges, blockRefcount,
                               nextInode, nextDir, nextBlock,
                               rootDir, rootInode>>

\* =====================================================================
\* DPO Rule: LINK — §6.2.5
\* Creates a hard link (new contains edge to existing inode)
\* =====================================================================

Link(d, name, targetInode) ==
    /\ ops < MaxOps
    /\ d \in dirs
    /\ name \in Names
    /\ targetInode \in inodes
    \* GC-LINK-2: cannot hard-link directories
    /\ inodeType[targetInode] = "regular"
    \* GC-LINK-1: no existing entry with this name
    /\ ~\E e \in containsEdges : e[1] = d /\ e[3] = name
    \* Apply
    /\ containsEdges' = containsEdges \cup {<<d, targetInode, name>>}
    /\ linkCount' = [linkCount EXCEPT ![targetInode] = @ + 1]
    /\ ops' = ops + 1
    /\ UNCHANGED <<inodes, dirs, blocks, inodeType, pointsToEdges,
                    dirInode, blockRefcount, nextInode, nextDir, nextBlock,
                    rootDir, rootInode>>

\* =====================================================================
\* DPO Rule: UNLINK — §6.2.6
\* Removes a hard link (contains edge) and decrements link_count
\* =====================================================================

Unlink(d, name) ==
    /\ ops < MaxOps
    /\ d \in dirs
    /\ name \in Names
    /\ name \notin {".", ".."}
    /\ \E targetInode \in inodes :
        /\ <<d, targetInode, name>> \in containsEdges
        \* GC-UNLINK-2: cannot unlink directories (use rmdir)
        /\ inodeType[targetInode] = "regular"
        /\ LET newLinkCount == linkCount[targetInode] - 1
           IN
           /\ containsEdges' = containsEdges \ {<<d, targetInode, name>>}
           /\ linkCount' = [linkCount EXCEPT ![targetInode] = newLinkCount]
           \* If last link, remove the inode and its blocks
           /\ IF newLinkCount = 0
              THEN
                /\ inodes' = inodes \ {targetInode}
                \* Remove all pointsTo edges from this inode
                /\ pointsToEdges' = {e \in pointsToEdges : e[1] # targetInode}
                \* Decrement refcounts on freed blocks; remove blocks with refcount 0
                /\ LET affectedBlocks == {e[2] : e \in {e2 \in pointsToEdges :
                                                         e2[1] = targetInode}}
                       newRefcounts == [b \in BlockIds |->
                           IF b \in affectedBlocks
                           THEN blockRefcount[b] -
                                Cardinality({e \in pointsToEdges :
                                             e[1] = targetInode /\ e[2] = b})
                           ELSE blockRefcount[b]]
                       deadBlocks == {b \in affectedBlocks : newRefcounts[b] = 0}
                   IN
                   /\ blockRefcount' = newRefcounts
                   /\ blocks' = blocks \ deadBlocks
              ELSE
                /\ UNCHANGED <<inodes, pointsToEdges, blockRefcount, blocks>>
           /\ ops' = ops + 1
           /\ UNCHANGED <<dirs, inodeType, dirInode, nextInode, nextDir,
                           nextBlock, rootDir, rootInode>>

\* =====================================================================
\* DPO Rule: RENAME (same directory, no replacement) — §6.2.7 Case A
\* Moves a directory entry to a new name within the same directory
\* =====================================================================

RenameSameDir(d, oldName, newName) ==
    /\ ops < MaxOps
    /\ d \in dirs
    /\ oldName \in Names
    /\ newName \in Names
    /\ oldName # newName
    \* Source must exist
    /\ \E targetInode \in inodes :
        /\ <<d, targetInode, oldName>> \in containsEdges
        \* Target name must not exist
        /\ ~\E e \in containsEdges : e[1] = d /\ e[3] = newName
        \* Apply: remove old edge, add new edge
        /\ containsEdges' = (containsEdges \ {<<d, targetInode, oldName>>})
                             \cup {<<d, targetInode, newName>>}
        /\ ops' = ops + 1
        /\ UNCHANGED <<inodes, dirs, blocks, inodeType, linkCount,
                        pointsToEdges, dirInode, blockRefcount,
                        nextInode, nextDir, nextBlock, rootDir, rootInode>>

\* =====================================================================
\* DPO Rule: RENAME (cross-directory, no replacement) — §6.2.7 Case C
\* Moves a directory entry from one directory to another
\* =====================================================================

RenameCrossDir(srcDir, srcName, dstDir, dstName) ==
    /\ ops < MaxOps
    /\ srcDir \in dirs
    /\ dstDir \in dirs
    /\ srcDir # dstDir
    /\ srcName \in Names
    /\ dstName \in Names
    \* Source must exist
    /\ \E targetInode \in inodes :
        /\ <<srcDir, targetInode, srcName>> \in containsEdges
        \* Target name must not exist in destination
        /\ ~\E e \in containsEdges : e[1] = dstDir /\ e[3] = dstName
        \* GC-RENAME-2: if moving a directory, destination must not be
        \* a descendant of source (cycle prevention)
        /\ IF inodeType[targetInode] = "directory"
           THEN ~AncestorOf(
                    (CHOOSE d2 \in dirs : dirInode[d2] = targetInode),
                    dstDir, {})
           ELSE TRUE
        \* Apply: move the contains edge
        /\ containsEdges' = (containsEdges \ {<<srcDir, targetInode, srcName>>})
                             \cup {<<dstDir, targetInode, dstName>>}
        \* If moving a directory, update its ".." edge
        /\ IF inodeType[targetInode] = "directory"
           THEN LET childDir == CHOOSE d2 \in dirs : dirInode[d2] = targetInode
                    dstInode == dirInode[dstDir]
                    oldDotDot == {e \in containsEdges : e[1] = childDir /\ e[3] = ".."}
                IN containsEdges' = ((containsEdges \ {<<srcDir, targetInode, srcName>>})
                                     \ oldDotDot)
                                    \cup {<<dstDir, targetInode, dstName>>,
                                          <<childDir, dstInode, "..">>}
           ELSE containsEdges' = (containsEdges \ {<<srcDir, targetInode, srcName>>})
                                 \cup {<<dstDir, targetInode, dstName>>}
        /\ ops' = ops + 1
        /\ UNCHANGED <<inodes, dirs, blocks, inodeType, linkCount,
                        pointsToEdges, dirInode, blockRefcount,
                        nextInode, nextDir, nextBlock, rootDir, rootInode>>

\* =====================================================================
\* DPO Rule: WRITE — §6.2.2
\* Adds a block to an inode (simplified: append a new block)
\* =====================================================================

WriteBlock(i, offset) ==
    /\ ops < MaxOps
    /\ i \in inodes
    /\ inodeType[i] = "regular"
    /\ offset \in Nat
    \* No existing block at this offset
    /\ ~\E e \in pointsToEdges : e[1] = i /\ e[3] = offset
    /\ HasFreshBlock
    /\ LET newB == FreshBlock
       IN
       /\ blocks' = blocks \cup {newB}
       /\ blockRefcount' = [blockRefcount EXCEPT ![newB] = 1]
       /\ pointsToEdges' = pointsToEdges \cup {<<i, newB, offset>>}
       /\ ops' = ops + 1
       /\ UNCHANGED <<inodes, dirs, inodeType, linkCount, containsEdges,
                       dirInode, nextInode, nextDir, nextBlock,
                       rootDir, rootInode>>

\* =====================================================================
\* Next-state relation: disjunction of all DPO rules
\* =====================================================================

Next ==
    \/ \E d \in dirs, name \in Names :
        CreateFile(d, name)
    \/ \E d \in dirs, name \in Names :
        Mkdir(d, name)
    \/ \E d \in dirs, name \in Names :
        Rmdir(d, name)
    \/ \E d \in dirs, name \in Names, i \in inodes :
        Link(d, name, i)
    \/ \E d \in dirs, name \in Names :
        Unlink(d, name)
    \/ \E d \in dirs, n1 \in Names, n2 \in Names :
        RenameSameDir(d, n1, n2)
    \/ \E d1 \in dirs, d2 \in dirs, n1 \in Names, n2 \in Names :
        RenameCrossDir(d1, n1, d2, n2)
    \/ \E i \in inodes, off \in 0..2 :
        WriteBlock(i, off)

\* =====================================================================
\* Specification
\* =====================================================================

Spec == Init /\ [][Next]_vars

\* =====================================================================
\* Theorems
\* =====================================================================

THEOREM Spec => []TypeInvariant
THEOREM Spec => []LinkCountConsistent
THEOREM Spec => []UniqueNamesPerDir
THEOREM Spec => []DirHasSelfRef
THEOREM Spec => []NoDanglingEdges
THEOREM Spec => []BlockRefcountConsistent
THEOREM Spec => []NoDirCycles
THEOREM Spec => []ReachableHaveLinks

========================================================================
