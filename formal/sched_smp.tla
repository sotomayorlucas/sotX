------------------------------ MODULE sched_smp ------------------------------
\* TLA+ specification of the sotOS reschedule-IPI delivery hazard (R1).
\*
\* This model is intentionally narrow: its only job is to verify that the
\* `enqueue_to_cpu_pri` → reschedule IPI path delivers the IPI to the
\* RIGHT CPU when the kernel logical CPU index is not equal to the
\* CPU's physical LAPIC ID.
\*
\* The Chase-Lev WSDeque correctness lives in `chase_lev.tla`. The
\* scheduler's per-thread state machine is verified in the existing
\* `scheduler.tla`. Here we cut everything else away to keep the model
\* small enough that TLC's liveness checker terminates.
\*
\* R1 reproduction: set AddressingMode = "cpu_index" in the .cfg.
\*   - The kernel writes ICR_HI = cpu_index (logical 1 / 2).
\*   - LapicId is non-identity: C1 → 7, C2 → 11.
\*   - The IPI lands on the CPU whose LAPIC ID equals the cpu_index.
\*     With our mapping, no CPU has LAPIC 1 or 2, so the IPI vanishes.
\*   - The target CPU never wakes; the woken thread sits in its run
\*     queue forever; NoLostWake violates → R1 reproduced as a temporal
\*     property failure.
\*
\* R1 fix: set AddressingMode = "lapic_id". The kernel writes
\* ICR_HI = LapicId(cpu_index), the IPI lands correctly, and
\* NoLostWake holds.

EXTENDS Naturals, Sequences, FiniteSets, TLC

CONSTANTS
    CPUs,                \* set of CPU IDs (logical indices, e.g. {"C1","C2"})
    Threads,             \* set of thread IDs
    AddressingMode       \* "cpu_index" (legacy/buggy) or "lapic_id" (fixed)

ASSUME AddressingValid == AddressingMode \in {"cpu_index", "lapic_id"}

NULL == "NULL_THREAD"

\* Logical CPU index → physical LAPIC ID. Intentionally non-identity:
\* C1 → 7, C2 → 11 — so logical indices 1/2 do not match either real
\* LAPIC. This is what makes R1 observable in the model.
LapicId(c) ==
    CASE c = "C1" -> 7
      [] c = "C2" -> 11
      [] OTHER    -> 0

\* Logical CPU index treated *as if it were a LAPIC ID*. This is what
\* the legacy buggy code does: passes the logical index directly into
\* ICR_HI without translation.
LegacyIndexAsLapic(c) ==
    CASE c = "C1" -> 1
      [] c = "C2" -> 2
      [] OTHER    -> 0

\* The set of LAPIC IDs that actually exist on this machine.
PhysicalLapics == {LapicId(c) : c \in CPUs}

VARIABLES
    state,              \* Threads -> {"ready", "running", "done"}
    affinity,           \* Threads -> CPUs
    runqueue,           \* CPUs -> Seq(Threads)
    running,            \* CPUs -> Threads \cup {NULL}
    halted,             \* CPUs -> BOOLEAN  (TRUE = CPU is in HLT awaiting an IPI)
    ipi_pending,        \* CPUs -> BOOLEAN  (incoming reschedule IPI)
    woke                \* set of Threads that have been enqueued via the
                        \* "wake" path (whose IPI delivery is what we track)

vars == <<state, affinity, runqueue, running, halted, ipi_pending, woke>>

\* ---- helpers ----

\* This is the entire R1 fix in one expression: the legacy code passes
\* the logical CPU index in place of the LAPIC ID; the patched code
\* resolves through the index→LAPIC table.
ResolveTarget(cpu) ==
    IF AddressingMode = "lapic_id"
    THEN LapicId(cpu)
    ELSE LegacyIndexAsLapic(cpu)

\* Whether some real CPU has the given LAPIC ID. If FALSE, the IPI is
\* silently dropped — the precise mechanism of R1.
LapicExists(id) == \E c \in CPUs : LapicId(c) = id

\* The CPU whose physical LAPIC ID matches `id`. Caller must check
\* `LapicExists(id)` first.
LapicToCpu(id) == CHOOSE c \in CPUs : LapicId(c) = id

\* ---- type & init ----

TypeInv ==
    /\ state \in [Threads -> {"ready", "running", "done"}]
    /\ affinity \in [Threads -> CPUs]
    /\ runqueue \in [CPUs -> Seq(Threads)]
    /\ running \in [CPUs -> Threads \cup {NULL}]
    /\ halted \in [CPUs -> BOOLEAN]
    /\ ipi_pending \in [CPUs -> BOOLEAN]
    /\ woke \subseteq Threads

Init ==
    /\ state = [t \in Threads |-> "ready"]
    /\ affinity \in [Threads -> CPUs]
    /\ runqueue = [c \in CPUs |-> << >>]
    /\ running = [c \in CPUs |-> NULL]
    /\ halted = [c \in CPUs |-> TRUE]   \* every CPU starts in HLT idle loop
    /\ ipi_pending = [c \in CPUs |-> FALSE]
    /\ woke = {}

\* ---- the wake action: this is the path that R1 breaks ----
\*
\* `Wake(t)` models notify::signal → sched::wake → sched::enqueue:
\*   1. transition the thread from idle to enqueued
\*   2. push it onto its preferred CPU's run queue
\*   3. fire a reschedule IPI through ResolveTarget (R1 here)
\*   4. the IPI lands on whichever CPU's physical LAPIC matches the
\*      address that ResolveTarget produced; if no CPU matches it is
\*      silently dropped
\*
\* A thread can only be woken once — `t \notin woke`. This bounds the
\* model: liveness must hold for every wake event, not for an
\* unbounded sequence of them.

Wake(t) ==
    /\ state[t] = "ready"
    /\ t \notin woke
    /\ \A c \in CPUs : \A i \in 1..Len(runqueue[c]) : runqueue[c][i] /= t
    /\ \A c \in CPUs : running[c] /= t
    /\ LET c == affinity[t]
           target_lapic == ResolveTarget(c)
       IN
          /\ runqueue' = [runqueue EXCEPT ![c] = Append(@, t)]
          /\ ipi_pending' = [d \in CPUs |->
                IF LapicExists(target_lapic) /\ LapicId(d) = target_lapic
                THEN TRUE
                ELSE ipi_pending[d]]
          \* The IPI is what wakes a halted CPU. If the IPI is dropped
          \* (R1: LapicExists is false because the index doesn't match
          \* any real LAPIC), the target CPU stays halted forever.
          /\ halted' = [d \in CPUs |->
                IF LapicExists(target_lapic) /\ LapicId(d) = target_lapic
                THEN FALSE
                ELSE halted[d]]
          /\ woke' = woke \cup {t}
    /\ UNCHANGED <<state, affinity, running>>

\* ---- schedule(): pick next thread, drain IPI flag ----

\* Schedule fires only on a CPU that is NOT halted. A halted CPU is in
\* HLT and only the IPI delivery in `Wake` can clear `halted` to FALSE.
\* This is the load-bearing piece of the R1 hazard model: if the IPI
\* never lands, the CPU never un-halts, and the thread stays in the
\* run queue forever.
Schedule(c) ==
    /\ ~halted[c]
    /\ Len(runqueue[c]) > 0
    /\ LET next == Head(runqueue[c])
       IN
          /\ state[next] = "ready"
          /\ state' = [state EXCEPT ![next] = "running"]
          /\ running' = [running EXCEPT ![c] = next]
          /\ runqueue' = [runqueue EXCEPT ![c] = Tail(@)]
          /\ ipi_pending' = [ipi_pending EXCEPT ![c] = FALSE]
          /\ UNCHANGED <<affinity, halted, woke>>

\* The thread voluntarily yields and is marked done (terminal). The CPU
\* re-enters the HLT idle loop. Once every woken thread reaches "done",
\* the property is satisfied.
Finish(c) ==
    /\ running[c] /= NULL
    /\ state[running[c]] = "running"
    /\ state' = [state EXCEPT ![running[c]] = "done"]
    /\ running' = [running EXCEPT ![c] = NULL]
    /\ halted' = [halted EXCEPT ![c] = TRUE]
    /\ UNCHANGED <<affinity, runqueue, ipi_pending, woke>>

\* ---- next-state ----

Next ==
    \/ \E t \in Threads : Wake(t)
    \/ \E c \in CPUs : Schedule(c)
    \/ \E c \in CPUs : Finish(c)

Spec == Init /\ [][Next]_vars

FairSpec == Spec
    /\ \A c1 \in CPUs : WF_vars(Schedule(c1))
    /\ \A c2 \in CPUs : WF_vars(Finish(c2))

\* ---- Safety properties ----

SingleExecution ==
    \A c1, c2 \in CPUs :
        (c1 /= c2 /\ running[c1] /= NULL /\ running[c2] /= NULL)
        => running[c1] /= running[c2]

QueueConsistency ==
    \A c \in CPUs : \A i \in 1..Len(runqueue[c]) :
        state[runqueue[c][i]] = "ready"

MutualExclusion ==
    \A c \in CPUs : running[c] /= NULL =>
        state[running[c]] = "running"

\* ---- Liveness — the R1 catcher ----

\* Every woken thread eventually reaches the "done" state.
\*
\* Under AddressingMode = "lapic_id" the IPI is delivered correctly,
\* the target CPU schedules the thread, and Finish fires under WF.
\*
\* Under AddressingMode = "cpu_index" with a non-identity LapicId
\* mapping, the IPI is silently dropped. The thread sits in its run
\* queue. The CPU that should have woken up has running[c] = NULL
\* and queue empty, so Schedule(c) is enabled and WF fires it
\* eventually... unless the *target* CPU's run queue is empty
\* because the IPI never made it there.
\*
\* The hazard surfaces concretely as: enqueue to runqueue[C1] but
\* IPI flag set on whichever CPU has LAPIC 1 (none). The run queue
\* is non-empty but no CPU has been told to look. Schedule(C1) is
\* still enabled because running[C1] = NULL... wait, that means
\* WF should fire it anyway. The R1 hazard in this model only
\* surfaces when *another* CPU is busy and the IPI was supposed to
\* preempt it. Let me strengthen by saying: the woken thread must
\* be running OR done within a bounded window.
NoLostWake ==
    \A t \in Threads : (t \in woke) ~> (state[t] \in {"running", "done"})

THEOREM Spec => []TypeInv
THEOREM Spec => []SingleExecution
THEOREM Spec => []QueueConsistency
THEOREM Spec => []MutualExclusion
THEOREM (FairSpec /\ AddressingMode = "lapic_id") => NoLostWake

============================================================================
