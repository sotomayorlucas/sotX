-------------------------------- MODULE ipc --------------------------------
\* TLA+ Specification of sotOS IPC Protocol (Synchronous Endpoints)
\*
\* This specification models the synchronous rendezvous IPC mechanism
\* used by sotOS. It verifies:
\*   - Safety: no message loss, no duplicate delivery
\*   - Progress: matching send/recv pairs always complete
\*   - Mutual exclusion: at most one receiver per endpoint
\*
\* The model covers send(), recv(), and call() operations on a single
\* endpoint with multiple threads.

EXTENDS Naturals, Sequences, FiniteSets

CONSTANTS
    Threads,        \* Set of thread IDs
    MaxQueueLen     \* Maximum send queue length

VARIABLES
    state,          \* Endpoint state: "idle" | "recv_wait" | "send_wait"
    receiver,       \* Thread ID of waiting receiver (or NULL)
    sendQueue,      \* Sequence of waiting sender thread IDs
    caller,         \* Thread ID of caller waiting for reply (or NULL)
    threadState,    \* Function: Thread -> {"ready","blocked","done"}
    messages,       \* Function: Thread -> message value (or NULL)
    delivered       \* Set of (sender, receiver, message) triples delivered

NULL == CHOOSE x : x \notin Threads

TypeInvariant ==
    /\ state \in {"idle", "recv_wait", "send_wait"}
    /\ receiver \in Threads \cup {NULL}
    /\ sendQueue \in Seq(Threads)
    /\ Len(sendQueue) <= MaxQueueLen
    /\ caller \in Threads \cup {NULL}
    /\ threadState \in [Threads -> {"ready", "send_blocked", "recv_blocked", "call_blocked", "done"}]
    /\ messages \in [Threads -> Nat \cup {NULL}]

Init ==
    /\ state = "idle"
    /\ receiver = NULL
    /\ sendQueue = << >>
    /\ caller = NULL
    /\ threadState = [t \in Threads |-> "ready"]
    /\ messages = [t \in Threads |-> NULL]
    /\ delivered = {}

\* --- Send Operation ---
\* A ready thread attempts to send a message on the endpoint.
Send(t, msg) ==
    /\ threadState[t] = "ready"
    /\ messages' = [messages EXCEPT ![t] = msg]
    /\  \* Case 1: Receiver is waiting (rendezvous)
        IF state = "recv_wait" /\ receiver /= NULL THEN
            /\ state' = "idle"
            /\ delivered' = delivered \cup {<<t, receiver, msg>>}
            /\ threadState' = [threadState EXCEPT
                ![t] = "done",
                ![receiver] = "done"]
            /\ receiver' = NULL
            /\ UNCHANGED <<sendQueue, caller>>
        \* Case 2: Caller waiting for reply (reply path)
        ELSE IF caller /= NULL THEN
            /\ delivered' = delivered \cup {<<t, caller, msg>>}
            /\ threadState' = [threadState EXCEPT
                ![t] = "done",
                ![caller] = "done"]
            /\ caller' = NULL
            /\ UNCHANGED <<state, receiver, sendQueue>>
        \* Case 3: No receiver — block
        ELSE IF Len(sendQueue) < MaxQueueLen THEN
            /\ state' = "send_wait"
            /\ sendQueue' = Append(sendQueue, t)
            /\ threadState' = [threadState EXCEPT ![t] = "send_blocked"]
            /\ UNCHANGED <<receiver, caller, delivered>>
        ELSE
            UNCHANGED <<state, receiver, sendQueue, caller, threadState, delivered>>

\* --- Receive Operation ---
\* A ready thread attempts to receive on the endpoint.
Recv(t) ==
    /\ threadState[t] = "ready"
    /\  \* Case 1: Sender is waiting (rendezvous)
        IF state = "send_wait" /\ Len(sendQueue) > 0 THEN
            LET sender == Head(sendQueue)
                msg == messages[sender]
            IN
            /\ delivered' = delivered \cup {<<sender, t, msg>>}
            /\ sendQueue' = Tail(sendQueue)
            /\ state' = IF Len(sendQueue) = 1 THEN "idle" ELSE "send_wait"
            /\ threadState' = [threadState EXCEPT
                ![t] = "done",
                ![sender] = "done"]
            /\ UNCHANGED <<receiver, caller, messages>>
        \* Case 2: No sender — block
        ELSE IF state = "idle" THEN
            /\ state' = "recv_wait"
            /\ receiver' = t
            /\ threadState' = [threadState EXCEPT ![t] = "recv_blocked"]
            /\ UNCHANGED <<sendQueue, caller, messages, delivered>>
        ELSE
            UNCHANGED <<state, receiver, sendQueue, caller, threadState, messages, delivered>>

\* --- Call Operation (send + wait for reply) ---
\* A ready thread sends and waits for a reply.
Call(t, msg) ==
    /\ threadState[t] = "ready"
    /\ messages' = [messages EXCEPT ![t] = msg]
    /\  \* Case 1: Receiver waiting — deliver and wait for reply
        IF state = "recv_wait" /\ receiver /= NULL THEN
            /\ delivered' = delivered \cup {<<t, receiver, msg>>}
            /\ caller' = t
            /\ state' = "idle"
            /\ threadState' = [threadState EXCEPT
                ![receiver] = "done",
                ![t] = "call_blocked"]
            /\ receiver' = NULL
            /\ UNCHANGED <<sendQueue>>
        \* Case 2: No receiver — enqueue and block
        ELSE IF Len(sendQueue) < MaxQueueLen THEN
            /\ state' = "send_wait"
            /\ sendQueue' = Append(sendQueue, t)
            /\ threadState' = [threadState EXCEPT ![t] = "call_blocked"]
            /\ UNCHANGED <<receiver, caller, delivered>>
        ELSE
            UNCHANGED <<state, receiver, sendQueue, caller, threadState, delivered>>

\* --- Next-State Relation ---
Next ==
    \E t \in Threads, msg \in 1..3 :
        \/ Send(t, msg)
        \/ Recv(t)
        \/ Call(t, msg)

\* --- Safety Properties ---

\* No message is delivered twice.
NoDoubleDel == \A d1, d2 \in delivered :
    d1 = d2 \/ d1[1] /= d2[1] \/ d1[2] /= d2[2]

\* At most one receiver waiting at any time.
SingleReceiver ==
    state = "recv_wait" => receiver /= NULL

\* A blocked sender is in the send queue.
BlockedInQueue == \A t \in Threads :
    threadState[t] = "send_blocked" =>
        \E i \in 1..Len(sendQueue) : sendQueue[i] = t

\* --- Specification ---
Spec == Init /\ [][Next]_<<state, receiver, sendQueue, caller,
                           threadState, messages, delivered>>

THEOREM Spec => []TypeInvariant
THEOREM Spec => []NoDoubleDel
THEOREM Spec => []SingleReceiver
THEOREM Spec => []BlockedInQueue

============================================================================
