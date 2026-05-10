---- MODULE AuditLogContinuity ----
\* Copyright 2026 Exochain Foundation
\*
\* Licensed under the Apache License, Version 2.0 (the "License");
\* you may not use this file except in compliance with the License.
\* You may obtain a copy of the License at:
\*
\*     https://www.apache.org/licenses/LICENSE-2.0
\*
\* Unless required by applicable law or agreed to in writing, software
\* distributed under the License is distributed on an "AS IS" BASIS,
\* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
\* See the License for the specific language governing permissions and
\* limitations under the License.
\*
\* SPDX-License-Identifier: Apache-2.0

\* TLA+ specification for the tamper-evident audit log hash chain.
\* Verifies invariants from the decision.forum PRD:
\*   - TNC-03: Audit chain integrity — unbroken hash chain, no gaps

EXTENDS Naturals, Sequences

VARIABLES
    log,             \* Sequence of audit entries
    nextSequence     \* Next sequence number to assign

vars == <<log, nextSequence>>

\* An audit entry is [sequence: Nat, prevHash: Nat, eventHash: Nat, entryHash: Nat]
\* We model hashes as naturals for simplicity in TLA+.

\* Simple hash model: H(a, b) = a * 31 + b (collision-free enough for model checking)
Hash(a, b) == a * 31 + b

GENESIS_HASH == 0

Init ==
    /\ log = <<>>
    /\ nextSequence = 0

\* Append a new audit entry
AppendEntry(eventHash) ==
    /\ LET prevHash == IF Len(log) = 0 THEN GENESIS_HASH
                        ELSE log[Len(log)].entryHash
           seq == nextSequence
           entryHash == Hash(Hash(seq, prevHash), eventHash)
       IN
        /\ log' = Append(log, [sequence |-> seq,
                                prevHash |-> prevHash,
                                eventHash |-> eventHash,
                                entryHash |-> entryHash])
        /\ nextSequence' = nextSequence + 1

\* Next state: append with any event hash
Next ==
    \E eh \in 1..100 : AppendEntry(eh)

Spec == Init /\ [][Next]_vars

\* ==================== INVARIANTS ====================

\* INV-1: TNC-03 — Sequence numbers are monotonically increasing with no gaps
MonotonicSequence ==
    \A i \in 1..Len(log) :
        log[i].sequence = i - 1

\* INV-2: TNC-03 — Hash chain is unbroken (each entry's prevHash matches prior entry's entryHash)
UnbrokenChain ==
    \A i \in 1..Len(log) :
        IF i = 1
        THEN log[i].prevHash = GENESIS_HASH
        ELSE log[i].prevHash = log[i-1].entryHash

\* INV-3: TNC-03 — Entry hash is correctly computed from its components
HashIntegrity ==
    \A i \in 1..Len(log) :
        log[i].entryHash = Hash(Hash(log[i].sequence, log[i].prevHash), log[i].eventHash)

\* INV-4: No empty gaps in the log
NoGaps ==
    \A i \in 1..(Len(log) - 1) :
        log[i+1].sequence = log[i].sequence + 1

\* Combined type invariant
TypeOK ==
    /\ nextSequence \in Nat
    /\ \A i \in 1..Len(log) :
        /\ log[i].sequence \in Nat
        /\ log[i].prevHash \in Nat
        /\ log[i].eventHash \in Nat
        /\ log[i].entryHash \in Nat

====
