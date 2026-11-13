# Preregistration: the gap pass of 0.2 on a second corpus (A2A), 0.2.1

Written 2026-11-13, before any run on the corpus. Fixed here: the question, the corpus, the pair, what is measured and what would
count against the gap pass.

## Question

The gap pass of 0.2 was built and measured on one corpus, the MCP specification: on run 1 of the release it used all 12 of its
packs, covered 94 units and added 111 records. Does it work the same way on a corpus it was not built on?

## Corpus and reference

- `benchmarks/corpora/a2a-spec-v1.0.1`: the A2A specification of v0.2.5, v0.3.0 and v1.0.1, the v1.0.1 changelog and the summary of
  v1, 380,731 bytes in five files, pinned by tag, commit and bytes.
- Oracle: `benchmarks/corpora/gold/a2a-spec-v1.0.1-stale-facts.json`, 14 facts that ended and 2 controls that still hold, judged
  against v1.0.1.
- The blind checklist and the withdrawal plan are fixed with this file and ship in each run's archive. The withdrawal plan:
  - 2A withdraws a peripheral line of the summary of v1, which the changelog also states;
  - 2B withdraws the one changelog item that states the removal of the `stateTransitionHistory` capability.

## The pair

- Only the kernel's side, with the flags of the runs of 0.2 (`--freeze-arm-a`).
- Three readers on `deepseek-flash`, thinking off, temperature 0.
- One factor changes: the gap pass, on (at most 12 packs of 8 units) or off.
- Two runs on each side. The sides run one after the other, alternating, on one binary and one tree.
- Budget: at most $3 per run, $6 for the four.

## What is measured

1. **The pass itself**, on the side with it:
   - packs used, units covered, records added and how many of them stand;
   - the coverage table (`sbgk audit-read coverage`): what each read unit came to, and whether its totals equal the report of the
     pass.
2. **Coverage**, both sides: read units quoted, units left without a quote.
3. **The answers**, graded blind by Gemini 4 Argon through Antigravity on the checklist:
   - stale-current errors on the 14 facts;
   - false-superseded errors on the 2 controls;
   - statement grades;
   - withdrawal discipline at 2A and 2B.
4. **Cost and time**, per run.

## What would count against the gap pass

- Its records do not stand: refused, or falling without a withdrawal.
- The coverage table and the report of the pass disagree.
- The side with the pass makes more stale-current or false-superseded errors than the side without, on both of its runs.

Two runs a side make a check, not a measure with bounds: a difference within the spread of the two runs of a side is reported as no
difference.

## Amendment, 2026-11-13, before any answer was read

Written after a review of the corpus and the oracle, with two of the four runs finished and the third running. Seen so far: the runs'
status, cost and record counts; no answer, packet or grade.

### The source of the files

The review found that the manifest names one Git source, commit `3303592588e388e62e0f69f701af531d2f4e3991` (v1.0.1) of
a2aproject/A2A, with the corpus paths (`v0.3.0/docs/specification.md` and the others). Those paths are not in that commit: the two
earlier specifications are `docs/specification.md` of their own tags, and the three v1.0.1 files have no version prefix there. The
kernel writes this repository, commit and path into the identity of each document, so the journals of the four runs carry them.

The bytes are the upstream bytes: each file matches its upstream blob, named per entry in `upstream`. Both sides read the same bytes
under the same names, so the pair is not affected.

Decision: the four runs stand as the measurement, and their report names the wrong source. For the release, the manifest is
corrected to name a repository and commit that hold the five files at their paths. Recording a separate upstream source per document
would change the kernel's identity contract; that is left for a later release.

### The counting unit

- Per run and stage, there is one row per oracle item (14 facts, 2 controls), judged from the answers to both questions together.
- A stale-current error is a fact stated as current for v1.0.1.
- An answer that states a fact current without scope and also states it ended keeps the stale-current error, marked as a
  contradiction.
- A false-superseded error is a control stated as ended.
- "Absent" is reported per item and is not counted as right.
- The transitions named in the answer to RQ1 are reported apart.

### Withdrawals

Whether a run quoted the withdrawn line (2A, 2B) is read from its own journal. A run that never quoted it has nothing to withdraw:
its withdrawal check there is "not hit", not a success.

### Bounds given to the grader

The bound of a right judgment for each item, from the review, given to the grader with the oracle:

| Item | Bound |
|---|---|
| `message-send` | The JSON-RPC method was renamed; sending a message did not end. |
| `tasks-resubscribe` | The method is now `SubscribeToTask`; subscribing to a task's updates did not end. |
| `extended-card-method` | `GetExtendedAgentCard` replaces the old name; the extended card after authentication remains. |
| `extended-card-flag` | The flag was renamed and moved to `capabilities.extendedAgentCard`; the extended card did not end. The three mentions of `supportsExtendedAgentCard` in the v1.0.1 specification are its legacy structure, the instruction to remove it and a client fallback: they do not make the old flag current. |
| `transport-fields` | `supportedInterfaces` replaces the two fields; the order of preferred transports remains. |
| `card-protocol-version` | The version moved to each interface; `protocolVersion` itself is not stale. |
| `http-v1-prefix` | The binding no longer requires the relative `/v1` prefix; an agent may still put `/v1` in its base URL. |
| `final-flag` | The field of `TaskStatusUpdateEvent` was removed; the end of a stream and the terminal task states remain. |
| `event-kind` | The `kind` field of events was removed, not the way to tell event types apart (now the JSON member names). |
| `part-types` | Three part types were replaced by one `Part`; text, files and structured data are still supported. |
| `task-state-values` | The serialized names of the states changed; the task lifecycle remains. |
| `push-config-set` | The method is now `CreateTaskPushNotificationConfig`; push notifications remain. |
| `well-known-agent-json` | The standard well-known path changed in v0.3.0; the old path stated for old clients only is right. |
| `state-transition-history` | An optional, unimplemented capability flag was removed; the history of messages or states did not end. |
| `task-not-found-code` | `-32001` is the JSON-RPC code; other bindings map the error their own way. |
| `well-known-agent-card` | The current well-known path for this way of discovery; not the only way to find a card. |

The v1.0.1 specification is source Markdown. Its tables of messages are 59 unexpanded macros (`proto_to_table` 56,
`proto_enum_to_table` 2, `proto_service_to_table` 1). A field missing from that text is no evidence that the protocol lacks it.

### Budget and dates

- The launcher holds each run to $3. The total of the four runs is checked against $6 from their recorded costs, in the report.
- The date of v0.3.0, 2025-07-31, is the date of the commit its tag names; the tag was moved there a day after the release.
