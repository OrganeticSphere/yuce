# Audit storage

`AuditState` stores swarm records and the growing audit ontology separately from the fixed engine ontology. The graph builder is a separate internal role, outside the external swarm. This module implements storage and validation, not a running swarm or a model adapter.

## Opening a session

Use `AuditState::create` with explicit document IDs, `create_from_docs` for a set of supplied files, or `create_from_manifest` with the original manifest bytes and selected `(repository_relative_path, raw_bytes)` pairs. The manifest loader checks the pinned repository/commit/path/raw-SHA256 identity and excludes auxiliary Markdown and non-report files. Lexical revision mentions remain unresolved metadata.

`AuditState::new` provides read-only inspection. Mutations require a durable journal. `create` never overwrites an existing file; `open` validates and replays it under an exclusive writer lock.

## Dispatcher integration

- Authenticate the subject and authorize its role on the server. Strings such as `owner`, `builder` and `kernel` are provenance within this trusted in-process interface, not credentials.
- Call `submit_scoped_records_id` with a stable transport submission ID, authenticated actor, directive, document/range scope, exact issued record IDs and the result lines. References may use issued records and the actor's previously accepted prefix for that directive. Observations must match a unique exact byte span inside an issued range. The compatibility `submit_records_id` checks document provenance instead of exact issued record capabilities.
- On partial failure, retain the accepted prefix and submit only the repaired suffix under a new submission ID. Exact retries return the durable original receipt before fresh context validation; reuse of an ID with different content fails. Locals are scoped by actor/directive and survive recovery.
- Call `submit_operations_id` for one coordinator operation prefix, its receipt and an optional processed-cursor checkpoint. Its checkpoint is `{key, from, to, context}`; `from` must equal the durable cursor and `to` must lie within the ingest head. Empty successful batches can acknowledge a checkpoint. Check `error` and `checkpointed` in the returned result. A failed suffix keeps the accepted operation prefix but does not advance the checkpoint.
- Restore completed tasks and receipts from durable coordinator checkpoints. Active leases, issued cards, RPC routing and retry lookup before ephemeral-card validation belong to the dispatcher. The builder/directive skeleton does not yet use all these APIs.

There are three distinct axes: source `stance`, current structural `is_grounded`, and established `is_answer_support`. A relation can remain structurally grounded after rejection while losing answer support. `link_usable` also requires active proposal and verifier evidence. Do not treat record existence, a stored `Accepted` label, or an old `done` as current task completion. Check support and all task conditions at the same cutoff; terminal unknown remains a separate outcome.

## Ontology and records

The six strict record shapes are embedded in `schema.json`; runtime validation also checks calendar integers, UTF-8 byte limits and the documented schema extensions. Record IDs commit to resolved content, actor, directive and a per-directive ordinal. Renaming a local ID or inserting another directive does not rename a record.

New concepts are provisional. Status changes require a separately authorized coordinator decision. `same_as` and `duplicate_of` are explicit proposals, never inferred identity from equal names. Record relations must have a declared record-to-record signature; non-rejected `supersedes` links must be acyclic, including reactivation.

Source observations bind legacy engine evidence to a specific document version. Document updates and revocation invalidate dependent support without rewriting historical records. Manifest-derived IDs are immutable; a changed source needs its new identity. Agent-supplied valid dates and kernel ingest order are labeled separately; publication dates are not inferred from filenames.

## Durability and commitments

One `sbgk-session-log/2` frame commits the staged engine changes, audit changes, request/outcome receipt and coordinator checkpoint. Storage writes and synchronizes the frame before publishing the new in-memory state. A write/sync failure poisons that writer; reopen and retry the same submission ID to resolve an uncertain outcome.

Frames have a version, monotonic sequence, previous hash and canonical JSON payload. Recovery checks framing/hash continuity, then reexecutes commands and compares outcomes and both post-roots before repairing an unterminated final tail. A malformed complete frame or semantic divergence fails without tail repair. The reader rejects duplicate fields and noncanonical encodings. There is a 64 MiB frame limit and a 1 GiB log limit.

`audit_root` commits records/provenance, source identities, ontology, mappings, links/decisions, receipts and checkpoints. `engine_root` remains the engine commitment. `session_root = SHA256("R2R-AUDIT-SESSION/1" || engine_root || audit_root)` binds both. `wal_head` separately commits journal order. Authenticating a historical head requires an externally trusted checkpoint: a hash chain alone cannot detect replacement by a rehashed history or truncation to a valid prefix.

The old engine WAL, `sbgk-session-log/1` and binary `.sbgk` container v1 are unchanged. The old journal reader refuses v2. An exported engine container contains only the engine component; it does not persist audit records, the growing ontology, receipts or task state. Retain the outer v2 journal for full recovery. No implicit migration is provided.

Transactions currently reconstruct the engine from its WAL when staging. This conservative prototype has O(WAL) staging cost and does not demonstrate throughput for hundreds or thousands of workers. Replication, network services and power-loss behavior across filesystems need separate validation.
