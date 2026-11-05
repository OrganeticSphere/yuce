# YuCe

**A deterministic evidence control kernel for AI agent teams.**

YuCe is the environment a team of AI agents works in. It hands each agent one bounded task at a time, accepts a quote only
when its bytes occur in the source, records which conclusions rest on which quotes, and keeps everything it accepts in a
hash-chained journal. When a source is revoked, the kernel itself finds the conclusions that rested on it and leaves the
others standing: no model is asked what the revocation touches. A stopped run replays its journal to the same roots, and
anyone can check a published journal against its receipt without a model.

**An agent sends the text of a quote, not offsets: the kernel itself finds its bytes in the section the agent was leased.**

The kernel is written in Rust and calls no model. Agents of any model are its clients, over MCP. Deterministic here means that
the kernel's answers follow from its inputs and a journal replays to the same roots; two runs of a team differ, in their
timestamps and in what their models write.

## Source revoked: one minute, no model, no API key

```bash
cargo build --release
python examples/revoke-and-replay/demo.py --html inspector_report.html
```

Three readers and an owner work on one page of the MCP specification through the real audit server, in six checked steps:

1. A quote with one byte changed is refused, and nothing is stored.
2. Two byte-exact quotes and one claim on each are accepted, with receipts.
3. The owner revokes the first quote: the claim on it loses its support, the claim on the other quote keeps it.
4. The server is stopped and started on the same journal: the replay reaches the same roots and the same two states.
5. A copy of the journal with one letter changed is refused on start.
6. Without the server, `sbgk audit-verify` checks the journal against the receipt saved before the stop: verified; the
   edited copy: refused.

Open `inspector_report.html` to see what the kernel answered at each step: the quotes found byte for byte in the section
the reader was handed, the claims before and after the revocation, and both journal checks. The page works offline and
shows only the kernel's recorded answers ([examples/revoke-and-replay/](examples/revoke-and-replay/README.md)).

## Results

The same team of agents with the kernel (K) and without it, on native [Temporal](https://temporal.io/) (T) and native
[LangGraph](https://www.langchain.com/langgraph) (L), on 22 pages of the MCP specification across five revisions. Share of
correct statements, graded blind; after reading (stage 1) and after each of two source withdrawals (2A, 2B):

| Agents (grader) | Stage 1: K / T / L | 2A: K / T / L | 2B: K / T / L |
|---|---|---|---|
| Claude Haiku 5.5 (Fable 5.1) | 89.9 / 79.3 / 84.9 | 90.5 / 86.6 / 88.8 | 88.7 / 86.7 / 85.8 |
| DeepSeek Flash, series 1 (Opus 5.5) | 91.8 / 83.3 / 83.0 | 91.8 / 74.6 / 81.4 | 91.7 / 91.9 / 86.7 |
| DeepSeek Flash, series 2 (Opus 5.5) | 89.6 / 92.1 / 84.9 | 89.6 / 83.8 / 85.2 | 89.7 / 81.0 / 88.9 |

**We claim no gain in answer quality.** The samples are small: one corpus, one or two runs per side, 45 to 121 graded statements
each. The 95% interval of a difference is about 10 to 12 points either way; one difference of the 18 clears it (DeepSeek series 1,
2A, against T: +17.2), none after correcting for 18 comparisons, and they are not independent: the kernel's answers of stage 1
and 2A are the same text. The advantage of DeepSeek series 1 did not repeat in series 2. The kernel's side was at worst 2.4 points
below another side.

**What the kernel adds is the record, not the score.** Every accepted quote is byte-exact and every claim names what it rests on,
so what a withdrawal touches is read from those links rather than asked of a model, and a journal can be checked against its
receipt by anyone. Every grading found that the kernel's side kept both withdrawals. The sides without it kept them fully in
10 (T) and 8 (L) of 12 gradings and partly in the rest. A withdrawal touched an answer of the kernel's side three times in all,
once per run, on this one corpus.

**The price.** 2.3 to 2.5 times the wall time and 1.4 times the cost on Haiku; 1.2 to 1.3 and 1.5 to 1.6 on DeepSeek. Its side also
makes 1.8 to 2.6 times the model calls in stage 1, and no side with an equal budget of calls was run, so what the kernel adds to
the answers cannot be told from the extra reading. On DeepSeek it named fewer version transitions than T (9 and 7 to 8 of 13,
against 13 and 12). It checks bytes and registered dependencies, not meaning: on correct quotes its side once gave a current rule
as replaced (Haiku) and once an outdated one as current (DeepSeek, series 2). See [BENCHMARKS.md](BENCHMARKS.md) and
[LIMITATIONS.md](LIMITATIONS.md).

## What the kernel does

The environment for agent teams is the audit server, `sbgk audit-serve`:

* **Shared records with exact quotes.** Agents submit records: `observe`, `claim`, `relation`, `hypothesis`, `question`,
  `done`. An `observe` must quote its source byte for byte, inside the document range issued with the task; otherwise it
  is rejected. Each source document is pinned by repository, commit, path and SHA-256 of its raw bytes, as listed in a
  manifest.
* **Grounds.** A claim names the quotes it is based on (`based_on`), and every one of them is required. The kernel
  tracks whether each claim is still grounded: all its quotes must stand. A claim cannot rest on another claim here;
  chains of derivations belong to the engine below.
* **Withdrawal with cascade.** The owner can withdraw an `observe` record (`audit_revoke`). Every record whose required
  grounds include it loses its support at once; since all entries of `based_on` are required, one withdrawn quote is
  enough. Records grounded independently of it stay available, and history is not rewritten. A claim in an answer also
  carries a time label for its reader: `CURRENT_UNCERTAIN` (a claim that rested on an earlier and a later report lost the
  later quote; the kernel opens a task on that report and warns the next summary) or `LATEST_KNOWN` (no later state is known
  to the kernel, which is not proof that the state is current). With the
  experimental graph, accepted `supersedes` links add `CITES_REPLACED` (its quotes include an earlier state that was
  replaced, and none of the replacing one) and `CITES_EARLIER_AND_LATER` (quotes of both).
* **Hash-chained journal.** Each accepted transaction is one frame of an append-only journal (`sbgk-session-log/2`):
  canonical JSON (RFC 8785), linked by SHA-256 to the previous frame, written and synced before the new state is
  published. Reopening a journal replays it and checks that it reproduces the same `audit_root` and `engine_root`.
* **Coordination.** Work is cut into tasks. Each task is leased to one agent at a time; an expired lease is taken back.
  A retry with the same submission id returns the original receipt instead of committing twice. Readers work in circles
  (reading, then answering), with roles given per task. When the run is complete, the owner closes it (`audit_close`), and agents that ask for work
  receive `DONE`.
* **MCP access.** The server answers MCP-style JSON-RPC 2.0 (`initialize`, `tools/list`, `tools/call`) over TCP. Each
  agent has its own token from a subjects file, and the token's role (`swarm`, `builder` or `owner`) decides which tools
  it sees and may call. `sbgk mcp-bridge` lets an MCP client that starts its servers as stdio child processes join the
  shared server.

Underneath is the engine (`sbgk apply`, `serve`, `mcp-serve`). It binds evidence to exact byte spans of a document
version split into content-defined chunks, keeps facts and rule derivations, withdraws conclusions whose evidence is
revoked while re-deriving those that have another valid derivation, and stores the state as a `.sbgk` container with a
hash-chained log and a Merkle root. The minimal example below uses the engine.

**Experimental, off by default.** A graph builder (`--build-scope full`, with a dedicated `builder` subject) proposes links between records of
different agents (`supports`, `contradicts`, `qualifies`, `supersedes`, `depends_on`, `same_as`, `duplicate_of`), each
accepted or rejected by a kernel rule, by an agent that wrote neither end, or by the owner; the dynamic ontology
(`--ontology-revisions`, `--ontology-review`) grows and revises concepts during a run. Both are measured but not the default:
see [LIMITATIONS.md](LIMITATIONS.md).

## What it does not do

* **It checks bytes and structure, not meaning.** The kernel checks that a quote occurs in the source and that a claim
  names live grounds. It does not check that a claim says what its quotes say; two agents can agree on a wrong reading.
* **A hash chain alone does not authenticate history.** Detecting a rehashed history, or a journal cut back to a valid
  prefix, needs a checkpoint trusted from outside the journal.
* **The bridge restricts only what it is configured to.** Without `--allow-tools`, `mcp-bridge` passes every tool
  through, and the server's role check is the only filter. The agent id and the token come from the bridge's
  configuration. Give each agent a restricted profile: `--allow-tools`, `--agent-id` and its own token. The servers have
  no TLS; a non-loopback `--listen` address needs `--allow-remote` (and, for `mcp-serve`, `--token`).
* **A closed run opens again on a restart.** `audit_close` is held in memory, not in the journal: a server started on the same
  journal is open again.
* **Verification costs model calls.** Link checks and re-reads after a withdrawal are extra work for the agents.
* **Size.** Up to 8 agents at once are recommended for 0.1, and runs of a few thousand records: the cost of a commit and of
  reopening the journal grows with it. A real run's journal of about 3,000 records reopens in about 2 s, as does a journal of
  10,000 records of quotes and claims alone.

All of them, with what was measured: [LIMITATIONS.md](LIMITATIONS.md). Reporting a vulnerability: [SECURITY.md](SECURITY.md).

## Three ways to use it

* **On its own.** Run `sbgk audit-serve` on your corpus (a manifest of source files pinned by commit and SHA-256) and let
  your agents call its MCP tools, each with its own token. See [An audit server on the open corpus](#an-audit-server-on-the-open-corpus).
* **With a team you run.** The benchmark runner (`benchmarks/run_pilot_ac.py`) drives a team of readers and a checker
  through the kernel on DeepSeek, on Claude through Claude Code, or on a stub model that makes no calls, and runs the same
  team without the kernel for comparison. `python benchmarks/run_pilot_ac.py --help` lists its options.
* **Next to the tools you use.** An MCP client such as Claude Code joins as one agent through `sbgk mcp-bridge` (below).
  An orchestrator calls the same MCP tools from its own steps: the runner's native Temporal and LangGraph sides show the
  same team on those frameworks (`benchmarks/sbgk_bench/arm_a_temporal.py`, `arm_a_langgraph.py`; their packages:
  `benchmarks/requirements-baselines.txt`). There is no dedicated adapter in 0.1.

## Quick start

Build with a current stable Rust toolchain and run the tests:

```bash
cargo build --workspace --release
cargo test --workspace --release
```

The build produces `sbgk` and its alias `yuce` (the same commands) in `target/release/`; `sbgk --help` lists them. Release
binaries for Linux, macOS and Windows, with SHA-256 sums, are on the releases page; the examples below are in this repository,
not in the release archives.

### A minimal example

`examples/quickstart/` holds an ontology, one policy document and a five-step JSONL stream: two exact quotes, two facts
resting on them, and one derivation.

```bash
Q=examples/quickstart

# Apply the stream: every quote must occur byte for byte in the document, or the step is refused
# (QUOTE_NOT_FOUND_IN_BYTES, with the nearest candidates from the document)
./target/release/sbgk apply --ontology $Q/ontology.json --docs $Q/docs --stream $Q/stream.jsonl --out graph.sbgk
./target/release/sbgk apply --ontology $Q/ontology.json --docs $Q/docs --stream $Q/stream_prefix.jsonl --out graph_prefix.sbgk

# Check the container: header, chunks, node table, hash chain of the log, quote anchors (exit code 1 if a check fails)
./target/release/sbgk verify graph.sbgk

# The support cone of one entity: only what its conclusions rest on
./target/release/sbgk cone graph.sbgk --entity svc_auth --out cone.json

# What differs between two states, and the state after step 3
./target/release/sbgk diff graph_prefix.sbgk graph.sbgk
./target/release/sbgk timetravel graph.sbgk --seq 3
```

### An audit server on the open corpus

`benchmarks/corpora/mcp-spec-2026-07-28/` holds 22 pages of the Model Context Protocol specification across its five
released versions, pinned to an upstream commit. To start a run on it, write a subjects file (one token per agent, at
least 16 bytes each) and a questions file:

```bash
C=benchmarks/corpora/mcp-spec-2026-07-28

cat > subjects.json <<'EOF'
{"subjects": [
  {"id": "reader-1", "role": "swarm", "token": "replace-with-a-secret-1"},
  {"id": "reader-2", "role": "swarm", "token": "replace-with-a-secret-2"},
  {"id": "reader-3", "role": "swarm", "token": "replace-with-a-secret-3"},
  {"id": "owner",    "role": "owner", "token": "replace-with-a-secret-4"}
]}
EOF
cat > questions.json <<'EOF'
[{"id": "q1", "text": "Which transports does the latest specification define, and which earlier transports did it replace?",
  "about": ["transport"]}]
EOF

./target/release/sbgk audit-serve --manifest $C/manifest.json --repo $C --select $C/reports.txt \
  --run-id demo --wal demo.wal --subjects subjects.json --questions questions.json --listen 127.0.0.1:8787
```

Without further flags the server runs the measured v0.1 profile: no graph builder, reading in circles with dynamic roles,
stale suspects and the dated summary. It needs at least three reading agents, as above. `--profile custom` takes every flag as
given instead (for example a dedicated `builder` subject with the experimental `--build-scope full`).

The first line of output gives the address and the initial `audit_root`. Each new run needs a new `--wal` path; started
again on an existing journal without `--manifest`, the server resumes that run.

A recorded run can be checked without a model and without the server: `sbgk audit-verify --wal demo.wal` replays the
journal as a resumed server would (frame hashes, source identities, every entry to its committed outcome and roots),
reading the file once and read-only, and prints the record count, the audit, engine and session roots and the chain head.
With `--expect receipt.json`, the receipt's roots must name a state the journal passed through (a phase receipt or the
final one), and its `wal_head`, if it has one, the chain up to that state; a refused journal or a receipt that names no
state of it exits 1. With `--at-end` that state must also be the journal's last. Keep the receipt where the journal's writer cannot change it, for example in a
protected git commit or a CI artifact: a party that can rewrite the whole journal can also rewrite its hash chain.

An MCP client joins as one agent through the bridge, for example with this `.mcp.json` entry:

```json
{"mcpServers": {"r2r-reader-1": {
  "command": "/path/to/sbgk",
  "args": ["mcp-bridge", "--connect", "127.0.0.1:8787", "--agent-id", "reader-1",
           "--allow-tools", "audit_acquire,audit_submit,audit_renew,audit_release"],
  "env": {"SBGK_MCP_TOKEN": "replace-with-a-secret-1"}}}}
```

The bridge adds the token to every message, so the token stays in the bridge's environment and out of the model's prompt.
It refuses `shutdown` unless started with `--allow-shutdown`, so a worker cannot stop the shared server. The agent calls `audit_acquire`, does what the directive asks, and sends its JSON lines with
`audit_submit`. The owner's token gives `audit_status`, `audit_record`, `audit_revoke` and `audit_close`.

More on the audit layer: [crates/sbgk-core/src/audit/README.md](crates/sbgk-core/src/audit/README.md).

## Repository

* `crates/sbgk-core/`: the kernel (engine, container, journal and the audit layer in `src/audit/`).
* `crates/sbgk-cli/`: the `sbgk` / `yuce` command line and its servers (`serve`, `mcp-serve`, `audit-serve`,
  `mcp-bridge`).
* `examples/quickstart/`: the minimal example above.
* `examples/revoke-and-replay/`: the no-LLM demo of the audit server and its offline inspector page.
* `benchmarks/`: the benchmark runner and its tests, and the open corpus in `benchmarks/corpora/`.
* `scripts/check_no_cyrillic.py`: the repository language check; `scripts/check_snapshot.py`: the check of an unpacked
  release snapshot.
* [BENCHMARKS.md](BENCHMARKS.md), [LIMITATIONS.md](LIMITATIONS.md), [SECURITY.md](SECURITY.md), [CHANGELOG.md](CHANGELOG.md).

## The name: 玉策 → 玉冊

The project began as R2R, *Recipe to
Receipt*. **YuCe** is the reading *yù cè* shared by two Chinese words:

| | Characters | Literal sense | Role in the kernel |
| :--- | :--- | :--- | :--- |
| **Recipe** | **玉策**: 玉 *yù*, jade; 策 *cè*, a writing slip, also a plan or a strategy | an instruction written on a slip | a **directive**: one bounded task the kernel leases to one agent, such as "read this byte range of this document" or "check this proposed link" |
| **Receipt** | **玉冊**: 玉 *yù*, jade; 冊 *cè*, slips bound into a book, a register | a book of jade slips bound together | the **journal**: accepted submissions bound into a hash chain, with a receipt for each submission and a terminal receipt that names the state root of a finished run |

The jade book is a real object. The National Palace Museum in Taipei holds the jade book (禪地祇玉冊) of Emperor Zhenzong
of Song. It carries the prayer of the sacrifice to the Earth (禪) in the feng-shan ceremonies held at Mount Tai in 1008.
Its 16 slips of nephrite are inscribed in regular script filled with gold and joined by two rows of gold wire.
It was found in 1931 at the foot of Mount Tai. Source:
[ARTouch, on the Tang and Song jade books of the National Palace Museum](https://artouch.com/gumeishu/content-129264.html)
(in Chinese).

Reading 玉策 as the recipe and 玉冊 as the receipt is this project's own interpretation of the homophone pair: work is
handed out one slip at a time, and what is accepted is bound into one record that can be checked later.

## Who built it

YuCe was conceived and led by Aset Uisin (OrganeticSphere). It was built with a team of AI models, each in its own role:

* **Gemini Argon**: architecture and system design.
* **Claude Opus 5.5**: software development.
* **ChatGPT-6.1 Sol**: software development, code review and verification.

The benchmark answers were graded by other models, named with each comparison in [BENCHMARKS.md](BENCHMARKS.md).

## License

Copyright 2026 Aset Uisin, OrganeticSphere (organetic.ai). Licensed under the [Apache License, Version 2.0](LICENSE); see
[NOTICE](NOTICE). The corpus in `benchmarks/corpora/mcp-spec-2026-07-28/` keeps its upstream license files. Third-party
software and its licenses: [THIRD_PARTY_LICENSES.md](THIRD_PARTY_LICENSES.md).
