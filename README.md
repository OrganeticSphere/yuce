# YuCe

**A source your AI agents quoted was withdrawn. Which of their conclusions need re-checking?**

[简体中文](README.zh-CN.md)

YuCe answers that from the record, not by asking a model. Your agents work through it over MCP: it hands each agent one bounded
task at a time, accepts a quote only when its bytes occur in the source, records which conclusions rest on which quotes, and keeps
the accepted records and their grounds in a sealed, hash-chained journal. When a source is withdrawn, the kernel itself lists the
conclusions that stood on it, and the others stay standing. A stopped run replays its journal to the same roots, and anyone can
check a published journal without a model.

**A deterministic evidence control kernel for AI agent teams:** Rust, Apache-2.0, calls no model. Agents of any model are its
clients. Deterministic here means that the kernel's answers follow from its inputs and a journal replays to the same roots; two
runs of a team differ, in their timestamps and in what their models write. An agent sends the text of a quote, not offsets: the
kernel itself finds its bytes in the section the agent was leased.

## What 0.2 adds

* **What fell, and why.** `sbgk audit-read fallen --wal run.wal` names each record that lost a ground, the quotes that went (by their
  bytes, not their text) and why, the quotes under it that still stand, claims on other sources that say much the same, and what
  to reread.
* **A quittance for one conclusion.** `sbgk audit-proof` cuts one file with a record and everything it rests on, down to its quotes,
  under the signed checkpoint of a seal: 7 to 24 KB in the control runs. `sbgk audit-proof-verify` checks it alone, with no journal
  and no model.
* **A journal anyone can check.** The server seals the journal as it goes, and the seals are signed as C2SP checkpoints (Ed25519).
  `sbgk audit-verify` checks a journal against a receipt or a checkpoint kept elsewhere. Checking is always free.
* **Nothing skipped in silence.** The gap pass (`--gap-pass`, off by default) hands the parts of read sections that no quote
  covers back to the agents as narrow tasks: record what a part states, or answer empty.
* **An index beside the journal.** `sbgk audit-index` builds a SQLite file any tool reads, rebuilt from the journal at any time.

The full list is in [CHANGELOG.md](CHANGELOG.md).

## Source revoked: one minute, no model, no API key

```bash
python examples/revoke-and-replay/demo.py --bin path/to/sbgk --html inspector_report.html
```

`path/to/sbgk` is the binary of a release (see [Quick start](#quick-start)), or `cargo build --release` builds it and the script
finds it without `--bin`.

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
| Four makers, run 1, before the fix of 0.1.6 (Opus 5.5) | 87.8 / 86.6 / 84.0 | 83.6 / 93.7 / 67.1 | 87.0 / 92.5 / 82.3 |
| Four makers, run 2 (Opus 5.5) | 88.2 / 50.0 / 81.8 | 85.9 / 80.5 / 77.5 | 82.2 / 70.4 / 76.9 |
| Four makers, control run of 0.1.7: K new, T and L of run 2 graded again (Opus 5.5) | 82.0 / 56.9 / 86.4 | 87.1 / 87.7 / 77.5 | 82.6 / 78.2 / 83.8 |
| Four makers, control run of 0.2: K new, T and L of run 2 graded again (Fable 5.2) | 98.9 / 66.7 / 89.6 | 98.9 / 89.6 / 83.8 | 98.9 / 85.9 / 92.5 |
| The same grading, K of the control run of 0.1.7 (Fable 5.2) | 86.5 / 66.7 / 89.6 | 86.5 / 89.6 / 83.8 | 88.8 / 85.9 / 92.5 |
| Three DeepSeek Flash readers with the gap pass, 0.2, no side without the kernel (Fable 5.2) | 91.5 / – / – | 90.4 / – / – | 91.4 / – / – |

**We claim no gain in answer quality.** The samples are small: one corpus, one or two runs per side, 45 to 158 graded statements
each. The 95% interval of a difference is about 10 to 12 points either way; on the single-model runs one difference of the 18
clears it (DeepSeek series 1, 2A, against T: +17.2), none after correcting for 18 comparisons, and they are not independent: the
kernel's answers of stage 1 and 2A are the same text. The advantage of DeepSeek series 1 did not repeat in series 2. Agents of four
makers show how far two runs can fall apart: the kernel's side was 10.1 points below T in 2A of run 1, and T fell by 36.6 points in
stage 1 of run 2 with nothing changed on its side. In the grading of 0.2 the same four readers scored 98.9 at every stage on 0.2
and 86.5 to 88.8 on 0.1.7, a gap wider than the grader's own spread (up to 2.6 points on the same text, 5.6 between its two label
orders), but each side is one run.

**What the kernel adds is the record, not the score.** Every accepted quote is byte-exact and every claim names what it rests on,
so what a withdrawal touches is read from those links rather than asked of a model, and a journal can be checked against its
receipt by anyone. On the single-model runs every grading found that the kernel's side kept both withdrawals, and the sides without
it kept them fully in 10 (T) and 8 (L) of 12 gradings and partly in the rest. On four makers the grader found a real gap: a reader
stored a withdrawn sentence again, three bytes wider, the kernel took it as a new record, and an answer cited it. Since 0.1.6 a
withdrawal closes the bytes, and in the second run no grounded record rests on the withdrawn text. Its answer was still graded
partly kept after the second withdrawal, for dropping a conclusion another page supports. T kept all 8 gradings there, L 6. In
0.1.7 the kernel names what fell: in its control run the repair took one new claim per answer and the conclusion stood. The grader
marked the second withdrawal kept in one order and partly in the other, for an earlier state written as current, which the answer
held before the withdrawals. In 0.2 a repair also shows the live support of what fell. In both control runs no grounded record
rests on the withdrawn text after either withdrawal, and the grader found no earlier state written as current in the kernel's
answers, against 8 to 12 for 0.1.7. With four makers both withdrawals were kept in both orders. With three DeepSeek readers the
second was kept partly: the model read the withdrawal of one changelog line as the withdrawal of the whole revision, and its
repaired answer lost the sessions conclusion that a standing page supports.

**The price.** 2.3 to 2.5 times the wall time and 1.4 times the cost on Haiku; 1.2 to 1.3 and 1.5 to 1.6 on DeepSeek. Its side also
makes 1.8 to 2.6 times the model calls in stage 1, and no side with an equal budget of calls was run, so what the kernel adds to
the answers cannot be told from the extra reading. On DeepSeek it named fewer version transitions than T (9 and 7 to 8 of 13,
against 13 and 12), and on 0.2 with four makers 9 or 10 of 13, against 12 for 0.1.7 and 13 for L. It checks bytes and registered dependencies, not meaning: on correct quotes its side once gave a current rule
as replaced (Haiku) and once an outdated one as current (DeepSeek, series 2). See [BENCHMARKS.md](BENCHMARKS.md) and
[LIMITATIONS.md](LIMITATIONS.md).

## What the kernel does

The environment for agent teams is the audit server, `sbgk audit-serve`:

* **Shared records with exact quotes.** Agents submit records: `observe`, `claim`, `relation`, `hypothesis`, `question`,
  `done`. An `observe` must quote its source byte for byte, inside the document range issued with the task; otherwise it
  is rejected. Each source document is pinned by repository, commit, path and SHA-256 of its raw bytes, as listed in a
  manifest, or, for your own files, by its path in a folder and the SHA-256 of its bytes.
* **Grounds.** A claim names the quotes it is based on (`based_on`), and every one of them is required. The kernel
  tracks whether each claim is still grounded: all its quotes must stand. A claim cannot rest on another claim here;
  chains of derivations belong to the engine below.
* **Withdrawal with cascade.** The owner can withdraw an `observe` record (`audit_revoke`) or a text of a document, quoted
  or not (`audit_withdraw_text`). That closes those bytes in the document: every stored quote overlapping them goes with it,
  and a new quote overlapping them is refused. Every record whose
  required grounds include one of those quotes loses its support at once; since all entries of `based_on` are required,
  one withdrawn quote is enough. Records grounded independently of it stay available, and history is not rewritten. The report of
  what fell (`audit_fallen`, or `sbgk audit-read fallen` over the journal) names each record that lost a ground, the quotes that went
  (by their bytes, without their text), the quotes under it that still stand, and claims on other sources that say much the same. A claim in an answer also
  carries a time label for its reader: `CURRENT_UNCERTAIN` (a claim that rested on an earlier and a later report lost the
  later quote; the kernel opens a task on that report and warns the next summary) or `LATEST_KNOWN` (no later state is known
  to the kernel, which is not proof that the state is current). With the
  experimental graph, accepted `supersedes` links add `CITES_REPLACED` (its quotes include an earlier state that was
  replaced, and none of the replacing one) and `CITES_EARLIER_AND_LATER` (quotes of both).
* **Hash-chained journal.** Each accepted transaction is one frame of an append-only journal (`sbgk-session-log/3`):
  canonical JSON (RFC 8785), a header that names the body by its hash and the accepted records by the root of their tree,
  linked by SHA-256 to the previous header, written and synced before the new state is published. Reopening a journal
  replays it and checks that it reproduces the same `audit_root` and `engine_root`. The server seals the journal from time
  to time: the frames so far, the roots of the state and the hashes of what stands and what rests on what.
  Journals of 0.1 (`sbgk-session-log/2`) still verify.
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
* **Verification costs model calls.** Link checks and re-reads after a withdrawal are extra work for the agents.
* **Size.** Up to 8 agents at once are recommended, as measured on 0.1, and runs of a few thousand records: the cost of a commit and of
  reopening the journal grows with it. A real run's journal of about 3,000 records reopens in about 2 s, as does a journal of
  10,000 records of quotes and claims alone.

All of them, with what was measured: [LIMITATIONS.md](LIMITATIONS.md). Reporting a vulnerability: [SECURITY.md](SECURITY.md).

## Three ways to use it

* **On its own.** Run `sbgk audit-serve` on your corpus (a folder of text files, or a manifest of sources pinned by commit and SHA-256) and let
  your agents call its MCP tools, each with its own token, from any language or through the
  [Python client](clients/python). See [An audit server on the open corpus](#an-audit-server-on-the-open-corpus).
* **With a team you run.** The benchmark runner (`benchmarks/run_pilot_ac.py`) drives a team of readers and a checker
  through the kernel on DeepSeek, on Claude through Claude Code, or on a stub model that makes no calls, and runs the same
  team without the kernel for comparison. `python benchmarks/run_pilot_ac.py --help` lists its options.
* **Next to the tools you use.** An MCP client such as Claude Code joins as one agent through `sbgk mcp-bridge` (below).
  An orchestrator calls the same MCP tools from its own steps: the runner's native Temporal and LangGraph sides show the
  same team on those frameworks (`benchmarks/sbgk_bench/arm_a_temporal.py`, `arm_a_langgraph.py`; their packages:
  `benchmarks/requirements-baselines.txt`). There is no dedicated adapter yet.

## Quick start

The shortest way is a release: binaries for Linux, macOS and Windows, with SHA-256 sums, are on the
[releases page](https://github.com/OrganeticSphere/yuce/releases). Check the sum, unpack, and run `sbgk --help` (or `yuce --help`,
the same commands). The Python client is on PyPI:

```bash
pip install organetic-yuce
```

### One agent on your own folder

A folder of UTF-8 text files, one question, one agent (Claude Code, Cursor or any MCP client):

```bash
cat > questions.json <<'EOF'
[{"id": "q1", "text": "What do these documents say about refunds?", "about": ["refund"]}]
EOF
sbgk audit-serve --profile solo --docs ./my-docs --questions questions.json --run-id mine --wal mine.wal --listen 127.0.0.1:8787
```

`--profile solo` runs one reading agent without a graph builder. Without `--subjects` the server writes `mine.wal.subjects.json`
beside the journal with two tokens, `agent` for your agent and `owner` for you, and never prints them. Join your MCP client as
`agent` with the bridge entry below (`--agent-id agent`, its token in `SBGK_MCP_TOKEN`). `about` names the words your documents
use for the topic: if no document holds any of them, the server says so at the start and in `audit_status`.

The same flags fit in one file: `sbgk audit-serve --settings settings.json`, with relative paths taken from the file's folder.
`examples/settings/` holds one you can run as it is.

The examples below are in this repository, not in the release archives. To build from source with a current stable Rust
toolchain and run the tests:

```bash
cargo build --workspace --release
cargo test --workspace --release
```

The build puts `sbgk` and `yuce` in `target/release/`.

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
stale suspects and the dated summary. It needs at least three reading agents, as above; `--profile solo` is the same for one agent,
without circles and dynamic roles. `--profile custom` takes every flag as
given instead (for example a dedicated `builder` subject with the experimental `--build-scope full`).

The first line of output gives the address and the initial `audit_root`. Each new run needs a new `--wal` path; started
again on an existing journal without `--manifest` or `--docs`, the server resumes that run: give it the same `--questions` and the
same profile, as neither is in the journal.

Your own documents need no manifest: `--docs` takes the UTF-8 text files of a folder, such as contracts, policies, logs or code.

```bash
./target/release/sbgk audit-serve --docs ./contracts --run-id contracts-1 --wal contracts.wal \
  --subjects subjects.json --questions questions.json --listen 127.0.0.1:8787
```

A document is named by its path inside the folder. The server leaves out hidden files such as `.env`, service folders, links and
its own files with their copies, and prints on stderr what it took and what it left. A file that is not UTF-8 text stops the start, by name: convert
PDF and Word files to text first, or name the files to take with `--select` (one path per line). The journal keeps the full text of
what was taken, and whoever checks it gets that text: see [LIMITATIONS.md](LIMITATIONS.md).

A recorded run can be checked without a model and without the server: `sbgk audit-verify --wal demo.wal` replays the
journal as a resumed server would (frame hashes, source identities, every entry to its committed outcome and roots),
reading the file once and read-only, and prints the record count, the audit, engine and session roots and the chain head.
With `--expect receipt.json`, the receipt's roots must name a state the journal passed through (a phase receipt or the
final one), and its `wal_head`, if it has one, the chain up to that state; a refused journal or a receipt that names no
state of it exits 1. With `--at-end` that state must also be the journal's last. `VERIFIED` without `--expect` says that the chain
and every entry check out, not that this is the journal a receipt names: only `--expect` says that. Keep the receipt where the journal's writer cannot change it, for example in a
protected git commit or a CI artifact: a party that can rewrite the whole journal can also rewrite its hash chain.

A 0.2 server started with `--signing-key` (made by `sbgk keygen`) signs every seal into a checkpoint beside the journal, in the
C2SP `signed-note` format; `sbgk audit-verify --wal demo.wal --checkpoint <file> --trusted-keys <file>` checks the signature and
that the checkpoint names this journal's frames. Keep the checkpoint where the journal's writer cannot change it.

`sbgk audit-read <tool> --wal demo.wal` reads a recorded journal after the same check: `status`, `dependents --record <id>` (or
`--doc-id`), `active-claims`, `diff --from <n> [--to <n>]`, `record --record <id>`, `fallen [--since <n>]` and `coverage
[--doc-id] [--unit-status <status>]`, where a point `<n>` is a number of frames, as in a seal. They answer as the owner's tools of
the live server do. `coverage` says what each list item, paragraph and table row of the documents came to: quoted, answered empty
by a pack of the gap pass, left by its budget, or not read.

An MCP client joins as one agent through the bridge, for example with this `.mcp.json` entry:

```json
{"mcpServers": {"r2r-reader-1": {
  "command": "/path/to/sbgk",
  "args": ["mcp-bridge", "--connect", "127.0.0.1:8787", "--agent-id", "reader-1",
           "--allow-tools", "audit_acquire,audit_submit,audit_renew,audit_release"],
  "env": {"SBGK_MCP_TOKEN": "replace-with-a-secret-1"}}}}
```

The owner joins the same way with the owner's token and its tools:

```json
{"mcpServers": {"r2r-owner": {
  "command": "/path/to/sbgk",
  "args": ["mcp-bridge", "--connect", "127.0.0.1:8787", "--agent-id", "owner",
           "--allow-tools", "audit_status,audit_record,audit_fallen,audit_revoke,audit_withdraw_text,audit_terminal_receipt"],
  "env": {"SBGK_MCP_TOKEN": "replace-with-a-secret-4"}}}}
```

The bridge adds the token to every message, so the token stays in the bridge's environment and out of the model's prompt.
It refuses `shutdown` unless started with `--allow-shutdown`, so a worker cannot stop the shared server. The agent calls `audit_acquire`, does what the directive asks, and sends its JSON lines with
`audit_submit`. The owner's token gives `audit_status`, `audit_record`, `audit_dependents`, `audit_active_claims`, `audit_diff`,
`audit_fallen`, `audit_revoke`, `audit_withdraw_text`, `audit_seal` and `audit_close`.

More on the audit layer: [crates/sbgk-core/src/audit/README.md](crates/sbgk-core/src/audit/README.md).

## Repository

* `crates/sbgk-core/`: the kernel (engine, container, journal and the audit layer in `src/audit/`).
* `crates/sbgk-cli/`: the `sbgk` / `yuce` command line and its servers (`serve`, `mcp-serve`, `audit-serve`,
  `mcp-bridge`).
* `examples/quickstart/`: the minimal example above.
* `examples/revoke-and-replay/`: the no-LLM demo of the audit server and its offline inspector page.
* `examples/findings-gate/`: a security review's findings on code files through the kernel: a made-up finding, a lost agent, a
  file that changes.
* `benchmarks/`: the benchmark runner and its tests, and the open corpus in `benchmarks/corpora/`.
* `verifier/`: `yuce-verify`, an independent verifier of 0.2 journals written in a clean room from the specification of the
  format, in TypeScript for Node.js and the browser, with that specification and its test journals.
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
