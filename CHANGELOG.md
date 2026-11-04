# Changelog

## 0.1.3 (2026-11-05)

Fixes from an outside review of 0.1.2.

* **`apply` exits 1 when a step is refused.** The refusal was only in its JSON report and the exit code stayed 0, so
  `apply && verify` took a refused run for a sound one: the container of the steps accepted before it is still written and
  verifies. The benchmark helpers read that report as they read `verify`'s.
* **An unknown flag or a stray argument is refused.** Any `--name value` used to be accepted, and anything else dropped, so a
  typo switched a check or a limit off in silence: `audit-verify --expct receipt.json` and `-expect` printed `VERIFIED` without
  looking at the receipt, and `mcp-bridge --allow-tool x` passed every tool. Each command now names its flags and how many other
  arguments it takes, and anything else exits 2 before the command runs.
* **A journal whose end is no complete entry is no longer a clean pass.** Without a receipt, `audit-verify` reports bytes after
  the last complete entry as `TORN_TAIL` with exit 1 (it said `VERIFIED`, exit 0). A resuming server still recovers from them, as
  it must after a crash, but now says so at once on stderr and in its first line and keeps the bytes in a file beside the journal,
  which `audit-verify` then lists; it used to cut them off in silence, which could undo what they held without a trace. A journal
  cut back to a complete entry still shows nothing without a receipt: see LIMITATIONS.md.
* **`audit-verify` on a file it cannot read exits 2**, not 1: a missing file is not a refused journal.
* **A port that is taken leaves no journal behind:** `audit-serve` binds its socket before it creates the run.
* **`update-doc` refuses a document the container does not have** (it added one in silence) and reports `saved_to`; without
  `--out` it saves nothing.
* **The inspector page** refuses a report whose fields have the wrong type, instead of stopping halfway with the previous
  badges still on the page.
* **The results are stated as far as they go.** README and BENCHMARKS no longer present a count of comparisons won or the model
  calls after a withdrawal as a result: the numbers stand, but the samples are small, most of those calls had nothing to do with
  the withdrawal, and the kernel's side makes more calls. See "How far these numbers go" in BENCHMARKS.md.

## 0.1.2 (2026-11-05)

* **The benchmark helpers read `sbgk verify`'s verdict again when a check fails.** Since 0.1.1 verify exits 1 on a failed
  check; the CLI wrappers of the benchmark suite took any non-zero exit for a crash, so the tamper-attack experiment
  (`run_sbgk_suite.py --only 6`) stopped at its first tampered container. The wrappers now take exit 1 from verify, with its
  verdict on stdout, as the answer; every other non-zero exit is still a failure. A test runs the experiment and checks that
  every attack is caught. The binaries behave as in 0.1.1.

## 0.1.1 (2026-11-04)

* **`sbgk verify` exits 1 when a check fails.** It printed `"ok": false` for a tampered container but exited 0, so a
  script or a CI step that reads the exit code took the container for a sound one. Exit codes now: 0 verified, 1 a check
  failed, 2 usage, as for `sbgk audit-verify`.

## 0.1.0

The first public release of YuCe, a deterministic evidence control kernel for AI agent teams.

* **The audit server** (`sbgk audit-serve`): an MCP server (newline-delimited JSON-RPC over TCP, one token per agent) that a
  team of agents works through. It leases sections of a corpus to readers, accepts a quote only when its bytes occur in the
  leased section, records claims with the quotes they rest on (`based_on`), and keeps every accepted record in a hash-chained
  journal. When an owner revokes a quote, the claims resting on it lose their support and the others keep it, without a model
  deciding which claims are touched. A restart replays the journal to the same audit and engine roots; a journal with a changed
  byte is refused.
* **The v0.1 profile** is the default: roles assigned per task, work in circles (reading, then answering), a suspicion mark on
  answers whose support was withdrawn, version-aware summaries with their companion quotes, and no graph building.
* **`sbgk audit-verify --wal run.wal [--expect receipt.json]`**: replays a journal read-only, without the server or a model, and
  reports its records, roots and chain head; with a receipt it checks that the journal reaches that state. Exit codes: 0
  verified, 1 refused or mismatch, 2 usage.
* **`sbgk --help` and `sbgk --version`.**
* **The no-LLM demo** (`examples/revoke-and-replay/`): three readers and an owner on one page of the MCP specification through the
  real server, in six checked steps, and `inspector.html`, a single offline page that shows the demo's report.
* **The benchmark runner** (`benchmarks/run_pilot_ac.py`): the same team of agents with the kernel and without it, the latter on
  its own orchestration, on native Temporal or on native LangGraph; DeepSeek, Claude (through Claude Code) and a stub model
  that makes no calls. The open MCP corpus, its questions, checklist and gold files are included.
* **Binaries** for Linux x86_64, macOS (arm64, x86_64) and Windows x86_64, with SHA-256 sums.
