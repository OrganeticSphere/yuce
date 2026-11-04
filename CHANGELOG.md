# Changelog

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
