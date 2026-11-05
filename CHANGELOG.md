# Changelog

## 0.1.5 (2026-11-05)

The Python client, and a fix of the runner for a team of several makers, found while preparing the run of
`benchmarks/PREREGISTRATION_0.1.5.md`. The kernel did not change: its code is that of 0.1.4.

* **A Python client of the audit server** in [clients/python](clients/python): one connection per agent, the server's tools as methods,
  standard library only. A refusal of the kernel is an ordinary answer; an exception means the call itself failed. It installs from the
  repository or the wheel of the release as `organetic-yuce`, and it is not on PyPI, where the name `yuce` belongs to an unrelated project.

* **The side on Temporal starts with a Codex or an Antigravity seat.** Neither declared its longest call, which bounds a Temporal step,
  so that side stopped at its start.
* **The money brake runs beside a seat without a price per call.** With an Antigravity seat the runner refused the brake even when other
  seats were paid. It now counts the paid seats, as it already did beside a Codex seat. A team with no paid seat is refused as before.
* **`benchmarks/PREREGISTRATION_0.1.5.md`** replaces the pre-registration of 0.1.4 for the run, which had not started: four readers of four
  makers, and what else changed is listed in the file.

## 0.1.4 (2026-11-05)

Answers to the outside reviews of 0.1.3: a faster check of a journal, the campaign of the limits in the open, and the runner ready
for a run from this tag. What that run will measure is fixed in `benchmarks/PREREGISTRATION_0.1.4.md`.

* **A journal replays about five times faster.** On the recorded runs of about 3,000 records, `audit-verify` went from about 11 s to
  2 s, and reopening a journal gains the same. Every entry copied the whole state, built its text again and hashed it. An entry that
  reports no failure now runs on the state itself; its outcome and roots are still computed and compared on every entry, so a journal
  that misreports one is refused as before. Roots, journal format and checks are unchanged, and old journals verify as they did. The
  whole state is still hashed at every entry, so the time grows close to the square of the length.
* **Tables of records take a key per process.** An agent writes what a record id hashes, and could otherwise search for ids that fall
  in one bucket and slow every pass. Nothing depends on the order of these tables, and they can no longer be walked.
* **The limits campaign is in the open.** `benchmarks/run_limits.py` with the example `limits` repeats section 4 of BENCHMARKS.md, and
  says how busy the machine was. The section is taken again on this code, and its memory column is now the peak of the whole process.
* **A refused start of `audit-serve` no longer writes to a journal or leaves a new one.** Every flag that needs no journal is now
  checked before the journal is opened, so a mistyped one does not cost a recovery. What is checked against the journal is only
  read: `--build-scope versions` on a run of another scope grew the journal and was then refused. A new run whose start fails
  after it was created is taken away again, so the same command can be given twice; before, only a taken port did that. One thing
  stays: opening a journal cuts a torn tail, so a start refused by a check against that journal has already cut it. It says so at
  once and keeps the bytes. A one-entry journal also resumes with `--build-scope versions` now.
* **`audit-verify --at-end`.** With `--expect`, the receipt's state must be the journal's last: a journal that went on after a
  terminal receipt is a mismatch, and so are bytes after the last complete entry. `at_end` in the report counts them too.
* **BENCHMARKS section 3 keeps the check of quotes alone.** The comparison of answers with knowledge-graph systems is out until the
  graph work of a later version: those systems have another purpose. It stays in the texts of 0.1.0 to 0.1.3.
* **The runner.** On the sides without the kernel, a closing line over its length limit is cut with a visible mark and counted, no longer
  refused: refused, it marked an answer incomplete and the page was done again after a withdrawal. A run's provenance names the tag, the
  trees of `crates` and `benchmarks`, the binary's version and the hash of every runner source, and a run refuses a binary of another
  version than its tag. `benchmarks/revision_outcomes.py` counts what a withdrawal cost and what it took with it, on every side.
* **`cone` refuses an entity no claim names** (exit 2), and a container it cannot read. It printed an empty cone and exited 0.
  With `--full-out` the entity is not checked: that output does not depend on it.

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
