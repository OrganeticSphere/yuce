# Limitations

What YuCe 0.1 does not do, does not show, or does at a cost.

## What the kernel checks, and what it does not

* **Bytes and registered dependencies, not meaning.** The kernel accepts a quote only when its bytes occur in the leased
  section, and a claim only when the records it names (`based_on`) are live. It does not check that a claim says what its
  quotes say. In the Haiku pair of [BENCHMARKS.md](BENCHMARKS.md) the kernel's side wrote, on correct quotes, that a current
  header rule had been replaced, and the structural checks accepted it; the error stayed in every stage. In the second
  DeepSeek series it once gave an outdated rule as current. Two agents can agree
  on a wrong reading.
* **Only registered dependencies.** A revocation reaches the claims that name the revoked quote, directly or through other
  records. A conclusion that rests on a source without naming it is not tracked.
* **`LATEST_KNOWN` is not proof of being current.** It says that no later state is known to the kernel's records.

## What a command checks

* Only `verify` and `tamper` check a container first. `root`, `diff`, `cone`, `view`, `timetravel`, `node-table` and the `dump-*`
  commands read it as it is and can exit 0 on a damaged one: on a file you do not trust, run `verify` first and stop if it exits
  non-zero.

## What the journal proves, and what it does not

* The journal is hash-chained and replays to the same audit and engine roots, and a changed byte in a complete entry is refused.
* **Without a receipt the journal cannot show that its end is missing.** Cut back to a complete entry, it is a shorter sound
  journal: `sbgk audit-verify` says `VERIFIED` and a server resumes on it, and that can undo a revocation without rebuilding any
  chain. Keep the latest receipt and check against it.
* An end that is no complete entry, as a crash in the middle of a write leaves and a lost line end does too: without a receipt
  `sbgk audit-verify` reports `TORN_TAIL` (exit 1), and a server that resumes on it recovers to the last complete entry, says so
  at once on stderr and in its first line, and keeps the bytes beside the journal (`<wal>.torn-*`, which `audit-verify` then
  lists). More than one entry can be lost this way. A receipt older than the lost entries still matches: only the latest one
  shows that nothing is missing.
* Check a stopped journal: a live server's lock blocks reading on Windows (exit 2), and elsewhere a read in the middle of a write
  can report a torn tail that is not there.
* `--expect` finds the receipt's state anywhere in the journal, so a journal that went on after a terminal receipt passes too:
  `at_end` in the report says whether the state is the journal's end, and `--at-end` makes that a condition.
* `audit_close` is not journaled: a server restarted on the same journal is open again.
* **What a withdrawal reaches.** In the journal, no claim stays grounded on a withdrawn quote: that holds by construction. The
  text an agent writes is another matter: a later answer can repeat withdrawn content in other words, and how often it does is
  measured, not prevented.
* **`CURRENT_UNCERTAIN` needs one claim on both dates.** In the default profile the mark falls on a claim that rested on an earlier
  and a later report, and on the next summary. A reader's claim on the earlier quote alone stays `LATEST_KNOWN`, and a summary written
  as one claim per quote gets no mark. With accepted `supersedes` links, off by default, the earlier claim itself is marked.
* A party that can rewrite the whole journal can also rewrite its chain: keep the terminal receipt (`audit_root`,
  `engine_root`, `wal_head`) where the journal's writer cannot change it, such as a protected commit or a CI artifact, and
  check the journal against it with `sbgk audit-verify --expect`. There is no external witness service in 0.1.

## Measured scope

* **One corpus, few runs.** The results in [BENCHMARKS.md](BENCHMARKS.md) are on the MCP specification: one run per side
  on Claude Haiku 5.5, two series on DeepSeek Flash, and the DeepSeek advantage of the first series in two stages did not
  repeat in the second; graders differ between comparisons.
* **The kernel costs time and money.** Against the same team without it, the kernel's side took 2.3 to 2.5 times the wall
  time and 1.4 times the cost on Claude Haiku 5.5, 1.2 to 1.3 times and 1.5 to 1.6 times on DeepSeek Flash. Revocations themselves are cheap: the kernel found without a model call that the
  first withdrawal touched no answer.

## Size

* Up to 8 agents at once and runs of a few thousand records are recommended for 0.1. On a journal of quotes and claims alone one
  commit takes about 25 ms (p50) at 10,000 records and reopening the journal about 2 s; a real run's journal takes as long at about
  3,000 records, with more entries per record. The time of a replay grows close to the square of the journal's length, as the
  whole state is hashed at every entry. More than 16 agents add little throughput
  ([BENCHMARKS.md](BENCHMARKS.md), section 4).
* One process, one writer. There is no compaction of the journal, no rotation of tokens and no format migration in 0.1.
* The connection limit is shared: connections that send nothing hold a place until the 5 s admission timeout, and there is no
  limit per address. This matters with `--allow-remote`.

## Off by default, experimental

* **The graph builder** (`--build-scope full`, a dedicated `builder` subject) and the links it proposes between records
  (`supports`, `contradicts`, `supersedes`, ...), with their checks by an agent that wrote neither end. It is measured but
  not the default: it knew fewer version transitions than a dedicated graph system and cost three times as much.
* **Reading version transitions into the kernel** (`--build-scope versions`).
* **The dynamic ontology** (`--ontology-revisions`, `--ontology-review`): concepts that grow and are revised during a run.

## Not in 0.1

* The Python client ([clients/python](clients/python)) is a thin client of the server's tools, with no model or loop of its own. It
  installs from the repository or from the wheel of a release; it is not on PyPI, where the name `yuce` belongs to an unrelated project.
* Settings as a file and a page to edit them, and agents of any model joining and leaving with their own profile, are planned
  for 0.2.
* TLS: the servers listen on loopback by default and have no TLS. See [SECURITY.md](SECURITY.md).

## Platforms

* CI builds and tests on Linux at every push and on Windows on a manual run, done before each release. Release binaries are built for Linux x86_64, Windows x86_64 and macOS (arm64,
  x86_64); the Linux, Windows and macOS arm64 binaries are started once in the build, the macOS x86_64 one is not.
* The published runs were made on Windows x86_64.
* The Linux binary needs glibc 2.34 or later (Ubuntu 22.04, Debian 12, RHEL 9). Binaries and tags are not signed; the SHA-256 sums
  sit in the same release as the files.
