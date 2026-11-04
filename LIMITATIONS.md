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

## What the journal proves, and what it does not

* The journal is hash-chained and replays to the same audit and engine roots, and a journal with a changed byte is refused.
  A party that can rewrite the whole journal can also rewrite its chain: keep the terminal receipt (`audit_root`,
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

* Up to 10,000 records in one run and up to 8 agents at once are recommended for 0.1. At 10,000 records one commit takes
  about 41 ms (p50) and reopening the journal 13 s, both growing with the journal; more than 16 agents add little
  throughput ([BENCHMARKS.md](BENCHMARKS.md), section 4).

## Off by default, experimental

* **The graph builder** (`--build-scope full`, a dedicated `builder` subject) and the links it proposes between records
  (`supports`, `contradicts`, `supersedes`, ...), with their checks by an agent that wrote neither end. It is measured but
  not the default: it knew fewer version transitions than a dedicated graph system and cost three times as much.
* **Reading version transitions into the kernel** (`--build-scope versions`).
* **The dynamic ontology** (`--ontology-revisions`, `--ontology-review`): concepts that grow and are revised during a run.

## Not in 0.1

* A Python client library (`pip install yuce`) is planned for 0.1.2; until then agents talk to the server over MCP JSON-RPC
  or through `sbgk mcp-bridge`.
* Settings as a file and a page to edit them, and agents of any model joining and leaving with their own profile, are planned
  for 0.2.
* TLS: the servers listen on loopback by default and have no TLS. See [SECURITY.md](SECURITY.md).

## Platforms

* CI builds and tests on Linux and Windows. Release binaries are built for Linux x86_64, Windows x86_64 and macOS (arm64,
  x86_64); the Linux, Windows and macOS arm64 binaries are started once in the build, the macOS x86_64 one is not.
* The published runs were made on Windows x86_64.
