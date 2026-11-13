# A2A specification corpus, v0.2.5 to v1.0.1

The Agent2Agent (A2A) protocol specification of three releases, with the changelog and the summary of v1 of the latest one: a second
corpus for the gap pass of 0.2, beside the MCP specification corpus.

| File | Release | Upstream |
|---|---|---|
| `v0.2.5/docs/specification.md` | v0.2.5 (2025-06-30) | `a2aproject/A2A` at `22b52705…`, `docs/specification.md` |
| `v0.3.0/docs/specification.md` | v0.3.0 (2025-07-31) | at `8d57eba2…`, `docs/specification.md` |
| `v1.0.1/CHANGELOG.md` | v1.0.1 (2026-05-28) | at `33035925…`, `CHANGELOG.md` |
| `v1.0.1/docs/whats-new-v1.md` | v1.0.1 | at `33035925…`, `docs/whats-new-v1.md` |
| `v1.0.1/docs/specification.md` | v1.0.1 | at `33035925…`, `docs/specification.md` |

- Every file holds the bytes of its release unchanged. `manifest.json` names, for each one, its tag, commit, upstream path, size,
  SHA-256 and git blob id; the git blob ids were checked against the ones GitHub names when the corpus was built.
- A file's corpus path is its release and its upstream path, since the three specifications have one upstream path. The manifest's
  source commit is that of v1.0.1: the kernel's document ids come from it and from the corpus path.
- `reports.txt` gives the files in release order, and `document_order.json` gives the kernel's document ids in that order.
- The specification is licensed under the Apache License 2.0 (`LICENSE`, from v1.0.1). Its copyright stays with its authors, the A2A
  project; this repository only pins its bytes for a benchmark.

**`../gold/a2a-spec-v1.0.1-stale-facts.json` is the oracle of the stale-current measure,** judged against v1.0.1.
- It holds 14 facts that held in v0.2.5 or v0.3.0 and ended later, each with a quote where it held and a quote where it ended.
  For example: `message/send` became SendMessage; the `final` flag of status events was removed; the Agent Card moved from
  `/.well-known/agent.json` to `/.well-known/agent-card.json` in v0.3.0.
- It also holds 2 control facts that still hold in v1.0.1.
- It was written by Claude before any run on the corpus.

`benchmarks/test_a2a_corpus.py` checks:
- the bytes of every file against the manifest;
- the document order against the kernel's document ids;
- every quote of the oracle, verbatim.
