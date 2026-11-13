# MCP specification corpus, pinned at tag 2026-07-28

An open corpus for public runs of the kernel: 22 normative pages of the Model Context Protocol specification across its five
released versions (2024-11-05, 2025-03-26, 2025-06-18, 2025-11-25, 2026-07-28), 293,854 bytes in total.

The specification changes over time and records its own transitions. Each version's changelog names the previous
version and lists what was added, replaced, removed or deprecated. Mechanisms are added and later withdrawn: JSON-RPC
batching was added in 2025-03-26 and removed in 2025-06-18, and the `initialize` handshake was removed in 2026-07-28. So
the corpus tests whether an answer tells what is current from what was replaced.

## Source

- Repository: https://github.com/modelcontextprotocol/modelcontextprotocol
- Tag `2026-07-28`, commit `5f5440bb26a62e2cf3440b92da5a667efa03b267`; all files were read at this commit.
- Every file keeps its bytes and its upstream repository-relative path (`docs/specification/<version>/....mdx`), so the
  kernel's document identity (repository, commit, path, SHA-256) names the upstream file itself. `manifest.json` also
  records each file's upstream git blob id. The kernel reads `.mdx` as Markdown.

## Selection

| Group | Files |
|---|---|
| Changelogs of 2025-03-26, 2025-06-18, 2025-11-25, 2026-07-28; the deprecated-features registry and the versioning page of 2026-07-28 | 6 |
| Transports in every version (2026-07-28: `streamable-http` and `stdio`) | 6 |
| Lifecycle in 2024-11-05 ... 2025-11-25; in 2026-07-28 the handshake is gone and `basic/index` takes its place | 5 |
| Authorization in 2025-03-26 ... 2026-07-28 (2026-07-28: `authorization/index` and `client-registration`) | 5 |

The generated schema reference (`schema.mdx`, TypeDoc HTML) and the per-version overview pages are left out: the first is
markup rather than prose, the second barely changes between versions.

## License

The MCP project is moving from the MIT License to Apache-2.0. Specification contributions are Apache-2.0, or MIT where the
author has not agreed to relicense. Documentation other than the specification is CC-BY-4.0. Both texts are included:

- `LICENSE`: the project's license file at tag 2026-07-28 (Apache-2.0, with the CC-BY-4.0 notice).
- `LICENSE-MIT`: the MIT license text at tag 2025-06-18 (commit `f5ccad944fdf2b7d9cc70cf817f66ca5a8aa03a4`),
  "Copyright (c) 2024–2025 Anthropic, PBC and contributors".

Attribution: Model Context Protocol specification, (c) Anthropic, PBC and contributors.

## Files for a run

- `manifest.json`: the corpus manifest (`r2r.tobi_corpus_metadata_manifest.v1`), passed as `--manifest`; this folder
  is the `--repo`. The pages carry no `date` front matter, so each entry's `date` is its release (`version`): the kernel
  orders reports by these dates, and pages of one release are not earlier or later than each other.
- `reports.txt`: the 22 report paths in version order, passed as `--reports`.
- `document_order.json`: the kernel's document ids in version order (`--evolution-document-order`). The kernel uses it
  only where a report has no date; within one version it is only the listing order.

## Gold

Both files sit in `../gold/`, outside this folder, so a run never selects them.

**`mcp-spec-2026-07-28-stale-facts.json` is the oracle of the stale-current measure.**
- Thirteen facts that held in an earlier version, each one unit of counting:
  - seven were removed or replaced by 2026-07-28;
  - one changed its normative force (Dynamic Client Registration went from SHOULD to MAY in 2025-11-25);
  - five are deprecated but still in force.
- Facts are judged against the target version 2026-07-28. A statement explicitly scoped to an older version, or to legacy
  clients, is not an error.
- Each fact has two quotes: where it held and where it ended. Each also has a boundary: what did not end with it.
- Two control facts are still true, and marking them superseded counts as an error.
- Facts that only the later changelog attests are left out.

**`mcp-spec-2026-07-28-transitions.json` is a catalog of relations, not an oracle.**
- It holds one event per changelog item (71 in all), each with the item's first line as an exact quote and its kind
  (added, removed, replaced, deprecated, changed, clarified, governance).
- It also gives the earlier events whose mechanism each event removes, replaces, deprecates or changes, in whole or in part
  (25 links). A link does not make every earlier statement about that mechanism false.
- How it was made:
  1. Claude wrote a draft.
  2. Gemini 4 Argon labeled every item blind, without seeing the draft. Antigravity reported status ERROR for that call,
     but its final response held the complete answer.
  3. On the 24 items where the two differed, Claude Fable 5.1 decided between the unnamed sides, with a quote from the
     changelogs.
  4. One link was corrected after review: the `MCP-Protocol-Version` header stays required in 2026-07-28.
  5. On 2026-11-13 the links of two later items to a clarification were checked again by the same procedure, with Claude
     Fable 5.2 deciding. The two procedures split three to three, so the rule was written into the catalog: a clarified event
     has no mechanism of its own and is never the earlier end of a link. No link changed.

`benchmarks/test_mcp_corpus.py` checks:
- the bytes of every file against the manifest;
- the document order against the kernel's document ids;
- every quote of both gold files against the corpus.

Line endings are kept byte for byte (`.gitattributes`: `-text`).
