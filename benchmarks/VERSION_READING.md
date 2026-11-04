# Version reading (experimental v0.1 profile)

`--build-scope versions` runs the normal reading/request/answer queue plus `CHANGE` tasks. It has no graph builder, term mapping,
BUILD cards, or BUILD barrier. A `CHANGE` task compares byte ranges in an explicit pair of snapshots. Relations are proposals;
an independent nonauthor still verifies them. Exact quotes and a valid relation structure do not prove semantic correctness.

The legacy `--whole-reader` profile is refused with `versions`, before any server or model starts: its cached answers bypass the
summary context. Use the ordinary readers for this profile. In-card reuse of explicitly issued or own prior records is allowed;
authors of either endpoint and the relation proposer cannot verify the link, so reuse may narrow the pool of independent verifiers.

CHANGE grants are closed durably on completion, release, observed expiry, and recovery. Old task ids cannot grant new writes
after closure; already committed proposals remain available to independent verification. A failed grant publication leaves the
work available for a fresh acquire.

Provide `--version-lineage path/to/lineage.json` to `audit-serve` or `benchmarks/run_pilot_ac.py`:

```json
{"lineages":[{"id":"product-spec","snapshots":[
  {"id":"v1","docs":[{"doc_id":"d_...","raw_sha256":"..."}],"changelog":[]},
  {"id":"v2","docs":[{"doc_id":"d_...","raw_sha256":"..."}],"changelog":[{"doc_id":"d_...","raw_sha256":"..."}]}
]}]}
```

The operator explicitly declares lineage and snapshot order. Document ids are the immutable manifest ids, not paths. Each hash
must match the selected document's raw UTF-8 bytes in genesis. A document belongs to exactly one snapshot. Dates, paths and
`document_order.json` do not imply lineage. Without this input the map is empty, and ordinary reading continues.

The kernel stores the derived `version:map` checkpoint once, without changing genesis. It commits `r2r-version-map/1`, its 35/100
threshold, first-maximum tie break in explicit document/section order, 9000 UTF-8 byte packing budget, lineage, cards and digest.
Markdown body sections are matched across paths as in the prephase reference. Very large individual sections are not split by
the packing budget. New changelog text is included as source scope, so an explicit removal statement can support a proposal.

On recovery the kernel recomputes the map from the saved lineage and genesis bytes, then checks the outcome and roots. The map
and its source bytes cannot change in that run. Resume with `--build-scope versions`; the saved lineage is reused when the flag
is omitted. A supplied changed lineage is refused.

Only dispatcher-issued `CHANGE` leases can create links. The core checks the staged effects, including relation records inside
a batch: both endpoints must rest on evidence inside that card, two different snapshots must support the link, and `supersedes`
runs new to old. Agents cannot grant themselves authority with a directive/origin field. An unmatched section is
`unmatched_by_version_map` metadata, never proof that a fact was deleted; summaries see that uncertainty separately from accepted
replacement. Existing accepted-link warnings remain in use.

Offline checks (set `SBGK_BIN` to an isolated release binary):

```text
cargo test -p sbgk-core --test version_reading
python benchmarks/run_pilot_ac.py --selftest --build-scope versions --executor threads --out <new-directory>
python benchmarks/run_pilot_ac.py --selftest --build-scope versions --executor langgraph --out <new-directory>
python benchmarks/run_pilot_ac.py --selftest --build-scope versions --executor temporal --out <new-directory>
```

These selftests use synthetic sources and the deterministic stub only, including a withdrawal. They do not establish model
answer quality, speedup, or a release scaling result. The `version_map` Rust example exports maps from explicit pinned inputs
without running an engine or a model; its input shape is documented in that example.

## CHANGE refusal and repair

CHANGE admits cross-snapshot relations only. Each endpoint claim uses quotes from one snapshot, the other endpoint from the
other snapshot; `supersedes` goes from NEW to OLD. `based_on` includes grounded Observe support from both snapshots inside the
issued card. Claims that mix OLD and NEW support must be split before proposing a relation.

New version-mode submissions name the committed command rule `version_relations/1`. A refused relation reports its actual
index and local id, endpoint ids, snapshot sides and the failed condition. The store keeps the accepted prefix. The dispatcher
then excludes dependents of the refused line and stores independent suffix lines through its existing item-repair path. Send
only corrected or excluded rows; accepted local ids remain valid. A valid observation or claim need not propose a relation.

Old commands without that rule retain their original whole-command refusal on replay, and exact retries retain their original
receipt. The final staged effect guard still applies to all commands, including trusted raw batches without the new rule. The
WAL framing, root formulas and version map algorithm are unchanged. This repair does not establish semantic truth or live-run
cost/latency improvement.
