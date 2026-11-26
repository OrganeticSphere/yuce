# An independent verifier of YuCe journals

This folder holds `yuce-verify`, a verifier of YuCe journals in the format `sbgk-session-log/3` (YuCe 0.2): a standalone
implementation in TypeScript, written from the open specification in `spec/` and the journals in `inputs/`. It shares no code and no
dependencies with the kernel: it has no third-party runtime dependencies (Node.js or a browser runs it), and TypeScript and esbuild
only build it. It checks levels J0 to J3:

* **J0, J1** — the file is a well-formed journal, its frames chain, every seal names the right prefix of the journal, and, given a
  seal or a head kept elsewhere, the journal matches them;
* **J2** — the genesis record, the body of every frame with its request hash, and the batches;
* **J3** — given the source documents, every quote the kernel accepted is, byte for byte, in its document, found by the SHA-256 of
  the document's bytes, and the records tree of every frame is the one its header names.

| Folder | What it holds |
|---|---|
| `yuce-verify/` | the verifier: TypeScript sources, the single built file `dist/yuce-verify.mjs`, the tests |
| `spec/` | the specification it was written from, `SPEC_INDEPENDENT_VERIFIER/7` (version 3 with its amendments 1 to 5) in an English translation of the original, and the control vectors |
| `inputs/` | 23 test journals (valid, corrupt, boundary), the source documents of each (`<name>.docs/`) and the results expected of them (`expected.json`) |

## Run it

Node.js 24, no install:

```
node yuce-verify/dist/yuce-verify.mjs journal path/to/run.wal --docs path/to/documents
node yuce-verify/dist/yuce-verify.mjs journal path/to/run.wal --expect-seal <hex>
```

Without `--docs`, levels J0 to J2 are checked and the line says the quotes were not checked against their sources. In a browser the
same file loads as an ES module: see [yuce-verify/README.md](yuce-verify/README.md).

## What it does not establish

Read this before you trust a PASS.

* Without a seal or a head kept out of the writer's reach, the levels say only that the file is internally consistent. Anyone who
  can recompute the hashes passes J0 to J2; the tests forge such journals.
* J3 catches a quote that is not in its source, even when the forger recomputed every hash. It does not catch a quote replaced by
  another phrase that also occurs exactly once in the same document: only an external seal or head shows that.
* No level checks the meaning of the records, and J3 does not repeat the kernel's rules of acceptance (for example, whether a
  basis still stands, or who may judge a link).
* It does not recompute the withdrawal cascade or the projections of what stands and what rests on what: those stay the kernel's
  (`sbgk audit-verify`).
* Signatures, anchors and quittances (J5) are not part of this verifier.
* It reads only the format `sbgk-session-log/3`. A journal of YuCe 0.1 (`sbgk-session-log/2`, releases 0.1.0 to 0.1.7) has no frame
  header, and the verifier stops at its first frame with `OUTER_KEYS`: check such a journal with the kernel, `sbgk audit-verify`.

## How it was checked

* 694 tests (`node --test "verifier/yuce-verify/test/*.test.mjs"` from the repository root, as the CI runs them), against the built
  file.
* The same journals went through the kernel and through this verifier: on every input, accepting or refusing agrees with
  `sbgk audit-verify` (for the journal of YuCe 0.2.3, with the kernel of 0.2.3). The questions raised while it was written were
  answered from the kernel: appendix A of the specification and its amendments.
* The control vectors of delivery 2 were computed by the kernel's own functions and, separately, from the text of amendment 3.
* In a real browser (Chromium 156, `crypto.subtle`) the built file checked a journal of 455 frames and 788 quotes with its documents
  in 0.25 s, and refused it after one byte was changed.

License: Apache-2.0, as the rest of this repository (see [LICENSE](../LICENSE) and [NOTICE](../NOTICE)).
