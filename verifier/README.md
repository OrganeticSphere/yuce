# An independent verifier of YuCe journals

This folder holds `yuce-verify`, a verifier of YuCe journals in the format `sbgk-session-log/3` (YuCe 0.2): a standalone
implementation in TypeScript, written from the open specification in `spec/` and the journals in `inputs/`. It shares no code and no
dependencies with the kernel: it has no runtime dependencies at all, and TypeScript and esbuild only build it. It checks levels J0
and J1: the file is a well-formed journal, its frames chain, every seal names the right prefix of the journal, and, given a seal or
a head kept elsewhere, the journal matches them.

| Folder | What it holds |
|---|---|
| `yuce-verify/` | the verifier: TypeScript sources, the single built file `dist/yuce-verify.mjs`, the tests |
| `spec/` | the specification it was written from, `SPEC_INDEPENDENT_VERIFIER/4` (version 3 with its amendments 1 and 2) in an English translation of the original, and the control vectors |
| `inputs/` | 14 test journals (valid, corrupt, boundary) and the results expected of them (`expected.json`) |

## Run it

Node.js 24, no install:

```
node yuce-verify/dist/yuce-verify.mjs journal path/to/run.wal
node yuce-verify/dist/yuce-verify.mjs journal path/to/run.wal --expect-seal <hex>
```

In a browser the same file loads as an ES module: see [yuce-verify/README.md](yuce-verify/README.md).

## What it does not establish

Read this before you trust a PASS.

* Without a seal or a head kept out of the writer's reach, J0 and J1 say only that the file is internally consistent. Anyone who can
  recompute the hashes passes them; the tests forge such journals.
* No level checks the meaning of the records.
* It does not recompute the withdrawal cascade or the projections of what stands and what rests on what: those stay the kernel's
  (`sbgk audit-verify`).
* Quotes against their sources (level J3) and signatures, anchors and quittances (J5) are not part of this verifier.
* It reads only the format `sbgk-session-log/3`. A journal of YuCe 0.1 (`sbgk-session-log/2`, releases 0.1.0 to 0.1.7) has no frame
  header, and the verifier stops at its first frame with `OUTER_KEYS`: check such a journal with the kernel, `sbgk audit-verify`.

## How it was checked

* 390 tests (`npm test` in `yuce-verify/`), run against the built file.
* The same journals went through the kernel and through this verifier, and every difference between them was explained. The
  questions raised while it was written were answered from the kernel before release: appendix A of the specification and its
  amendments.
* In a real browser it gave the reports of Node.js, byte for byte (see `yuce-verify/README.md`).
* It passed both journals of the control runs of 0.2 ([BENCHMARKS.md](../BENCHMARKS.md)).

License: Apache-2.0, as the rest of this repository.
