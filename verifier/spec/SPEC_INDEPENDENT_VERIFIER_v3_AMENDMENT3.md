# Amendment 3 to the specification of the independent journal verifier, version 3: levels J2 and J3

OrganeticSphere, 19 November 2026. Written from the kernel code, branch `dev`, commit `d5620f83` (version 0.2.2).

**Status: normative for delivery 2.** It applies together with specification version 3, amendments 1 and 2, and the clean-room task statement of delivery 2 (not published). Where amendment 3 differs from their text, amendment 3 applies.

**Identifier.** Specification version 3 with amendments 1, 2 and 3 is called `SPEC_INDEPENDENT_VERIFIER/5`. The verifier report must name exactly this identifier.

**What the amendment does.**
- It closes gaps GAP-03 (the structure of a frame body, `request_hash`), GAP-11 (the structure of a batch), GAP-04 (the value of a record), GAP-05 (the list of accepted records), GAP-06 (the identity of a document), GAP-09 (the rules).
- It gives levels J2 and J3 in full: rules, order, failure codes, report.
- It adds vectors V10–V16 (a new vectors file).
- It describes the changes of release 0.2.3 (section P3-11). That section was **not normative until PR 59–61 were merged**; amendment 4 pins it.

**Boundary.** This text describes what is checked in a journal, not how the kernel decides what to accept. Task hand-out, settings profiles and selection rules are not part of the specification. Everything the verifier takes from a journal it checks only by form and by the formulas of this amendment.

---

## P3-0. Closed gaps

| Gap | What | Where closed |
|---|---|---|
| GAP-03 | structure of a frame body, the formula of `request_hash` | P3-2, P3-3 |
| GAP-11 | structure of a batch | P3-4 |
| GAP-06 | identity of a document | P3-6 |
| GAP-05 | the list of records a frame accepted | P3-7 |
| GAP-04 | the record value `L`, the record id, the anchor of a quote | P3-7, P3-8 |
| GAP-09 | rules: what J3 repeats after the kernel and what it does not | P3-9 |

All norms of this amendment are **[CONFIRMED]**: they were checked against the kernel code, and on every journal of `inputs/valid/` they give the same `records_root` and record ids the kernel wrote (2,867 records, 1,407 quotes).

## P3-1. Notation

Added to section 1 of the specification:

- **`SHA256(x)`** — SHA-256 of the bytes `x`, **without a domain and without a zero byte**. The request hash, the record id, the document version and the anchor id are computed this way. `H(d, …)` with a domain stays for the trees and the frame hashes, as before.
- **`u16le(n)`, `u32le(n)`** — an unsigned integer in 2 or 4 bytes, least significant byte first.
- **Hash** — as before: a string of exactly 64 characters `[0-9a-f]`. Formulas concatenate the raw 32 bytes unless they say "hex".
- **`hex(x)`** — 32 bytes written as 64 lowercase hexadecimal characters.
- **Identifier** — a string that:
  - has 1 to 1024 bytes in UTF-8;
  - has no control characters: U+0000–U+001F and U+007F–U+009F;
  - has at least one character that is not white space. White space here: U+0009–U+000D, U+0020, U+0085, U+00A0, U+1680, U+2000–U+200A, U+2028, U+2029, U+202F, U+205F, U+3000.
- **Empty records root** `E = H("R2R-REC-EMPTY/2")`, hex `fe7c90ca…8c41` (vector `V1_rec_empty`).

## P3-2. A new input: the source documents

```
yuce-verify journal <file> [--docs <folder>] [earlier flags]
```

- **`--docs <folder>`** — the folder with the documents the journal was built on. Without it J3 is not checked (`NOT_CHECKED`).
- The verifier reads **every regular file of the folder and its subfolders**. File names do not matter: a document is identified only by the SHA-256 of its bytes (P3-6).
- Files the journal does not name do no harm. In the report they only count in the number of files read, `input.sources.files`.
- A folder that cannot be read is a read error, exit code 2.
- Documents are untrusted input, as the journal is. Nothing in them is executed.
- **Memory.** For J2 and J3 the verifier keeps in memory the pairs `(actor, submission_id)`, the documents, and the ids and anchors of accepted records. The requirement "one line and O(log n) hashes" stays for J0 and J1.

## P3-3. The frame body (GAP-03)

### Frame 0: the genesis record

The body of frame 0 is the genesis record. It has **exactly 15 keys**:

| key | what | what J2 checks |
|---|---|---|
| `format` | format of the genesis record | `"r2r-audit-genesis/3"` |
| `rules_version` | the kernel's rules | `"r2r-audit-rules/3"` |
| `state_root_format` | format of the state root | `"r2r-state-root/2"` |
| `seal_format` | format of a seal | `"r2r-seal/2"` |
| `run_id` | name of the run | identifier |
| `source_mode` | kind of document descriptions | `"opaque"` or `"git_manifest"` |
| `source_documents` | documents of the run | object: key — `doc_id`, value — description (P3-6) |
| `questions` | questions of the run | array; its content is not checked |
| `operator_meta` | operator's note | `null` or an object whose `JCS` is at most 4096 bytes |
| `settings_hash` | hash of the settings | hash; the value is not checked (P3-11) |
| `manifest_hash` | hash of the corpus manifest | hash; the value is not checked |
| `engine_root` | engine root after the genesis record | hash; the value is not checked |
| `audit_root` | state root after the genesis record | hash; the value is not checked |
| `engine_container_hex` | engine state | a string of an even number of characters `0-9`, `a-f`, `A-F`; the bytes are not parsed |
| `base_ontology` | initial ontology | object; its content is not checked |

The kernel computes `settings_hash` as `H("R2R-SETTINGS/2", JCS(settings))`. A run started without settings has `settings = {}` and `settings_hash = 6b360691…a73e` (vectors `V8_settings_hash_empty`, `V15_*`).

### Frames 1 and on

The body of a frame at position `i ≥ 1` has **exactly 7 keys**:

| key | what | what J2 checks |
|---|---|---|
| `actor` | who submitted the command | identifier |
| `submission_id` | submission id | identifier |
| `command` | the command | any JSON value; the formulas below read from it only what they name |
| `request_hash` | hash of the request | a hash equal to the formula below |
| `outcome` | the outcome | one of three forms |
| `engine_root` | engine root after the frame | hash; the value is not checked |
| `audit_root` | state root after the frame | hash; the value is not checked |

**The formula of `request_hash`:**

```
request_hash = hex( SHA256( JCS( ["r2r-audit-request/1", actor, command] ) ) )
```

Example (vector V10): `actor = "owner"`, `command = {"doc_id":"note.txt","kind":"put_document","text":"Vector text."}`. Preimage:

```
["r2r-audit-request/1","owner",{"doc_id":"note.txt","kind":"put_document","text":"Vector text."}]
```

`request_hash = 2ba189a45a0bd63c5a4cbaa1cfe2cd2a617922a0cedc9dc3f04cd00650ece554`.

The kernel's own frames have a request hash too: a seal (`actor = "kernel"`, `command = {"kind":"seal","seal":P}`) and a close.

**The three forms of an outcome.** The keys are exactly those listed.

| `outcome.kind` | form | when |
|---|---|---|
| `"records"` | `{"kind":"records","result":{"accepted":[…],"error":E,"failed_index":F}}` | only for the command `submit` |
| `"value"` | `{"kind":"value","result":V}` | any command but `submit`, executed |
| `"error"` | `{"kind":"error","error":E}` | the command was refused as a whole; the state did not change |

In an outcome `records`:
- `accepted` — an array of hashes: the ids of the accepted records in the order of acceptance;
- `failed_index` — `null` or a number: the index of the first refused line;
- `error` — `null` or an object.

The lines of a `submit` command are accepted in order up to the first refused one: `accepted[j]` is the id of the record from line `lines[j]`. J2 does not parse the values `V` and `E`, except for a batch (P3-4).

## P3-4. The batch (GAP-11)

A batch is a command of the form `{"kind":"batch","operations":[…],"checkpoint":C}`. The kernel, the graph builder and the dispatcher submit batches. Each operation is a command of the same kind as a frame's command and runs under the same `actor`.

**How the kernel runs a batch.**
- Operations run in order.
- An operation the kernel refused does not change the state, and the following ones are not run.
- An operation `submit` with a refused line keeps the records accepted before it, and the following operations are not run.
- The `checkpoint` mark is written only if every operation passed.
- A batch inside a batch, a seal inside a batch and a close inside a batch are **never run**: the kernel refuses such an operation and writes the refusal into the outcome.

**The outcome of a batch.** If the batch ran, `outcome.kind = "value"`, and

```
outcome.result = {"accepted_operations": K, "checkpointed": true|false,
                  "error": null|E, "failed_index": null|number, "results": [R0, …, R(K-1)]}
```

- `results[k]` is the result of the operation `operations[k]`; there are exactly `K` results.
- For an operation `submit` the result has the form `{"accepted":[…],"error":…,"failed_index":…}`, as the `result` of an outcome `records`.
- For an operation `put_document` the result is `{"document_version": hex}` (P3-6).
- J2 and J3 do not parse the results of other operations.

If the batch was refused as a whole (an unknown key, no `operations` array), `outcome.kind = "error"`, and no operation ran.

An example of a real batch (frame 1 of `baicalin-n3-shard1.wal`): the kernel writes the settings of the run as a mark with no operations.

```
command = {"checkpoint":{"context":{…},"from":0,"key":"audit:mcp:coverage","to":0},"kind":"batch","operations":[]}
outcome = {"kind":"value","result":{"accepted_operations":0,"checkpointed":true,"error":null,"failed_index":null,"results":[]}}
```

## P3-5. Level J2: the genesis record, frame bodies, batches

J2 is checked only if J0 and J1 passed. Frames go in the order of their positions, the rules of one frame in the order of their numbers. The J2 failure is the first one in this order.

### Frame 0

- **J2-1.** `header.records_root` of frame 0 equals the empty root `E`. Otherwise `GENESIS_RECORDS_ROOT`.
- **J2-2.** The body is an object with exactly the 15 keys of P3-3. Otherwise `GENESIS_KEYS`.
- **J2-3.** `format`, `rules_version`, `state_root_format`, `seal_format` equal the values of P3-3. Otherwise `GENESIS_FORMAT`.
- **J2-4.** The other keys have the form of the table in P3-3. Otherwise `GENESIS_FIELD`.
- **J2-5.** Each document description in `source_documents` has the form of P3-6. Otherwise `GENESIS_FIELD`. If the key of a description does not equal the document id of P3-6, the failure is `SOURCE_ID_MISMATCH`.

The frame number of failures J2-1…J2-5 is `0`.

### A frame at position `i ≥ 1`

- **J2-6.** The body is an object with exactly the 7 keys of P3-3. Otherwise `BODY_KEYS`.
- **J2-7.** `actor` and `submission_id` are identifiers; `request_hash`, `engine_root`, `audit_root` are hashes; `outcome` is one of the three forms of P3-3; an outcome `records` stands only on a command object with `kind = "submit"`. Otherwise `BODY_FIELD`.
- **J2-8.** `request_hash` equals the formula of P3-3. Otherwise `REQUEST_HASH_MISMATCH`.
- **J2-9.** The pair `(actor, submission_id)` did not occur in frames `1 … i−1`. Otherwise `DUPLICATE_SUBMISSION`.
- **J2-10. Form of a batch.** If `command` is an object with `kind = "batch"` and `outcome.kind = "value"`, then:
  - the keys of `command` are only among `kind`, `operations`, `checkpoint`;
  - `operations` is an array of at most 256 elements;
  - `outcome.result` is an object; its `results` is an array; `accepted_operations` equals the length of `results`; the length of `results` is at most the length of `operations`;
  - for each `k` below the length of `results`: if `operations[k]` is an object with `kind = "submit"`, then `results[k]` has the form of a `submit` result (P3-4).

  Otherwise `BATCH_FORM`.
- **J2-11. The kernel inside a batch.** In the same case, for each `k` below the length of `results`: `operations[k].kind` is not `"batch"`, `"seal"` or `"close"`. Otherwise `KERNEL_OP_IN_BATCH`.

  A batch where such an operation stands but was refused by the kernel (its index is not below the length of `results`) is allowed: it is a recorded refusal.

**Vector.** The journal `boundary/nested-seal.wal`: in frame 2 a batch of the kernel ran a seal as operation 0. J0–J1 pass it, J2 refuses it: `KERNEL_OP_IN_BATCH`, frame 2. The kernel refuses it too.

## P3-6. Documents and their identity (GAP-06)

### The description of a document in the genesis record

A key in `source_documents` is the document id `doc_id`. The value is the description. Its form depends on `source_mode`, and the `kind` of the description equals `source_mode`.

**`opaque`** — documents given as files:

```
{"doc_id": <the same doc_id>, "kind": "opaque", "raw_sha256": <hash>}
```

**`git_manifest`** — documents pinned by a repository manifest:

```
{"commit": <40 characters [0-9a-f]>, "kind": "git_manifest", "path": <string>, "raw_sha256": <hash>,
 "repo": <string>, "size_bytes": <number>, "revision_refs": {…}, "date": "YYYY-MM-DD" (not always)}
```

The document id of this form is computed:

```
doc_id = "d_" + hex( SHA256( JCS( ["R2R-AUDIT-GIT-DOCUMENT/1", repo, commit, path, raw_sha256] ) ) )
```

Example — vector V16: the preimage `["R2R-AUDIT-GIT-DOCUMENT/1","https://example.invalid/reports.git","0123456789abcdef0123456789abcdef01234567","reports/a.md","783c2630…6480"]`, the id `d_607b2fc0581c7b790a9ea1acd3e26cdfe2c18c8dca0c6709eb99614115016cde`.

The verifier does not parse the keys `date` and `revision_refs`.

### A document is identified by the hash of its bytes

- The document `doc_id` of the genesis record is the file of `--docs` whose bytes have the `SHA-256` equal to the `raw_sha256` of the description.
- If there is no such file, J3 has nothing to check with: outcome `NOT_CHECKABLE`, reason `document <doc_id> not supplied`, verdict `INCOMPLETE`, exit code 3 (P3-10).
- For a description `git_manifest` the number of bytes of the file must equal `size_bytes`. Otherwise failure `SOURCE_IDENTITY`, frame 0.

### A new version of a document during the run

The command `{"kind":"put_document","doc_id":D,"text":T}` puts the document `D` with the bytes `UTF-8(T)`. It stands as a frame of its own or as an operation of a batch. The document is taken only if the command ran:
- a frame — with outcome `value`;
- an operation of a batch — with an index below the length of `results`.

From that point on the **current bytes** of the document `D` are the new ones; the earlier ones are no longer used. In an `opaque` run a new document can appear this way too.

The result of such a command is `{"document_version": hex(v)}`, where `v` is the version of the new bytes by P3-8. J3 checks it (J3-8).

The document version (P3-8) is a computed value. It is needed because it is part of the record value. A document is always identified by the `SHA-256` of its bytes.

## P3-7. The records of a frame (GAP-05, GAP-04)

### The list of the records a frame accepted (GAP-05)

Only the command `submit` accepts records: as a frame of its own or as an operation of a batch. For a frame at position `i ≥ 1` the steps go in order:

1. An outcome `records` (the command is `submit`): one group — `command`, ids `outcome.result.accepted`.
2. A command `batch` with outcome `value`: for `k = 0 … length(results)−1` in order:
   - `operations[k]` with `kind = "submit"` — a group of `operations[k]` and the ids `results[k].accepted`;
   - `operations[k]` with `kind = "put_document"` — a new document version (P3-6);
   - other operations are skipped.
3. A command `put_document` with outcome `value` — a new document version.
4. Any other frame accepts no records. These are seal and close frames, refusals, marks, builder frames without `submit`.

A group is:
- the frame's `actor`;
- the `directive` and `scope` of the `submit` command;
- its lines `lines`;
- the ids `accepted`.

The line `lines[j]` with `j < length(accepted)` gave the record with id `accepted[j]`.

The records of a frame are all records of its groups in the order of the steps. Their positions in the whole journal follow each other, from the first record of the run.

### A record line

A line is an object with a key `kind` of one of six kinds. The keys of a line are only among those allowed for its kind:

| `kind` | allowed keys |
|---|---|
| `observe` | `kind`, `local_id`, `doc_id`, `exact_quote`, `terms` |
| `claim` | `kind`, `local_id`, `text`, `subject`, `predicate`, `object`, `stance`, `as_of`, `based_on` |
| `relation` | `kind`, `local_id`, `from`, `rel`, `to`, `based_on` |
| `hypothesis` | `kind`, `local_id`, `text`, `falsifier`, `subject`, `stance`, `based_on` |
| `question` | `kind`, `local_id`, `text`, `about`, `needed` |
| `done` | `kind`, `local_id`, `rq_id`, `directive_id`, `answer_ids`, `outcome`, `text` |

`local_id` is a string: the local name of the record for its author in its task.

### The record value `L` (GAP-04)

Each accepted record gives a leaf of the records tree of its frame: `leaf = H("R2R-REC-LEAF/2", JCS(L))`. `L` is an object:

| key | value |
|---|---|
| `id` | record id, hex (below) |
| `seq` | position of the record among all accepted records of the run, counting from 1 |
| `kind` | kind of the line |
| `author` | the frame's `actor` |
| `directive` | the group's `directive` |
| `doc_id` | for `observe` — the line's `doc_id`; otherwise `null` |
| `quote` | for `observe` — the line's `exact_quote`; otherwise `null` |
| `terms` | the record's terms (below) |
| `text` | for `claim`, `hypothesis`, `question` — the line's `text`; for `done` — `text` if present, otherwise `null`; for `observe`, `relation` — `null` |
| `stance` | for `claim` — `stance`; for `hypothesis` — `stance` if present, otherwise `null`; otherwise `null` |
| `based_on` | ids of the grounds, hex, in order (below); `[]` for a record without grounds |
| `ends` | for `relation` — `[hex(from), rel, hex(to)]`; otherwise `null` |
| `body` | the record body (below) |
| `evidence` | **only for `observe`**: `{"id": hex, "span": [start, end], "version": hex}` — the anchor of the quote (P3-8) |
| `grounds` | **only if `based_on` is not empty**: one object per ground, in the order of `based_on` |

An object of `grounds`:
- `{"evidence": <the ground's anchor>, "id": hex}` if the ground is an `observe` record;
- `{"id": hex}` otherwise.

The anchor of a ground is the same `evidence` object as in the ground's own `L`: it does not change after the record is accepted.

**Terms.** Their order is the order of appearance; repeats are removed (the first occurrence stays):
- `observe`: the array `terms`; empty if the key is absent;
- `claim`: `subject`, then `object` if present (`predicate` does not count);
- `hypothesis`: `subject` if present;
- `question`: the array `about`;
- `relation`, `done`: empty.

**References and grounds.** A reference `name` is resolved in order:
1. If a record of the same `actor` and the same `directive` with `local_id = name` was accepted earlier, it is that record. Records of earlier frames and of earlier lines of the same group count.
2. Otherwise `name` must have the form `@` followed by 16 to 64 hexadecimal characters in any case. After lowering their case, exactly one id among all records of the run accepted earlier must start with these characters.
3. Otherwise the reference is not resolved: failure `UNRESOLVED_REFERENCE`.

The grounds `based_on` of a record:
- `claim`, `relation`, `hypothesis`: the resolved references of the line's array `based_on`, in order;
- `done`: the resolved references of the array `answer_ids`;
- `observe`, `question`: no grounds.

Order of resolving references: `based_on`, then `from`, then `to`, then `answer_ids`.

**The body `body`.** It is the line without the key `local_id`, with these replacements:
- if the line has a non-empty `based_on` — `body.based_on = ["@" + hex(ground), …]`;
- for `relation` — `body.from = "@" + hex(from)`, `body.to = "@" + hex(to)`;
- for `done` — `body.answer_ids = ["@" + hex(…), …]`;
- for `observe` the keys `body.evidence_id` and `body.document_version` are added — the same values as `evidence.id` and `evidence.version`.

The other keys of the line stay as they were, with no check of their values. This includes repeats in `terms`: in `body.terms` they stay, in `L.terms` they are removed.

**The record id:**

```
ordinal = 1 + the number of records accepted earlier with the same (actor, directive)
id      = hex( SHA256( JCS( ["r2r.audit.record.v1", actor, directive, ordinal, body] ) ) )
```

Example — vector V13: `actor = "worker"`, `directive = "task"`, `ordinal = 2`. Preimage:

```
["r2r.audit.record.v1","worker","task",2,{"based_on":["@fb510d9e…1d64"],"kind":"claim","stance":"reported","subject":"component","text":"It is reported."}]
```

`id = f7333f9726d62a191a5f065b13a461e6e8b7df3609b3de119afd3a59b65e096f`.

The record id computed this way must equal the id of the outcome (J3-7).

**Examples of `L`** — vector V14: thirteen records of all six kinds from the journal `kinds-batch-put.wal`, as the kernel writes them, with the leaves and the roots of the frames. An observation from V14 (frame 1, position 0):

```
{"author":"w1","based_on":[],"body":{"doc_id":"vector-a.txt","document_version":"826a3898…9820","evidence_id":"f9f375e9…80f3",
 "exact_quote":" 009: the vector document states fact number ","kind":"observe","terms":["fact","corpus","fact"]},
 "directive":"T1","doc_id":"vector-a.txt","ends":null,"evidence":{"id":"f9f375e9…80f3","span":[688,733],"version":"826a3898…9820"},
 "id":"479c73e5…b7e","kind":"observe","quote":" 009: the vector document states fact number ","seq":1,"stance":null,
 "terms":["fact","corpus"],"text":null}
```

Only the hashes are shortened here; the full values are in V14.

### The records tree of a frame

The leaves of a frame are the leaves of its records in the order of acceptance. The root is computed as in section 7 of the specification (vectors V1, V2):
- a frame without records — the empty root `E`;
- one record — its leaf;
- more — `H("R2R-REC-NODE/2", left, right)` with a left subtree of the largest power of two strictly below the number of leaves.

The root must equal the frame's `header.records_root` (J3-9).

## P3-8. The anchor of a quote and the document version

### Where the quote is in the document

For an `observe` line the current bytes of the document `doc_id` are taken (P3-6). `q = UTF-8(exact_quote)`.

- **Occurrences** of `q` are counted at every start position, overlapping ones included: `aa` occurs twice in `aaa`. An empty `q` occurs nowhere.
- There must be **exactly one** occurrence. Its start is `start`, its end `end = start + length(q)`. Counted in bytes, the end excluded.
- **The task's scope.** `doc_id` must be in the array `scope.docs` of the group. If the array `scope.ranges` is not empty, at least one of its elements `[d, a, z]` must give: `d = doc_id`, `a ≤ start`, `end ≤ z`, `a < z`, `z ≤ length of the document`.

### The document version

The version depends only on the bytes of the document. The bytes are cut into chunks by their content, and the version is the hash of the list of the chunk hashes.

**1. The table GEAR** — 256 numbers of 64 bits. Arithmetic is modulo 2^64, `>>` is an unsigned right shift.

```
st = 0x5342474B43444301
for i = 0 … 255:
    st = st + 0x9E3779B97F4A7C15
    z  = st
    z  = (z XOR (z >> 30)) × 0xBF58476D1CE4E5B9
    z  = (z XOR (z >> 27)) × 0x94D049BB133111EB
    GEAR[i] = z XOR (z >> 31)
```

Vector `V11_gear_*`: `GEAR[0] = 7ce8bb23b8f1bd32`, `GEAR[1] = 6c15dd941e896853`, `GEAR[2] = 676c0c68b5d87f66`, `GEAR[255] = 96eb1800e4698ba7`.

**2. The score of a byte.** For a document of `n` bytes `b[0] … b[n−1]`:

```
fp = 0
for p = 0 … n−1:
    fp = (2 × fp + GEAR[b[p]]) mod 2^64
    score[p] = fp
```

**3. Boundaries.** `w = 512`. The window of position `c` is the positions from `max(0, c−w)` to `min(n−1, c+w)` inclusive. Position `c` is a boundary if:
- `score[c] > score[j]` for each position `j < c` of the window;
- `score[c] ≥ score[j]` for each position `j > c` of the window.

With equal scores the earlier position wins. Each boundary `c` gives a cut after byte `c`, that is at point `c+1`.

The cut points go in increasing order. If the last of them is not `n`, `n` is added.

Checking "by the definition" costs `O(n·w)`: for a document of 16 MiB that is slow. A sliding window with a queue of candidates gives the same result in `O(n)`. A position enters the queue after pushing out from its end every position it beats. The head of the queue is the best position of the window.

**4. Chunks.** From `start = 0` over the cut points `t` in order:
- while `t − start > 2048`: chunk `[start, start+2048)`, `start = start + 2048`;
- if `t > start`: chunk `[start, t)`, `start = t`.

The chunks cover the document one after another, without gaps. An empty document has no chunks.

**5. The version:**

```
chunk_hash = SHA256(bytes of the chunk)
version    = SHA256( ASCII("SBGK-DOCVER-v1") ‖ chunk_hash_1 ‖ chunk_hash_2 ‖ … )
```

There is no zero byte after the string. Vectors V11 give three whole documents: plain text of 11 chunks; a long run of one byte value, where chunks are cut at the limit 2048; text that is not ASCII. For each, the chunks, their hashes and the version are given. The version of an empty document is given too, and that of short documents (amendment 4, P4-1).

### The anchor id

The segments of a quote are the chunks that intersect `[start, end)`, in document order. For a chunk `[cs, ce)` with hash `h`:

```
segment = (h, max(start, cs) − cs, min(end, ce) − cs)
```

The anchor bytes:

```
0x01
‖ u16le(length of doc_id in UTF-8) ‖ doc_id in UTF-8
‖ SHA256(q)
‖ u32le(length of q)
‖ one byte: the number of segments
‖ for each segment: h (32 bytes) ‖ u32le(start) ‖ u32le(end)

evidence.id = hex( SHA256(anchor bytes) )
evidence.version = hex(version)
evidence.span = [start, end]
```

Vector V12: a quote within one chunk and a quote across a chunk boundary (two segments), with the whole anchor bytes.

## P3-9. Rules (GAP-09)

The genesis record names the rules `r2r-audit-rules/3` (J2-3). Of them J3 repeats what concerns bytes:
1. the quote of an observation occurs in the current version of its document **exactly once**;
2. its document is in the task's scope, and the quote lies inside an issued range if ranges were issued;
3. the id, the leaf and the root of the records of a frame are as in P3-7.

**What J3 does not repeat.** A journal that breaks only these rules passes J3, and the kernel refuses it (section P3-12, difference 6):
- the quote does not touch withdrawn text, and its anchor was not revoked earlier;
- the grounds of `claim`, `relation` and `hypothesis` are standing observations;
- a record refers only to records issued to it or visible in its scope;
- an answer `done` rests on established records of its task;
- a `relation` is declared in the ontology, and the decision on it follows the link rules (including "four eyes", P3-11);
- limits of strings and values: lengths, the allowed values of `stance` and `rel`, the date `as_of`;
- commands of the ontology, concepts, mappings and marks.

**J3 does not recompute the withdrawal cascade,** as before.

## P3-10. Level J3: rules, order, report

J3 is checked only if `--docs` was given and J0, J1, J2 passed.

### Rules

**J3-0. Documents.** The documents of the genesis record are taken one by one, in the order of their keys by JCS. For each:
- a file is found by `raw_sha256`; with no file — `NOT_CHECKABLE` (P3-6), the reason names this `doc_id`, and J3 goes no further;
- for a description `git_manifest` the number of bytes of the file equals `size_bytes`; otherwise `SOURCE_IDENTITY`, frame 0.

Then frames `i ≥ 1` in order, the steps of a frame by P3-7. For each group:

- **J3-1.** The group's `directive` is a string. `scope` is an object with an array of strings `docs` and an array `ranges`, each element of which is `[string, number, number]`. `lines` is an array, and there are no more ids `accepted` than lines. Otherwise `RECORD_FORM`.

For each line `lines[j]`, `j < length(accepted)`, in order:

- **J3-2.** The line is an object; `kind` is one of the six kinds; all keys are among those allowed for the kind; `local_id` is a string. The values from which `L` is built are of the right type:
  - strings: `doc_id`, `exact_quote`, `text`, `subject`, `object`, `stance`, `from`, `rel`, `to`;
  - arrays of strings: `terms`, `based_on`, `about`, `answer_ids`.

  Required:
  - for `observe` — `doc_id`, `exact_quote`;
  - for `claim` — `text`, `subject`, `stance`, `based_on`;
  - for `relation` — `from`, `rel`, `to`, `based_on`;
  - for `hypothesis` — `text`, `based_on`;
  - for `question` — `text`, `about`;
  - for `done` — `answer_ids`.

  Otherwise `RECORD_FORM`.
- **J3-3.** All references are resolved (P3-7). Otherwise `UNRESOLVED_REFERENCE`.
- **J3-4.** For `observe`: the document `doc_id` is among the current documents. Otherwise `UNKNOWN_DOCUMENT`.
- **J3-5.** For `observe`: no occurrence of the quote — `QUOTE_NOT_IN_SOURCE`; more than one — `QUOTE_AMBIGUOUS`.
- **J3-6.** For `observe`: the quote is within the task's scope (P3-8). Otherwise `QUOTE_OUTSIDE_SCOPE`.
- **J3-7.** The record id by P3-7 equals `accepted[j]`. Otherwise `RECORD_ID_MISMATCH`.

Then the verifier has accepted the record: its id, anchor and local name are kept for the following lines and frames.

- **J3-8.** For a step "new document version": the command's `doc_id` and `text` are strings, the result is an object, and the version of the new bytes equals its `document_version`. Otherwise `DOCUMENT_VERSION_MISMATCH`.
- **J3-9.** After all steps of a frame the root of its records equals `header.records_root`. For a frame without records it is `E`. Otherwise `RECORDS_ROOT_MISMATCH`.

The frame number of a failure is the position of the frame where the rule was broken.

**The main case.** A forger changes a quote and recomputes everything it knows: `request_hash`, the records root of the frame, the frame hashes and the seals. J0, J1 and J2 pass such a journal, and J3 refuses it: `QUOTE_NOT_IN_SOURCE` at the frame with the changed quote. Input: `corrupt/forger-full-rehash.wal`.

**What no level catches.** A quote replaced by another phrase that also occurs exactly once in the same document, with everything recomputed. Only an external seal or head shows such a change (section 6.5 of the specification).

### Report

Section 8 of the specification changes.

**`verifier.spec`** — `"SPEC_INDEPENDENT_VERIFIER/5"`.

**`input.sources`** — `{"given": false}` without `--docs`; `{"given": true, "files": N}` with it, where `N` is the number of files read.

**`levels.J2`:**
- passed — `{"result":"PASS","documents":D,"settings_hash":"…"}`: `D` is the number of documents of the genesis record;
- failed — `{"result":"FAIL"}`;
- not checked because of an earlier failure — `{"result":"NOT_CHECKABLE","reason":"J0 failed"}` or `"J1 failed"`.

**`levels.J3`:**
- passed — `{"result":"PASS","records":R,"quotes":Q}`: `R` is the number of records the journal accepted, `Q` the number of quotes checked;
- failed — `{"result":"FAIL"}`;
- `--docs` not given — `{"result":"NOT_CHECKED"}`;
- given, but a level before it failed — `{"result":"NOT_CHECKABLE","reason":"J0 failed"}` (or `"J1 failed"`, `"J2 failed"`);
- a document missing — `{"result":"NOT_CHECKABLE","reason":"document <doc_id> not supplied"}`.

**`not_verified`:**
- if J3 passed — `["withdrawal_cascade","signatures"]`;
- otherwise — `["quotes_against_sources","withdrawal_cascade","signatures"]`, as before.

**`verdict`:**
- `FAIL` if there is at least one `FAIL`;
- otherwise `INCOMPLETE` if J3 is `NOT_CHECKABLE` because of a document;
- otherwise `PASS`.

**Exit codes:** 0 — `PASS`; 1 — `FAIL`; 2 — call error, or error reading the file or the folder; 3 — `INCOMPLETE`.

**`first_failure.frame`** for failures of J2 and J3 is always a frame number, never `null`.

**The line for a human.** Part 1 on success:
- J3 checked: `J0-J3 PASS. Frames: <N>. Seals: <M>. Records: <R>. Quotes: <Q>.`
- J3 not asked for: `J0-J2 PASS. Frames: <N>. Seals: <M>.`
- a document missing: `J0-J2 PASS. Frames: <N>. Seals: <M>. J3 not checkable: document <doc_id> not supplied.`

Parts 2 and 3 — unchanged. Part 4:
- if J3 passed — `Not verified: withdrawal cascade, signatures.`
- otherwise — `Not verified: quotes against sources, withdrawal cascade, signatures.`

On a failure — as before: `FAIL at <level>, frame <i>: <code>.` and part 4.

### Order of the levels

Section 9 of the specification reads:
1. If J0 failed anywhere in the file — the first J0 failure.
2. Otherwise, if J1 failed — the first J1 failure (`ANCHOR_NOT_FOUND` last).
3. Otherwise, if J2 failed — the first J2 failure.
4. Otherwise, if J3 was asked for and failed — the first J3 failure.

A level after a failed one is not checked: `NOT_CHECKABLE` with the reason `"<level> failed"`. The exception is J3 without `--docs`: it is `NOT_CHECKED`. An implementation may run the levels in one pass if the reported failure is the same.

### Failure codes

- **J2:** `GENESIS_RECORDS_ROOT`, `GENESIS_KEYS`, `GENESIS_FORMAT`, `GENESIS_FIELD`, `SOURCE_ID_MISMATCH`, `BODY_KEYS`, `BODY_FIELD`, `REQUEST_HASH_MISMATCH`, `DUPLICATE_SUBMISSION`, `BATCH_FORM`, `KERNEL_OP_IN_BATCH`.
- **J3:** `SOURCE_IDENTITY`, `RECORD_FORM`, `UNRESOLVED_REFERENCE`, `UNKNOWN_DOCUMENT`, `QUOTE_NOT_IN_SOURCE`, `QUOTE_AMBIGUOUS`, `QUOTE_OUTSIDE_SCOPE`, `RECORD_ID_MISMATCH`, `DOCUMENT_VERSION_MISMATCH`, `RECORDS_ROOT_MISMATCH`.

## P3-11. Changes of 0.2.3 — to be pinned after the merge

**Not normative until PR 59, 60 and 61 are merged into `dev`.** Amendment 4 pins this section against the merged code (P4-7). The text below is as written on 19 November, before the merge.

**The journal format, the replay rules and levels J0–J3 do not change.** All three PRs say so; with them the kernel gives byte for byte the same `audit-verify` output on the earlier journals (PR 61, checked on 24 journals). What changes is the content of the settings mark and of one command.

### The settings of a run (PR 60)

The server `sbgk audit-serve` writes the settings of a run twice:
- as a hash, `settings_hash`, in the genesis record;
- readably — as the first mark: a batch of the kernel with no operations and `checkpoint = {"key":"audit:mcp:coverage","from":0,"to":0,"context":S}`, `submission_id = "audit-mcp-coverage-config"`.

For runs of the server `settings_hash = H("R2R-SETTINGS/2", JCS(S))`. It is so on four journals of the server in `valid/`: `baicalin-n3-shard1`, `live-server-unsealed-tail`, `gap-primary-exhausted`, `gap-second-exhausted`. A journal rewritten by the library (`k017-oracle-v3.wal`) names the empty settings in its genesis record, and its mark names others. So **the equality is not a rule of the kernel**, and J2 does not require it.

New keys of `S` from 0.2.3:
- **`unit_is_task`** — `true` or `false`, now always. Before 0.2.3 the key was there only when `true`; its absence reads as `false`.
- **`auto_reread_limit`** — a number, the limit of rereads after losses; 20 by default. Before 0.2.3 there is no key: any limit goes.
- **`corpus_description`** — a string of at most 200 bytes on one line: the words the directives name the documents by. Written only if given.
- **`four_eyes`** — `true` for every new run (PR 61).

**The historical form.** A journal before 0.2.3 has none of these keys. On resume the 0.2.3 server keeps its settings in the earlier form, without the new keys. So neither the mark nor `settings_hash` of an old journal changes, including a run cut off between its genesis record and the mark.

**A proposal for the verifier after the merge** (not part of delivery 2). Add a field `settings` to the object `J2`:
- `pinned` — `settings_hash` is not the hash of the empty settings;
- `checkpoint` — whether there is a mark `audit:mcp:coverage`, and whether the hash of its `context` equals `settings_hash`: `"matches"`, `"differs"` or `"none"`;
- the values `four_eyes`, `unit_is_task`, `auto_reread_limit` from the mark.

It would not be a failure.

### Four eyes and the owner's arbitration (PR 61)

- In a run whose settings mark names `four_eyes: true`, the kernel refuses a `set_link_status` that accepts or rejects a link if the `actor` wrote one of its ends. The refusal is written into the frame's outcome.
- The owner decides such a link with a command carrying the key `"arbitration": true`. The key is allowed only in such a run and only with the value `true`. The decision is recorded with the mark `arbitration: true` in the state; in the journal the mark stands in the frame's command and is covered by `request_hash`.
- The owner's tool `audit_link_status` sets the mark. The kernel does not know roles. The mark records the owner's decision as the server identified the caller; it is not the owner's signature.
- A settings mark that drops `four_eyes` from a run where it was set is refused.

**What it means for the verifier.** `set_link_status` accepts no records: J3 does not change. For J2 the key `arbitration` is part of an opaque command. The "four eyes" rule is a rule of meaning (P3-9): J3 does not repeat it.

After the merge a summary in the report could be proposed: the number of frames `set_link_status` with `arbitration: true` and outcome `value`. Not part of delivery 2.

### Coverage (PR 59)

- The coverage table gets the state `reading_given_up`: the reading of a section was given up and nothing was recorded.
- The report of the gap pass, which the server writes into the final record with `--unattested-at-end`, gets the count `units_reading_given_up`.
- The index becomes `yuce-index/3`.

The journal format and the rules do not change: for J0–J3 it is an opaque value of a result. A "completeness" level is not part of this delivery; its name is still being decided.

## P3-12. Known differences with the kernel: addition to section 10

Items 1–4 of section 10 stay. Item 5 was removed by amendment 1. Item 2 narrows: J2 now checks the rules of a batch. Added:

6. **Rules of record acceptance that J3 does not repeat** (P3-9). A journal with true quote bytes that breaks only them passes the verifier, and the kernel refuses it.
7. **The verifier is stricter than the kernel about values the kernel always writes one way.** In a `git_manifest` description the kernel accepts `raw_sha256` and `commit` in capitals; the verifier does not. The kernel writes no such descriptions.
8. **Documents.** The kernel takes the bytes of the documents from the `engine_container_hex` of the genesis record, the verifier from `--docs`. Without `--docs` J3 is not checked. If a document is missing, the verdict is `INCOMPLETE`, not `FAIL`.
9. **Chunking.** The kernel takes the chunking parameters from the container of the genesis record. Kernel 0.2.x always writes the same ones (`w = 512`, limit 2048). The kernel writes no container with other parameters; on such a journal versions and anchors would differ.
10. **Values the kernel checks by replay and the verifier does not:** `engine_root`, `audit_root`, `manifest_hash`, `settings_hash`, the content of `engine_container_hex` and of `base_ontology`.

The table of section 4 of the specification reads:

| What happened | Where caught |
|---|---|
| a missing or extra key of the genesis record, other formats and rules | J2 |
| a frame body changed without recomputing `request_hash` (the forger of delivery 1) | J2 |
| a seal or a close run inside a batch | J2 |
| a record of a frame changed or hidden, the records root not recomputed | J3 |
| the kernel accepted a quote whose bytes are not in the source, even with every hash recomputed | J3 |
| a quote replaced by another phrase of the same document, everything recomputed | only an external seal or head |
| the withdrawal cascade computed wrongly | no level of the verifier |

## P3-13. Vectors V10–V16

The file `VECTORS_INDEPENDENT_VERIFIER_20261119.json` replaced `VECTORS_INDEPENDENT_VERIFIER_20261110.json`; amendment 4 replaced it in turn with `VECTORS_INDEPENDENT_VERIFIER_20261119_v2.json` (P4-9). V1–V9 are the same, unchanged, and V10–V16 are new.

| Vector | What it checks | Needed in delivery 2 |
|---|---|---|
| `V10_*` | `request_hash` | yes |
| `V11_*` | the table GEAR, chunks and versions of three documents, the version of an empty document and of short documents | yes |
| `V12_*` | anchor bytes and id: a quote within one chunk and across a boundary | yes |
| `V13_*` | the record id | yes |
| `V14_*` | `L`, the leaf and the root of every frame of the journal `valid/kinds-batch-put.wal`: all six record kinds, references by name and by `@`, scope ranges, a batch with `submit` and a new document version, a refused line | yes |
| `V15_*` | `settings_hash` | desirable |
| `V16_*` | the id of a `git_manifest` document | yes |

**How they were computed.**
- Every value of V10–V16 was given by a function of the kernel itself, in a test module of a working copy of `dev` `d5620f83`, not committed to the repository.
- The functions: the request hash — `request_hash` of `state.rs`; the table GEAR and the chunks — `cdc.rs`; the version — `Arena::put_document`; the anchor — `Arena::anchor_for_span` and `Arena::evidence_node`; the record id — `records::record_id`; the settings hash — `state::settings_hash`; the document id — `sources::prepare` and `sources::verify_identity`.
- V14 is a run the kernel wrote itself: `create_from_docs_with`, `submit_records_id`, `submit_operations_id`, `withdraw_text`, `seal`, `close_run`. The values of `L` were taken while the kernel checked the journal (`verify_scan`, `record_leaf_value_at`, `trees::record_leaf`).
- A separate script, written only from the text of this amendment, computed every value of V10–V16 again and got the same. It also passed J2 and J3 on every journal of `inputs/valid/` with its documents. Neither the script nor the test module was given to the clean room.

**What the command `vectors` checks.** V10–V16 — the same way as V1–V9, naming the skipped ones:
- V11 — the chunks and the version from the `text` of each document;
- V12 — the anchor bytes and id from the document `vector-a.txt` of V11 and the range `span`;
- V14 — the leaf of each record from its `L_jcs` and the root of each frame from these leaves.

That these `L` are built from the journal is checked by the command `journal` on `valid/kinds-batch-put.wal` with its documents: the roots of the journal's frames equal `V14_records_roots`.
