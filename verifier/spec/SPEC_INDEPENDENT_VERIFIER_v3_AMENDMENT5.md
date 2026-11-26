# Amendment 5 to the specification of the independent journal verifier, version 3: the rules `r2r-audit-rules/4` of release 0.3.0

OrganeticSphere, 26 November 2026. Written from the kernel code of release 0.3.0 (the journal that takes its sources as they come).

**Status: normative.** It applies together with specification version 3 and amendments 1, 2, 3 and 4. Where amendment 5 differs from their text, amendment 5 applies.

**Identifier.** Specification version 3 with amendments 1–5 is called `SPEC_INDEPENDENT_VERIFIER/7`. The verifier report must name exactly this identifier.

**What the amendment does.**
- A genesis record may name the rules `r2r-audit-rules/3` or `r2r-audit-rules/4` (P5-1).
- Under the rules 4 a `question` line may name the record it is about (P5-2).
- It says what the other additions of the rules 4 mean for levels J0–J3: nothing changes (P5-3).
- It adds a journal of the rules 4 to `valid/` (P5-4).

No outcome on a journal of the rules 3 changes: every input of amendments 1–4 has the outcome it had.

---

## P5-1. The rules a genesis record names

The journal format stays `sbgk-session-log/3`, the genesis format `r2r-audit-genesis/3`, the root format `r2r-state-root/2` and the seal format `r2r-seal/2`. Only the rules of acceptance have a new version.

**What changes.** In P3-3, the value of `rules_version` is one of:

| value | written by |
|---|---|
| `"r2r-audit-rules/3"` | the kernel of 0.2, and the kernel of 0.3 for a run started under the rules 3 |
| `"r2r-audit-rules/4"` | the kernel of 0.3 |

J2-3 reads: `format`, `state_root_format` and `seal_format` equal the values of P3-3, and `rules_version` is one of the two values above. Otherwise `GENESIS_FORMAT`. The keys are checked in the order `format`, `rules_version`, `state_root_format`, `seal_format`, as before.

A verifier written from amendments 1–4 alone (`SPEC_INDEPENDENT_VERIFIER/6`) refuses a journal of the rules 4 at J2 with `GENESIS_FORMAT` at frame 0. That is the right answer for it: it does not know the rules the journal names.

## P5-2. The record a question is about

Under the rules 4 a line of the kind `question` may have one more key, `about_record`: a reference to an accepted record.

**What changes, for a journal whose genesis record names `r2r-audit-rules/4`.**
- P3-7, the keys of a `question` line: `kind`, `local_id`, `text`, `about`, `needed`, `about_record`. The key is optional. Its value is a string.
- J3-2: a `question` line with `about_record` that is not a string is `RECORD_FORM`, as any other field of a wrong kind.
- J3-3: `about_record` is resolved as a reference, by the two rules of P3-7 (a local name of the same actor and directive, else `@` and 16 to 64 hex digits that exactly one accepted id starts with), after `based_on`, `from`, `to` and `answer_ids`. A reference that does not resolve is `UNRESOLVED_REFERENCE`.
- P3-7, the body of the record: the value of `about_record` is replaced by `"@"` and the whole id of the record it resolved to, as the references of `based_on` are.
- The value `L` of the record is otherwise as before: `about_record` is in `body` only. It is not among `based_on`, it adds nothing to `grounds`, and `ends` stays `null`. A question rests on nothing, as before.

For a journal that names `r2r-audit-rules/3` nothing changes: a `question` line with the key `about_record` is `RECORD_FORM` (`key "about_record" is not allowed for question`).

## P5-3. What else the rules 4 add, and why J0–J3 do not change for it

The rules 4 change what the kernel accepts in three more places. None of them changes a check of J0–J3, by the boundary P3-9 already draws: J3 repeats what concerns bytes, not the kernel's rules of acceptance.

1. **A claim may rest on a claim.** Under the rules 3 the `based_on` of a claim named observations only; under the rules 4 it names observations and claims. J3-3 already resolves `based_on` to any accepted record, whatever its kind, and `grounds` already carries `evidence` only for a ground that is an observation. Nothing to change.
2. **A context checkpoint.** A command `{"kind":"checkpoint","key":"vsc:checkpoint:<epoch>","from":0,"to":<n>,"context":{…}}` is a frame of its own, with the outcome `value` and the empty records root. It accepts no record, so J3-9 expects the empty records root for it, as for any frame without records. The kernel checks its epoch and what its manifest lists, and refuses such a key as the checkpoint or as an operation of a batch; the verifier does not.
3. **The reason of a withdrawal.** The commands `revoke` and `revoke_text` may carry `reason_source_id`, the name of a document. The verifier does not parse these commands; the request hash of J2-8 covers the whole command, as before.

The projections a seal names (`status`, `dependencies`) are computed by the same rule under both versions of the rules: a record stands while every ground of it stands. They are still not recomputed by J0–J3 (`not_verified`: `withdrawal_cascade`).

## P5-4. A journal of the rules 4 in `valid/`

`valid/stream-context-checkpoints.wal`, written by the kernel of 0.3.0 with `sbgk audit-stream`:

- its genesis record names `r2r-audit-rules/4`, the source mode `opaque` and no document (`source_documents` is `{}`);
- every document comes after the start, by `put_document`: three sources and a notice;
- claims rest on observations and on claims; a relation `supersedes` replaces a claim by plan; a question names a record with `about_record`;
- three context checkpoints, `vsc:checkpoint:1` to `vsc:checkpoint:3`, each a frame of its own;
- a withdrawal by text with its reason; a seal and a close.

Its documents folder holds one file that no document of the genesis record names: the journal starts without a document, and J3 takes every later version from the `put_document` commands.

Tests B2, B5 and B6 include it. In the task statement, section 6, `valid/` now has nine journals.

## P5-5. What to change: summary

1. The identifier in the report — `SPEC_INDEPENDENT_VERIFIER/7`.
2. J2-3: `rules_version` is `r2r-audit-rules/3` or `r2r-audit-rules/4` (P5-1).
3. J3-2, J3-3 and the body of a record: under the rules 4 a `question` line may have `about_record`, resolved as a reference (P5-2).
4. A new input `valid/stream-context-checkpoints.wal` with its documents folder (P5-4).
