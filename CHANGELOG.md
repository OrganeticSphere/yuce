# Changelog

## Unreleased

* **`audit_seal`: the owner seals the journal when he asks,** for example before a withdrawal, between the seals the server writes by
  itself, so that a quittance can show what stood at that point after it fell. A server with a signing key signs it; a seal right
  after another is not written again (`ALREADY_SEALED`). It is the seal the kernel already writes, a frame replay accepts at any point:
  no rule changes. The Python client has `seal()`. In 0.2.0 no seal fell between an answer and a withdrawal made right after it.
* **The library writes no seal right after another,** as its documentation said: `State::seal` answers `already` with the seal
  that is the last frame, and closing a run right after a seal writes the close only. In 0.2.0 a run closed right after a seal
  of the server could get a second seal of the same frames; none of the four runs of release 0.2.0 has one. Replay takes a seal at
  any frame, as before.
* **`verifier/`: the specification names the vectors file as published,** 12,779 bytes, and a test checks its size and SHA-256.
  The numbers were those of the file before its two notes were put into English; every vector is the same. The README says that a
  journal of 0.1 is checked by the kernel, not by `yuce-verify`.
* **`scripts/verify_published_runs.py` checks the runs of 0.2 too.** A journal of 0.2 goes on past its last receipt, as the
  server seals and closes the run after the last stage: it is checked against each receipt as a prefix, and then whole. The
  four kernel runs of release v0.2.0 are in its list.
* **`audit-proof` and `audit-sign` never write over what they read.** `audit-proof` refuses an output path that is its journal,
  the checkpoint of its seal or the verifier key beside it, in any spelling of the path; `audit-sign` refuses a checkpoint or
  verifier key path that is its journal or its signing key, before it writes anything. Both write a new file and rename it into
  place, so an output named by a second name of an input, a hard link, takes that name and leaves the input as it was. In 0.2.0
  a quittance written to the journal's path destroyed the run.
* **An answer lists each of its records once.** After a repair in several attempts, the done line of the last attempt could name
  records that the same task had stored in its earlier attempts, by their local names, while the kernel added the same records
  again by their short ids as rows the answer keeps: the answer, the done record and its grounds listed them twice (control
  run 1 of 0.2: 11 of 54 records), and the report of what fell counted the standing grounds of such an answer too high. The
  kernel now keeps each record once, in the order first named, in the done record it stores, in the answer, in a summary's
  coverage prefix and in the lists it writes after recovering an answer. It reads each name of the done line as the store reads
  it, a local name of the task first, and refuses a name the answer may not cite before the done record is stored. A row the
  kernel keeps goes into the answer under a prefix of its id that no local name takes, and a done line that would leave such a
  row out is refused before it is stored. Journals already written replay as they are.
* **`verifier/`: `yuce-verify`, an independent verifier of 0.2 journals,** written in a clean room from the specification of the
  format and no line of the kernel's code. It checks levels J0 and J1 under Node.js and in a browser; the folder holds the
  specification in English, its control vectors and its test journals. The verifier passed both control runs of 0.2.
* **The journal of a running server is read by other processes, on Windows too.** The server locked the whole file, and on Windows
  that lock stops every read through another handle: `audit-verify`, `audit-read`, `audit-index` and `audit-proof` failed beside a
  live server (os error 33). On Windows the server now holds its journal by opening it shared for reading only and takes no lock;
  elsewhere the advisory lock stays. One writer still, on every system: a second server is refused, and so is a server of 0.2.0 or
  earlier beside one of this version, in either order. A reading command reads up to the last complete entry of that moment and
  says so (`live`, with `frames_read`): an entry in flight is no torn tail, while the end of a stopped journal that is no complete
  entry is `TORN_TAIL` as before. Beside a server of 0.2.0 or earlier, whose lock still stops reading on Windows, a reading command
  says so in words (exit 2). `audit-index` and `audit-proof` take all they use from one read of the journal. The format of the
  journal, the rules of the kernel and the replay are unchanged.

## 0.2.0 (2026-11-12)

A journal of sealed frames, signed checkpoints, quittances for one record, a report of what fell after a withdrawal, an index beside
the journal and a gap pass. Both control runs of this tree were graded blind before the tag (`BENCHMARKS.md`).

A new run writes the 0.2 journal; `audit-verify` checks journals of both formats, and the published journals of 0.1 verify as before.
The server no longer resumes a 0.1 journal: finish it with a 0.1 release.

* **Frames of `sbgk-session-log/3`.** A frame is a header and a body: the header names the body by its hash and the records the frame
  accepted by the root of their tree, and the frame hash covers the header. One record with all its grounds is one leaf of that tree.
* **The state root `r2r-state-root/2` grows with what changed, not with the run.** Every value of the state is a leaf in one of
  thirteen named sections, each spread over 256 buckets; a command rehashes the leaves it changed, their buckets and their sections.
  Whether a record still stands is not a leaf: it is the status projection's. The withdrawn text is, by its hash.
* **The genesis names its rules and the run:** the version of the rules, the formats of the root and of the seal, the questions of the
  run, the hash of its settings, and an object of the operator's (at most 4 KB) that the kernel never reads. A field it does not
  know is refused. A resumed run takes its questions from the genesis and must have the same settings.
* **`audit_close` is an entry of the journal:** a server started on a closed run's journal finds it closed.
* **Seals.** The server writes a seal every 256 frames, at each phase of a circle and before it closes the run: the number of frames
  before it, their RFC 6962 tree, the roots of the state and the hashes of the status and dependency projections. Signatures come
  later, without a change of this format. A seal and a close are frames of their own, never operations of a batch; the ids `seal-<n>`
  and `audit-close` of the kernel are theirs alone. A seal that fails does not undo the command it follows: the next command writes
  it, after a restart too.
* **The status projection names the direct grounds that fell:** a done that rests on a claim on a withdrawn quote names the claim;
  the first cause is found by following the chain down to the withdrawn quote.
* **A repair after a withdrawal shows the live support of what fell first.** The window of an `INCREMENTAL REPAIR` was chosen by the
  question alone, and the standing quotes of another page that still carried a fallen conclusion could all be left out of it: in a
  control run of this candidate the repair then dropped a conclusion that still stood. Now the standing claims most like what the
  fallen answer rows lost, by words (a row's text and the quotes of it that are gone; the retrieval of `LATER ON THE SAME WORDS`),
  take up to 12 places of that window, at most 4 per fallen row, each with all it rests on and none on withdrawn text. A claim on
  nothing but the quotes still standing under a fallen row takes no place: the task names those quotes with the row. The rest of
  the window is chosen by the question as before, in the same budget. The task names these claims (`LIVE SUPPORT`) and may rest
  what fell on their quotes, a row with no quote left included. Repair tasks change; the window an answer was given stays in its
  frame (`allowed_records`), so recorded journals replay as before.
* **The gap pass (`--gap-pass <packs>`, `--gap-units 4..8`, `--gap-profile <file>`), off by default.** After the first readings, the
  units of the read sections (a list item, a paragraph, a table row) that no standing quote covers go out in packs as narrow tasks
  (`TG`): record what a unit states with an exact quote, or answer empty. The section heading and a nested item's parent are shown
  as context that cannot be quoted. Tiers from the profile set the order; a tier closes after three empty packs in a row. A second
  reader, never the first, checks the units a pack of a named tier left unquoted. The reading is not done while the pass runs,
  the coverage report says what each read unit came to, and the settings are pinned with the run.
* **A section cut from the middle of a document comes with its context:** the first reading's task shows the nearest heading above
  the section and the header row of the table it begins inside (a line of three or more ` | ` cells in plain text), marked as never
  to be quoted. The gap pass shows the same. Reading tasks change, so new runs differ from the published ones.
* **A `#` line or a table row inside a fenced code block is code:** it starts no section of the first reading and is shown as no
  heading or table header. The sections of a Markdown document with such blocks change.
* **Reading tools over the two projections,** live for the owner and over a recorded journal with `sbgk audit-read <tool> --wal`,
  which checks the journal first as `audit-verify` does and answers as the live server does for the same state:
  * `status` (the `projections` block of `audit_status`): records by kind, standing, fallen (a ground of theirs went) and otherwise
    not standing, withdrawn texts by hash, gone quotes, seals and the projection hashes;
  * `dependents` (`audit_dependents`): every record resting on a record or on the quotes of a document, by depth;
  * `active-claims` (`audit_active_claims`): the claims that stand, those of equal text in one row with the documents under them;
  * `diff` (`audit_diff`): what changed between two points of the journal (a point is a number of frames, as a seal's `log_size`);
  * `record` (`audit_record`): now with its row of the status projection, how many records rest on it and its first causes;
  * `fallen` (`audit_fallen`): what fell and on what it stood. Each fallen claim, relation or answer names the grounds that fell,
    the gone quotes with their bytes and why they went, as the command that took them recorded it then (`withdrawn`, with the
    withdrawn text's hash and the bytes that overlapped; `revoked`; `version_replaced`), the quotes under it that stand, with their
    text, twins on other sources found by comparing words, and what to reread. The text of a fallen row, of a gone quote and of a
    twin is never in it, nor the bytes of a gone quote inside a wider one that stands (a journal of the first rule). A withdrawal's
    answer names the point before it (`since`) and how many records fell.
* **A frame of a 0.2 journal nests at most 64 levels of JSON,** its outer object counting one: a command whose frame would be
  deeper is refused before it is written, and a journal with such a frame is refused on replay. Real journals nest at most 11.
  The writer holds every frame to the limits of the format, the genesis included: a run whose genesis would break them (a deep
  or fractional `operator_meta`) is refused before any journal is written.
* **Signed checkpoints (C2SP `signed-note` and `tlog-checkpoint`, Ed25519).** The journal does not change: a checkpoint is a file
  beside it whose three lines name the run (`yuce/<run_id>`), a number of frames and the RFC 6962 root over them, up to and with a
  seal frame, so the signed root also covers the seal's state roots and projection hashes. `sbgk keygen --name --out` writes a
  signing key to a file and prints its verifier key; `audit-serve --signing-key <file>` signs every new seal into
  `<run.wal>.checkpoints/`; `audit-sign` signs the seals of a recorded journal; `audit-verify --checkpoint <file>` checks one with
  the journal: `signature valid, key pinned` under `--trusted-keys` (a file of verifier keys with role and dates), `key not
  pinned` under the key beside it or `--key`, refused for a revoked key unless `--anchored-at` names a day before the revocation,
  and refused when it names no prefix of this journal ending with a seal. The cryptography is `ed25519-dalek`'s.
  An anchored day is a day of the calendar or the check refuses; the days a key is valid hold for a revoked key too; a note
  with a control character other than the line end is refused whole. A server that could not write a seal's checkpoint says so
  in `audit_status` and in the reply of `audit_close` (`signing`) and on stderr; the seal stands, `audit-sign` writes it later.
* **Quittances (`yuce-proof/1`).** `sbgk audit-proof --wal <run.wal> --record <id>` (the whole id, or the `@` short form the
  reading tools show) cuts one file that shows a record with every record it rests on, down to its quotes, under the signed
  checkpoint of a seal; `sbgk audit-proof-verify --proof <file>` checks it alone, without the journal and without a model, with
  the key statuses of a checkpoint and `--expect-seal` for an anchored seal. `--self-contained` adds the bytes of every quote with
  its document version's chunk list, `--with-status` the status projection of the seal. A quittance proves that the records were
  written before the seal (and with the projection, that they stood at it), not that they stand now. It is cut only of records
  that stand at the seal, carries no hypothesis of a model, and a self-contained one hands out no chunk that holds withdrawn text.
* **The index beside a journal (`sbgk audit-index`).** A SQLite database any tool reads (`<run.wal>.index.sqlite`): frames,
  records with their frame and leaf hash, grounds, quotes, seals and the status of every record. It is rebuilt from the journal at
  any time and adds the rows of new frames to an index of the frames before them; `--check` compares it with the journal row by
  row, and an index built in steps has the `index_hash` of one built at once; an index behind its journal is checked against the
  prefix it names. It is never written over its journal or over a file that is no index, and a journal that ends in a torn frame
  is refused. The truth stays in the journal. The binaries build in SQLite (public domain) through `rusqlite`.
* **A settings file (`audit-serve --settings <file>`, `yuce-settings/1`).** One JSON object of the flags of `audit-serve`: text or
  a whole number, `true` for a switch, relative paths from the file's folder. A flag of the file given again on the command line
  is refused. The settings hash in the genesis is what the same flags give by hand, and the same file resumes the run.
  `examples/settings/` holds one that runs as it is.
* **One agent on its own folder in one command.** `--profile solo` without `--subjects` writes `<run.wal>.subjects.json` with
  the tokens of one reading agent and the owner, readable by its owner only where the system has such modes, and never prints
  them; a resumed run takes the same file.
* **A question whose `about` no document holds is said, not lost in silence:** on stderr at the start and in `audit_status`
  (`about_unmatched`).
* **Task numbers are drawn under the chain head,** not the audit root, so they differ from those of a 0.1 run.
* **The terminal receipt no longer has `tasks_committed`:** it counted only the tasks since the last start of the server.

### Also since 0.1.7

* **`--profile solo` runs the measured profile with one agent:** no circles and no dynamic roles, which need a team of three.
* **A wait for a graph builder nobody runs says so.** With `--build-scope full` and no builder subject the readers finished and every
  agent was told to wait, with no reason given. The server warns at the start, and the wait names the builder and `--build-scope none`.
  Links proposed by agents and decided by the owner still need no builder.
* **`audit-verify --expect` checks the receipt's `corpus_manifest_hash` and `run_id`** where it has them. A receipt with the roots of
  the journal and another corpus named in it passed.
* **A manifest refusal names the file** and points a text file to `--docs`.
* **A repair knows a copy that names its quote without the `@`,** as the store reads such a reference.
* **`--select` refuses a stream of a Windows file** (`a.txt:notes`), which no walk of the folder would give.
* **`LIMITATIONS.md` no longer plans agents with their own profile for 0.2:** they come later, with rights per agent.
* **CI checks every published journal** of the recorded runs against the receipts of its stages, with the binary of the tree under
  test (`scripts/verify_published_runs.py`, public repository only). A rule change that a published journal does not survive fails
  there before a release does.
* **`LIMITATIONS.md` says that a withdrawal takes away support and does not erase:** the journal keeps the withdrawn text.

## 0.1.7 (2026-11-08)

A repair after a withdrawal names what fell, and the audit server takes your own text files. The blind grading of the second run of
four makers found the first: the kernel kept the conclusion, and its answer lost it in the repair.

* **`sbgk audit-serve --docs <folder>` runs on your own text files.** Contracts, policies, logs, code: any UTF-8 text, with no manifest
  and no repository. A document is named by its path inside the folder and bound by its bytes, and the same files give the same
  roots anywhere. Hidden files, service folders, links, the server's own files and their copies stay out, and the server prints what
  it took and what it left. A file that is not text stops the start, by name. `--select` names the files instead of walking the
  folder, and it stops on a link or a file of the server. The journal format does not change: `audit-verify` of 0.1.6 passes such a
  journal.
* **`audit-verify` checks the file set of a journal on supplied documents.** It computes the hash of the list again and says whether
  the documents still are the set the run started on (`sources`). `corpus_manifest_hash` was only read before.
* **Only Markdown is cut at `#` lines.** In a code or text file that line is a comment. Such a file is cut by size, at a blank line or
  a line end, for either line ending. Pinned sources are cut as before.
* **A new quote looks for closed text near itself.** Each new quote searched the whole document for every closed text. An occurrence
  that overlaps the quote lies within one length of it, so the decision and the span it reports stay the same at a fraction of the
  cost.
* **A repair after a withdrawal names what fell.** The kernel asked for a replacement of "the invalidated part" without saying which,
  under the task of a whole answer, so the model wrote the answer again: 34 lines, 23 of them copies of rows it was told to keep, and
  not the row that fell. Now the repair names each fallen row by id with the quotes under it that stand. The row's text stays out, as
  it may state what was withdrawn. A repair takes a few lines, and the report coverage of a new answer does not apply to it.
* **Copies of the kept rows stay out of a repaired answer.** The kernel leaves out a claim line that says what a kept row says on the
  same grounds, and says so (`dropped_copies`, in its reply and in the answer's checkpoint). The same words with another date or on
  another quote are another claim. The rule is the dispatcher's, not the store's: a journal that holds such copies replays as before.
* **`examples/findings-gate/` puts a security review's findings through the kernel.** A check of the shape passes all three; the
  made-up one is refused by its bytes, a lost reader does not hang the work, and a file that changes takes the findings on it
  until each is checked again.
* **`yuce --version` says `yuce`.** It printed the name of the other binary.
* **README starts with a release binary and the Python client,** shows how the owner joins through the bridge, and says what
  `VERIFIED` means without a receipt.
* **BENCHMARKS: the control run of 0.1.7,** side K run again from this tree before the tag, graded blind with T and L of run 2.
* **`LIMITATIONS.md` says that the research questions are not in the journal,** and what follows from it.

## 0.1.6 (2026-11-06)

A withdrawal closes text of a document. The blind grading of the first run on four makers found the gap: after a
withdrawal a reader went back to the page and stored the withdrawn sentence with its list number, three bytes wider, and the
answer of the kernel's side cited it.

* **A wider quote no longer brings withdrawn text back.** The kernel refused only the exact span, so any quote that contained it was
  a new record with its support. Now a new quote that overlaps the withdrawn bytes is refused with `EVIDENCE_REVOKED`, which names
  the span. The text stays closed wherever those bytes stand in the document, in any version.
* **A withdrawal takes every stored quote that overlaps it.** It reached one record: the others were found only by the benchmark's
  runner. The answer now says how many other records went with it (`also_revoked`). A quote that went with another can still be
  withdrawn itself, which closes the rest of its text.
* **`audit_withdraw_text` withdraws text nobody has quoted yet,** so a withdrawal no longer depends on a stored record. The Python
  client has it as `withdraw_text`.
* **Old journals keep their rule.** New journals record the rule in their genesis (`r2r-audit-genesis/2`). A journal of an earlier
  release replays under the rule it was written with, so the published runs verify with the same roots. An earlier binary refuses
  a new journal.
* **`LIMITATIONS.md` said too much.** "No claim stays grounded on a withdrawn quote" held for the record, not for its text. It is
  corrected, and `BENCHMARKS.md` names the one wider quote of the published runs.
* **`benchmarks/revision_outcomes.py` counts the quotes taken after a withdrawal** that still touch its text, and the runner withdraws
  the planned text itself.
* **`benchmarks/PREREGISTRATION_0.1.6.md`** fixes the repeat of the run from this tag.

## 0.1.5 (2026-11-05)

The Python client, and a fix of the runner for a team of several makers, found while preparing the run of
`benchmarks/PREREGISTRATION_0.1.5.md`. The kernel did not change: its code is that of 0.1.4.

* **A Python client of the audit server** in [clients/python](clients/python): one connection per agent, the server's tools as methods,
  standard library only. A refusal of the kernel is an ordinary answer; an exception means the call itself failed. Install it with
  `pip install organetic-yuce` and import it as `yuce`: the name `yuce` on PyPI belongs to an unrelated project. A release tag publishes it.

* **The side on Temporal starts with a Codex or an Antigravity seat.** Neither declared its longest call, which bounds a Temporal step,
  so that side stopped at its start.
* **The money brake runs beside a seat without a price per call.** With an Antigravity seat the runner refused the brake even when other
  seats were paid. It now counts the paid seats, as it already did beside a Codex seat. A team with no paid seat is refused as before.
* **`benchmarks/revision_outcomes.py` counts what it says.** A quote that partly overlaps the withdrawn text is touched, found in the page's
  bytes, and a reader's stored quotes come from the journal, apart from its other records.
* **`benchmarks/run_limits.py` fails a campaign whose journal does not verify.** It marked it complete and exited 0.
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
