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
* A journal is read while its server runs, and what is read is that moment's. The server is the journal's one writer on every
  system; `audit-verify`, `audit-read`, `audit-index`, `audit-prov` and `audit-proof` read up to the last complete entry of that
  moment and say so (`live`), and an entry the server has not finished is no torn tail then. `audit-watch` goes on reading as
  the journal grows; what it says of the journal (a writer holds it, none does, the run was closed) is a fact of the file at
  that moment, not a check that the agents or their server are well. The journal may have grown since: only a stopped
  journal has an end to check, and `--at-end` on a live one holds for that moment alone. On Windows any program that holds the
  journal open for writing counts as its writer: no server starts on it, and a torn tail is taken for an entry in flight. Beside
  a server of 0.2.0 or earlier, which locks the whole file, a reading command on Windows stops with exit 2 and says so.
* `--expect` finds the receipt's state anywhere in the journal, so a journal that went on after a terminal receipt passes too:
  `at_end` in the report says whether the state is the journal's end, and `--at-end` makes that a condition.
* **A journal holds the full text of its sources.** Whoever checks a journal gets them: to publish a journal is to publish its
  documents. A journal cannot be checked without their text.
* **A reading-only shard holds no answer.** A run with `--reading-only` records its reading only; the summary made from its
  shards is outside its journal, and the journal proves nothing about it. Its receipt says so (`summaries.in_journal: false`).
* `sbgk audit-serve` takes two kinds of sources: Markdown pinned by commit and SHA-256 (`--manifest`), or the UTF-8 text files of a
  folder (`--docs`). Either way a run is fixed at its start: a source that changes means a new run. The library also takes new
  versions of a document, which is what `examples/findings-gate/` uses.
* **A run on a folder proves the bytes, not where they came from.** Its journal names each file by its path inside the folder, with
  the SHA-256 of its bytes, and `corpus_manifest_hash` is the hash of that list. No repository or commit stands behind it: to compare
  a journal with your files, compare the hashes. `audit-verify` computes that hash again: `sources.set_matches_manifest_hash` says
  whether the documents as they stand at the end are the set the journal names, and `sources.put_document_entries` how many entries
  put a document, as one can change and come back. It says `false` for a journal the library wrote with a value of its own. This is
  a check of a journal against itself: one rewritten with its hash computed again passes it, and only a receipt kept elsewhere shows that.
* `--docs` leaves out what a walk should not give away: hidden files, service folders, links, the server's own files and copies of
  `--subjects` and `--questions`. A list given with `--select` may name a hidden file, and it stops the start on a link or a file of
  the server. Neither can tell a secret in an ordinary file: read the list of taken files it prints, as what is taken stays in the
  journal for good. A name takes at most 512 bytes. Each path is checked before and after its file is read, not the open file itself:
  nobody else should write to the folder while the server starts.
* **PDF and Word are not read.** Convert them to text first. A quote is matched by its bytes and nothing is normalized, so text
  from Word with curly quotes or no-break spaces fails when an agent writes them differently, as any changed byte does. How often
  that happens on such text has not been measured.
* Only Markdown is cut at `#` lines. Other text and code files are cut by size, at a blank line or else at a line end, so a passage
  can fall on two sections, and a quote cannot cross them. A document without a date has no place in time, and whatever compares an
  earlier document with a later one says nothing about it. The dated summary needs a `+++` block in the file for that.
* The research questions are not in the journal: it holds a hash of their set in a few entries, not their text. A server reopened on
  a journal with another `--questions` file takes the work up again for the new set, and `audit-verify` still passes, as it checks
  what the journal holds. Keep the questions file with its journal.
* **What a withdrawal reaches.** A withdrawal closes text of one document: those bytes wherever they stand in it, in any version.
  Every stored quote that overlaps them goes with it, and a new quote that overlaps them is refused, even when most of it is other
  text. So no claim stays grounded on those bytes of that document. The owner names a stored quote (`audit_revoke`) or the text
  itself, quoted or not (`audit_withdraw_text`); to withdraw a sentence that repeats in a document, name the sentence, as a quote
  with its list number closes those bytes and not the other line. The same sentence in another document is another source and
  is not touched. So a withdrawal can take more than the claims that needed the text: a claim on a wide quote falls when the quote
  overlaps the withdrawn bytes, though the rest of the quote still stands, and every place in the document where the same bytes
  stand is closed with them. The text an agent writes is another matter: a later answer can repeat withdrawn content in other
  words, and how often it does is measured, not prevented. A note that a claim lost its later quote speaks for that claim: another record may
  still show the later state. With `--withdrawn-anchor`, a standing claim that names a hash, version, `#`number, error code or
  file path found only in withdrawn text, and in none of its own quotes, is flagged; the kernel does not judge meaning, and
  nothing falls by the flag. A whole number with its unit is no such name: a claim that keeps "4 mm/s" after the sentence
  holding it was withdrawn is not flagged. A decimal number reads as a version, so "0.691" is one.
* **`audit-proof --out` of 0.2.0 does not refuse the journal's own path.** Pointed at the journal, it writes the quittance over
  it, and the run is lost. 0.2.1 refuses it, as `audit-index` does for its database; with 0.2.0 keep the default
  (`<run.wal>.proofs/`) or name another file.
* **In a journal of 0.2.0 an answer's list of records can name a record twice.** After a repair in several attempts, the done
  record of an answer and the list the kernel keeps for it (`answer_ids`) could name a record twice: once as the model named a record
  of an earlier attempt of the same task and once as the kernel added it as a row the answer keeps. The answer is the same set of
  records, and its text shows each once. 0.2.1 keeps each record once; a journal of 0.2.0 replays as it was written, so in such a
  journal count distinct ids. A count over such an answer's grounds, as `grounds_standing` in the report of what fell, can come out
  too high.
* **What the reading tools can prove.** The projections are complete as to the kernel's rule: every `based_on` and relation end
  the records declare. They are not complete as to the world: a dependency an agent did not declare is in no projection, so
  `dependents` and the report of what fell cannot show it. From the journal the report proves what stands, what fell and which
  quote went. Its twins are found by comparing words, a heuristic that misses a claim worded otherwise and can name one that only
  sounds alike; what it says to reread is advice.
* **What the PROV-O export says.** `audit-prov` is a reading of the journal by the kernel's rules, complete as the projections are:
  only the dependencies the records declare. It has no times, because the journal holds none; frames are ordered by their
  number. It leaves out the graph builder's links and concepts, the server's own checkpoints and the texts of the directives. In
  it a record is never invalidated, only a period in which it stood: a record stands again when its document is put back to the
  bytes it quotes. Standing is read at the end of each frame, the points the kernel's projections name: an observation that one
  batch accepted and made fall has no period, though it still quotes its version. Like the journal, it holds the text of every
  quote, withdrawn ones too.
* **The live support of a repair is found by words too.** It can miss a claim worded otherwise and bring one that only sounds
  alike; the repair is told so and answers from the quotes. It holds at most 12 claims, 4 per fallen row: when many rows fall,
  the later rows in id order may get none, and a claim too large for what the kept rows leave of the window is left out. A
  question whose every answer row fell is not repaired but answered anew, from a window chosen by the question alone.
* **The window of an answer is chosen by words and kept to its size.** For a question about what changed, a claim of stance
  `reported` is taken by its words ("replaced", "superseded", "no longer" and a few more; "removed" and "renamed" as words of their
  own that the sentence does not negate); a change worded otherwise is taken only under a stance the question names or through a
  link. The window
  holds at most 100 claims and 256 records, taken in turns by document, so a claim it takes can put another out at its edge; the
  summary is told how many did not fit. On the A2A corpus the stance the readers chose for one changelog decided whether its
  claims reached the window (BENCHMARKS.md).
* **The packs of the gap pass go to documents in the order of their ids,** not by version or reading order: on the A2A corpus all
  12 packs of each run went to the v0.3.0 specification, and the pass added material on an older version only.
* **What the coverage table says.** That a quote touches the bytes of a unit, or that a pack was answered with no quote of it: not
  that the quote records what matters there, nor that an empty answer was right. A unit is cut by the lines of the text (a list
  item, a paragraph, a table row), not by its meaning. The table is the state of now: a unit under withdrawn text is `withdrawn`
  whatever it was before, and what a unit was at an earlier frame is in the table of that prefix. `pack` names the pack of the
  unit's tier whose bytes span it: a unit quoted before the pass can lie between a pack's targets without having been one. A unit
  of a section whose reading was given up with nothing recorded is `reading_given_up`, not read: its first reading was closed
  unresolved, ran out of attempts, or was closed by an answer abandoned after refused ones, and neither it nor a loss reread of
  the section stored a record. That holds even where a pack of the gap pass answered empty over the unit; only a quote that stands
  on it makes it `quoted`. A reading that stored records, or a reread that did, counts as reading the section, whatever it lost.
  Before 0.2.3 such units were counted as read. A document read as a zone, not by sections, has its units `unread`. A journal that
  pins no section size (a run the library started without `audit-serve`), or a journal of 0.1, whose sections were cut by the
  earlier rule, gives no table.
* **What a signed checkpoint proves.** Only that the holder of the key claimed that the journal of that many frames has that
  root. A key file next to the journal, or a checkpoint kept in the operator's own repository, does not protect against the
  operator: an anchor out of the writer's reach does, and a third-party witness is not in this version. Without a trusted keys file
  the check says `key not pinned`, and without `--anchored-at` it says the time of the signature is not pinned: until a witness,
  the only clock is the day the checkpoint was anchored.
  `sbgk keygen` makes the key file readable by its owner only where the system has such modes (Unix); on Windows the file takes
  the permissions of its folder, so keep it in a folder only you can read.
* **What a quittance proves.** That a record and every record it rests on were in the journal the kernel sealed, under a signed
  checkpoint; with the status projection inside, that they stood at that seal. Not that they stand now: that takes a later seal
  and its status. A quittance of an older seal is checked against an anchor of that same seal only, until a witness can prove two
  seals consistent. A self-contained quittance checks a quote's bytes against its document version, not its place in the document:
  the byte offsets are the kernel's word, under the signature. With `--with-status` the receiver sees the id, kind and status
  of every record of the run, not only of the target: no text, but what the run holds. There is no quittance of a record that
  fell: that it fell is shown by the status projection or the withdrawn section of the state, not by a quittance.
* **A withdrawal takes away support; it does not erase.** The journal keeps the withdrawn text: in the documents of its first entry
  and in the quotes stored before the withdrawal, and whatever is read or indexed from the journal can show it. Erasing a text on
  request, as a law may require, is not something the kernel does.
* **Journals before 0.1.6 keep a narrower rule.** They refused only the exact span, so a wider quote could bring withdrawn text
  back as a new record, with its support. A recorded outcome has to replay as it was recorded, so those journals keep that rule
  and verify as before. In the published runs it happened once: in DeepSeek series 1 a reader widened the refused sentence by 15
  bytes, and no answer cited it. The first run of four makers found the gap: there an answer did.
* **`CURRENT_UNCERTAIN` needs one claim on both dates.** In the default profile the mark falls on a claim that rested on an earlier
  and a later report, and on the next summary. A reader's claim on the earlier quote alone stays `LATEST_KNOWN`, and a summary written
  as one claim per quote gets no mark. With accepted `supersedes` links, off by default, the earlier claim itself is marked.
* **The rule of a journal is pinned by its chain, not by its roots.** The roots do not say whether a journal ran under the rule before
  0.1.6 or under that of 0.1.6: until a command the two rules answer differently, the same entries reach the same `audit_root` and
  `engine_root`. The first entry differs, and with it every `wal_head`. A receipt says which rule a journal ran under when it holds a
  `wal_head` you trust.
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
  These ratios were measured with 0.1, and the kernel's own share of that time was not separated from the rest of its side.

## Size

* Measured with 0.2.5 on a synthetic grid: equal numbers of quotes and claims, each claim on one to three quotes, one frame per
  document with `sync_data` at each frame. At 50,000 records over 100 MB of sources a withdrawal with the list of what fell
  takes 14 ms, reopening the journal 3.9 s, `audit-verify` 4.2 s and taking the records in 69 s; the server's working set
  peaks at 325 MB. At 100,000 records a withdrawal with the list takes 15 ms, reopening 9.3 s, and the working set peaks at
  523 MB: about 125 MB before the first record and about 3.9 KB per record. Taking the records in still grows faster than the journal,
  in the server's handing out of tasks and taking in of answers. These are single series on one Windows laptop.
* Before 0.2.4 a replay grew close to the square of the journal's length: every command copied the whole state and looked
  records up by a pass over all of them (0.2.3).
* Up to 8 agents at once, with more than 16 adding little throughput, was measured with 0.1
  ([BENCHMARKS.md](BENCHMARKS.md), section 4); the number of agents was not measured again on a quiet machine with 0.2.4 or 0.2.5.
* One process, one writer. There is no compaction of the journal, no rotation of tokens and no format migration in 0.1.
* The connection limit is shared: connections that send nothing hold a place until the 5 s admission timeout, and there is no
  limit per address. This matters with `--allow-remote`.
* `yuce mcp` cuts a long tool answer into parts of at most `--max-result-chars` characters (16,000 by default). It counts
  characters, not bytes, so a part in Chinese or Japanese can reach 48 KB. The parts live in the server's memory, for the newest
  8 answers only: a client fetches them with `audit_more` in the same session.

## The journal that takes its sources as they come (0.3.0)

* **Text only.** A source put into a running journal is UTF-8 text of at most 16 MiB, as a document given at the start is. A
  binary source has to be put as text (hex or base64) by its owner.
* **Not with a version map.** A run that pins a version map (`--build-scope versions`) freezes its documents: it takes no new
  source and no new bytes of a known one.
* **A claim on a claim is still AND.** A claim stands while every ground of it stands; a formula of support (this ground or that
  one) is not in 0.3.0. A number in a claim that rests on claims only has no quote of its own: the status of a run counts such
  claims (`claim_chains`), and nothing checks their arithmetic.
* **Conflicts and missing keys are read, not refused.** Two active claims of one key with different values (`VALUE_CONFLICT`)
  and a required key no active claim says (`MISSING_REQUIRED_KEY`) are found by the reads `key`, `keys` and `checkpoint`. The
  kernel stores both claims. The key is the exact string of a claim's `subject`: `A` and `a` are two keys.
* **A context checkpoint keeps what the agent listed.** The kernel checks that the listed records are active when the checkpoint
  is written, that the sources exist and that the epochs follow one another. It does not check that the list is complete, nor
  that a record says what its source means. `keys_not_carried` names the keys the checkpoint before listed and this one did not.
* **One submission rests on at most 256 documents.** The scope of a submission names the documents its lines quote and the
  documents under every earlier record they rest on, and a scope names at most 256. A journal may hold any number of sources;
  a claim whose grounds, through the claims it rests on, reach more than 256 documents is refused. A running total over more
  than 256 documents cannot end in one claim: steps that each rest on fewer can be made, but a claim that joins them rests on
  all their documents and is refused.
* **A new version of a source takes every quote of it.** A quote is bound to a version of its document: when the document gets
  other bytes, every quote of it and what rests on them is affected, also the quotes of lines that did not change, until the
  earlier bytes come back. The server gives the task of reading the document again for the new bytes. Not given again: a
  reading that was given up as unresolved before the new bytes came, and the packs of the gap pass over the earlier bytes.
* **A document's name takes at most 512 bytes**, at the start and for a source that comes later. A journal of rules 3 that
  already holds a longer name is replayed as it was written.
* **What a run under the rules of 0.2 promises** (`--rules r2r-audit-rules/3`). The format of its journal, and the reading, the
  replay and the verification of a finished journal, are those of 0.2.5 and `yuce-verify` 0.2.1. It does not promise that the
  program of 0.2.5 can take over a run that is not finished while a source put again with other bytes is still unread: the
  server of 0.2.5 counts that reading as done. A new write of a document takes a name of at most 512 bytes under both rules.
* **An empty start is for a reading-only run, on the server.** `audit-serve --empty-start` needs `--reading-only`: a run that
  makes its summaries in the journal would be asked for them before any source came. `sbgk mcp` (one agent on a folder) and
  the Python client start no run without a document. A run is told at its start when no document holds a term of a question;
  a start without a document has none to look in and says nothing, and the check is made again only when the run is resumed.
* **The reason of a withdrawal is named, not judged.** `reason_source_id` must be a document of the journal; the kernel does not
  read whether that document justifies the withdrawal. `sbgk audit-stream withdraw` requires it. The owner's tools
  `audit_revoke` and `audit_withdraw_text` take it as recommended and not required, so that the tools of 0.2 work on a journal
  of rules 4: a withdrawal without a reason is accepted there. The Python client does not send it. What tells a planned change
  from a withdrawal is the relation `supersedes`, not the reason.
* **The independent verifier does not check any of this by meaning.** `yuce-verify` 0.3.0 checks the bytes of a journal of rules
  4 as it checks one of rules 3 (levels J0 to J3); it recomputes no status, no cascade and no checkpoint. `yuce-verify` 0.2.1
  refuses a journal of rules 4 at J2: it does not know the rules the journal names.
* **Not measured yet:** the cost of the reads by key, of a checkpoint and of the status on a long journal of rules 4, of looking
  for the readings a new version of a source opens again, of the scope of a submission that rests on a long chain, and the
  memory of a journal of many sources. The sizes of the Size section are of journals of 0.2.

## Off by default, experimental

* **The graph builder** (`--build-scope full`, a dedicated `builder` subject) and the links it proposes between records
  (`supports`, `contradicts`, `supersedes`, ...), with their checks by an agent that wrote neither end. It is measured but
  not the default: it knew fewer version transitions than a dedicated graph system and cost three times as much. Since 0.2.3
  the kernel holds that rule when it accepts a verdict, not only when it hands out the check; a run started before 0.2.3 keeps
  the rule it had, held at the hand-out only. The owner can still decide such a link (`arbitration: true`): the journal marks
  the decision as an arbitration, on the server's word about who called; the mark is no signature of the owner.
* **Reading version transitions into the kernel** (`--build-scope versions`).
* **The dynamic ontology** (`--ontology-revisions`, `--ontology-review`): concepts that grow and are revised during a run.
* **The withdrawn-name notice** (`--withdrawn-anchor`): measured on the recorded runs, where it finds none.

## Not in 0.1

* The Python client ([clients/python](clients/python)) is a thin client of the server's tools, with no model or loop of its own. It
  installs as `organetic-yuce`: the name `yuce` on PyPI belongs to an unrelated project.
* Settings as a file and a page to edit them are planned for 0.2. Agents of any model joining and leaving with their own profile
  come later, with rights per agent.
* TLS: the servers listen on loopback by default and have no TLS. See [SECURITY.md](SECURITY.md).

## Platforms

* CI builds and tests on Linux at every push and on Windows on a manual run, done before each release. Release binaries are built for Linux x86_64, Windows x86_64 and macOS (arm64,
  x86_64); the Linux, Windows and macOS arm64 binaries are started once in the build, the macOS x86_64 one is not.
* The published runs were made on Windows x86_64.
* The Linux binary needs glibc 2.34 or later (Ubuntu 22.04, Debian 12, RHEL 9). Binaries and tags are not signed; the SHA-256 sums
  sit in the same release as the files.
