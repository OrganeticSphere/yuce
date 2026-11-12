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
* Check a stopped journal: a live server's lock blocks reading on Windows (exit 2), and elsewhere a read in the middle of a write
  can report a torn tail that is not there.
* `--expect` finds the receipt's state anywhere in the journal, so a journal that went on after a terminal receipt passes too:
  `at_end` in the report says whether the state is the journal's end, and `--at-end` makes that a condition.
* **A journal holds the full text of its sources.** Whoever checks a journal gets them: to publish a journal is to publish its
  documents. A journal cannot be checked without their text.
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
  still show the later state.
* **An answer's list of records can name a record twice (0.2.0).** After a repair in several attempts, the done record of an
  answer and the list the kernel keeps for it (`answer_ids`) can name a record twice: once as the model named a record of an earlier
  attempt of the same task and once as the kernel added it as a row the answer keeps. The answer is the same set of records, and its
  text shows each once; count distinct ids. A count over such an answer's grounds, as `grounds_standing` in the report of what fell,
  can come out too high. To be fixed in 0.2.1.
* **What the reading tools can prove.** The projections are complete as to the kernel's rule: every `based_on` and relation end
  the records declare. They are not complete as to the world: a dependency an agent did not declare is in no projection, so
  `dependents` and the report of what fell cannot show it. From the journal the report proves what stands, what fell and which
  quote went. Its twins are found by comparing words, a heuristic that misses a claim worded otherwise and can name one that only
  sounds alike; what it says to reread is advice.
* **The live support of a repair is found by words too.** It can miss a claim worded otherwise and bring one that only sounds
  alike; the repair is told so and answers from the quotes. It holds at most 12 claims, 4 per fallen row: when many rows fall,
  the later rows in id order may get none, and a claim too large for what the kept rows leave of the window is left out. A
  question whose every answer row fell is not repaired but answered anew, from a window chosen by the question alone.
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

## Size

* Up to 8 agents at once and runs of a few thousand records are recommended for 0.1. On a journal of quotes and claims alone one
  commit takes about 25 ms (p50) at 10,000 records and reopening the journal about 2 s; a real run's journal takes as long at about
  3,000 records, with more entries per record. The time of a replay grows close to the square of the journal's length, as the
  whole state is hashed at every entry. More than 16 agents add little throughput
  ([BENCHMARKS.md](BENCHMARKS.md), section 4).
* One process, one writer. There is no compaction of the journal, no rotation of tokens and no format migration in 0.1.
* The connection limit is shared: connections that send nothing hold a place until the 5 s admission timeout, and there is no
  limit per address. This matters with `--allow-remote`.

## Off by default, experimental

* **The graph builder** (`--build-scope full`, a dedicated `builder` subject) and the links it proposes between records
  (`supports`, `contradicts`, `supersedes`, ...), with their checks by an agent that wrote neither end. It is measured but
  not the default: it knew fewer version transitions than a dedicated graph system and cost three times as much.
* **Reading version transitions into the kernel** (`--build-scope versions`).
* **The dynamic ontology** (`--ontology-revisions`, `--ontology-review`): concepts that grow and are revised during a run.

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
