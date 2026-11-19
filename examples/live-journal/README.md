# YuCe Live: the journal of a run as one page

One HTML page of a journal. It shows what the kernel accepted, what each claim rests on, and what falls when a text is
withdrawn, frame by frame, with a slider and a play button. There are two ways to get it:

* **while the journal is written**: `sbgk audit-watch --wal run.wal` serves the page on this computer and adds each new frame
  to it as the frame is written ([below](#a-journal-while-it-is-written));
* **of a recorded journal**: `make_page.py` writes the page as one offline file, which reads nothing at run time and makes no
  network requests; its content security policy forbids them.

Both read the journal alone, and both show the same page for the same frames.

```bash
cargo build --release
python examples/live-journal/demo.py --html live_journal.html
```

The demo plays three readers and an owner against the real `sbgk audit-serve`, with no model and no API key, in a few seconds:

1. three readers read three short documents about refunds and hand in quotes and claims;
2. the owner seals; three answers to three questions are handed in; the owner seals again;
3. the owner withdraws one sentence of the 2023 policy: five claims and three answers fall, and the kernel sends the three
   questions back to be answered;
4. the readers answer again from what still stands, and the owner seals.

Then `make_page.py` turns the journal into `live_journal.html`, compared with the kernel at every frame, and `check_states.mjs` runs
the page's own script on the kernel's states at every frame. Open the page in a browser and press *Play the run*.

## A page of any journal

```bash
python examples/live-journal/make_page.py --wal run.wal --out page.html [--docs folder] [--note "a sentence about the run"]
```

Any journal that `sbgk audit-verify` verifies gets a page, the older journal formats included.
- `--docs` is the folder the documents were read from: the repository of a git manifest, or the folder of an opaque run. With it,
  each quote is shown in its line of the document, after the SHA-256 of the document is checked against the journal. Without it,
  a quote is shown as its bytes alone.
- `--note` is shown at the top of the page: for example, how a withdrawal in the run was chosen.

## A journal while it is written

```bash
sbgk audit-watch --wal run.wal [--docs folder] [--note "a sentence about the run"] [--listen 127.0.0.1:7117]
```

The command prints the address of the page (`http://127.0.0.1:7117/` by default) and runs until it is stopped. Open the address in
a browser: the page stays on the latest frame and draws each new one as it is written. Step back with the slider or the arrows
and the page says how many frames it is behind; *Latest frame* returns to the end. `yuce watch` is the same command.

* **It reads the journal and nothing else.** No token, no call to the server that writes the journal, no network beyond this
  computer: the page asks only the command that serves it. The journal is opened for reading, never locked, copied or written,
  and a server starts and stops on it as if no one watched.
* **It reads the journal from its start once.** After that it reads only the frames written since, up to the last complete
  frame, as every reading command reads a journal a server holds. A long journal is caught up with in steps, and the page shows
  the frames read so far meanwhile.
* **Every frame gets the checks `sbgk audit-verify` gives it**, in the same order: the chain of frame hashes, then the replay to
  the outcome and the roots the frame committed. A frame that does not pass stops the reading: the page shows the frames before
  it and says which frame did not pass and why. Nothing is skipped.
* **The states are the ones `sbgk audit-prov` gives.** The command builds them with the same code as it reads: at frame N they
  are what `sbgk audit-prov --upto N+1` gives. Coverage is the kernel's table at a frame.
* The journal may not exist yet: the page waits for its first frame. A file that becomes another journal is read from its start.

What the page says of the journal's file:

| The page says | What it means |
|---|---|
| Live: the journal is open | the run is not closed, and a writer holds the file |
| Behind by N frames | you are looking at an earlier frame than the last one read |
| Catching up | a long journal is being read from its start; more frames are written than were read so far |
| Recorded journal | the run is not closed, and no writer holds the file now; the page goes on when frames are written again |
| The run was closed | a `close` frame ends the journal; nothing follows it |
| The journal does not verify | a frame did not pass the checks; the page shows the frames before it |

These are facts of the file. They do not say whether the agents, or the server that writes the journal, are well: the journal
holds no clock, and a writer that holds the file and writes nothing looks the same as one about to write.

The server answers GET only, on a loopback address only (another address is refused at the start), and only its own page: a
request under another name than the address it listens on, or one that a page of another site makes, is refused before any data
is made, and no other site can put the page in a frame. The address printed at the start is the one that answers: open it
itself, since a link to it from another site, or from a file on the disk, is refused as that site's request. It has no
password: anyone who can open a page on this computer can read what the journal holds.

With `--docs`, a document is read only when the name the journal gives it leads to a regular file inside that folder: no path
out of the folder, no link, no device, and no file longer than 64 MiB.

`watch_demo.py` shows all of this with no model and no API key: it starts `sbgk audit-watch` on a journal that does not exist
yet, plays the run of `demo.py` against the real `sbgk audit-serve`, and after each part of the run compares the watched page
with the journal and with the page `make_page.py` makes from the same frames.

```bash
cargo build --release
python examples/live-journal/watch_demo.py
python examples/live-journal/watch_demo.py --slow 1.5 --hold     # slowly, to look at the page in a browser while the run goes
```

`check_live.mjs` then runs the page's own script on what the server sent: the page that took the frames one part at a time must
hold the same data as the page of the whole journal, and give the kernel's states at every frame.

## Where every state on the page comes from

The kernel gives every state the page shows: what stands, what fell and why, at each frame.

* `sbgk audit-verify` checks the journal first. A journal that does not verify gets no page.
* `sbgk audit-prov` gives the records, what each rests on, and the periods in which each stood, with the frame and the reason
  that ended a period. At frame N a record handed in by then:
  * stands while a period of it holds frame N;
  * fell, was withdrawn, went with its bytes to a new version of its document, or (an answer) is no longer supported by
    grounds that still stand, when its last period ended;
  * never stood when the kernel gave it no period, such as an answer that settles nothing.
* `make_page.py` compares this with `sbgk audit-prov --upto N+1`, the export of the first frames alone, and stops with exit code 1
  on a difference.
  * It compares at every frame of a journal of up to 200 frames and records, and in the demo.
  * For a longer journal it compares at every seal, every frame where a record stopped standing, and the last frame. `--check all`
    asks for every frame.
* `check_states.mjs` runs the page's own `stateAt` on those kernel states and compares them record by record. CI does this at
  every frame of the demo. `check_page.py` makes sure the page has that one `stateAt` and takes every state from it.
* The coverage of the documents is `sbgk audit-read coverage` over the first frames of the journal: at every frame of a short
  journal, at seals and where records stopped standing in a long one. A run for which the kernel keeps no coverage table says so.
* The question of each answer is the one the kernel named when it closed the answer task, or else the one handed in with the
  answer.

The page works out how to draw these states (the steps of a fall, the focused view, the counters) and which questions an
answer that fell sends back.

A journal of more than 200 frames or records opens in a focused view: what stopped standing, and the answers with what they rest
on. *Everything* shows the rest. The strip of frames keeps seals, withdrawals, falls and answers as slips of their own and folds
the frames between them; *Play* steps from one of them to the next.

The text of a record that fell, and of a withdrawn quote, is hidden by default, as in the kernel's report of what fell. *Show
historical text from the journal* shows it struck through: a withdrawal is not an erasure, and the journal keeps the text. The
address `page.html#film` opens the view for recording a film: the journal and the map only, with the historical text shown.

For every quote, claim and answer the page gives the commands that read the same from the journal: `sbgk audit-read record`,
`dependents` and `fallen`.

## Not on the page

The page shows only what the journal holds: accepted records and what each rests on.

* No clock: frames have an order, not a time.
* Nothing else: the journal keeps no search and no draft that was not accepted.
* An agent is the id the journal's frame names, and nothing more.

It does not measure whether a conclusion is true, or whether the agents missed something in the parts they read. The kernel
checks bytes and registered dependencies, not meaning.

`check_page.py [page.html]` checks the template, and a page made from it, in CI. Python 3.10 or newer, standard library only;
`check_states.mjs` and `check_live.mjs` need Node.js 18 or newer. The template is one file for both ways: `sbgk audit-watch`
serves it with the data of the frames read, a policy that also allows requests to the command itself, and a short script that
asks the command for new frames; the recorded page has neither.
