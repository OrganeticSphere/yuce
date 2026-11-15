# YuCe Live: a recorded run, played back frame by frame

One HTML page made from a journal. It shows what the kernel accepted, what each claim rests on, and what falls when a text is
withdrawn, frame by frame, with a slider and a play button. The page reads nothing at run time and makes no network requests;
its content security policy forbids them.

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

## Where every state on the page comes from

The kernel gives every state the page shows: what stands, what fell and why, at each frame.

* `sbgk audit-verify` checks the journal first. A journal that does not verify gets no page.
* `sbgk audit-prov` gives the records, what each rests on, and the periods in which each stood, with the frame and the reason
  that ended a period. At frame N a record handed in by then:
  * stands while a period of it holds frame N;
  * fell, was withdrawn, or was replaced (by a new version of its document, or by a later answer) when its last period ended;
  * never stood when the kernel gave it no period, such as an answer that settles nothing.
* `make_page.py` compares this with `sbgk audit-prov --upto N+1`, the export of the first frames alone, and stops with exit code 1
  on a difference.
  * It compares at every frame of a journal of up to 200 frames and records, and in the demo.
  * For a longer journal it compares at every seal, every frame where a record stopped standing, and the last frame. `--check all`
    asks for every frame.
* `check_states.mjs` runs the page's own script on those kernel states and compares them record by record. CI does this at every
  frame of the demo.
* The coverage of the documents is `sbgk audit-read coverage` over the first frames of the journal: at every frame of a short
  journal, at seals and where records stopped standing in a long one. A run for which the kernel keeps no coverage table says so.
* The question of each answer is the one the kernel named when it closed the answer task, or else the one handed in with the
  answer.

The page works out only how to draw these states: the steps of a fall, the focused view and the counters.

A journal of more than 200 frames or records opens in a focused view: what stopped standing, and the answers with what they rest
on. *Everything* shows the rest. The strip of frames keeps seals, withdrawals, falls and answers as slips of their own and folds
the frames between them; *Play* steps from one of them to the next.

The text of a record that fell, and of a withdrawn quote, is hidden by default, as in the kernel's report of what fell. *Show
historical text from the journal* shows it struck through: a withdrawal is not an erasure, and the journal keeps the text. The
address `page.html#film` opens the view for recording a film: the journal and the map only, with the historical text shown.

For every quote, claim and answer the page gives the commands that read the same from the journal: `sbgk audit-read record`,
`dependents` and `fallen`.

## Not on the page

The page shows only what the journal holds:

* no clock: frames have an order, not a time;
* no tasks handed out and not yet returned, and no texts of the tasks;
* no hand-ins the kernel refused: a refused line stores nothing.

It does not measure whether a conclusion is true, or whether the agents missed something in the parts they read. The kernel
checks bytes and registered dependencies, not meaning.

`check_page.py [page.html]` checks the template, and a page made from it, in CI. Python 3.10 or newer, standard library only;
`check_states.mjs` needs Node.js 18 or newer.
