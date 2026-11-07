# No-LLM example: a security review's findings through the kernel

A findings file names a file and a line for every step of a finding. A check of its shape can tell that the file and the line
exist. It cannot tell that the line says what the finding claims, that the file is still the one that was read, or that the
agent who took the work is still there.

This example puts such a file through the kernel. The script plays the agents itself: no model, no API key, under a second once
it is built.

```bash
cargo run --release -p sbgk-core --example findings_gate
```

The files:

* `findings.json`: three findings. Each step carries a `quote`, copied byte for byte from the file. Two findings are real, and one
  is made up: it cites a real file and real lines, and its quotes are in no file.
* `before/`: a small service as the review read it.
* `after/`: the same service later. One finding is fixed, and a comment moves the other down by a line.

What it shows:

1. A check of the shape passes all three findings.
2. The made-up finding is refused (`QUOTE_NOT_FOUND_IN_BYTES`) and nothing of it is stored. The real finding beside it is stored.
3. A reader takes a task and goes silent. While its lease runs the task is held, after that another reader gets the same task, and
   a late answer of the first reader is refused (`STALE_TASK`). The work does not hang on it.
4. The review closes with an answer on the two findings that stand.
5. Both files change. Neither finding is grounded any more, and the review is open again: its quotes were taken from a version of
   the file that is gone, whatever changed in it.
6. Each finding is checked again on the new bytes. The fixed one has lost its bytes and goes back to open. The other one stands on
   the new version, at line 5 where the file says line 4: the quote finds it, and the line number would have pointed at a comment.
7. All of this is one journal. It replays to the same roots without a model. With `--keep` the journal stays, and
   `sbgk audit-verify --wal <journal>` checks it from outside.

What it does not show:

* **The kernel checks bytes, not meaning.** A real line quoted under a false claim passes. Whether the line says what the finding
  claims stays with the people and agents who verify it. What the kernel removes is the finding with nothing under it.
* It finds no vulnerability and judges none. `orders-sql-injection` goes back to open because its quote is gone, not because the
  kernel saw a fix.
* The example runs on the library, not on `sbgk audit-serve`: the server takes code files with `--docs`, but its run is fixed at
  the start, so a file that changes means a new run there.
