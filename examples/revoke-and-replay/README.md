# No-LLM demo: quote gate, revoke, replay

A team of three readers and an owner work on one page of the MCP specification through the real `sbgk audit-serve` in its
default v0.1 profile. The script plays the agents itself: no model, no API key, a few seconds.

```bash
cargo build --release
python examples/revoke-and-replay/demo.py
```

What it shows:

1. A quote with one byte changed is refused (`QUOTE_NOT_FOUND_IN_BYTES`) and no record is stored.
2. Two byte-exact quotes and one claim `based_on` each are accepted, with receipt ids.
3. The owner revokes the first quote: the claim on it is no longer grounded, the claim on the other quote still is. No model
   is asked which claims the revocation touches: the registered `based_on` links answer it.
4. The server is stopped and started again on the same journal: the replay reaches the same audit and engine roots, with the
   same two claim states.
5. A copy of the journal with one letter of the claim changed (`must` to `Must`, still valid JSON) is refused on start:
   `hash mismatch`. The original journal is left as it was.
6. Without the server, `sbgk audit-verify --wal demo.wal --expect receipt.json` replays the journal and finds the state
   named by the receipt saved before the stop (audit and engine roots, chain head): `VERIFIED`. The edited copy is
   `REFUSED` with exit code 1. This is the check anyone can run on a published journal and its receipt.

What it does not show: model quality, semantic truth of a claim (the kernel checks bytes and registered dependencies, not
meaning), dependencies nobody registered, or protection against someone who can rewrite the whole journal and its hash chain:
for that, keep the terminal receipt (audit and engine roots) somewhere they cannot write, such as a protected git commit or a
CI artifact, and compare the replay against it.

Options: `--bin path/to/sbgk` to use another binary, `--keep` to keep the work folder with the journal, `--report report.json`
to write what the kernel answered at each step, `--html page.html` to write the inspector page with that report inside. Python 3.10 or newer, standard library only.

## See it in a browser

```bash
python examples/revoke-and-replay/demo.py --html inspector_report.html
```

Then open `inspector_report.html` in a browser: `--html` writes `inspector.html` with the report inside it, so it opens with its
data. With `--report report.json` instead, open `examples/revoke-and-replay/inspector.html` and choose `report.json` (or drop it
on the page). It shows the six steps, the section the kernel handed the reader with both quotes found byte for byte in it and their byte ranges in
the page, the refused quote with its changed byte, the claims and the quotes they rest on before the revocation, after it and after the restart, and both journal
checks with their roots. The page has no data of its own: every state on it is the kernel's answer from the report, no state is
computed in the browser (it only compares recorded roots and searches the recorded section for the quotes' bytes). It makes no network requests (its content security policy forbids them) and needs no build step.
`check_inspector.py report.json` checks that in CI.
