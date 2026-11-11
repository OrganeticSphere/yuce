# A settings file

`solo.json` holds the flags of `sbgk audit-serve` for one agent on the folder `docs/`, in place of typing them:

```bash
sbgk audit-serve --settings examples/settings/solo.json
```

- Each key is a flag of `audit-serve`; a value is text or a whole number, a switch is `true`.
- A relative path is taken from the file's folder, so the journal is written here as `settings-example.wal`.
- A flag in the file may not be given again on the command line: the run has one source.
- The run's settings hash in its journal is what the same flags give by hand.
- Started again with the same file, the server resumes the run: the flags that started it (`docs`, `run-id`) are the journal's now.
- Without `subjects`, `--profile solo` writes `settings-example.wal.subjects.json` with the tokens of `agent` and `owner`.

A team of three or more readers takes `"profile": "v0.1"` and a `subjects` file of its own (see the main README).
