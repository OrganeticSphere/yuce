"""Synthetic table regression only: no recorded run, Rust replay, model, network or process is used."""
import contextlib
import importlib.util
import io
import json
import pathlib
import sys
import tempfile
import unittest
from unittest import mock

source_path = pathlib.Path(__file__).resolve().parent / "replay_table.py"
spec = importlib.util.spec_from_file_location("reviewed_replay_table", source_path)
TABLE = importlib.util.module_from_spec(spec)
spec.loader.exec_module(TABLE)


class ReplayTableUnavailableRow(unittest.TestCase):
    def test_a_real_replay_error_row_keeps_its_reason_in_the_report(self):
        # This shape is produced by replay_wal::builder when the journal has a first answer but no matching WAL submission.
        reason = "no submission of this card in the WAL"
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            (root / "journal.jsonl").write_text("", encoding="utf-8")
            event = {"agent": "gb", "card": "Csynthetic", "outcome": "ERROR", "repairs": 0, "abandoned": True}
            (root / "events.jsonl").write_text(json.dumps(event) + "\n", encoding="utf-8")
            replay = root / "synthetic_replay.jsonl"
            replay.write_text(json.dumps({"card": "Csynthetic", "error": reason}) + "\n", encoding="utf-8")
            output = io.StringIO()
            with mock.patch.object(sys, "argv", ["replay_table.py", str(root), str(replay)]), contextlib.redirect_stdout(output):
                TABLE.main()
            report = output.getvalue()
        self.assertIn(reason, report,
                      "An unavailable builder comparison must keep its concrete error, rather than silently becoming None statuses")


if __name__ == "__main__":
    unittest.main()