"""The benchmark helpers read `sbgk verify`'s verdict, also when a check fails. Since 0.1.1 verify exits 1 on a failed check
(it exited 0 before); the tamper-attack experiment (exp6) and the continuity run verify tampered or legacy containers and
read `"ok"`, so their CLI wrappers must take exit 1 from verify as an answer, and keep every other non-zero exit a failure.
Needs the kernel binary; no provider is called."""
from __future__ import annotations

import pathlib
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from sbgk_bench import common as C  # noqa: E402

QUICKSTART = C.ROOT / "examples" / "quickstart"


def container(out: pathlib.Path) -> pathlib.Path:
    applied = C.cli("apply", "--ontology", QUICKSTART / "ontology.json", "--docs", QUICKSTART / "docs",
                    "--stream", QUICKSTART / "stream.jsonl", "--out", out)
    assert applied["error"] is None, applied
    return out


class VerifyVerdict(unittest.TestCase):
    def test_wrapper_returns_the_verdict_of_a_failed_check(self):
        self.assertTrue(C.BIN.is_file(), "built kernel required")
        with tempfile.TemporaryDirectory(prefix="cli-verdict-") as tmp:
            sound = container(pathlib.Path(tmp) / "sound.sbgk")
            self.assertIs(C.cli("verify", sound)["ok"], True)
            data = bytearray(sound.read_bytes())
            data[len(data) // 2] ^= 1
            tampered = pathlib.Path(tmp) / "tampered.sbgk"
            tampered.write_bytes(bytes(data))
            # the process says "check failed" by its exit code; the wrapper hands the verdict to the caller
            self.assertEqual(subprocess.run([str(C.BIN), "verify", str(tampered)], capture_output=True).returncode, 1)
            verdict = C.cli("verify", tampered)
            self.assertIs(verdict["ok"], False)
            self.assertTrue(verdict["kind"])

    def test_usage_error_and_other_commands_still_fail(self):
        self.assertTrue(C.BIN.is_file(), "built kernel required")
        with self.assertRaises(RuntimeError):
            C.cli("verify")  # no container: exit 2, a usage error, not a verdict
        failed = subprocess.CompletedProcess([], 1, stdout='{"ok": false}', stderr="boom")
        with mock.patch.object(C.subprocess, "run", return_value=failed), self.assertRaises(RuntimeError):
            C.cli("apply", "x")  # exit 1 is a verdict only for verify
        silent = subprocess.CompletedProcess([], 1, stdout="", stderr="crash")
        with mock.patch.object(C.subprocess, "run", return_value=silent), self.assertRaises(RuntimeError):
            C.cli("verify", "x")  # exit 1 without a verdict on stdout is a crash

    def test_tamper_experiment_runs_and_catches_every_attack(self):
        # exp6 verifies hundreds of tampered containers; it stopped at the first one when verify began to exit 1
        self.assertTrue(C.BIN.is_file(), "built kernel required")
        from sbgk_bench import exp6

        result = exp6.run(quick=True)
        self.assertEqual(result["pass"], {k: True for k in result["pass"]})
        self.assertEqual(result["chain_recomputing_attacker"]["caught"], result["chain_recomputing_attacker"]["trials"])
        self.assertEqual(result["forged_chunk_with_consistent_hash"]["caught"],
                         result["forged_chunk_with_consistent_hash"]["trials"])

    def test_continuity_recorder_takes_the_same_rule(self):
        sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
        import run_exp1_continuity as E  # noqa: E402

        with tempfile.TemporaryDirectory(prefix="cli-verdict-rec-") as tmp:
            rec = E.CliRecorder(pathlib.Path(tmp))
            failed = subprocess.CompletedProcess([], 1, stdout='{"ok": false, "kind": "x"}', stderr="")
            with mock.patch.object(E.subprocess, "run", return_value=failed):
                self.assertIs(rec("verify", "c.sbgk")["ok"], False)
                with self.assertRaises(RuntimeError):
                    rec("update-doc", "c.sbgk")


if __name__ == "__main__":
    unittest.main()
