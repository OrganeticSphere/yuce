"""The open runner without the closed layer (sbgk_bench.closed, which the public snapshot leaves out): each option or model that
needs it stops with one message, the DeepSeek key comes from the environment, the Antigravity CLI from AGY_BIN or PATH. Offline:
no model or provider is called."""
from __future__ import annotations

import contextlib
import importlib
import io
import os
import pathlib
import sys
import tempfile
import unittest
import uuid
from unittest import mock

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from sbgk_bench import pilot_ac as P  # noqa: E402
import run_pilot_ac as R  # noqa: E402


def absent(feature=None):
    """closed_layer as it answers when the package is not installed."""
    if feature is not None:
        raise P.ClosedLayerMissing(P.closed_missing(feature))
    return None


class Boundary(unittest.TestCase):
    def test_the_package_is_found_only_where_it_is(self):
        present = (pathlib.Path(P.__file__).parent / "closed" / "__init__.py").is_file()
        self.assertEqual(P.closed_layer() is not None, present)
        if not present:
            with self.assertRaisesRegex(P.ClosedLayerMissing, r"^Jev needs the closed layer \(benchmarks/sbgk_bench/closed\)"):
                P.closed_layer("Jev")

    def test_only_a_missing_package_is_absent(self):
        # on temporary packages in place of sbgk_bench.closed: an error inside the package surfaces; a directory without its
        # __init__.py (a leftover __pycache__, claude-reviewer's D01 on PR 6) is a namespace package and counts as absent
        with tempfile.TemporaryDirectory() as tmp:
            root, tag = pathlib.Path(tmp), uuid.uuid4().hex
            broken, leftover, whole = (f"closed_{kind}_{tag}" for kind in ("broken", "leftover", "whole"))
            (root / broken).mkdir()
            (root / broken / "__init__.py").write_text("raise ImportError('a defect inside the closed layer')\n", encoding="utf-8")
            (root / leftover / "__pycache__").mkdir(parents=True)
            (root / leftover / "__pycache__" / "jev.cpython-313.pyc").write_bytes(b"stale")
            (root / whole).mkdir()
            (root / whole / "__init__.py").write_text("MODELS = {}\n", encoding="utf-8")
            sys.path.insert(0, tmp)
            importlib.invalidate_caches()
            try:
                with mock.patch.object(P, "CLOSED_PACKAGE", broken):
                    for feature in (None, "Jev"):
                        with self.assertRaisesRegex(ImportError, "a defect inside the closed layer"):
                            P.closed_layer(feature)
                with mock.patch.object(P, "CLOSED_PACKAGE", leftover):
                    self.assertIsNone(P.closed_layer())
                    with self.assertRaisesRegex(P.ClosedLayerMissing, "^Jev needs the closed layer"):
                        P.closed_layer("Jev")
                with mock.patch.object(P, "CLOSED_PACKAGE", whole):
                    self.assertEqual(P.closed_layer().__name__, whole)
            finally:
                sys.path.remove(tmp)
                for name in (broken, leftover, whole):
                    sys.modules.pop(name, None)

    def main(self, *args: str) -> tuple[int | str | None, str]:
        err = io.StringIO()
        argv = ["pilot", "--manifest", "m", "--repo", "r", *args]
        with mock.patch.object(P, "closed_layer", side_effect=absent), mock.patch.dict(P.__dict__), \
                mock.patch.object(sys, "argv", argv), mock.patch.object(R.C, "BIN", pathlib.Path(__file__)), \
                mock.patch.object(R, "run", side_effect=AssertionError("no run may start")), \
                contextlib.redirect_stderr(err), contextlib.redirect_stdout(io.StringIO()):
            with self.assertRaises(SystemExit) as stop:
                R.main()
        return stop.exception.code, err.getvalue()

    def test_an_option_of_the_closed_layer_stops_with_one_message(self):
        for args in (["--jev"], ["--jev-key-file", "key.txt"], ["--jev-mode", "footer"], ["--jev-mode=footer"]):
            with self.subTest(args=args):
                code, err = self.main("--model", "stub", *args)
                option = args[0].split("=")[0]
                self.assertEqual(code, 2)
                self.assertIn(f"{option} needs the closed layer (benchmarks/sbgk_bench/closed)", err)
                self.assertNotIn("unrecognized arguments", err)

    def test_a_model_of_the_closed_layer_stops_before_any_work(self):
        for args in (["--model", "gemini-lite"], ["--model", "stub", "--builder-model", "gemini-lite-openclaw"],
                     ["--model", "stub", "--team-models", "stub, gemini-lite,stub"], ["--model", "stub", "--checker-model", "gemini-lite"],
                     ["--model", "stub", "--circles-refiner", "gemini-lite-openclaw"], ["--model", "stub", "--team", "gemini-lite"]):
            with self.subTest(args=args):
                code, _ = self.main(*args)
                self.assertRegex(str(code), r"^the model gemini-lite(-openclaw)? needs the closed layer")
        with mock.patch.object(P, "closed_layer", side_effect=absent):
            with self.assertRaisesRegex(P.ClosedLayerMissing, "the model gemini-lite needs the closed layer"):
                P.make_model("gemini-lite")
            self.assertIsInstance(P.make_model("stub"), P.StubModel)

    def test_a_run_without_reports_names_what_to_give(self):
        code, _ = self.main("--model", "stub")
        self.assertIn("give the corpus by --reports with its --checklist and --withdrawal-plan", str(code))

    def test_the_deepseek_key_comes_from_the_environment(self):
        env = {k: v for k, v in os.environ.items() if k != "DEEPSEEK_API_KEY"}
        with mock.patch.object(P, "closed_layer", side_effect=absent), mock.patch.dict(os.environ, env, clear=True):
            with self.assertRaisesRegex(RuntimeError, r"^no DeepSeek API key: set DEEPSEEK_API_KEY$"):
                P.deepseek_key()
            with mock.patch.dict(os.environ, {"DEEPSEEK_API_KEY": "env-key"}):
                self.assertEqual(P.deepseek_key(), "env-key")
                self.assertEqual(P.DeepSeekModel()._key, "env-key")


class Antigravity(unittest.TestCase):
    def test_the_cli_is_agy_bin_else_agy_on_path(self):
        env = {k: v for k, v in os.environ.items() if k != "AGY_BIN"}
        with mock.patch.dict(os.environ, env, clear=True):
            with mock.patch.object(P.shutil, "which", return_value="/opt/agy/bin/agy") as which:
                self.assertEqual(P.agy_exe(), "/opt/agy/bin/agy")
                which.assert_called_with("agy")
            with mock.patch.object(P.shutil, "which", return_value=None):
                with self.assertRaisesRegex(RuntimeError, "set AGY_BIN to its executable or put agy on PATH"):
                    P.agy_exe()
                with mock.patch.dict(os.environ, {"AGY_BIN": "/custom/agy"}):
                    self.assertEqual(P.agy_exe(), "/custom/agy")

    def test_a_call_runs_the_cli_it_found(self):
        seen = []

        def stream(cmd, line, cwd, timeout_s):
            seen.append(cmd)
            return {"status": "SUCCESS", "response": "ok", "usage": {"input_tokens": 1, "output_tokens": 1, "thinking_tokens": 0}}, 0, {}

        with mock.patch.dict(os.environ, {"AGY_BIN": "/custom/agy"}), mock.patch("sbgk_bench.agy_stream.run_stream", side_effect=stream):
            text, usage, cost = P.AgyModel("flash-low", timeout_s=5).complete("task")
        self.assertEqual((text, cost, seen[0][0]), ("ok", None, "/custom/agy"))
        self.assertNotIn("AppData", " ".join(seen[0]))

    def test_a_run_with_an_agy_model_and_no_cli_stops_before_any_work(self):
        env = {k: v for k, v in os.environ.items() if k != "AGY_BIN"}
        argv = ["pilot", "--manifest", "m", "--repo", "r", "--model", "agy:flash-low"]
        with mock.patch.dict(os.environ, env, clear=True), mock.patch.object(P.shutil, "which", return_value=None), \
                mock.patch.dict(P.__dict__), mock.patch.object(sys, "argv", argv), mock.patch.object(R.C, "BIN", pathlib.Path(__file__)), \
                mock.patch.object(R, "corpus_choice", return_value=(["x"], {"steps": []}, "")), \
                mock.patch.object(R, "run", side_effect=AssertionError("no run may start")):
            with self.assertRaises(SystemExit) as stop:
                R.main()
        self.assertIn("set AGY_BIN to its executable or put agy on PATH", str(stop.exception.code))


if __name__ == "__main__":
    unittest.main()
