"""Argon follow-up: actual CLI defaults and fail-fast boundaries; no providers or server startup."""
from __future__ import annotations

import pathlib
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import run_pilot_ac as R
from sbgk_bench import pilot_ac as P


class VersionsReview(unittest.TestCase):
    def setUp(self):
        self.saved = {k:v for k,v in vars(P).items() if k.isupper()}

    def tearDown(self):
        vars(P).update(self.saved)

    def flags(self):
        return mock.patch.object(sys, "argv", ["run_pilot_ac.py", "--selftest", "--model", "stub", "--build-scope", "versions", "--whole-reader", "--workers", "1"])

    def test_argon_v05_real_whole_defaults_enable_relations_and_the_checker(self):
        # These values are set by the real CLI, before any selftest patching. Unknown --link-checker/--whole-links are not needed.
        with self.flags(), mock.patch.object(R.C, "BIN", pathlib.Path(__file__)), mock.patch("sbgk_bench.versions_selftest.run"):
            try:
                R.main()
            except SystemExit as e:
                self.assertIn("--whole-reader", str(e))
        self.assertTrue(P.WHOLE_LINKS)
        self.assertTrue(P.LINK_CHECKER)

    def test_argon_v05_cached_whole_summary_profile_is_refused_before_execution(self):
        with self.flags(), mock.patch.object(R.C, "BIN", pathlib.Path(__file__)), mock.patch("sbgk_bench.versions_selftest.run") as execute:
            with self.assertRaisesRegex(SystemExit, "--whole-reader.*versions|versions.*--whole-reader"):
                R.main()
            execute.assert_not_called()

    def test_argon_v05_direct_kernel_cannot_bypass_the_cli_profile_restriction(self):
        with tempfile.TemporaryDirectory() as tmp, mock.patch.multiple(P, BUILD_SCOPE="versions", WHOLE_READER=True), mock.patch.object(P.subprocess,"Popen",side_effect=AssertionError("must refuse before spawning")):
            root=pathlib.Path(tmp)/"kernel"
            with self.assertRaisesRegex(ValueError, "whole.reader.*versions|versions.*whole.reader"):
                P.Kernel(root,pathlib.Path(tmp)/"manifest.json",pathlib.Path(tmp),[],"test",1)
            self.assertFalse(root.exists())


if __name__ == "__main__":
    unittest.main()
