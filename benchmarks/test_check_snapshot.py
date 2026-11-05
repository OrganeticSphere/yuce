"""scripts/check_snapshot.py on small snapshots built in a temporary folder (Codex's review of the 0.1.0 package, D03 and P3):
a secret-looking value is a placeholder only when the whole value has a placeholder's shape; the internal report family is
found by its glob; the version is read from Cargo.toml and Cargo.lock, not from a comment; a word of what stays out of a snapshot is
refused in any case. Offline, standard library only."""
from __future__ import annotations

import importlib.util
import pathlib
import tempfile
import unittest

SCRIPT = pathlib.Path(__file__).resolve().parents[1] / "scripts" / "check_snapshot.py"
spec = importlib.util.spec_from_file_location("check_snapshot", SCRIPT)
CS = importlib.util.module_from_spec(spec)
spec.loader.exec_module(CS)


def snapshot(root: pathlib.Path, extra: dict[str, str] | None = None, version: str = "0.1.0") -> pathlib.Path:
    files = {name: "x\n" for name in CS.REQUIRED}
    files["Cargo.toml"] = f'[workspace]\nmembers = []\n\n[workspace.package]\nversion = "{version}"\n'
    files["Cargo.lock"] = "".join(f'[[package]]\nname = "{n}"\nversion = "{version}"\n\n' for n in CS.OWN_PACKAGES)
    files.update(extra or {})
    for rel, text in files.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text, encoding="utf-8")
    return root


class CheckSnapshot(unittest.TestCase):
    def problems(self, extra=None, version="0.1.0"):
        with tempfile.TemporaryDirectory() as tmp:
            return CS.check(snapshot(pathlib.Path(tmp), extra, version), "0.1.0")[0]

    def test_a_clean_snapshot_passes(self):
        self.assertEqual(self.problems(), [])

    def test_a_key_is_refused_even_with_a_placeholder_word_inside_it(self):
        # random-looking values without any real provider's key prefix, so that no secret scanner takes this file for a leak
        for value in ("Qx7A8vL9K2mP7zR3bQ4w", "Qx7A8vL9testK2mP7zR3bQ4w", "local-Qx7A8vL9K2mP7zR3b"):
            with self.subTest(value=value):
                found = self.problems({"config.json": '{"token": "%s"}\n' % value})
                self.assertTrue(any("'token' field" in p for p in found), found)

    def test_the_known_placeholders_pass(self):
        for value in ("replace-with-a-secret-1", "synthetic-swarm-token-0001", "not-a-subject-token", "<your-token>", "${SBGK_TOKEN}"):
            with self.subTest(value=value):
                self.assertEqual(self.problems({"README.md": 'x\n{"token": "%s"}\n' % value}), [])

    def test_the_internal_report_family_is_found_by_its_glob(self):
        found = self.problems({"SBGK_EXPERIMENT_REPORT_DIRECTIVE.md": "x\n"})
        self.assertIn("shipped SBGK_EXPERIMENT_REPORT_DIRECTIVE.md (internal or private)", found)

    def test_the_version_is_read_from_the_manifest_not_from_a_comment(self):
        found = self.problems({"Cargo.toml": '# version = "0.1.0"\n[workspace]\nmembers = []\n\n[workspace.package]\nversion = "1.1.0"\n'})
        self.assertIn("Cargo.toml: workspace.package.version is not 0.1.0", found)
        found = self.problems(version="1.1.0")
        self.assertIn("Cargo.lock: sbgk-cli is 1.1.0, not 0.1.0", found)

    def test_a_subjects_file_and_a_home_path_are_refused(self):
        home = "C:" + "\\" + "Users" + "\\" + "someone" + "\\" + "work"  # built here, so this file does not hold one itself
        found = self.problems({"run/arm_c/subjects.json": "{}\n", "notes.md": home + "\n"})
        self.assertTrue(any("subjects file" in p for p in found), found)
        self.assertTrue(any("home path" in p for p in found), found)

    def test_a_listed_word_is_refused_in_any_case(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            snapshot(root, {"notes.md": "x\nsee a Secret-Word here\n"})
            found, _, _ = CS.check(root, "0.1.0", ["secret-word"])
        self.assertEqual(found, ["notes.md:2: a word of what stays out of a snapshot"])

    def test_a_word_in_capitals_is_refused_only_in_that_case(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            snapshot(root, {"notes.md": "a Word here\nand a word here\nand a WORD here\n"})
            found, _, _ = CS.check(root, "0.1.0", ["WORD"])
        self.assertEqual(found, ["notes.md:3: a word of what stays out of a snapshot"])


if __name__ == "__main__":
    unittest.main()
