"""YuCe Live (examples/live-journal): the template passes its own check and the check bites, and the generator reads the standing
periods of a PROV export as the kernel wrote them. The demo itself, with the page checked against the kernel at every frame, runs in
CI as a step of its own, since it needs the built binary."""
import json
import pathlib
import subprocess
import sys
import tempfile
import unittest

EXAMPLE = pathlib.Path(__file__).resolve().parent.parent / "examples" / "live-journal"
SAMPLE = EXAMPLE.parent / "prov-export" / "sample.prov.jsonld"
sys.path.insert(0, str(EXAMPLE))
import make_page  # noqa: E402


def check(*args) -> subprocess.CompletedProcess:
    return subprocess.run([sys.executable, str(EXAMPLE / "check_page.py"), *args], capture_output=True, text=True)


class TemplateCheck(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

    def made(self, data: str) -> pathlib.Path:
        page = (EXAMPLE / "page.html").read_text(encoding="utf-8").replace("/*DATA*/null", data)
        path = pathlib.Path(self.tmp.name) / f"page{len(list(pathlib.Path(self.tmp.name).iterdir()))}.html"
        path.write_text(page, encoding="utf-8")
        return path

    def test_the_template_passes(self):
        out = check()
        self.assertEqual(out.returncode, 0, out.stdout)

    def test_a_template_that_could_fool_check_states_is_refused(self):
        page = (EXAMPLE / "page.html").read_text(encoding="utf-8")
        nl = chr(10)
        cases = {
            "a second stateAt after the markers": page.replace(
                "// END stateAt", "// END stateAt" + nl + "function stateAt(f) { return { gone: {}, never: new Set(), here: new Set() }; }"),
            "a state that does not come from stateAt": page.replace("  S = stateAt(F);", "  S = { gone: {}, never: new Set(), here: new Set() };"),
            "a second pair of markers": page.replace("// END stateAt", "// END stateAt" + nl + "// BEGIN stateAt" + nl + "// END stateAt"),
            "stateAt reassigned": page.replace("let S = stateAt(F);", "let S = stateAt(F); stateAt = () => S;"),
        }
        for name, text in cases.items():
            self.assertNotEqual(text, page, name)
            path = pathlib.Path(self.tmp.name) / "template.html"
            path.write_text(text, encoding="utf-8")
            self.assertEqual(check("--template", str(path)).returncode, 1, name)

    def test_a_made_page_with_its_data_passes_and_a_bad_one_does_not(self):
        good = json.dumps({"format": make_page.FORMAT, "verify": {"status": "VERIFIED"}})
        self.assertEqual(check(str(self.made(good))).returncode, 0)
        script_end = json.dumps({"format": make_page.FORMAT, "verify": {"status": "VERIFIED"}, "t": "</script><script>alert(1)"})
        out = check(str(self.made(script_end)))
        self.assertEqual(out.returncode, 1, out.stdout)
        self.assertIn("could end the script", out.stdout)
        refused = json.dumps({"format": make_page.FORMAT, "verify": {"status": "REFUSED"}})
        self.assertEqual(check(str(self.made(refused))).returncode, 1)
        changed = self.made(good)
        changed.write_text(changed.read_text(encoding="utf-8").replace("<title>YuCe Live</title>", "<title>Other</title>"), encoding="utf-8")
        self.assertEqual(check(str(changed)).returncode, 1)


class Periods(unittest.TestCase):
    def test_the_kernel_state_of_each_record_is_read_from_its_periods(self):
        graph = json.loads(SAMPLE.read_text(encoding="utf-8"))["@graph"]
        state = make_page.kernel_states(graph)
        records = {n["yuce:recordId"] for n in graph if "yuce:Record" in n["@type"]}
        self.assertEqual(set(state), records, "every record of the export has a state")
        for rid, (st, end, why, by) in state.items():
            periods = [n for n in graph if "yuce:Standing" in n["@type"] and n["prov:specializationOf"].endswith(rid)]
            if not periods:
                self.assertEqual((st, end, why, by), ("never", None, None, []), rid)
            elif any("prov:wasInvalidatedBy" not in p for p in periods):
                self.assertEqual(st, "stands", rid)
            else:
                self.assertEqual(st, "ended", rid)
                self.assertIn(why, ("withdrawn", "new_version", "basis", "answer"))
                self.assertEqual(end, max(int(p["prov:wasInvalidatedBy"].rsplit(":", 1)[1]) for p in periods))
                self.assertEqual(bool(by), why == "basis", rid)

    def test_the_page_state_of_a_record_at_a_frame(self):
        periods = [[2, 5, "basis", ["q1"]], [7, None, None, []]]  # stood 2..4, fell at 5, stood again from 7
        self.assertIsNone(make_page.page_state(periods, 2, 1), "not handed in yet")
        self.assertEqual(make_page.page_state(periods, 2, 4), ["stands", None, None, []])
        self.assertEqual(make_page.page_state(periods, 2, 5), ["ended", 5, "basis", ["q1"]])
        self.assertEqual(make_page.page_state(periods, 2, 6), ["ended", 5, "basis", ["q1"]])
        self.assertEqual(make_page.page_state(periods, 2, 7), ["stands", None, None, []])
        self.assertEqual(make_page.page_state([], 3, 9), ["never", None, None, []], "accepted, but the kernel gave it no period")


if __name__ == "__main__":
    unittest.main()
