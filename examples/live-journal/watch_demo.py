"""No-LLM demo for `sbgk audit-watch`: the YuCe Live page follows a journal while a server writes it.

The script starts `sbgk audit-watch` on a journal that does not exist yet, then plays the run of demo.py (three readers and an
owner, no model, no API key) against the real `sbgk audit-serve`, and looks at the watched page after each part of the run:
1. before the run the page waits for the journal;
2. during the run the page has every frame written so far, it says a writer holds the journal, and it gets only what changed
   since the frames it already had;
3. after the withdrawal, and at the end, the data of the watched page equals the data make_page.py makes from the same frames,
   which is compared with `sbgk audit-prov --upto` at every frame;
4. when the server is gone, the page says no writer holds the journal;
5. the page is the template of the recorded page with its data, a policy that allows requests to its own server only, and the
   script that asks that server; the server answers GET under this computer's own names only;
6. a journal with a damaged frame is shown up to the frame before it, and the page says which frame does not pass.
With Node.js on the PATH, check_live.mjs then runs the page's own merge and stateAt on what the server sent.

usage: python watch_demo.py [--bin path/to/sbgk] [--keep] [--hold] [--slow SECONDS]
--slow waits that long before each step of the run, so that the page can be looked at in a browser while the run goes: the
script prints the address of the page and waits ten seconds before the run starts.
--hold keeps the watched page up after the run until Enter is pressed.
It exits 0 when every step behaves as described, 1 otherwise. Python 3.10+, standard library only."""
import argparse
import http.client
import json
import pathlib
import shutil
import subprocess
import sys
import tempfile
import threading
import time

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import demo  # noqa: E402
from make_page import find_binary  # noqa: E402

NOTE = "A scripted demo: three agents and an owner, played by a script, with no model. The documents are made up."
POLICY = "default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; base-uri 'none'; form-action 'none'"
POLICY_LIVE = POLICY.replace("base-uri", "connect-src 'self'; base-uri")


class Watch:
    """A running `sbgk audit-watch` and requests to it."""

    def __init__(self, binary: pathlib.Path, wal: pathlib.Path, *more: str):
        self.proc = subprocess.Popen([str(binary), "audit-watch", "--wal", str(wal), "--listen", "127.0.0.1:0", "--every-ms", "50", *more],
                                     stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, encoding="utf-8")
        first = self.proc.stdout.readline()
        if not first:
            raise RuntimeError(f"audit-watch did not start: {self.proc.stderr.read()[:600]}")
        threading.Thread(target=self.proc.stdout.read, daemon=True).start()
        self.url = json.loads(first)["url"]
        self.port = int(self.url.rsplit(":", 1)[1].strip("/"))

    def get(self, path: str, host: str | None = None, method: str = "GET") -> tuple[int, str]:
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=30)
        conn.putrequest(method, path, skip_host=True)
        conn.putheader("Host", host or f"127.0.0.1:{self.port}")
        conn.endheaders()
        reply = conn.getresponse()
        body = reply.read().decode("utf-8")
        conn.close()
        return reply.status, body.replace("\r\n", "\n")

    def json(self, path: str) -> dict:
        return json.loads(self.get(path)[1])

    def until(self, test, seconds: float = 30.0) -> dict:
        """The status once `test(status)` holds; the last status when it never does."""
        end = time.monotonic() + seconds
        while True:
            status = self.json("/status")["status"]
            if test(status) or time.monotonic() > end:
                return status
            time.sleep(0.05)

    def stop(self) -> None:
        self.proc.kill()
        self.proc.wait()


def data_of(page: str) -> dict:
    """The data a page holds, as check_states.mjs takes it."""
    start = page.index("const D = ") + len("const D = ")
    return json.loads(page[start:page.index(";\n", start)])


def frames_in(wal: pathlib.Path) -> int:
    return wal.read_bytes().count(b"\n")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--bin", help="path to the sbgk (or yuce) binary")
    ap.add_argument("--keep", action="store_true", help="keep the work folder with the journal, the pages and what the server sent")
    ap.add_argument("--hold", action="store_true", help="keep the watched page up after the run until Enter is pressed")
    ap.add_argument("--slow", type=float, default=0.0, metavar="SECONDS", help="wait this long before each step of the run, to watch the page meanwhile")
    a = ap.parse_args()
    binary = find_binary(a.bin)
    work = pathlib.Path(tempfile.mkdtemp(prefix="yuce_watch_demo_"))
    tokens = demo.setup(work)
    wal = work / "run.wal"
    step = demo.step
    template = (HERE / "page.html").read_text(encoding="utf-8")
    watch = Watch(binary, wal, "--docs", str(work / "repo"), "--note", NOTE)
    print(f"YuCe Live watch demo: the page follows the journal of a scripted run\n  binary {binary}\n  journal {wal}\n  page {watch.url}")
    good, others = True, []
    held = {"frames": 0, "epoch": None, "page": None, "deltas": []}
    if a.slow > 0:
        call = demo.Agent.call

        def slowly(agent, tool, **arguments):
            time.sleep(a.slow)
            return call(agent, tool, **arguments)

        demo.Agent.call = slowly
        print(f"  open {watch.url} in a browser now: the run starts in ten seconds and takes about {round(a.slow * 45)} seconds", flush=True)
        time.sleep(10)

    def made_by_make_page(name: str) -> dict:
        """The data make_page.py makes from the frames written so far, compared with audit-prov --upto at every frame."""
        copy = work / f"{name}.wal"
        shutil.copyfile(wal, copy)
        out = subprocess.run([sys.executable, str(HERE / "make_page.py"), "--wal", str(copy), "--out", str(work / f"{name}.html"),
                              "--docs", str(work / "repo"), "--bin", str(binary), "--check", "all", "--note", NOTE,
                              "--states", str(work / f"{name}.states.json")], capture_output=True, text=True, encoding="utf-8")
        if out.returncode != 0:
            raise RuntimeError(f"make_page.py on the journal at '{name}': {out.stderr.strip()[:400]}")
        return data_of((work / f"{name}.html").read_text(encoding="utf-8"))

    def same(watched: dict, made: dict) -> list:
        """The fields in which the data of the watched page and of the recorded page differ. `checked` says how a recorded page
        was compared when it was made, and a watched page has no such comparison of its own."""
        return sorted(k for k in set(watched) | set(made) if k != "checked" and watched.get(k) != made.get(k))

    def stage(name: str) -> bool:
        ok = True
        written = frames_in(wal)
        status = watch.until(lambda s: s["frames"] == written and not s["more"] and s["writer"] == (name != "stopped"))
        if name == "stopped":
            ok &= step(f"the server is gone: the page says no writer holds the journal ({status['mode']}, {status['frames']} frames)",
                       status["mode"] == "recorded" and status["frames"] == written)
        else:
            ok &= step(f"after '{name}': the page has the {written} frames written, and a writer holds the journal ({status['mode']})",
                       status["mode"] == "live" and status["frames"] == written and status["pending"] == 0)
        if held["page"] is None:
            code, page = watch.get("/")
            held["page"] = page
            (work / "watched_first.html").write_text(page, encoding="utf-8", newline="\n")
            first = data_of(page)
            held["frames"], held["epoch"] = len(first["frames"]), first["live"]["epoch"]
            plain = page.replace(POLICY_LIVE, POLICY, 1)
            script = plain.rfind("<script>")
            plain = plain[:script] + plain[plain.index("</script>\n", script) + len("</script>\n"):]
            head, tail = template.split("/*DATA*/null", 1)
            body = plain[len(head):len(plain) - len(tail)]
            ok &= step("the watched page is the template with its data, a policy for its own server only, and the script that asks it",
                       code == 200 and page.count(POLICY_LIVE) == 1 and plain.startswith(head) and plain.endswith(tail)
                       and body.isascii() and "<" not in body and "delta?epoch=" in page[script:])
        else:
            reply = watch.json(f"/delta?epoch={held['epoch']}&frames={held['frames']}")
            delta = reply.get("delta") or {}
            new = len(delta.get("frames", []))
            born = {k for k, v in list(delta.get("quotes", {}).items()) + list(delta.get("recs", {}).items()) if v["f"] >= held["frames"]}
            changed = set(delta.get("quotes", {})) | set(delta.get("recs", {}))
            ok &= step(f"the page is sent what changed since its {held['frames']} frames: {new} frames, {len(born)} new records, "
                       f"{len(changed - born)} changed ones, the periods of {len(delta.get('periods', {}))}",
                       not reply.get("reset") and delta.get("from") == held["frames"] and held["frames"] + new == written
                       and all(v["f"] < held["frames"] for k, v in list(delta["quotes"].items()) + list(delta["recs"].items()) if k not in born))
            held["deltas"].append(delta)
            held["frames"] += new
        if name in ("withdrawn", "stopped"):
            diff = same(watch.json("/data"), made_by_make_page(name.replace(" ", "_")))
            ok &= step(f"after '{name}': the data of the watched page equals the data make_page.py makes from the same {written} frames"
                       + (f"; they differ in {diff}" if diff else ""), not diff)
        return ok

    try:
        code, page = watch.get("/")
        status = watch.json("/status")["status"]
        good &= step(f"before the run the page waits for the journal ({status['mode']})",
                     code == 200 and "Waiting for the first frame" in page and status["mode"] == "waiting" and status["frames"] == 0)
        good &= demo.play(binary, work, tokens, stage)
        if good:
            (work / "deltas.json").write_text(json.dumps(held["deltas"]), encoding="utf-8")
            final = watch.json("/data")
            (work / "final.json").write_text(json.dumps(final), encoding="utf-8")
            good &= step("a page that holds every frame is sent no frame", watch.json(f"/delta?epoch={held['epoch']}&frames={held['frames']}")
                         .get("delta", {}).get("frames") == [])
            good &= step("a page of another reading, or with more frames than were read, is told to take the data whole",
                         watch.json(f"/delta?epoch={held['epoch'] + 1}&frames={held['frames']}").get("reset") is True
                         and watch.json(f"/delta?epoch={held['epoch']}&frames={held['frames'] + 1}").get("reset") is True)
            refused = [watch.get("/", host="example.org")[0], watch.get("/data", host=f"example.org:{watch.port}")[0], watch.get("/", method="POST")[0],
                       watch.get("/nothing")[0]]
            good &= step(f"the server answers GET under this computer's own names only: {refused}", refused == [403, 403, 405, 404])
            good &= step("it answers under localhost too", watch.get("/status", host=f"localhost:{watch.port}")[0] == 200)

            # a journal with a damaged frame: the page shows the frames before it and says which frame does not pass
            lines = wal.read_bytes().splitlines(keepends=True)
            at = len(lines) // 2
            lines[at] = lines[at].replace(b'"actor":"', b'"actor":"x', 1)
            (work / "damaged.wal").write_bytes(b"".join(lines))
            others.append(Watch(binary, work / "damaged.wal"))
            status = others[-1].until(lambda s: s["mode"] == "broken")
            shown = len(others[-1].json("/data")["frames"])
            good &= step(f"a journal whose frame {at} was changed: the page shows the {shown} frames before it and says frame "
                         f"{(status.get('broken') or {}).get('frame')} does not pass",
                         status["mode"] == "broken" and status["broken"]["frame"] == at and status["frames"] == at and shown == at)

            # a file that is no journal: no frame to show, and the page that waits says why
            (work / "not_a_journal.wal").write_text("this is not a journal\n", encoding="utf-8")
            others.append(Watch(binary, work / "not_a_journal.wal"))
            status = others[-1].until(lambda s: s["mode"] == "broken")
            code, page = others[-1].get("/")
            good &= step(f"a file that is no journal: no frame is shown, and the page says frame {(status.get('broken') or {}).get('frame')} does not pass",
                         status["mode"] == "broken" and status["frames"] == 0 and status["broken"]["frame"] == 0 and code == 200
                         and "does not pass the checks of a journal" in page)

            node = shutil.which("node")
            if node:
                out = subprocess.run([node, str(HERE / "check_live.mjs"), str(work / "watched_first.html"), str(work / "deltas.json"),
                                      str(work / "final.json"), str(work / "stopped.states.json")], capture_output=True, text=True, encoding="utf-8")
                good &= step(f"the page's own script on what the server sent: {out.stdout.strip().splitlines()[-1] if out.stdout.strip() else out.stderr.strip()[:300]}",
                             out.returncode == 0)
            else:
                print("  [skipped] no Node.js on the PATH: the page's own script was not run on what the server sent")
        if a.hold:
            input(f"  the watched page stays up at {watch.url} until Enter is pressed here ")
    except (RuntimeError, KeyError, OSError, ValueError) as e:
        good = step(f"the demo stopped: {type(e).__name__}: {e}", False)
    finally:
        for w in (watch, *others):
            w.stop()
    if a.keep:
        print(f"  work folder kept: {work}")
    else:
        shutil.rmtree(work, ignore_errors=True)
    print("OK: sbgk audit-watch --wal <run.wal> serves this page for any journal" if good else "FAILED")
    return 0 if good else 1


if __name__ == "__main__":
    sys.exit(main())
