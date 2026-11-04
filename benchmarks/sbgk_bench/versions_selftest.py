"""Real kernel + selected executor, deterministic stub only. Keeps evidence when --out is supplied."""
from __future__ import annotations

import contextlib
import hashlib
import json
import pathlib
import tempfile
from unittest import mock

from . import pilot_ac as P


def run(out: pathlib.Path | None = None, *, whole: bool = False) -> dict:
    if whole:
        raise ValueError("whole-reader is not supported with build scope versions")
    with contextlib.ExitStack() as stack:
        if out is None:
            root = pathlib.Path(stack.enter_context(tempfile.TemporaryDirectory(prefix="r2r_versions_")))
        else:
            root = out.resolve()
            root.mkdir(parents=True, exist_ok=False)
        docs = {"reports/old.md": "# Rule\nThe version mismatch is warning only.\n",
                "reports/new.md": "# Rule\nThe version mismatch is now blocking.\n",
                "reports/log.md": "# Changelog\nThe blocking rule supersedes the warning rule.\n"}
        entries = []
        for path, text in docs.items():
            dest = root / "repo" / path
            dest.parent.mkdir(parents=True, exist_ok=True)
            raw = text.encode()
            dest.write_bytes(raw)
            entries.append(dict(path=path, extension=".md", corpus_role="markdown_document_candidate", size_bytes=len(raw),
                                raw_sha256=hashlib.sha256(raw).hexdigest(), references=dict(commit_candidates=[], pull_request_candidates=[])))
        manifest = root / "manifest.json"
        manifest.write_text(json.dumps(dict(format="r2r.tobi_corpus_metadata_manifest.v1", entries=entries,
                                          source=dict(origin_recorded="https://example.invalid/versions.git", commit="1" * 40))), encoding="utf-8")
        ids = {path: id for id, path in P.source_document_paths(manifest.read_bytes(), docs).items()}
        doc = lambda p: dict(doc_id=ids[p], raw_sha256=hashlib.sha256(docs[p].encode()).hexdigest())
        lineage = {"lineages":[{"id":"explicit-test-product","snapshots":[
            {"id":"v1","docs":[doc("reports/old.md")],"changelog":[]},
            {"id":"v2","docs":[doc("reports/new.md")],"changelog":[doc("reports/log.md")]}]}]}
        linefile = root / "lineage.json"
        linefile.write_text(json.dumps(lineage), encoding="utf-8")
        stack.enter_context(mock.patch.multiple(P, BUILD_SCOPE="versions", VERSION_LINEAGE=linefile, DYNAMIC_ROLES=not whole,
                            CIRCLES=not whole, CIRCLES_REFINER=None, WAVE_SECTIONS=3, ONTOLOGY_REVISIONS=False,
                            ONTOLOGY_REVIEW=False, GRAPH_QUALITY={}, LINK_CHECKER=whole,
                            WHOLE_READER=whole, WHOLE_STEPS=False, WHOLE_LINKS=True, BUILDER_REQUESTS=0, MAX_LINES=32,
                            QUESTIONS=[dict(id="RQ1", text="What is the version mismatch rule?", about=["version mismatch"])],
                            ACQUIRE_WAIT_MS=200))
        try:
            result = P.run_arm_c(P.StubModel(), P.StubModel(), root / "kernel", manifest, root / "repo", list(docs), docs,
                                {"quote":"The version mismatch is now blocking.","report":"reports/new.md"},
                                workers=1 if whole else 3, timeout_s=60, max_calls=300,
                                team=None if whole else [P.StubModel() for _ in range(3)])
        finally:
            P.executors.close()
        (root / "result.json").write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
        for phase in ("phase1", "phase2"):
            assert result[phase]["receipt"]["status"] == "TERMINAL", result[phase]
        events = result["events"]
        assert any(e.get("kind") == "CHANGE" and e.get("outcome") == "COMMITTED" for e in events), events
        assert any(e.get("kind") == "VERIFY_LINK" and e.get("outcome") == "COMMITTED" for e in events), events
        assert not any(e.get("kind") == "BUILD" or e.get("agent") == "gb" or e.get("circle_phase") == "BUILD" for e in events), events
        summary = dict(selftest="versions-ok", executor=P.executors.EXECUTOR, whole_reader=whole,
                       phase1=result["phase1"]["receipt"]["status"], phase2=result["phase2"]["receipt"]["status"],
                       change_tasks=sum(e.get("kind") == "CHANGE" and e.get("outcome") == "COMMITTED" for e in events),
                       no_builder=True, no_build_barrier=True)
        print(json.dumps(summary))
        return summary
