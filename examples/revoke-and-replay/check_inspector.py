"""Check inspector.html against a report written by demo.py --report: the page makes no network requests, its content security
policy forbids them, its source is ASCII, and every report field it reads (the list in its `report-fields` block) is in the report.

usage: python check_inspector.py report.json     It exits 0 when every check passes, 1 otherwise. Standard library only."""
import json
import pathlib
import re
import sys

PAGE = pathlib.Path(__file__).resolve().parent / "inspector.html"
FORMAT = "yuce-no-llm-demo-report/1"
SVG_NAMESPACE = "http://www.w3.org/2000/svg"  # a name, never fetched
NETWORK = [r"https?://", r"//[a-z0-9.-]+\.[a-z]{2,}/", r"\bfetch\s*\(", r"XMLHttpRequest", r"WebSocket", r"EventSource", r"sendBeacon",
           r"\bimport\s*\(", r"@import", r"<link\b", r"<iframe\b", r"<img\b", r"\bsrc\s*=", r"url\s*\(", r"\.open\s*\(",
           # navigation and other requests the policy does not cover (review of PR #11)
           r"http-equiv\s*=\s*[\"']?refresh", r"\blocation\b\s*(=|\.\s*(href|assign|replace))", r"<a\b", r"<form\b", r"<base\b",
           r"<(object|embed|audio|video|source|track|picture|frame)\b", r"\bsrcset\b", r"\bping\s*=", r"\baction\s*=",
           r"\bnew\s+(Image|Worker|SharedWorker)\b", r"importScripts", r"\.src\s*=", r"@font-face", r"serviceWorker",
           r"RTCPeerConnection", r"\bhref\s*=", r"\bwss?://", r"image-set", r"\[\s*[\"']location[\"']\s*\]",
           r"setAttribute\s*\(\s*[\"'](href|src|action|srcset|ping)[\"']"]


def main() -> int:
    if len(sys.argv) != 2:
        print(__doc__)
        return 2
    page = PAGE.read_text(encoding="utf-8")
    report = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
    problems = []
    if not page.isascii():
        problems.append("the page has non-ASCII characters")
    bare = page.replace(SVG_NAMESPACE, "")
    for pattern in NETWORK:
        for m in re.finditer(pattern, bare, flags=re.I):
            line = bare.count("\n", 0, m.start()) + 1
            problems.append(f"line {line}: {m.group(0)!r} could reach the network")
    csp = re.search(r'<meta http-equiv="Content-Security-Policy" content="([^"]+)">', page)
    policy = csp.group(1) if csp else ""
    if ("default-src 'none'" not in policy or "form-action 'none'" not in policy or "base-uri 'none'" not in policy
            or re.search(r"connect-src|https?:", policy)):
        problems.append("the content security policy must be default-src 'none', form-action 'none' and base-uri 'none', no source allowed")
    if report.get("format") != FORMAT:
        problems.append(f"report format {report.get('format')!r}, expected {FORMAT!r}")
    block = re.search(r'<script type="application/json" id="report-fields">(.*?)</script>', page, flags=re.S)
    fields = json.loads(block.group(1)) if block else []
    if not fields:
        problems.append("the page lists no report fields")
    for path in fields:
        node = report
        for key in path.split("."):
            node = node.get(key) if isinstance(node, dict) else None
        if node is None:
            problems.append(f"the report lacks {path}, which the page reads")
    for p in problems:
        print("  " + p)
    print(f"inspector.html: {len(fields)} report fields, {'OK' if not problems else f'{len(problems)} problem(s)'}")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
