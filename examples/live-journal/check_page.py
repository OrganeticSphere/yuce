"""Check page.html, the template of YuCe Live, and optionally a page made from it: the template makes no network requests and its
content security policy forbids them, its source is ASCII, it has one place for the data; a made page is the template with a
JSON object of format yuce-live-journal/1 in that place and nothing else changed.

usage: python check_page.py [made_page.html]     It exits 0 when every check passes, 1 otherwise. Standard library only."""
import json
import pathlib
import re
import sys

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "revoke-and-replay"))
from check_inspector import NETWORK, SVG_NAMESPACE  # noqa: E402  one list of patterns for both pages

TEMPLATE = HERE / "page.html"
PLACE = "/*DATA*/null"
FORMAT = "yuce-live-journal/1"


def main() -> int:
    if len(sys.argv) > 2:
        print(__doc__)
        return 2
    page = TEMPLATE.read_text(encoding="utf-8")
    problems = []
    if not page.isascii():
        problems.append("the template has non-ASCII characters")
    if page.count(PLACE) != 1:
        problems.append(f"the template must hold {PLACE} once")
    bare = page.replace(SVG_NAMESPACE, "")
    for pattern in NETWORK:
        for m in re.finditer(pattern, bare, flags=re.I):
            problems.append(f"line {bare.count(chr(10), 0, m.start()) + 1}: {m.group(0)!r} could reach the network")
    csp = re.search(r'<meta http-equiv="Content-Security-Policy" content="([^"]+)">', page)
    policy = csp.group(1) if csp else ""
    if ("default-src 'none'" not in policy or "form-action 'none'" not in policy or "base-uri 'none'" not in policy
            or re.search(r"connect-src|https?:", policy)):
        problems.append("the content security policy must be default-src 'none', form-action 'none' and base-uri 'none', no source allowed")
    if len(sys.argv) == 2:
        made = pathlib.Path(sys.argv[1]).read_text(encoding="utf-8")
        head, tail = page.split(PLACE, 1)
        if not (made.startswith(head) and made.endswith(tail) and len(made) > len(head) + len(tail)):
            problems.append("the made page is not the template with its data in place")
        else:
            data = made[len(head):len(made) - len(tail)]
            if "<" in data or not data.isascii():
                problems.append("the data holds '<' or non-ASCII characters: it could end the script")
            try:
                parsed = json.loads(data)
                if not isinstance(parsed, dict):
                    raise ValueError("not a JSON object")
                if parsed.get("format") != FORMAT:
                    problems.append(f"data format {parsed.get('format')!r}, expected {FORMAT!r}")
                if parsed.get("verify", {}).get("status") != "VERIFIED":
                    problems.append("the data does not come from a journal that verified")
            except ValueError as e:
                problems.append(f"the data is not JSON: {e}")
    for p in problems:
        print("  " + p)
    print(f"page.html{' and ' + sys.argv[1] if len(sys.argv) == 2 else ''}: {'OK' if not problems else f'{len(problems)} problem(s)'}")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
