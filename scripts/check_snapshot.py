"""Check an unpacked public snapshot before it is published: what a reader must find in it, and what must not be in it.

usage: python scripts/check_snapshot.py <snapshot dir> [--version 0.1.0]
Checks: the license files, NOTICE and third-party list are present; the workspace version (Cargo.toml, parsed) and this
repository's packages in Cargo.lock are the release version; no file holds Cyrillic text, a personal home path
(C:\\Users\\<name>, /home/<name>, /Users/<name>), a token / key / password / secret field whose value is not one of the known
placeholders, or a private key block; no runtime subjects file (agent tokens) is shipped; no file of the internal experiment
history is shipped. It prints each problem (path and line, never the matched value) and exits 1 when there is one, 0
otherwise. It is one control next to a secret scanner (gitleaks), not a replacement for it. Standard library only."""
from __future__ import annotations

import argparse
import json
import pathlib
import re
import sys
import tomllib

REQUIRED = ["LICENSE", "NOTICE", "THIRD_PARTY_LICENSES.md", "README.md", "CHANGELOG.md", "Cargo.toml", "Cargo.lock",
            "benchmarks/corpora/mcp-spec-2026-07-28/LICENSE", "benchmarks/corpora/mcp-spec-2026-07-28/LICENSE-MIT"]
ABSENT = ["results", "docs/internal", "benchmarks/sbgk_bench/closed", "SBGK_EXPERIMENT_REPORT*.md", "BYTEANCHOR_CONTINUITY.md",
          "scripts/package_runs.py", "benchmarks/sbgk_bench/exp11a_native.py", "benchmarks/sbgk_bench/exp12_tiered.py"]
OWN_PACKAGES = ("sbgk-cli", "sbgk-core")
HOME = re.compile(r"[A-Za-z]:[\\/]+Users[\\/]+(?!<|\{|\*|Public\b|Default\b|runneradmin\b)[A-Za-z0-9._-]+|/home/(?!runner\b|<)[a-z0-9._-]+/|/Users/(?!<|runner\b)[A-Za-z0-9._-]+/")
SECRET_FIELD = re.compile(r"""["']?(api[_-]?key|secret|password|passwd|auth[_-]?token|access[_-]?token|token)["']?\s*[:=]\s*["']([^"'\s]{12,})["']""", re.I)
# a value is a placeholder only when the whole value has one of these shapes; a known word inside a longer value is not enough
PLACEHOLDERS = [re.compile(p) for p in (
    r"replace-with-a-secret-\d+",                  # README examples
    r"synthetic-[a-z]+-token-[0-9a-z]+",          # kernel tests
    r"not-a-subject-token",                       # kernel tests
    r"<[^<>]+>", r"\$\{?[A-Z_][A-Z0-9_]*\}?",      # shell and template placeholders
)]
PRIVATE_KEY = re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")
CYRILLIC = re.compile(r"[\u0400-\u04FF]")
TEXT = {".rs", ".py", ".md", ".toml", ".json", ".jsonl", ".yml", ".yaml", ".txt", ".html", ".mdx", ".lock", ".cfg", ".ini", ".sh",
        ".ps1", ".hbs", ".gitattributes", ".gitignore", ""}


def placeholder(value: str) -> bool:
    return any(p.fullmatch(value) for p in PLACEHOLDERS)


def check(root: pathlib.Path, version: str) -> tuple[list[str], int, int]:
    problems: list[str] = []
    for rel in REQUIRED:
        if not (root / rel).is_file():
            problems.append(f"missing {rel}")
    for pattern in ABSENT:
        for hit in sorted(root.glob(pattern)):
            problems.append(f"shipped {hit.relative_to(root).as_posix()} (internal or private)")
    try:
        cargo = tomllib.loads((root / "Cargo.toml").read_text(encoding="utf-8-sig"))
        if cargo.get("workspace", {}).get("package", {}).get("version") != version:
            problems.append(f"Cargo.toml: workspace.package.version is not {version}")
        lock = tomllib.loads((root / "Cargo.lock").read_text(encoding="utf-8"))
        for pkg in lock.get("package", []):
            if pkg["name"] in OWN_PACKAGES and pkg["version"] != version:
                problems.append(f"Cargo.lock: {pkg['name']} is {pkg['version']}, not {version}")
    except (OSError, tomllib.TOMLDecodeError) as e:
        problems.append(f"Cargo.toml / Cargo.lock unreadable: {type(e).__name__}")
    files = [p for p in root.rglob("*") if p.is_file() and ".git" not in p.relative_to(root).parts]
    scanned = 0
    for p in files:
        rel = p.relative_to(root).as_posix()
        if p.name == "subjects.json":
            problems.append(f"{rel}: a runtime subjects file (agent tokens) is shipped")
        if p.suffix.lower() not in TEXT and p.name not in ("LICENSE", "NOTICE", "LICENSE-MIT"):
            continue
        try:
            text = p.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        scanned += 1
        for n, line in enumerate(text.splitlines(), 1):
            if CYRILLIC.search(line):
                problems.append(f"{rel}:{n}: Cyrillic text")
            if HOME.search(line):
                problems.append(f"{rel}:{n}: a personal home path")
            if PRIVATE_KEY.search(line):
                problems.append(f"{rel}:{n}: a private key block")
            for m in SECRET_FIELD.finditer(line):
                if not placeholder(m.group(2)):
                    problems.append(f"{rel}:{n}: a '{m.group(1)}' field with a value that is not a known placeholder")
    return problems, len(files), scanned


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("snapshot", type=pathlib.Path)
    ap.add_argument("--version", default="0.1.1")
    a = ap.parse_args()
    root = a.snapshot.resolve()
    problems, files, scanned = check(root, a.version)
    for p in problems:
        print("  " + p)
    print(json.dumps({"snapshot": str(root), "files": files, "text_files_scanned": scanned, "problems": len(problems)}))
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
