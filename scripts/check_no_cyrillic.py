#!/usr/bin/env python3
"""Repository language gate: no tracked text file may contain Cyrillic characters (U+0400..U+04FF).

The open-source repository is English, with Chinese/Japanese concept terms (玉策, 玉冊, Yùcè, 禪地玉冊) allowed.
Files that are not valid UTF-8 (binary containers such as `.sbgk`) are skipped.

    python scripts/check_no_cyrillic.py          # exit 0 when clean, 1 with a list of offending files and lines
"""

from __future__ import annotations

import pathlib
import re
import subprocess
import sys

CYRILLIC = re.compile("[" + chr(0x0400) + "-" + chr(0x04FF) + "]")  # built from code points, so this file stays ASCII


def main() -> int:
    files = subprocess.check_output(["git", "ls-files", "-z"], text=True, encoding="utf-8").split("\0")
    bad: list[str] = []
    checked = 0
    for name in filter(None, files):
        p = pathlib.Path(name)
        if not p.is_file():
            continue
        try:
            text = p.read_bytes().decode("utf-8")
        except UnicodeDecodeError:
            continue  # binary file
        checked += 1
        hits = [i for i, line in enumerate(text.splitlines(), 1) if CYRILLIC.search(line)]
        if hits:
            shown = ", ".join(map(str, hits[:10])) + (" …" if len(hits) > 10 else "")
            bad.append(f"{name}: lines {shown}")
    if bad:
        print(f"Cyrillic found in {len(bad)} tracked file(s):")
        print("\n".join(f"  {b}" for b in bad))
        return 1
    print(f"OK: no Cyrillic in {checked} tracked text files")
    return 0


if __name__ == "__main__":
    sys.exit(main())
