"""Write THIRD_PARTY_LICENSES.md (private tooling: export-ignore keeps it out of the snapshot; its output is public).

usage: python scripts/third_party_licenses.py <cargo-about.exe> <pip-licenses.exe> <baselines python.exe>
1. cargo-about 0.9.2 (about.toml, about.hbs) lists the Rust crates of the four release targets with their license texts.
2. It leaves out some crates of Cargo.lock (build-time proc-macro crates and serde): each one is added from its own
   Cargo.toml in the cargo registry, with every license file it ships that the list does not hold yet (unicode-ident's
   LICENSE-UNICODE).
3. This repository's own crates are taken out of the third-party list.
4. The Python packages of the optional baselines (benchmarks/requirements-baselines.txt) are listed from the venv they were
   installed in, with name, version, license and home page. They are not shipped: the file only installs them."""
from __future__ import annotations

import json
import pathlib
import re
import subprocess
import sys
import tomllib

ROOT = pathlib.Path(__file__).resolve().parents[1]
OUT = ROOT / "THIRD_PARTY_LICENSES.md"
OWN = ("sbgk-cli", "sbgk-core")


def main() -> int:
    about, pip_licenses, baselines_python = sys.argv[1:4]
    subprocess.run([about, "generate", "--locked", "--fail", "about.hbs", "-o", str(OUT)], cwd=ROOT, check=True)
    text = OUT.read_text(encoding="utf-8")
    for name in OWN:
        text = re.sub(rf"{name} \d+\.\d+\.\d+(, )?", "", text)
    text = re.sub(r" \(\d+\):", ":", text)  # the counts would include the crates taken out
    lock = tomllib.loads((ROOT / "Cargo.lock").read_text(encoding="utf-8"))
    missing = [(p["name"], p["version"]) for p in lock["package"] if p["name"] not in OWN and f"{p['name']} {p['version']}" not in text]
    registry = list((pathlib.Path.home() / ".cargo" / "registry" / "src").glob("*"))
    rows, extra = [], []
    for name, version in missing:
        src = next((r / f"{name}-{version}" for r in registry if (r / f"{name}-{version}").is_dir()), None)
        if src is None:
            raise SystemExit(f"{name} {version} is not in the cargo registry cache: run cargo fetch --locked first")
        manifest = tomllib.loads((src / "Cargo.toml").read_text(encoding="utf-8"))["package"]
        rows.append(f"* {name} {version}: `{manifest.get('license')}`")
        for f in sorted(src.glob("LICENSE*")):
            if f.name not in ("LICENSE-APACHE", "LICENSE-MIT"):  # their texts are above
                extra.append(f"### {name} {version}: {f.name}\n\n```text\n{f.read_text(encoding='utf-8').strip()}\n```\n")
    text += ("\n## Crates the generated list leaves out\n\nBuild-time crates (procedural macros, not linked into the binaries) and "
             "serde, added from each crate's own manifest. Their Apache-2.0 and MIT texts are above; other license files they ship "
             "follow.\n\n" + "\n".join(rows) + "\n\n" + "\n".join(extra))
    # C code the binaries build in: the SQLite amalgamation libsqlite3-sys bundles (rusqlite, feature `bundled`)
    sqlite = next((p for p in lock["package"] if p["name"] == "libsqlite3-sys"), None)
    if sqlite is not None:
        src = next((r / f"libsqlite3-sys-{sqlite['version']}" for r in registry if (r / f"libsqlite3-sys-{sqlite['version']}").is_dir()), None)
        if src is None:
            raise SystemExit(f"libsqlite3-sys {sqlite['version']} is not in the cargo registry cache: run cargo fetch --locked first")
        header = (src / "sqlite3" / "sqlite3.h").read_text(encoding="utf-8", errors="replace")
        version = re.search(r'#define SQLITE_VERSION\s+"([^"]+)"', header).group(1)
        text += (f"\n## C code built into the binaries\n\nSQLite {version}, built in by libsqlite3-sys {sqlite['version']} for the index "
                 "beside a journal (`sbgk audit-index`). SQLite is in the public domain: https://sqlite.org/copyright.html\n")
    pkgs = json.loads(subprocess.run([pip_licenses, "--python", baselines_python, "--format=json", "--with-urls"], check=True,
                                     capture_output=True, text=True).stdout)
    lines = [f"| {p['Name']} | {p['Version']} | {p['License']} | {p['URL']} |" for p in sorted(pkgs, key=lambda p: p["Name"].lower())]
    text += ("\n## Python packages of the optional baselines\n\nInstalled by `benchmarks/requirements-baselines.txt` for the LangGraph "
             "and Temporal baselines; not shipped in this repository or its release archives. Listed by pip-licenses 5.5.5 from the "
             "environment the runs used. MPL-2.0 applies to certifi and to orjson's own files.\n\n| Package | Version | License | Home page |\n"
             "|---|---|---|---|\n" + "\n".join(lines) + "\n")
    # the license texts some crates ship end lines in spaces: `git diff --check` refuses them, and they mean nothing
    text = re.sub(r"[ \t]+\n", "\n", text)
    OUT.write_text(re.sub(r"\n{3,}", "\n\n", text), encoding="utf-8", newline="\n")
    print(f"{OUT.name}: {len(missing)} crates added, {len(pkgs)} Python packages")
    return 0


if __name__ == "__main__":
    sys.exit(main())
