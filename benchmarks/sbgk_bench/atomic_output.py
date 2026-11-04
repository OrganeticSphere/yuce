"""Atomic replace with bounded Windows sharing retries. A failed payload is retained for recovery."""
from __future__ import annotations
import os
from pathlib import Path
import time
import uuid

def write_text(path: Path, text: str):
    path=Path(path)
    tmp=path.with_name(path.name+"."+uuid.uuid4().hex+".tmp")
    with tmp.open("x",encoding="utf-8",newline="\n") as stream:
        stream.write(text)
        stream.flush()
        os.fsync(stream.fileno())
    for attempt in range(6):
        try:
            tmp.replace(path)
            return
        except PermissionError as exc:
            if attempt==5:
                raise PermissionError(f"cannot replace {path}; complete payload retained at {tmp}") from exc
            time.sleep(0.05*(2**attempt))
