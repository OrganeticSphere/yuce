"""Bounded Antigravity NDJSON capture. Only the subprocess created by this call is stopped."""
from __future__ import annotations
import codecs
import json
import os
import queue
import re
import subprocess
import threading
import time

CAPTURE_CHARS = 64_000
_CALLS = {"tool", "tool_call", "tool_use", "tool_invocation", "tool_start", "tool_call_start", "function_call"}
_HUMAN_EVENTS = {"ask_question", "ask_permission", "ask_custom_permission", "permission_request",
                 "approval_request", "permission", "question", "custom_permission", "user_input_required", "request_user_input", "waiting_for_user"}
_HUMAN_NAMES = {"askquestion", "askpermission", "askcustompermission", "askuserquestion", "requestuserinput",
                "requestpermission", "requestapproval", "requestconfirmation", "waitforuser", "askhuman", "askfollowupquestion", "askforclarification"}
_ENVELOPES = ("message", "content", "data", "delta", "item", "request", "tool", "function", "functionCall", "function_call", "tool_call", "tool_calls", "tool_use")

def human_request(value, invocation=False):
    """Inspect invocations/wait events, never a tool registry or words in ordinary model text."""
    if isinstance(value, list):
        return next((name for item in value if (name := human_request(item, invocation))), None)
    if not isinstance(value, dict):
        return None
    kind = value.get("event") or value.get("type")
    kind = kind if isinstance(kind,str) else None
    if kind == "init" or value.get("subtype") == "init":
        return None
    call = invocation or kind in _CALLS
    name = value.get("name") or value.get("tool_name")
    if not isinstance(name, str) and isinstance(value.get("tool"), str):
        name = value["tool"]
    if kind in _HUMAN_EVENTS:
        return name if isinstance(name, str) else kind
    waits = any(value.get(k) is True for k in ("requires_user_input", "requires_human", "requires_approval", "requires_confirmation"))
    if value.get("waiting_for") in ("user", "human") or waits:
        return name if isinstance(name, str) else str(kind or "human_input_required")
    if call and isinstance(name, str):
        normalized = re.sub(r"[^a-z0-9]", "", name.casefold())
        if any(normalized.endswith(n) for n in _HUMAN_NAMES) or ("permission" in normalized or "approval" in normalized):
            return name
    for key in _ENVELOPES:
        if key in value:
            found = human_request(value[key], call or key in ("tool_call", "tool_calls", "tool_use", "function_call", "functionCall"))
            if found:
                return found
    return None

class StreamFailure(RuntimeError):
    def __init__(self, reason, diagnostics, result):
        super().__init__(reason)
        self.diagnostics, self.result = diagnostics, result

def run_stream(cmd, input_line, cwd, timeout_s):
    captured = {"stdout": "", "stderr": ""}
    seen, retained = 0, 0
    result = {}
    pending = ""
    reason = None
    messages = queue.Queue()
    proc = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            cwd=cwd, bufsize=0, creationflags=0x08000000 if os.name == "nt" else 0)
    deadline = time.monotonic() + timeout_s

    def reader(name, pipe):
        decoder = codecs.getincrementaldecoder("utf-8")(errors="replace")
        try:
            while chunk := pipe.read(4096):
                messages.put((name, decoder.decode(chunk)))
            last = decoder.decode(b"", final=True)
            if last:
                messages.put((name, last))
        except Exception as exc:
            messages.put(("error", f"{name}: {type(exc).__name__}: {exc}"))
        finally:
            messages.put((name, None))

    def writer():
        try:
            remaining = memoryview(input_line.encode("utf-8"))
            while remaining:
                written = proc.stdin.write(remaining)
                if not written:
                    raise BrokenPipeError("stdin closed before the whole prompt")
                remaining = remaining[written:]
            proc.stdin.flush()
        except Exception as exc:
            messages.put(("error", f"stdin: {type(exc).__name__}: {exc}"))
        finally:
            proc.stdin.close()

    readers = [threading.Thread(target=reader, args=(name, pipe), daemon=True)
               for name, pipe in (("stdout", proc.stdout), ("stderr", proc.stderr))]
    writing = threading.Thread(target=writer, daemon=True)
    for thread in (*readers, writing):
        thread.start()

    def capture(name, text):
        nonlocal seen, retained
        seen += len(text)
        prefix = text[:max(0, CAPTURE_CHARS-retained)]
        captured[name] += prefix
        retained += len(prefix)

    def event(line):
        nonlocal result
        try:
            value = json.loads(line)
        except (ValueError, TypeError):
            return None
        tool = human_request(value)
        if tool:
            return f"AGY_ASKED_HUMAN: {tool}"
        if isinstance(value, dict) and value.get("event") == "result" and isinstance(value.get("result"), dict):
            result = value["result"]
        return None

    eof = set()
    try:
        while len(eof) < 2 or writing.is_alive() or proc.poll() is None:
            remaining = deadline-time.monotonic()
            if remaining <= 0:
                reason = f"AGY_TIMEOUT: timed out after {timeout_s:g}s"
                break
            try:
                name, text = messages.get(timeout=min(0.1, remaining))
            except queue.Empty:
                continue
            if name == "error":
                reason = f"AGY_STREAM_ERROR: {text}"
                break
            if text is None:
                eof.add(name)
                if name == "stdout" and pending:
                    reason = event(pending)
                    pending = ""
            else:
                capture(name, text)
                if name == "stdout":
                    pending += text
                    while "\n" in pending:
                        line, pending = pending.split("\n", 1)
                        reason = event(line)
                        if reason:
                            break
            if reason:
                break
    finally:
        if proc.poll() is None:
            proc.kill()
        proc.wait(timeout=5)
        for thread in (*readers, writing):
            thread.join(timeout=1)
        # Readers can deliver their final chunk while the owned process exits.
        while not messages.empty():
            name, text = messages.get_nowait()
            if name in captured and text:
                capture(name, text)
        proc.stdout.close()
        proc.stderr.close()

    diagnostics = {"stdout_prefix": captured["stdout"], "stderr_prefix": captured["stderr"],
                   "capture_limit_chars": CAPTURE_CHARS, "captured_chars": retained,
                   "observed_chars": seen, "truncated": seen > retained}
    if reason:
        raise StreamFailure(reason, diagnostics, result)
    return result, proc.returncode, diagnostics
