"""Adapters that turn a prompt into a model reply for three different agent runtimes.

  codex     Codex CLI            model gpt-5.6-sol
  deepseek  OpenClaw             model deepseek/deepseek-chat (one-shot `infer model run`)
  opus      Claude Code CLI      model claude-opus-5-5 (newest bundled binary; the old PATH copy is too old)

Every call runs in an empty temporary directory, without tools, and is cached on disk by (backend, model, prompt)
so reruns of an experiment are cheap and reproducible. All prompts contain synthetic data only.
"""

from __future__ import annotations

import hashlib
import json
import pathlib
import re
import shutil
import subprocess
import tempfile
import threading
import time

from . import common as C

CACHE = C.RESULTS / "exp7" / "calls"
_lock = threading.Lock()


def _ver(text: str):
    m = re.search(r"(\d+)\.(\d+)\.(\d+)", text or "")
    return tuple(int(x) for x in m.groups()) if m else (0, 0, 0)


def find_claude() -> str:
    cands = list(pathlib.Path.home().glob("AppData/Roaming/Claude/claude-code/*/*/claude.exe"))
    cands += list(pathlib.Path.home().glob("AppData/Local/Claude-Data/*/claude-code/*/*/claude.exe"))  # newer desktop app layout
    cands += [pathlib.Path(p) for p in [shutil.which("claude")] if p]
    best, best_v = None, (0, 0, 0)
    for c in cands:
        try:
            v = _ver(subprocess.run([str(c), "--version"], capture_output=True, text=True, timeout=30).stdout)
        except Exception:
            continue
        if v > best_v:
            best, best_v = str(c), v
    if not best or best_v < (2, 1, 280):
        raise RuntimeError(f"no Claude Code >= 2.1.280 found (best: {best} {best_v})")
    return best


def find_codex() -> str:
    cands = [shutil.which("codex")] + [str(p) for p in pathlib.Path.home().glob(
        "AppData/Roaming/npm/node_modules/@openai/codex/node_modules/@openai/codex-*/vendor/*/bin/codex.exe")]
    best, best_v = None, (0, 0, 0)
    for c in filter(None, cands):
        try:
            v = _ver(subprocess.run([c, "--version"], capture_output=True, text=True, timeout=30).stdout)
        except Exception:
            continue
        if v > best_v:
            best, best_v = c, v
    if not best:
        raise RuntimeError("codex CLI not found")
    return best


def find_openclaw_entry() -> str:
    p = pathlib.Path.home() / "AppData/Roaming/npm/node_modules/openclaw/openclaw.mjs"
    if not p.exists():
        raise RuntimeError("openclaw not found")
    return str(p)


class Backend:
    name = "?"
    label = "?"
    exact_tokens = True

    def __init__(self, timeout: int = 900):
        self.timeout = timeout
        self.overhead_in = 0  # fixed per-call input tokens that belong to the runtime, not to our prompt

    def _key(self, prompt: str) -> str:
        return hashlib.sha256((self.name + self.label + prompt).encode()).hexdigest()[:24]

    def _run(self, prompt: str) -> dict:  # pragma: no cover - implemented by subclasses
        raise NotImplementedError

    def call(self, prompt: str, tag: str = "") -> dict:
        f = CACHE / f"{self._key(prompt)}.json"
        if f.exists():
            r = json.loads(f.read_text(encoding="utf-8"))
            r["from_cache"] = True
            return r
        last = None
        for attempt in range(3):
            try:
                t0 = time.time()
                r = self._run(prompt)
                r["seconds"] = time.time() - t0
                r.update({"backend": self.name, "model": self.label, "tag": tag, "attempts": attempt + 1, "prompt_chars": len(prompt)})
                if not r.get("text", "").strip():
                    raise RuntimeError("empty reply")
                with _lock:
                    CACHE.mkdir(parents=True, exist_ok=True)
                    f.write_text(json.dumps({**r, "prompt": prompt}, ensure_ascii=False), encoding="utf-8")
                return r
            except Exception as e:  # noqa: BLE001 - retry any transport failure
                last = e
                time.sleep(2)
        raise RuntimeError(f"{self.name} call failed ({tag}): {last}")


class CodexBackend(Backend):
    name = "codex"
    label = "gpt-5.6-sol"

    def __init__(self, exe: str | None = None, **kw):
        super().__init__(**kw)
        self.exe = exe or find_codex()
        self.version = subprocess.run([self.exe, "--version"], capture_output=True, text=True).stdout.strip()

    def _run(self, prompt: str) -> dict:
        tmp = pathlib.Path(tempfile.mkdtemp(prefix="sbgk7_cx_"))
        try:
            cmd = [self.exe, "exec", "-m", self.label, "-s", "read-only", "--ephemeral", "--skip-git-repo-check",
                   "--ignore-user-config", "--ignore-rules", "--json", "-C", str(tmp), "-"]
            p = subprocess.run(cmd, input=prompt, capture_output=True, text=True, encoding="utf-8", timeout=self.timeout)
        finally:
            shutil.rmtree(tmp, ignore_errors=True)
        text, usage, tools = "", {}, 0
        for line in p.stdout.splitlines():
            try:
                ev = json.loads(line)
            except Exception:
                continue
            if ev.get("type") == "item.completed":
                it = ev.get("item", {})
                if it.get("type") == "agent_message":
                    text = it.get("text", "")
                elif it.get("type") != "reasoning":
                    tools += 1
            elif ev.get("type") == "turn.completed":
                usage = ev.get("usage", {})
        if not text:
            raise RuntimeError(p.stderr[-300:] or "no agent_message")
        return {"text": text, "in_tokens": usage.get("input_tokens", 0), "cached_tokens": usage.get("cached_input_tokens", 0),
                "out_tokens": usage.get("output_tokens", 0), "cost_usd": None, "tool_items": tools, "tokens_estimated": False}


class DeepSeekBackend(Backend):
    name = "deepseek"
    label = "deepseek/deepseek-chat"
    exact_tokens = False

    def __init__(self, **kw):
        super().__init__(**kw)
        self.entry = find_openclaw_entry()
        self.version = subprocess.run(["node", self.entry, "--version"], capture_output=True, text=True).stdout.strip()

    def _run(self, prompt: str) -> dict:
        tmp = pathlib.Path(tempfile.mkdtemp(prefix="sbgk7_ds_"))
        try:
            cmd = ["node", self.entry, "infer", "model", "run", "--local", "--model", self.label, "--json", "--prompt", prompt]
            p = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", timeout=self.timeout, cwd=str(tmp))
        finally:
            shutil.rmtree(tmp, ignore_errors=True)
        m = re.search(r'\{\s*"ok"\s*:', p.stdout)
        if not m:
            raise RuntimeError((p.stdout + p.stderr)[-300:])
        data = json.loads(p.stdout[m.start():])
        if not data.get("ok"):
            raise RuntimeError(str(data)[:300])
        text = "\n".join(o.get("text", "") for o in data.get("outputs", []))
        usage = data.get("usage") or {}
        in_t = usage.get("input") or usage.get("input_tokens") or usage.get("promptTokens")
        out_t = usage.get("output") or usage.get("output_tokens") or usage.get("completionTokens")
        est = in_t is None or out_t is None
        return {"text": text, "in_tokens": in_t if in_t is not None else len(prompt) // 4, "cached_tokens": 0,
                "out_tokens": out_t if out_t is not None else len(text) // 4, "cost_usd": None, "tool_items": 0, "tokens_estimated": est}


class OpusBackend(Backend):
    name = "opus"
    label = "claude-opus-5-5"

    def __init__(self, exe: str | None = None, **kw):
        super().__init__(**kw)
        self.exe = exe or find_claude()
        self.version = subprocess.run([self.exe, "--version"], capture_output=True, text=True).stdout.strip()

    def _run(self, prompt: str) -> dict:
        tmp = pathlib.Path(tempfile.mkdtemp(prefix="sbgk7_op_"))
        try:
            cmd = [self.exe, "-p", "--model", self.label, "--output-format", "json", "--tools", "", "--no-session-persistence",
                   "--disable-slash-commands"]
            p = subprocess.run(cmd, input=prompt, capture_output=True, text=True, encoding="utf-8", timeout=self.timeout, cwd=str(tmp))
        finally:
            shutil.rmtree(tmp, ignore_errors=True)
        try:
            data = json.loads(p.stdout)
        except Exception:
            raise RuntimeError((p.stdout + p.stderr)[-300:])
        if data.get("is_error"):
            raise RuntimeError(str(data.get("result"))[:300])
        u = data.get("usage", {})
        return {"text": data.get("result", ""), "in_tokens": u.get("input_tokens", 0) + u.get("cache_creation_input_tokens", 0) + u.get("cache_read_input_tokens", 0),
                "cached_tokens": u.get("cache_read_input_tokens", 0), "out_tokens": u.get("output_tokens", 0),
                "cost_usd": data.get("total_cost_usd"), "tool_items": 0, "tokens_estimated": False}


def make(name: str) -> Backend:
    return {"codex": CodexBackend, "deepseek": DeepSeekBackend, "opus": OpusBackend}[name]()
