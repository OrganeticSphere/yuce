"""Comparative pilot on a corpus of dated reports (Gemini's directive of 2026-10-22): arm A (shared Markdown notes and a task
queue, no R2R) against arm C (R2R: `sbgk audit-serve`, 10 swarm agents and 1 graph builder) on the same reports, research
questions, sections and models. Phase 1 is the audit; then pre-registered withdrawal steps (Gemini's preflight: 2A a peripheral
quote, 2B a load-bearing one) withdraw a source text and ask both arms to update.

Every model call goes through one adapter (contract v0.1 R9): one task -> one fresh call without history, and the call's text,
id, outcome, usage, cost (None = unknown, never 0) and latency are recorded. `StubModel` is deterministic and free: it checks
the mechanics. `DeepSeekModel` calls the DeepSeek API directly: one chat completion per task,
the provider's token usage priced at DEEPSEEK_RATES, and the provider balance before and after the run as the actual spend.

An optional closed package (`sbgk_bench.closed`, see closed_layer) adds options to this runner; without it argparse simply does
not know them.
"""
from __future__ import annotations

import hashlib
import contextvars
import importlib
import importlib.util
import json
import os
import pathlib
import queue
import re
import secrets
import shutil
import socket
import subprocess
import tempfile
import threading
import time
import urllib.error
import urllib.request
from collections import defaultdict
from dataclasses import asdict, dataclass, field
from types import SimpleNamespace
from typing import Callable, Protocol

from . import common as C
from . import executors
from . import answer_guidance as G
from .model_policy import RunHook

# Test-only question metadata. ContextVar isolates concurrent tasks and supports StubModel subclasses without changing the
# production Model.complete signature or sending hidden topics in a provider request. Set/reset at the actual call boundary.
_stub_about = contextvars.ContextVar("r2r_stub_about", default=())

# The models of the closed package. Without the package each of them stops with one message (closed_missing) instead of an unknown
# model.
CLOSED_MODELS = ("gemini-lite", "gemini-lite-openclaw")
CLOSED_PACKAGE = f"{__package__}.closed"


class ClosedLayerMissing(RuntimeError):
    """A feature of the closed layer was asked for, and the package is not installed."""


def closed_missing(feature: str) -> str:
    return f"{feature} needs the closed layer (benchmarks/sbgk_bench/closed), which this distribution does not include"


def closed_layer(feature: str | None = None):
    """The closed package, or None when it is absent; with `feature`, an absent package raises ClosedLayerMissing. Only a missing
    package counts as absent: an error inside it is raised as it is. A `closed` directory without its __init__.py (a leftover
    __pycache__ after the package was removed) is a namespace package with no origin: absent too (claude-reviewer's D01 on PR 6)."""
    spec = importlib.util.find_spec(CLOSED_PACKAGE)
    if spec is None or spec.origin is None:
        if feature is not None:
            raise ClosedLayerMissing(closed_missing(feature))
        return None
    return importlib.import_module(CLOSED_PACKAGE)


# The research questions of every corpus (the open MCP specification corpus and the first pilot's private set alike). The topics
# of each question and the structure that selects a claim too - its stance, a standing link, the type of its concept - so a
# summary does not miss what names no topic word (Gemini's run-10 corrections; Codex review c78060e, F09). Arm A sees the id and
# the text only. A run records them in its snapshot and --reuse-arm-c requires the same ones.
QUESTIONS = [
    {"id": "RQ1", "text": "Which conclusions were later superseded, made stale or qualified?",
     "about": ["stale", "supersed", "qualif", "revok", "reconcil", "no longer", "replaced", "candidate only"],
     "stances": ["superseded", "qualified"], "relations": ["supersedes", "qualifies", "contradicts"]},
    {"id": "RQ2", "text": "Which limitations and future-work items remain open?",
     "about": ["future work", "limitation", "defer", "unverified", "unsupported", "out of scope", "not yet"],
     "stances": ["open"], "concept_types": ["Limitation", "Issue"]},
]
SECTION_BYTES = 6000
# the graph builder's typed requests per run (U1; 0: off, the kernel's default)
BUILDER_REQUESTS = 0
# backpressure (run 10A-17): first readings wait while the builder's backlog plus BACKPRESSURE_PER_TASK per reading in flight would
# exceed BACKPRESSURE_RECORDS (0: off, the kernel's default); the owner's status sample every STATUS_SAMPLE_S seconds draws its curve
BACKPRESSURE_RECORDS = 0
BACKPRESSURE_PER_TASK = 20
STATUS_SAMPLE_S = 30.0
# The comparison of one strong model with the kernel against the same model without it (drop the swarm, see
# what one strong model does through the kernel, then give the same task to one agent without the kernel). MAX_LINES: the lines one
# answer of the kernel may hold (None: the kernel's default; a strong reader of a whole report writes more than the swarm's 32).
# PAIRS_ONLY: the graph builder judges only the pairs the kernel finds, a record card is closed without a model. LINK_CHECKER: a
# second agent of the same model checks the links and does nothing else (the single reader wrote every claim, so it may check none
# of the links between them). ARM_A_MODE "single": arm A is one agent of the same model without the kernel.
# ARM_A_MODE "team": a team of agents of different vendors with the kernel against the same team without it
# (R2R is for several agents working together; how would Opus and an independent GPT agent work without it?). The team's first agent
# leads and alone writes the answers in both arms; the others read and check (TEAM_READER_KINDS).
MAX_LINES: int | None = None
PAIRS_ONLY = False
LINK_CHECKER = False
LINK_CHECKER_ID = "wv"
LINK_CHECKER_KINDS = ["VERIFY_LINK", "RESOLVE_CONFLICT"]
TEAM_READER_KINDS = ["RESOLVE_CONFLICT", "VERIFY_LINK", "REQUEST", "INVESTIGATE", "EXTEND", "CHANGE"]
# Run S1.2: one strong agent reads every report in one zone task of the kernel and hands in its records,
# their relations and its answers in one answer. The kernel checks and stores them, the link checker checks the relations, the
# summaries are handed in from that answer (the kernel shows them no records, --summary-records 0, and they cite the agent's own
# observes, --own-refs), a withdrawal is the kernel's alone, without a model call, and the builder runs no model. Arm A takes the
# same answer without the kernel (ARM_A_MODE "whole").
WHOLE_READER = False
WHOLE_LINES = 250
WHOLE_KINDS = ["EXTEND", "CHANGE", "SUMMARIZE"]
WHOLE_GRAPH = ("observe", "claim", "relation")
WHOLE_ANSWERS = ("answer", "answer_done")
WHOLE_RULES = (
    "\n\nWrite no question or hypothesis lines. After the record lines, answer each research question with answer lines, which do not "
    "count against the bound above:\n"
    '  {"kind":"answer","rq_id":"<RQ id>","local_id":"<prefix>a<n>","text":"<at most 240 characters>","subject":"...",'
    '"stance":"reported|confirmed|refuted|qualified|superseded|open|unknown","based_on":["<observe local_ids of this answer>"]}\n'
    "at most 40 for a question, each a short text that merges related findings and rests on all their quotes, then for each "
    'question one {"kind":"answer_done","rq_id":"<RQ id>","text":"<at most 240 characters: what the reports do not settle>"}. '
    "Cover every report that bears on the question.")
# Run S1.3: S1.2 with four changes. The records are atomic (one fact a claim, every quote necessary), so a
# withdrawal takes out only what rests on the withdrawn text; the answers come in a call of their own after the zone (the same for
# both arms); a line the kernel refuses goes back to the agent once with the kernel's reasons; after a withdrawal the rows the kernel
# took out that still have quotes go back to the agent with those quotes only, not the reports.
WHOLE_STEPS = False
# Run S1.3 without link checks (the full cost of the arms without the checker that cost $2.6-3.7 a
# run and changed no answer): the agent's relation lines are kept aside, not handed in, so no link waits for a check.
WHOLE_LINKS = True
WHOLE_STEP_RULES = (
    "\n\nWrite no question or hypothesis lines and no answers yet. Each claim states one fact, and its based_on holds exactly the "
    "observes that fact needs: every one necessary, none spare. A finding several reports bear on is several claims, one for each "
    "report, connected by relation lines.")
WHOLE_ANSWER_RULES = (
    "Now answer each research question with answer lines only, no record lines:\n"
    '  {"kind":"answer","rq_id":"<RQ id>","local_id":"a<n>","text":"<at most 240 characters>","subject":"...",'
    '"stance":"reported|confirmed|refuted|qualified|superseded|open|unknown","based_on":["<observe local_ids of your records above>"]}\n'
    "at most 40 for a question. Each answer line states one finding, and its based_on holds exactly the observes that finding needs, "
    'every one necessary. Then for each question one {"kind":"answer_done","rq_id":"<RQ id>","text":"<at most 240 characters: what '
    'the reports do not settle>"}. Cover every report that bears on the question; where a conclusion was superseded, made stale or '
    "qualified, say what replaced it.")
ARM_A_MODE = "notes"
DYNAMIC_ROLES = False
# arm C's graph builder: full, concepts (links off) or none (no builder)
BUILD_SCOPE = "full"
VERSION_LINEAGE = None  # explicit snapshot/doc_id/SHA256 JSON; no inference from paths or dates
BUILD_BACKLOG = 16
CIRCLES = False
# Circles +1: the model of the swarm's independent graph builder "gb", a fixed role outside the ring that
# refines the graph after the swarm's BUILD of every circle; None keeps circles as they were
CIRCLES_REFINER = None
# The longest REFINE of a circle; past it the swarm goes on and the refiner keeps its cursor (None: wait for the refiner)
REFINE_BUDGET_S: float | None = None
ONTOLOGY_REVISIONS = False
ONTOLOGY_THRESHOLDS = {"unmapped_circles":3,"catchall_mappings":8,"catchall_reports":2}
BASE_ONTOLOGY: str | None = None  # a seed ontology file for audit-serve --base-ontology; None = the built-in schema
WAVE_SECTIONS: int | None = None
AGY_TIMEOUT_S = 240.0
AGENT_TIMEOUT_S = 300.0
ANSWER_TIMEOUT_S = 900.0
ONTOLOGY_REVIEW = False
AGENT_ATTEMPTS = None
AGENT_RETRY_PAUSE_S = 1.0
ARM_A_ANSWER = "direct"
ARM_A_REDUCE = "single"  # map-reduce reduction: one call, or "tree" (pairwise merges in report order)
ARM_A_ORCHESTRATION = "runner"  # the team arm on the runner's threads, "langgraph-native" (arm_a_langgraph) or "temporal-native" (arm_a_temporal)
# arm A (no kernel) frozen: a run makes the kernel's arm only (how the swarm works without the kernel is
# known; the comparisons come back later)
ARM_A_FROZEN = False
# an earlier run whose finished arm C this run takes as it ended, to run only arm A (run_pilot_ac --reuse-arm-c)
REUSE_ARM_C: pathlib.Path | None = None
UNATTESTED_AT_END = False
GRAPH_QUALITY = {}
# the steps of a run around its calls and cards (model_policy.RunHook; run_pilot_ac sets it)
RUN_HOOK = RunHook()
CHECKER_MODEL: Model | None = None
WORKERS = 10
# The repair rounds of a refused submission, the same in both arms (--repairs, --summary-repairs)
REPAIRS = 2
# A summary is the whole answer of a research question: losing it to a format slip costs more than two more calls (live run 10A-3)
SUMMARY_REPAIRS = 4
# A link check given back this often stops the run (a task that cannot be done must not loop at the price of model calls).
MAX_RELEASES = 5  # a safety net: the dispatcher gives a key up as unresolved after 3 failed leases
MAX_CALLS = 1500  # quality first: arm C must reach its answers; money is held by the budget brake
# The kernel serves every client under one lock and a call costs O(state) (0.3 s at 808 records in live run 4): ten agents
# submitting at once queue for seconds, so a client waits for its answer this long (bounded, as before). Late in a run a call queues
# far longer (live run MCPsfun_r1: an acquire at the last circle's FINAL waited 112 s, and the owner's poll gave up at 120 s).
RPC_TIMEOUT_S = 300.0
# The owner's polls of the terminal receipt that may time out in a row before the phase deadline: a busy kernel is waited for again,
# a kernel silent this long is a failure.
KERNEL_SLOW_POLLS = 3
MAX_RPC_RESPONSE_BYTES = 16 * 1024 * 1024
STARTUP_TIMEOUT_S = 10.0
SHUTDOWN_TIMEOUT_S = 10.0
# While the owner exports a terminal phase that is not the last, an idle agent polls only this often. In run MCPpair_r1 (2 850
# records) every acquire re-planned the circle, 8 s of the kernel's lock each, and four agents polling every 0.2 s left the owner's
# hundreds of small reads waiting behind them (34 s an acquire, the export stalled for hours). Once in 120 s the four take a quarter
# of the lock; the pause stays below half the kernel's readiness timeout (agent_timeout_ms = AGENT_TIMEOUT_S), so the agents
# remain present members of their circle. A full stop of polling could outlast that timeout.
EXPORT_POLL_S = 120.0
# How long a stopping runner waits for model calls already sent: the longest model transport (a Codex session, 900 s) and a margin.
CALL_DRAIN_S = 960.0
# Phase 2 of both arms works under the same cap of model calls (--phase2-max-calls). 30 fits a direct answer; arm A's map-reduce
# answer takes a call per report and question and one reduction per question, 46 over the 22 MCP pages before any repair (run
# MCPpair_r1: arm A stopped at the cap in withdrawal 2A, and 2B was skipped). `--phase2-max-calls auto` takes arm A's answer
# protocol at its worst instead of a number: every answer call of a withdrawal phase made with all its repair rounds, each round
# with its timeout retries (phase2_cap_rule says how the cap was set; Codex review of 729eda8, BATCH-01: the retry was missed).
PHASE2_MAX_CALLS = 30
PHASE2_CAP_RULE = "fixed"
# invoke_answer asks an arm A answer again this many times after a timeout or a human wait
ANSWER_TIMEOUT_RETRIES = 1
# How long an agent's audit_acquire waits inside the kernel for work (--acquire-wait-ms; the kernel caps it at 30 s): the kernel
# answers as soon as a call frees or creates work, and each wake renews the agent's contact with its circle. 500 ms made each agent
# ask about 4000 times a phase (run MCPpair2_r1: 35 000 idle waits): wait for a signal instead of polling.
ACQUIRE_WAIT_MS = 10000
# replies.jsonl keeps a submission's whole reply up to this many characters of its JSON (a refusal of 32 lines with their hints is
# a few thousand); a longer one keeps this prefix, marked, and the SHA-256 of all of it
REPLY_MAX_CHARS = 64000
STRATEGIES = {
    "A": "each withdrawal step: one UPDATE call per research question, with the whole shared note, the previous answer and the "
         "withdrawals so far",
    "C": "each withdrawal step: the owner withdraws every observe quoting the withdrawn text (its anchor, in the same report); the "
         "kernel reopens only what rests on it and the swarm works its directives until the next terminal receipt",
}


# ------------------------------------------------------------------ the corpus, cut as the kernel cuts it

def sections(text: str, max_bytes: int) -> list[tuple[int, int]]:
    """Byte ranges of a Markdown document cut at headings, packed or split to at most `max_bytes` (a port of the kernel's
    `directives::sections`, so both arms read the same sections)."""
    b = text.encode("utf-8")
    mx = max(max_bytes, 64)
    starts, at = [0], 0
    for line in b.split(b"\n")[:-1] if b.endswith(b"\n") else b.split(b"\n"):
        if at > 0 and line.startswith(b"#"):
            starts.append(at)
        at += len(line) + 1
    starts.append(len(b))
    raw: list[tuple[int, int]] = []
    for x, y in zip(starts, starts[1:]):
        x = min(x, len(b))
        while y - x > mx:
            cut = x + mx
            while cut < len(b) and 0x80 <= b[cut] <= 0xBF:
                cut -= 1
            p = b[x:cut].rfind(b"\n\n")
            if p > 0:
                cut = x + p + 2
            raw.append((x, cut))
            x = cut
        if y > x:
            raw.append((x, y))
    out: list[list[int]] = []
    for x, y in raw:
        if out and y - out[-1][0] <= mx:
            out[-1][1] = y
        else:
            out.append([x, y])
    return [(x, y) for x, y in out]


def section_text(text: str, rng: tuple[int, int]) -> str:
    return text.encode("utf-8")[rng[0]:rng[1]].decode("utf-8")


# ------------------------------------------------------------------ the model adapter (R9)

@dataclass
class Call:
    call_id: str
    arm: str
    role: str
    phase: int
    prompt_chars: int
    text: str = ""
    ok: bool = True
    error: str | None = None
    usage: dict = field(default_factory=dict)
    diagnostics: dict = field(default_factory=dict)
    model_family: str | None = None
    cost_usd: float | None = None  # None: the provider reported no cost (unknown, never counted as 0)
    latency_s: float = 0.0
    model: str = ""
    prompt_bytes: int = 0
    # arm A: the revision of the shared note this call actually read (lines and hash of the snapshot)
    context_rev: str | None = None
    context_id: str | None = None
    prompt_sha256: str = ""
    sequence: int = 0
    started_at: float = 0.0
    finished_at: float = 0.0
    circle: int | None = None
    circle_phase: str | None = None
    extra: dict = field(default_factory=dict)  # more fields of this call's record, from the run's policy


def call_record(c: Call) -> dict:
    record = asdict(c)
    record.update(record.pop("extra"))
    return record


class Model(Protocol):
    name: str

    def complete(self, prompt: str) -> tuple[str, dict, float | None]:
        """One fresh call: (text, usage, cost in $ or None)."""


class CallFailed(RuntimeError):
    """A call that failed after attempts the provider billed: their cost goes to the brake (None: unknown, never counted as 0) and the
    tokens they reported to the evidence."""

    def __init__(self, message: str, cost_usd: float | None, usage: dict | None = None):
        super().__init__(message)
        self.cost_usd, self.usage = cost_usd, usage or {}


def call_model(model: Model, prompt: str, *, call_id: str, arm: str, role: str, phase: int, reserve_retry=None) -> Call:
    c = Call(call_id=call_id, arm=arm, role=role, phase=phase, prompt_chars=len(prompt), prompt_bytes=len(prompt.encode("utf-8")), model=model.name)
    t0 = time.perf_counter()
    try:
        if reserve_retry is not None and getattr(model, "reserves_retries", False):
            c.text, c.usage, c.cost_usd = model.complete(prompt, reserve_retry=reserve_retry)
        else:
            c.text, c.usage, c.cost_usd = model.complete(prompt)
    except Exception as e:  # the outcome of the call is recorded, the run goes on
        c.ok, c.error = False, f"{type(e).__name__}: {e}"
        c.cost_usd = getattr(e, "cost_usd", None)
        c.usage = getattr(e, "usage", {})
        c.diagnostics = getattr(e, "diagnostics", {})
    c.latency_s = time.perf_counter() - t0
    return c


# ------------------------------------------------------------------ DeepSeek, direct (contract v0.1 R9)

DEEPSEEK_URL = "https://api.deepseek.com"
DEEPSEEK_MODEL = "deepseek-flash"
# The output budget of one DeepSeek call: 8192 since 22.10 (the first series of the release run, 04.11, cut one long reduce answer of
# arm A at it). --deepseek-max-tokens raises it, e.g. to 32000, the output cap the Claude models run with (CLAUDE_CODE_MAX_OUTPUT_TOKENS).
DEEPSEEK_MAX_TOKENS = 8192
# $ per 1M tokens (cache miss, cache hit, output) of deepseek-flash (DeepSeek-V4.1-Flash, effective 04:00 UTC 2026-09-10, unchanged on
# 2026-10-17) at peak hours: 01:00-04:00 and 06:00-10:00 UTC on weekdays. Every other time is off-peak at half these rates (live run
# 10A-4 ran off-peak and the brake, priced at peak, stopped at half the money: estimate $1.94, balance $0.88). A public holiday is
# priced at peak here, never below what the provider bills. The per-call cost and the brake use it; the run's actual spend is the
# provider balance before minus after.
DEEPSEEK_RATES = (0.30, 0.006, 1.20)
DEEPSEEK_OFF_PEAK = 0.5
DEEPSEEK_RATES_SOURCE = "deepseek-flash V4.1-Flash table effective 2026-09-10 04:00 UTC; off-peak x0.5"


def deepseek_price_factor(at: float | None = None) -> float:
    """1 at DeepSeek's peak hours (UTC, weekdays), DEEPSEEK_OFF_PEAK at every other time."""
    u = time.gmtime(time.time() if at is None else at)
    peak = u.tm_wday < 5 and (1 <= u.tm_hour < 4 or 6 <= u.tm_hour < 10)
    return 1.0 if peak else DEEPSEEK_OFF_PEAK


def deepseek_price_factor_over(begin: float, end: float) -> float:
    """The highest factor at any moment from begin to end. It changes only on whole UTC hours, so begin and every hour that starts
    inside are checked: both ends of a long life can be off-peak around a peak window (Codex's review of 77a803e, R05)."""
    factor, hour = deepseek_price_factor(begin), (int(begin) // 3600 + 1) * 3600
    while hour <= end:
        factor = max(factor, deepseek_price_factor(hour))
        hour += 3600
    return factor


# Transient refusals and network failures are retried after 2, 4, 8, 16 and 32 s (about a minute in all).
RETRIES = 5


def deepseek_key() -> str:
    """DEEPSEEK_API_KEY, else the closed layer's fallback when it is installed (the local OpenClaw gateway's deepseek provider);
    read at run time, never written out."""
    key = os.environ.get("DEEPSEEK_API_KEY")
    closed = None if key else closed_layer()
    if closed is not None:
        key = closed.openclaw_deepseek_key()
    if not key:
        raise RuntimeError("no DeepSeek API key: set DEEPSEEK_API_KEY")
    return key


def deepseek_request(key: str, path: str, body: dict | None = None, timeout_s: float = 30.0) -> dict:
    data = None if body is None else json.dumps(body).encode("utf-8")
    req = urllib.request.Request(DEEPSEEK_URL + path, data=data, method="GET" if body is None else "POST",
                                 headers={"Authorization": f"Bearer {key}", "Content-Type": "application/json", "Accept": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout_s) as r:
        return json.loads(r.read())


class DeepSeekModel:
    """One fresh chat completion per task: no history, no tools, temperature 0, thinking off by default (live run 1 showed that
    deepseek-flash's reasoning spends a 4096-token output budget and truncates the answer). Usage (prompt, cache hit/miss,
    completion tokens) comes from the provider; the cost is that usage at DEEPSEEK_RATES at the time the call was sent (peak or
    off-peak, deepseek_price_factor). A transient refusal (429/5xx, network)
    is retried with growing pauses for about a minute (live run 6 lost the network for a while: DNS failed for both arms)."""

    def __init__(self, model: str = DEEPSEEK_MODEL, max_tokens: int | None = None, timeout_s: float = 180.0, key: str | None = None,
                 thinking: bool = False):
        max_tokens = max_tokens or DEEPSEEK_MAX_TOKENS  # read at construction, so the run's option reaches every DeepSeek agent
        self.name, self.max_tokens, self.timeout_s, self.thinking = model, max_tokens, timeout_s, thinking
        self.config = {"model": model, "max_tokens": max_tokens, "temperature": 0, "thinking": "enabled" if thinking else "disabled"}
        self._key = key or deepseek_key()

    def __repr__(self) -> str:
        return f"DeepSeekModel({self.name!r})"

    def estimate(self, prompt: str) -> float:
        """An upper bound of one call's cost: every prompt byte a token at the cache-miss rate, the whole output budget, at the highest
        rate of the call's longest life from now (its retries included), so a peak window that opens meanwhile is covered (Codex's
        static review of 6384733 and review of 77a803e, R05)."""
        now = time.time()
        factor = deepseek_price_factor_over(now, now + self.longest_s())
        return (len(prompt.encode("utf-8")) * DEEPSEEK_RATES[0] + self.max_tokens * DEEPSEEK_RATES[2]) * factor / 1e6

    def longest_s(self, timeout_s: float | None = None) -> float:
        """The longest life of one call: every attempt's timeout and the pauses between them (2, 4, ... s)."""
        return (RETRIES + 1) * (self.timeout_s if timeout_s is None else timeout_s) + sum(2 ** (a + 1) for a in range(RETRIES))

    def balance(self) -> float | None:
        try:
            infos = deepseek_request(self._key, "/user/balance").get("balance_infos") or []
            return sum(float(i["total_balance"]) for i in infos if i.get("currency") == "USD")
        except (OSError, urllib.error.URLError, KeyError, ValueError):
            return None

    def complete(self, prompt: str) -> tuple[str, dict, float | None]:
        body = {"model": self.name, "messages": [{"role": "user", "content": prompt}], "temperature": 0, "max_tokens": self.max_tokens,
                "stream": False, "thinking": {"type": "enabled" if self.thinking else "disabled"}}
        for attempt in range(RETRIES + 1):
            try:
                sent = time.time()
                r = deepseek_request(self._key, "/chat/completions", body, self.timeout_s)
                # the call that answered is priced at the highest rate of its life (a peak window may open meanwhile)
                factor = deepseek_price_factor_over(sent, time.time())
                break
            except urllib.error.HTTPError as e:
                detail = e.read()[:300].decode("utf-8", "replace")
                if e.code in (429, 500, 502, 503, 504) and attempt < RETRIES:
                    time.sleep(2 ** (attempt + 1))
                    continue
                raise RuntimeError(f"DeepSeek HTTP {e.code}: {detail}") from None
            except (urllib.error.URLError, TimeoutError, ConnectionError) as e:
                if attempt < RETRIES:
                    time.sleep(2 ** (attempt + 1))
                    continue
                raise RuntimeError(f"DeepSeek transport: {type(e).__name__}: {e}") from None
        choice = r["choices"][0]
        u = r.get("usage") or {}
        hit = u.get("prompt_cache_hit_tokens") or 0
        miss = u.get("prompt_cache_miss_tokens")
        if miss is None:
            miss = max((u.get("prompt_tokens") or 0) - hit, 0)
        out = u.get("completion_tokens") or 0
        usage = {"input": u.get("prompt_tokens") or 0, "output": out, "cache_hit": hit, "cache_miss": miss,
                 "reasoning": (u.get("completion_tokens_details") or {}).get("reasoning_tokens"), "finish_reason": choice.get("finish_reason"),
                 "provider_id": r.get("id"), "model": r.get("model"), "priced_at_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(sent)),
                 "price_factor": factor, "rates": DEEPSEEK_RATES_SOURCE}
        cost = (miss * DEEPSEEK_RATES[0] + hit * DEEPSEEK_RATES[1] + out * DEEPSEEK_RATES[2]) * factor / 1e6 if u else None
        return (choice.get("message") or {}).get("content") or "", usage, cost


# ------------------------------------------------------------------ Codex CLI (a subscription model: the strong graph builder)

# Codex feature families a one-shot answer does not need (as in EXP-12): connectors, sub-agents, shell, browser, ...
CODEX_DISABLE = ["apps", "multi_agent", "image_generation", "goals", "plugins", "memories", "browser_use", "browser_use_external",
                 "computer_use", "shell_tool", "skill_search", "in_app_browser", "hooks", "sleep_tool", "remote_plugin",
                 "skill_mcp_dependency_install"]
# An agentic CLI needs to be told it answers in text only; the task itself is the same prompt every model gets.
CODEX_PREFACE = "Answer the task below with exactly the lines it asks for. Do not run commands or tools and do not ask questions.\n\n"


class CodexModel:
    """One fresh `codex exec` session per task (contract v0.1 R9): no user config, read-only sandbox, tool families off, an empty
    working directory, the task on stdin. Usage comes from the session's events; the cost is unknown (a subscription), never 0."""

    def __init__(self, model: str = "gpt-5.6-sol", effort: str = "medium", timeout_s: float = 900.0, workdir: pathlib.Path | None = None):
        self.name, self.effort, self.timeout_s = model, effort, timeout_s
        self.workdir = workdir or (C.WORK / "codex_empty")
        self.config = {"model": model, "via": "codex exec (one session per task)", "reasoning_effort": effort, "sandbox": "read-only",
                       "cost": "subscription: unknown dollars per call"}

    def complete(self, prompt: str) -> tuple[str, dict, float | None]:
        self.workdir.mkdir(parents=True, exist_ok=True)
        exe = shutil.which("codex") or "codex"
        off = [x for f in CODEX_DISABLE for x in ("--disable", f)]
        cmd = [exe, "exec", "--ignore-user-config", "--ignore-rules", *off, "-c", 'web_search="disabled"', "--skip-git-repo-check", "--json",
               "-s", "read-only", "-m", self.name, "-c", f'model_reasoning_effort="{self.effort}"', "-c", 'approval_policy="never"',
               "-C", str(self.workdir), "-"]
        cp = subprocess.run(cmd, input=CODEX_PREFACE + prompt, capture_output=True, text=True, encoding="utf-8", timeout=self.timeout_s)
        events = []
        for line in cp.stdout.splitlines():
            if line.strip().startswith("{"):
                try:
                    events.append(json.loads(line))
                except json.JSONDecodeError:
                    pass
        texts = [e["item"].get("text") or "" for e in events
                 if e.get("type") == "item.completed" and isinstance(e.get("item"), dict) and e["item"].get("type") == "agent_message"]
        failed = [e for e in events if e.get("type") in ("turn.failed", "error")]
        if cp.returncode != 0 or failed or not texts:
            raise RuntimeError(f"codex exec: rc={cp.returncode} {json.dumps(failed[:1])[:300]} {cp.stderr[-300:]}")
        usage: dict[str, int] = {}
        for e in events:
            if e.get("type") == "turn.completed":
                for k, v in (e.get("usage") or {}).items():
                    usage[k] = usage.get(k, 0) + (v or 0)
        u = {"input": usage.get("input_tokens", 0), "output": usage.get("output_tokens", 0), "cache_hit": usage.get("cached_input_tokens", 0),
             "reasoning": usage.get("reasoning_output_tokens"), "model": self.name, "finish_reason": "stop"}
        return texts[-1], u, None


# ------------------------------------------------------------------ Claude Sonnet 5.5 through Claude Code (the owner's Max plan)

CLAUDE_MODEL = "claude-sonnet-5-5"
# $ per 1M tokens (input, cache read, output) of claude-sonnet-5-5, the Claude API list prices (model table cached 2026-10-06). The
# calls run on the owner's Max plan, not billed per call: Claude Code reports each call's API-equivalent cost (cost basis "list"),
# which the brake counts as a measure of the plan's limits used.
CLAUDE_RATES = (2.00, 0.20, 10.00)
CLAUDE_RATES_SOURCE = "claude-sonnet-5-5 Claude API list prices (model table cached 2026-10-06); billed to the Max plan's limits"
# Claude Haiku 5.5 as the swarm in place of DeepSeek. $ per 1M tokens (input, output) of each Claude model the
# runner calls, the same list prices; Haiku's hold for prompts up to 100K tokens, far above the pilot's. Only the brake's reservation
# reads them (a Sonnet-priced reserve for Haiku would be twenty times too high and hold up parallel calls): the cost the brake counts
# is the one Claude Code reports.
CLAUDE_HAIKU = "claude-haiku-5-5"
# Claude Opus 5.5 as the one strong reader in place of the swarm: $4 / $20 per MTok (the Claude API model
# table, claude-api skill models.md).
CLAUDE_OPUS = "claude-opus-5-5"
CLAUDE_MODEL_RATES = {CLAUDE_MODEL: (CLAUDE_RATES[0], CLAUDE_RATES[2]), CLAUDE_HAIKU: (0.10, 0.50), CLAUDE_OPUS: (4.00, 20.00)}
# The output a call may reserve against the brake: far above any answer of the pilot (its bound is 48 lines), not the model's 128K.
CLAUDE_RESERVED_OUTPUT = 32000
# The task is the whole conversation: no Claude Code system prompt, tools, skills, MCP servers, settings or session history.
CLAUDE_SYSTEM = ("Answer the task with exactly the lines it asks for. Do not run commands or tools and do not ask questions. Do not "
                 "include internal or system XML tags or your reasoning in the answer.")
# The marker of a call the model's safeguards declined (see model_refused).
MODEL_REFUSED = "MODEL_REFUSED"
# Variables that would send the child to another account or endpoint: an API key or token bills the API instead of the Max plan
# (Codex's review of d1f2474). They are not passed on, nor the enclosing Claude Code session's own CLAUDE* variables.
CLAUDE_ENV_DROPPED = ("ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN", "ANTHROPIC_BASE_URL")
# Errors worth a retry after a pause: the plan's rate limits, an overloaded or failing API, a dropped connection.
CLAUDE_TRANSIENT = ("rate limit", "rate_limit", "overloaded", "529", "500", "502", "503", "504", "timed out", "connection")
# An answer that ran past the output the brake reserved (CLAUDE_RESERVED_OUTPUT) is an agent that did not answer within its limits,
# as a timeout is (agent_failed): its task is released at once and given out again (live run MCPctl_none_r2: a summary's second
# repair ran 617 s past it and stopped the run; claude-reviewer's RV-01 of 87b54b2b: a retry inside the call made the task's fate
# depend on how fast the model overran)
CLAUDE_OVERRUN = "output token maximum"
OUTPUT_OVERRUN = "OUTPUT_OVERRUN"


class ClaudeCliModel:
    """One fresh `claude -p` session per task (contract v0.1 R9) with the owner's Claude Code login (Sonnet 5.5
    while DeepSeek is at its peak hours, to find the remaining defects). A short system prompt in place of Claude Code's, no tools, no
    MCP servers, no user settings or hooks, no session saved, an empty temporary working directory. The environment of an enclosing
    Claude Code session is not passed on: the child signs in with the stored login, not the host's. Usage and the API-equivalent cost
    come from Claude Code's result; an answer from any other model is an error."""

    def __init__(self, model: str = CLAUDE_MODEL, effort: str = "medium", timeout_s: float = 600.0, exe: str | None = None,
                 billed: bool = True):
        self.name, self.effort, self.timeout_s, self.billed = model, effort, timeout_s, billed
        self._exe = exe
        if model not in CLAUDE_MODEL_RATES:
            raise ValueError(f"no list prices for {model}: add them to CLAUDE_MODEL_RATES")
        self.rates = CLAUDE_MODEL_RATES[model]
        self.config = {"model": model, "via": "Claude Code `claude -p` (one session per task, no tools)", "effort": effort,
                       "rates": f"{model} Claude API list prices; billed to the Max plan's limits",
                       "cost": "Claude Code's API-equivalent cost; the Max plan's limits, not dollars", "counted_by_brake": billed}

    def longest_s(self, timeout_s: float | None = None) -> float:
        """The longest life of one call: every attempt's timeout and the pauses between them (2, 4, ... s)."""
        return (RETRIES + 1) * (self.timeout_s if timeout_s is None else timeout_s) + sum(2 ** (a + 1) for a in range(RETRIES))

    # a failed attempt may have been billed: every retry reserves its own estimate with the brake first (Codex's review of 06a578c, R04)
    reserves_retries = True

    def __repr__(self) -> str:
        return f"ClaudeCliModel({self.name!r})"

    @property
    def model_family(self):
        return "claude:" + self.name

    def for_role(self, effort, *, timeout_s=None):
        """The same model at another effort or call deadline."""
        result = ClaudeCliModel(self.name, effort=effort or self.effort, timeout_s=timeout_s if timeout_s is not None else self.timeout_s,
                                exe=self._exe, billed=self.billed)
        result.config.update(model_family=self.model_family, effort=effort or self.effort)
        return result

    def exe(self) -> str:
        if self._exe is None:
            from .agents import find_claude
            self._exe = find_claude()
        return self._exe

    def estimate(self, prompt: str) -> float:
        """An upper bound of one call's API-equivalent cost: every prompt byte a token at the input rate, CLAUDE_RESERVED_OUTPUT at the
        output rate."""
        return (len(prompt.encode("utf-8")) * self.rates[0] + CLAUDE_RESERVED_OUTPUT * self.rates[1]) / 1e6

    def complete(self, prompt: str, reserve_retry=None) -> tuple[str, dict, float | None]:
        """`reserve_retry()` asks the brake for one more attempt's estimate; refused, the call fails with what it has spent. The cost is
        the sum of every attempt's reported cost, or unknown (None) when any attempt reported none: an attempt without a result may
        still have been billed (Codex's review of 06a578c, R04: an unknown first attempt vanished behind a known second one)."""
        cmd = [self.exe(), "-p", "--model", self.name, "--output-format", "json", "--tools", "", "--system-prompt", CLAUDE_SYSTEM,
               "--strict-mcp-config", "--setting-sources", "project", "--no-session-persistence", "--disable-slash-commands",
               "--effort", self.effort]
        env = {k: v for k, v in os.environ.items() if not k.startswith("CLAUDE") and k not in CLAUDE_ENV_DROPPED}
        # the output the brake reserved is the output the CLI may write (Codex's review of d1f2474: 48000 tokens passed a 32000 bound)
        env["CLAUDE_CODE_MAX_OUTPUT_TOKENS"] = str(CLAUDE_RESERVED_OUTPUT)
        spent, unknown = 0.0, 0

        def cost() -> float | None:
            return None if unknown else spent

        for attempt in range(RETRIES + 1):
            if attempt and reserve_retry is not None and not reserve_retry():
                raise CallFailed(f"Claude Code failed and the brake holds no reserve for attempt {attempt + 1}: {detail}", cost())
            work = tempfile.mkdtemp(prefix="sbgk_claude_")
            try:
                cp = subprocess.run(cmd, input=prompt, capture_output=True, text=True, encoding="utf-8", cwd=work, env=env, timeout=self.timeout_s)
            finally:
                shutil.rmtree(work, ignore_errors=True)
            try:
                d = json.loads(cp.stdout)
            except json.JSONDecodeError:
                d = None
            if isinstance(d, dict) and isinstance(d.get("total_cost_usd"), (int, float)):
                spent += float(d["total_cost_usd"])
            else:
                unknown += 1
            if isinstance(d, dict) and not d.get("is_error") and isinstance(d.get("result"), str):
                if d.get("stop_reason") == "refusal":
                    # the API's refusal stop arrives as an ordinary result (Codex's review of d1f2474: read as a broken format, it
                    # stopped the run after two repairs)
                    raise CallFailed(f"{MODEL_REFUSED}: stop_reason refusal: {d['result'][:200]}", cost())
                turns = d.get("num_turns")
                if isinstance(turns, int) and turns > 1:
                    # a tool-less call has one turn; more are Claude Code asking the model to resume past the reserved output, and
                    # the result holds the last turn's text only (live run MCPsbase_r1: a summary arrived without its first 31 lines)
                    raise CallFailed(f"{OUTPUT_OVERRUN}: the answer ran past the {CLAUDE_RESERVED_OUTPUT} output token maximum and was "
                                     f"resumed in {turns} turns; the result holds the last turn only", cost())
                break
            detail = str(d.get("result") if isinstance(d, dict) else (cp.stdout[-300:] + cp.stderr[-300:]))[:300]
            if "safeguards flagged" in detail:
                raise CallFailed(f"{MODEL_REFUSED}: {detail}", cost())
            if CLAUDE_OVERRUN in detail:
                raise CallFailed(f"{OUTPUT_OVERRUN}: {detail}", cost())
            if attempt < RETRIES and any(t in detail.lower() for t in CLAUDE_TRANSIENT):
                time.sleep(2 ** (attempt + 1))
                continue
            raise CallFailed(f"Claude Code failed ({cp.returncode}): {detail}", cost())
        models = d.get("modelUsage") or {}
        if self.name not in models:
            raise CallFailed(f"Claude Code answered with {sorted(models)}, not {self.name}", cost())
        u, m = d.get("usage") or {}, models[self.name]
        hit, created = u.get("cache_read_input_tokens") or 0, u.get("cache_creation_input_tokens") or 0
        usage = {"input": (u.get("input_tokens") or 0) + hit + created, "output": u.get("output_tokens") or 0, "cache_hit": hit,
                 "cache_write": created, "reasoning": m.get("thinkingTokens"), "finish_reason": d.get("stop_reason"),
                 "other_models": sorted(k for k in models if k != self.name), "cost_basis": m.get("costBasis"), "model": self.name,
                 "attempts": attempt + 1, "known_cost_usd": round(spent, 6), "unknown_cost_attempts": unknown}
        # every attempt that reported a cost counts, the retried ones too (Codex's review of d1f2474: a failed 0.10 was dropped)
        return d["result"], usage, cost()



class AgyCallError(RuntimeError):
    def __init__(self, message: str, usage: dict, diagnostics: dict | None = None):
        super().__init__(message)
        self.usage, self.cost_usd = usage, None
        self.diagnostics = diagnostics or {}


def agy_exe() -> str:
    """The Antigravity CLI: AGY_BIN, else `agy` on PATH."""
    exe = os.environ.get("AGY_BIN") or shutil.which("agy")
    if not exe:
        raise RuntimeError("the Antigravity CLI is not found: set AGY_BIN to its executable or put agy on PATH")
    return exe


class AgyModel:
    """One fresh Antigravity print-mode session per call; unknown subscription price, recorded tokens, no hidden retries."""
    def __init__(self, model: str, timeout_s: float = 240.0, workdir: pathlib.Path | None = None):
        if not re.fullmatch(r"[A-Za-z0-9_.-]+", model) or not (0 < timeout_s < float("inf")):
            raise ValueError("an agy model id and a finite positive timeout are required")
        self.name, self.timeout_s = model, timeout_s
        self.workdir = pathlib.Path(workdir) if workdir else pathlib.Path(tempfile.gettempdir()) / "sbgk_agy_sessions"
        self.config = {"model": model, "via": "Antigravity CLI, fresh empty directory, plan mode, stream-json stdin",
                       "cost": "unknown subscription price; count calls and tokens", "retries": 0, "timeout_s": timeout_s,
                       "human_request_guard": "abort observed tool invocation or structured human-input wait",
                       "tool_filter": "not exposed by installed agy --help; plan mode retained",
                       "failure_capture_chars": 64_000}

    @property
    def model_family(self):
        return "agy:"+re.sub(r"-(low|medium|high)$","",self.name)

    def for_role(self, effort, *, timeout_s=None):
        name=re.sub(r"-(low|medium|high)$","",self.name)+"-"+effort if effort else self.name
        result=AgyModel(name,timeout_s=timeout_s if timeout_s is not None else self.timeout_s,workdir=self.workdir)
        result.config.update(model_family=self.model_family,effort=effort)
        return result

    def complete(self, prompt: str) -> tuple[str, dict, float | None]:
        self.workdir.mkdir(parents=True, exist_ok=True)
        line = json.dumps({"event": "user", "message": {"content": prompt +
            "\n\nDo not use any tool: everything you need is in this message. Answer in the requested format only."}}) + "\n"
        cmd = [agy_exe(), "-p=", "--input-format", "stream-json",
               "--output-format", "stream-json", "--model", self.name, "--mode", "plan"]
        from .agy_stream import run_stream, StreamFailure
        failure = None
        with tempfile.TemporaryDirectory(prefix="call_", dir=self.workdir) as cwd:
            try:
                result, returncode, diagnostics = run_stream(cmd, line, cwd, self.timeout_s)
            except StreamFailure as exc:
                result, returncode, diagnostics, failure = exc.result, None, exc.diagnostics, str(exc)
        raw = result.get("usage") or {}
        usage, unknown = {"model": self.name, "turns": result.get("num_turns"), "seconds": result.get("duration_seconds")}, []
        for target, field in (("input", "input_tokens"), ("output", "output_tokens"), ("reasoning", "thinking_tokens")):
            v = raw.get(field)
            if type(v) is not int or v < 0:
                unknown.append(field)
                v = 0
            usage[target] = v
        usage["usage_complete"], usage["unknown_token_fields"] = not unknown, unknown
        if failure or returncode != 0 or result.get("status") != "SUCCESS" or not isinstance(result.get("response"), str):
            raise AgyCallError(failure or f"agy did not return a successful text result (exit {returncode})", usage, diagnostics)
        return result["response"], usage, None


def make_model(name: str, effort: str = "medium", *, timeout_s: float | None = None) -> Model:
    if name.startswith("agy:"):
        return AgyModel(name[4:], timeout_s=timeout_s or AGY_TIMEOUT_S)
    aliases = {"stub": StubModel, "deepseek": DeepSeekModel, "sonnet": lambda: ClaudeCliModel(effort=effort),
               "haiku": lambda: ClaudeCliModel(model=CLAUDE_HAIKU, effort=effort),
               "opus": lambda: ClaudeCliModel(model=CLAUDE_OPUS, effort=effort, timeout_s=timeout_s or 600.0)}
    if name in aliases:
        return aliases[name]()
    if name in CLOSED_MODELS:
        return closed_layer(f"the model {name}").MODELS[name]()
    if name.startswith("codex:") or name.startswith("gpt-"):
        return CodexModel(name.removeprefix("codex:"), effort)
    raise ValueError(f"unknown model {name!r}: use an alias, agy:<id> or codex:<id>")


class Budget:
    """The money brake shared by both arms: a call reserves its upper estimate before it is sent and settles to its reported cost
    afterwards (an unknown cost keeps the reservation, it is never counted as 0)."""

    def __init__(self, cap_usd: float):
        self.cap, self.settled, self.reserved, self.unknown = cap_usd, 0.0, 0.0, 0
        self.lock = threading.Lock()

    def reserve(self, usd: float) -> bool:
        with self.lock:
            if self.settled + self.reserved + usd > self.cap:
                return False
            self.reserved += usd
            return True

    def settle(self, reserved: float, actual: float | None) -> None:
        with self.lock:
            self.reserved -= reserved
            if actual is None:
                self.unknown += 1
                self.settled += reserved
            else:
                self.settled += actual

    def state(self) -> dict:
        with self.lock:
            return {"cap_usd": self.cap, "spent_usd_estimate": round(self.settled, 6), "reserved_usd": round(self.reserved, 6),
                    "unknown_cost_calls": self.unknown}


KEYWORDS = ["stale", "supersed", "blocking", "warning", "future work", "unsupported", "not shipped", "no release", "fail closed", "removed",
            "limitation", "candidate only"]


class StubModel:
    """A deterministic stand-in for every role of both arms: a crude fixed reader (lines with audit keywords). It costs nothing
    and reports no usage; the point is the mechanics, not the audit."""

    name = "stub"

    def longest_s(self, timeout_s: float | None = None) -> float:
        """A stub answers at once."""
        return 0.0

    def complete(self, prompt: str) -> tuple[str, dict, float | None]:
        if prompt.startswith("RESTATE AFTER A WITHDRAWAL"):
            return self._restate(prompt), {}, 0.0
        if prompt.startswith("FIX THESE ANSWER LINES"):
            return prompt.split("LINES:\n", 1)[1].split("\nYOUR OBSERVES:", 1)[0], {}, 0.0
        if "ANSWER FROM YOUR RECORDS" in prompt:
            return self._answers(prompt), {}, 0.0
        if "TASK EXTEND" in prompt and "Each claim states one fact" in prompt:
            return self._whole(prompt, answers=False), {}, 0.0
        if prompt.startswith("REFINE_CARD:"):  # circles +1: the refiner's card is a builder card with what the swarm built
            prompt = prompt.split("\n", 1)[1]
        # links off (the build scope concepts): the concept builder's card, answered the same way (the stub writes no links)
        if prompt.startswith(("You are the graph builder", "You are the concept builder")):
            return self._builder(prompt), {}, 0.0
        if prompt.startswith("PAIR_CARD:"):
            return self._pair(prompt), {}, 0.0
        if prompt.startswith("EVOLUTION_LINK_CARD:"):
            return self._evolution(prompt), {}, 0.0
        if prompt.startswith("ARM A ANSWER REDUCE"):
            parts=json.loads(prompt.split("\nPARTIAL ANSWERS:\n",1)[1].split("\nEND PARTIAL ANSWERS",1)[0]);out=[]
            for part in parts:
                for claim in part["claims"]:
                    out.append(json.dumps({"kind":"claim","local_id":f"r{len(out)}","text":claim["text"],"quotes":[{"report":q["report"],"exact_quote":q["quote"]} for q in claim["quotes"]]}))
            out.append(json.dumps({"kind":"done","text":"The stub reduction adds no new facts."}))
            return "\n".join(out),{},0.0
        if prompt.startswith("ARM A SINGLE"):
            return self._single(prompt), {}, 0.0
        if prompt.startswith("ARM A TEAM"):
            return self._team(prompt), {}, 0.0
        if "TASK EXTEND" in prompt and '"answer_done"' in prompt:
            return self._whole(prompt), {}, 0.0
        if "TASK EXTEND" in prompt:
            return self._extend(prompt), {}, 0.0
        if "TASK CHANGE" in prompt:
            return self._change(prompt), {}, 0.0
        if "TASK VERIFY_LINK" in prompt or "TASK RESOLVE_CONFLICT" in prompt:
            link = re.search(r'"link":"(@[0-9a-f]+)"', prompt)
            claims = shown(prompt, "claim")
            return json.dumps({"kind": "verdict", "link": link.group(1) if link else "", "verdict": "confirm", "based_on": claims[:1]}), {}, 0.0
        if "TASK SUMMARIZE research question" in prompt:
            return self._summarize(prompt), {}, 0.0
        if "TASK RELATE" in prompt:
            return self._relate(prompt), {}, 0.0
        if "TASK INVESTIGATE" in prompt or "TASK REREAD" in prompt or "TASK CHECK_COVERAGE" in prompt or "TASK FIND_LINK_BASIS" in prompt:
            return "[]", {}, 0.0
        if prompt.startswith("ARM A WORKER"):
            return "\n".join(f"- [{doc}] \"{line}\"" for doc, line in a_findings(prompt)), {}, 0.0
        if prompt.startswith("ARM A SUMMARY") or prompt.startswith("ARM A UPDATE"):
            about = _stub_about.get()
            lines = [ln for ln in prompt.split("NOTES:\n", 1)[1].splitlines() if ln.startswith("- [") and any(t in ln.lower() for t in about)]
            for quote, report in re.findall(r'WITHDRAWN QUOTE: "(.*)" \(report ([^)]+)\)', prompt):
                lines = [ln for ln in lines if not (ln.startswith(f"- [{report}]") and (quote in ln or any(x in quote for x in re.findall(r'"(.+)"', ln))))]
            return "\n".join(lines) or "unknown: the notes do not settle it", {}, 0.0
        return "", {}, 0.0

    @staticmethod
    def _change(prompt: str) -> str:
        """Synthetic mechanics only: an explicit warning-to-blocking fixture, never a semantic oracle."""
        p = re.search(r"every local_id starts with (\S+?)\.", prompt).group(1)
        rows = json.loads(prompt.split("\nVERSION TEXTS:\n", 1)[1].split("\nEND VERSION TEXTS", 1)[0])
        old = next((r for r in rows if r["side"] == "old"), None)
        new = next((r for r in rows if r["side"] == "new"), None)
        if not old or not new:
            return "[]"
        quotes = [next((s.strip() for s in r["text"].splitlines() if s.strip() and not s.startswith("#")), "") for r in (old, new)]
        if not all(quotes) or any(len(q) > 200 for q in quotes):
            return "[]"
        out = []
        for i, (r, q) in enumerate(zip((old, new), quotes)):
            out += [{"kind":"observe","local_id":f"{p}o{i}","doc_id":r["doc_id"],"exact_quote":q,"terms":["version mismatch"]},
                    {"kind":"claim","local_id":f"{p}c{i}","text":q,"subject":"version mismatch","stance":"reported","based_on":[f"{p}o{i}"]}]
        if "warning" in quotes[0] and "blocking" in quotes[1]:
            out.append({"kind":"relation","local_id":f"{p}r","from":f"{p}c1","rel":"supersedes","to":f"{p}c0","based_on":[f"{p}o0",f"{p}o1"]})
        return "\n".join(json.dumps(v) for v in out)

    @staticmethod
    def _extend(prompt: str) -> str:
        doc = re.search(r'SECTION doc_id="([^"]+)"', prompt).group(1)
        p = re.search(r"every local_id starts with (\S+?)\.", prompt).group(1)
        out = []
        for i, line in enumerate(found_lines(section_of(prompt))[:2]):
            out.append(json.dumps({"kind": "observe", "local_id": f"{p}o{i}", "doc_id": doc, "exact_quote": line, "terms": [kw_of(line)]}))
            out.append(json.dumps({"kind": "claim", "local_id": f"{p}c{i}", "text": line[:200], "subject": kw_of(line), "stance": "reported",
                                   "based_on": [f"{p}o{i}"]}))
        return "\n".join(out) or "[]"

    @staticmethod
    def _pair(prompt: str) -> str:
        """The new assertion supersedes the old one, on their quotes: a link for the checker to verify."""
        card, _ = json.JSONDecoder().raw_decode(prompt.split("\nCARD:\n", 1)[1])
        records, basis = card["records"], [n["id"] for n in card["neighbors"] if n.get("kind") == "observe"][:2]
        if len(records) != 2 or not basis:
            return "[]"
        old, new = records
        return json.dumps({"op": "link", "from": new["id"], "rel": "supersedes", "to": old["id"], "basis": basis})

    @staticmethod
    def _evolution(prompt: str) -> str:
        """Every pair of the card decided: the first one superseded on a quote of each end, the others none (a packed card, K06)."""
        card, _ = json.JSONDecoder().raw_decode(prompt.split("\nCARD:\n", 1)[1])
        cone = {r["id"]: r.get("based_on") or [] for r in card["records"] + card["neighbors"]}
        out = []
        for i, pair in enumerate(card["pair_metadata"]["metadata"]["pairs"]):
            old, new = "@" + pair["old"][:16], "@" + pair["new"][:16]
            basis = cone.get(new, [])[:1] + cone.get(old, [])[:1]
            if i == 0 and len(basis) == 2:
                out.append(json.dumps({"op": "link", "from": new, "rel": "supersedes", "to": old, "basis": basis}))
            else:
                out.append(json.dumps({"op": "none", "pair": pair["pair"], "reason": "The stub links only the first pair of a card."}))
        return "\n".join(out) or "[]"

    @staticmethod
    def _single(prompt: str) -> str:
        """One claim per report on its first keyword line, leaving out withdrawn text, and the done line."""
        withdrawn = re.findall(r'WITHDRAWN QUOTE: "(.*)" \(report ([^)]+)\)', prompt)
        out = []
        for i, (path, text) in enumerate(re.findall(r"=== REPORT (.+?) ===\n(.*?)\n=== END OF \1 ===", prompt, re.S)):
            for line in found_lines(text)[:1]:
                if not any(rep == path and (w in line or line in w) for w, rep in withdrawn):
                    out.append(json.dumps({"kind": "claim", "local_id": f"a{i}", "text": line[:200], "quotes": [{"report": path, "exact_quote": line}]}))
        out.append(json.dumps({"kind": "done", "text": "The stub answer settles nothing else."}))
        return "\n".join(out)

    @staticmethod
    def _whole(prompt: str, answers: bool = True) -> str:
        """The zone answer of run S1.2: per report its first two keyword lines as observes and claims, and for each question one
        answer line on each observe and its done line."""
        p = re.search(r"every local_id starts with (\S+?)\.", prompt).group(1)
        out, observes = [], []
        for doc, text in re.findall(r'SECTION doc_id="([^"]+)" \(bytes \d+\.\.\d+\):\n<<<\n(.*?)\n>>>', prompt, re.S):
            for line in found_lines(text)[:2]:
                n = len(observes) + 1
                out.append(json.dumps({"kind": "observe", "local_id": f"{p}o{n}", "doc_id": doc, "exact_quote": line, "terms": [kw_of(line)]}))
                out.append(json.dumps({"kind": "claim", "local_id": f"{p}c{n}", "text": line[:200], "subject": kw_of(line), "stance": "reported",
                                       "based_on": [f"{p}o{n}"]}))
                observes.append(f"{p}o{n}")
        for rq in re.findall(r"^  (RQ\w+): ", prompt, re.M) if answers else []:
            for i, o in enumerate(observes, 1):
                out.append(json.dumps({"kind": "answer", "rq_id": rq, "local_id": f"{p}a{rq}{i}", "text": f"The reports record this, item {i}.",
                                       "subject": "summary", "stance": "reported", "based_on": [o]}))
            out.append(json.dumps({"kind": "answer_done", "rq_id": rq, "text": "The stub answer settles nothing else."}))
        return "\n".join(out)

    @staticmethod
    def _answers(prompt: str) -> str:
        """Run S1.3's answer call: for each question one answer line on each observe and the next one, and its done line."""
        records = prompt.split("as the kernel stored them:\n", 1)[1].split("\nNow answer", 1)[0]
        observes = [v["local_id"] for v in map(json.loads, records.splitlines()) if v.get("kind") == "observe"]
        out = []
        for rq in re.findall(r"^  (RQ\w+): ", prompt, re.M):
            for i, o in enumerate(observes):
                based = sorted({o, observes[(i + 1) % len(observes)]})
                out.append(json.dumps({"kind": "answer", "rq_id": rq, "local_id": f"a{rq}{i}", "text": f"The reports record this, item {i}.",
                                       "subject": "summary", "stance": "reported", "based_on": based}))
            out.append(json.dumps({"kind": "answer_done", "rq_id": rq, "text": "The stub answer settles nothing else."}))
        return "\n".join(out)

    @staticmethod
    def _restate(prompt: str) -> str:
        """Run S1.3's restatement: each candidate restated on its remaining quotes."""
        out = [json.dumps({"kind": "answer", "rq_id": x["rq_id"], "local_id": x["local_id"], "text": x["text"], "subject": x.get("subject") or "summary",
                           "stance": "reported", "based_on": x["remaining"]})
               for x in (json.loads(ln[len("CANDIDATE "):]) for ln in prompt.splitlines() if ln.startswith("CANDIDATE "))]
        return "\n".join(out) or "[]"

    @staticmethod
    def _team(prompt: str) -> str:
        """One claim per note of the team, leaving out withdrawn text, and the done line."""
        withdrawn = re.findall(r'WITHDRAWN QUOTE: "(.*)" \(report ([^)]+)\)', prompt)
        notes = prompt.split("\nQUESTION ", 1)[0]
        out = []
        for i, (path, line) in enumerate(re.findall(r'^- \[(.+?)\] "(.*)"$', notes, re.M)):
            if not any(rep == path and (w in line or line in w) for w, rep in withdrawn):
                out.append(json.dumps({"kind": "claim", "local_id": f"a{i}", "text": line[:200], "quotes": [{"report": path, "exact_quote": line}]}))
        out.append(json.dumps({"kind": "done", "text": "The stub answer settles nothing else."}))
        return "\n".join(out)

    @staticmethod
    def _relate(prompt: str) -> str:
        """One change on the first quote of its own first claim and the first quote of that claim's first hint, or []."""
        block = prompt.split("YOUR CLAIMS, EACH WITH RELATED RECORDS:\n", 1)[-1].split("\n\n", 1)[0]
        own, _, hints = block.partition("related (hints")
        mine, theirs = shown(own, "observe")[:1], shown(hints, "observe")[:1]
        p = re.search(r"new local_id that starts with (\S+?)r;", prompt)
        if not (mine and theirs and p):
            return "[]"
        return json.dumps({"kind": "claim", "local_id": f"{p.group(1)}r1", "text": "The later report changes what the earlier one stated.",
                           "subject": "change", "stance": "superseded", "as_of": None, "based_on": mine + theirs})

    @staticmethod
    def _summarize(prompt: str) -> str:
        p = re.search(r"every local_id starts with (\S+?)\.", prompt).group(1)
        rq = re.search(r'"rq_id":"([^"]+)"', prompt).group(1)
        directive = re.search(r'"directive_id":"([^"]+)"', prompt).group(1)
        obs = shown(prompt, "observe")[:4]
        # the kernel refuses an answer that leaves out a report of its window: one more quote for each report the first four miss
        # (a control run's window, --build-scope none|concepts, is not narrowed by concepts and spans more reports)
        seen = {doc for oid, doc in re.findall(r"(@[0-9a-f]+) observe by [^:]+: \[([^,\]]+)", prompt) if oid in obs}
        for oid, doc in re.findall(r"(@[0-9a-f]+) observe by [^:]+: \[([^,\]]+)", prompt):
            if doc not in seen:
                seen.add(doc)
                obs.append(oid)
        lines = []
        if obs:
            lines.append(json.dumps({"kind": "claim", "local_id": f"{p}c1", "text": "The shown records answer the question.", "subject": "summary",
                                     "stance": "reported", "based_on": obs}))
        lines.append(json.dumps({"kind": "done", "local_id": f"{p}d1", "rq_id": rq, "directive_id": directive,
                                 "outcome": "answered" if obs else "unknown", "answer_ids": [f"{p}c1"] if obs else []}))
        return "\n".join(lines)

    @staticmethod
    def _builder(prompt: str) -> str:
        # the card is the first JSON after CARD:, as for an evolution card
        card, _ = json.JSONDecoder().raw_decode(prompt.split("\nCARD:\n", 1)[1])
        ops, proposed = [], set()
        for r in card["records"]:
            for t in r["terms"]:
                cands = card["candidates"].get(t) or []
                if cands:
                    ops.append({"op": "map_term", "record": r["id"], "term": t, "concept": cands[0]["id"]})
                elif r["kind"] == "observe" and t not in proposed:
                    op = {"op": "propose_concept", "type": "Issue", "name": t, "aliases": [], "basis": [r["id"]]}
                    if "known_functions" in card:
                        # the address layer: a known function when the card shows one, else a new one named after the term
                        known = card["known_functions"]
                        op["function"] = known[0]["function"] if known else t
                    ops.append(op)
                    ops.append({"op": "map_term", "record": r["id"], "term": t, "concept": t})
                    proposed.add(t)
        ops = ops[: card["max_ops"]]
        # with the builder's requests on (U1): one second reading of the section of the card's first observe, about its own words
        board = card.get("requests") or {}
        first = next((r for r in card["records"] if r["kind"] == "observe" and r["id"] in (board.get("sections") or {})), None)
        loss = (board.get("losses") or [None])[0]
        if loss and first and board.get("card_left") and board.get("run_left"):
            ops.append({"op": "request", "type": "reread_gap", "local_id": "q2", "doc_id": loss["doc_id"], "section": loss["section"], "focus": [],
                        "reason": "section_refused", "based_on": [first["id"]]})
        if first and board.get("card_left") and board.get("run_left"):
            doc, k = board["sections"][first["id"]]
            ops.append({"op": "request", "type": "reread_gap", "local_id": "q1", "doc_id": doc, "section": k, "focus": [first["quote"][:60]],
                        "reason": "section_saturated", "based_on": [first["id"]]})
        return "\n".join(json.dumps(o) for o in ops) or "[]"


def kw_of(line: str) -> str:
    low = line.lower()
    return next(k for k in KEYWORDS if k in low)


def found_lines(section: str) -> list[str]:
    """Whole lines of a section that carry an audit keyword (deduplicated: a quote must be unique)."""
    out = []
    for ln in section.splitlines():
        ln = ln.strip()
        if 12 <= len(ln) <= 400 and any(k in ln.lower() for k in KEYWORDS) and ln not in out and section.count(ln) == 1:
            out.append(ln)
    return out


def section_of(prompt: str) -> str:
    a = prompt.index("<<<\n") + 4
    return prompt[a:prompt.index("\n>>>", a)]


def shown(prompt: str, kind: str) -> list[str]:
    ids = []
    for ln in prompt.splitlines():
        parts = ln.strip().split(" ", 2)
        if len(parts) >= 2 and parts[0].startswith("@") and parts[1] == kind:
            ids.append(parts[0])
    return ids


def a_findings(prompt: str) -> list[tuple[str, str]]:
    doc = re.search(r"SECTION OF (\S+):", prompt).group(1)
    notes = prompt.split("NOTES:\n", 1)[1].split("\nSECTION OF", 1)[0]
    return [(doc, ln) for ln in found_lines(section_of(prompt))[:2] if ln not in notes]


def broken_refusal(text: str, cut: bool = False, max_lines: int | None = None) -> dict:
    """The runner's own refusal of an answer with lines that start a JSON object but do not parse (Codex review c78060e, F02: they
    were dropped and the rest went on as complete). Nothing was submitted, so the whole answer comes again. An answer cut at the
    model's output limit says so: the model has to write less, not the same again (live run 10A-2 lost both summaries that way)."""
    bad, whole = [], 0
    for ln in text.splitlines():
        ln = ln.strip()
        if ln.startswith("{"):
            try:
                json.loads(ln)
                whole += 1
            except json.JSONDecodeError:
                bad.append(ln[:200])
    if cut:
        bound = f"at most {max_lines} lines, " if max_lines else ""
        return {"status": "REPAIR_REQUIRED", "failed_index": 0, "local": True,
                "error": {"code": "OUTPUT_LIMIT", "message": f"your answer was cut at the output limit after {whole} complete lines: send the whole "
                                                             f"answer again, shorter ({bound}short texts, related records merged)", "lines": bad}}
    return {"status": "REPAIR_REQUIRED", "failed_index": 0, "local": True,
            "error": {"code": "BROKEN_JSON_LINE", "message": "every line must be one complete JSON object on one line; these did not parse",
                      "lines": bad}}


def was_cut(c: "Call") -> bool:
    """The provider stopped the answer at its output limit."""
    # DeepSeek says length, Claude max_tokens (Codex's review of d1f2474: a cut Claude answer was submitted as complete)
    return (c.usage or {}).get("finish_reason") in ("length", "max_tokens")


def parse_lines(text: str) -> tuple[list[dict], int]:
    """JSON objects of a model answer, one per line (code fences and prose are skipped); the second value counts broken lines."""
    out, broken = [], 0
    for ln in text.splitlines():
        ln = ln.strip()
        if not ln.startswith("{"):
            continue
        try:
            v = json.loads(ln)
            out.append(v) if isinstance(v, dict) else None
        except json.JSONDecodeError:
            broken += 1
    return out, broken


EMPTY_RESPONSE_RULE = "\nReturn one JSON object per line, with no prose or code fences. If there is deliberately nothing to add, reply exactly []."


def submission_lines(text: str, *, allow_empty: bool) -> tuple[list[dict], dict | None, bool]:
    """Validate the whole response before submitting any of it; [] is an explicit empty result."""
    raw = text.strip()
    if raw == "[]" and allow_empty:
        return [], None, True
    rows, errors = [], []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            value = json.loads(line)
        except json.JSONDecodeError:
            # a broken JSON line is shown for its repair; prose or a tag is counted, not echoed (live run 10A-8)
            errors.append(line[:200] if line.startswith("{") else "(a line that is not JSON)")
            continue
        if not isinstance(value, dict):
            errors.append(line[:200] if line.startswith("{") else "(a line that is not JSON)")
        else:
            rows.append(value)
    if not raw:
        errors.append("(empty response)")
    if not errors:
        return rows, None, False
    refusal = broken_refusal(text)
    refusal["error"]["lines"] = errors
    refusal["error"]["message"] = ("Every nonblank line must be a complete JSON object; nothing from this response was submitted. "
                                    + ("Reply exactly [] only for an intentional empty result." if allow_empty else
                                       "This task requires its done or verdict record; [] cannot close it."))
    return [], refusal, False


def check_answer(c: Call, *, allow_empty: bool, bound: int | None) -> tuple[list[dict], dict | None, bool]:
    """`submission_lines`, and an answer the provider cut at its output limit is refused as such: it is never complete, even when
    every line it has parses (live run 10A-2), and its repair asks for a shorter answer without showing the cut one."""
    if was_cut(c):
        return [], broken_refusal(c.text, True, bound), False
    return submission_lines(c.text, allow_empty=allow_empty)


# ------------------------------------------------------------------ arm C: R2R through `sbgk audit-serve`

Evidence = Callable[[str, dict], None]


class Rpc:
    """One authenticated JSON-RPC connection, with bounded connect/read/write waits."""

    def __init__(self, port: int, token: str, timeout_s: float = RPC_TIMEOUT_S):
        if timeout_s <= 0:
            raise ValueError("RPC timeout must be positive")
        self.timeout_s, self.deadline, self._closed = timeout_s, None, False
        self.s = socket.create_connection(("127.0.0.1", port), timeout=timeout_s)
        self._buffer = b""
        self.n = 0
        try:
            init = self._rpc("initialize", {"protocolVersion": "2025-06-18", "capabilities": {}, "auth_token": token})
            if "error" in init:
                raise RuntimeError(f"audit-serve refused the subject: {init['error']}")
        except BaseException:
            self.close()
            raise

    def set_deadline(self, deadline: float | None) -> None:
        self.deadline = deadline

    def _rpc(self, method: str, params: dict) -> dict:
        deadline = time.monotonic() + self.timeout_s
        if self.deadline is not None:
            deadline = min(deadline, self.deadline)

        def remaining() -> float:
            seconds = deadline - time.monotonic()
            if seconds <= 0:
                raise TimeoutError("RPC absolute deadline expired")
            # never above the bound: (t + timeout) - t rounds above timeout when the clock has not moved (Windows CI, dev e4ace86)
            return min(seconds, self.timeout_s)

        self.s.settimeout(remaining())
        self.n += 1
        self.s.sendall((json.dumps({"jsonrpc": "2.0", "id": self.n, "method": method, "params": params}) + "\n").encode("utf-8"))
        while True:
            while b"\n" not in self._buffer:
                self.s.settimeout(remaining())
                chunk = self.s.recv(min(65536, MAX_RPC_RESPONSE_BYTES + 1 - len(self._buffer)))
                if not chunk:
                    raise RuntimeError("audit-serve closed the RPC connection")
                self._buffer += chunk
                if len(self._buffer) > MAX_RPC_RESPONSE_BYTES:
                    raise RuntimeError("RPC response exceeds the byte limit")
            line, self._buffer = self._buffer.split(b"\n", 1)
            response = json.loads(line.decode("utf-8"))
            # the late answer to an earlier call that timed out (live run 10A) is skipped, not taken for this one
            if not (isinstance(response.get("id"), int) and response["id"] < self.n):
                break
        remaining()
        if response.get("id") != self.n:
            raise RuntimeError("RPC response id does not match the request")
        return response

    def call(self, tool: str, **args) -> dict:
        r = self._rpc("tools/call", {"name": tool, "arguments": args})
        return r["error"] if "error" in r else r["result"]["structuredContent"]

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        # Shutdown first: it wakes a reader in another worker before closing its buffered file.
        try:
            self.s.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        self.s.close()


class Kernel:
    """A fresh audit-serve directory. Existing evidence is never reused or removed."""

    def __init__(self, work: pathlib.Path, manifest: pathlib.Path, repo: pathlib.Path, reports: list[str], run_id: str, workers: int,
                 startup_timeout_s: float = STARTUP_TIMEOUT_S, builder_card: dict | None = None, kinds: dict[str, list[str]] | None = None):
        if BUILD_SCOPE=="versions" and WHOLE_READER:
            raise ValueError("whole-reader is not supported with build scope versions: cached summaries ignore version-map context")
        if workers <= 0 or startup_timeout_s <= 0:
            raise ValueError("workers and startup timeout must be positive")
        work.mkdir(parents=True, exist_ok=False)
        self.tokens = {f"w{i}": secrets.token_hex(16) for i in range(1, workers + 1)}
        if LINK_CHECKER:
            self.tokens[LINK_CHECKER_ID] = secrets.token_hex(16)
        self.tokens["own"] = secrets.token_hex(16)
        # the graph builder's subject, unless there is no builder (--build-scope none; Codex review of 8023910, SCOPE-02: the kernel
        # refuses a builder subject with it)
        if (not DYNAMIC_ROLES or CIRCLES_REFINER is not None) and BUILD_SCOPE not in ("none", "hints", "versions"):
            self.tokens["gb"] = secrets.token_hex(16)
        self._connections: list[Rpc] = []
        self._connections_lock = threading.Lock()
        self.proc = None
        self._stderr = None
        role = lambda a: "builder" if a == "gb" else "owner" if a == "own" else "swarm"  # noqa: E731
        kinds = dict(kinds or {}) | ({LINK_CHECKER_ID: LINK_CHECKER_KINDS} if LINK_CHECKER else {})
        subject = lambda a, t: {"token": t, "role": role(a), "id": a} | ({"kinds": kinds[a]} if a in kinds else {})  # noqa: E731
        (work / "subjects.json").write_text(json.dumps({"subjects": [subject(a, t) for a, t in self.tokens.items()]}), encoding="utf-8")
        (work / "questions.json").write_text(json.dumps(QUESTIONS), encoding="utf-8")
        (work / "select.txt").write_text("\n".join(reports) + "\n", encoding="utf-8")
        args = [str(C.BIN), "audit-serve", "--profile", "custom", "--listen", "127.0.0.1:0", "--wal", str(work / "run.wal"), "--subjects", str(work / "subjects.json"),
                "--questions", str(work / "questions.json"), "--manifest", str(manifest), "--repo", str(repo), "--select",
                str(work / "select.txt"), "--run-id", run_id, "--section-bytes", str(SECTION_BYTES)]
        if DYNAMIC_ROLES:
            args += ["--dynamic-roles", "--build-backlog", str(BUILD_BACKLOG)]
        if BUILD_SCOPE != "full":
            args += ["--build-scope", BUILD_SCOPE]
        if VERSION_LINEAGE is not None:
            args += ["--version-lineage", str(VERSION_LINEAGE)]
        args += ["--answer-timeout-ms",str(round(ANSWER_TIMEOUT_S*1000))]
        if ONTOLOGY_REVIEW: args += ["--ontology-review"]
        if UNATTESTED_AT_END:args += ["--unattested-at-end"]
        for k,v in GRAPH_QUALITY.items():
            if isinstance(v,bool):
                if v: args += ["--"+k.replace("_","-")]
            else: args += ["--"+k.replace("_","-"),str(v)]
        if AGENT_ATTEMPTS is not None: args += ["--agent-attempts",str(AGENT_ATTEMPTS)]
        if CIRCLES:
            args += ["--circles", "--agent-timeout-ms", str(round(AGENT_TIMEOUT_S * 1000))]
            if WAVE_SECTIONS is not None:
                args += ["--wave-sections", str(WAVE_SECTIONS)]
            if CIRCLES_REFINER is not None:
                args += ["--circles-refiner", "gb"]
                if REFINE_BUDGET_S is not None:
                    args += ["--refine-budget-ms", str(round(REFINE_BUDGET_S * 1000))]
        if ONTOLOGY_REVISIONS:
            args += ["--ontology-revisions"]
            for key,value in ONTOLOGY_THRESHOLDS.items():
                args += ["--ontology-"+key.replace("_","-"),str(value)]
        if BASE_ONTOLOGY:
            args += ["--base-ontology", str(BASE_ONTOLOGY)]
        if BUILDER_REQUESTS:
            args += ["--builder-requests", str(BUILDER_REQUESTS)]
        if MAX_LINES:
            args += ["--max-lines", str(MAX_LINES)]
        if WHOLE_READER:
            (work / "zones.json").write_text(json.dumps([reports]), encoding="utf-8")
            args += ["--zones", str(work / "zones.json"), "--own-refs", "--summary-records", "0", "--ttl-ms", "3600000"]
        if BACKPRESSURE_RECORDS:
            args += ["--backpressure-records", str(BACKPRESSURE_RECORDS), "--backpressure-per-task", str(BACKPRESSURE_PER_TASK)]
        # the graph builder's card size (a strong model with a fixed cost per call works better on larger cards)
        for name, value in sorted((builder_card or {}).items()):
            args += [f"--builder-{name.replace('_', '-')}", str(int(value))]
        hello: queue.Queue = queue.Queue(maxsize=1)
        reader = None
        try:
            self._stderr = open(work / "server.err", "x", encoding="utf-8")
            self.proc = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=self._stderr, text=True)

            def read_hello() -> None:
                try:
                    hello.put((self.proc.stdout.readline(), None))
                except Exception as exc:
                    hello.put((None, exc))

            reader = threading.Thread(target=read_hello, name="audit-startup-reader", daemon=True)
            reader.start()
            try:
                line, error = hello.get(timeout=startup_timeout_s)
            except queue.Empty as exc:
                raise TimeoutError("audit-serve startup deadline expired") from exc
            if error:
                raise error
            if not line:  # it refused to start, an unknown flag for one: its reason is on stderr, not a line to parse
                self.proc.wait(timeout=SHUTDOWN_TIMEOUT_S)
                raise RuntimeError(f"audit-serve did not start: {(work / 'server.err').read_text(encoding='utf-8')[:500]}")
            self.hello = json.loads(line)
            self.port = self.hello["port"]
        except BaseException:
            self.stop()
            raise
        finally:
            if reader:
                reader.join(timeout=SHUTDOWN_TIMEOUT_S)
                if reader.is_alive():
                    raise RuntimeError("audit-serve startup reader did not finish")

    def connect(self, agent: str) -> Rpc:
        rpc = Rpc(self.port, self.tokens[agent])
        with self._connections_lock:
            self._connections.append(rpc)
        return rpc

    def stop(self) -> None:
        with self._connections_lock:
            connections, self._connections = self._connections, []
        for rpc in connections:
            rpc.close()
        if self.proc is not None:
            if self.proc.poll() is None:
                self.proc.kill()
            self.proc.wait(timeout=SHUTDOWN_TIMEOUT_S)
            if self.proc.stdout:
                self.proc.stdout.close()
        if self._stderr is not None:
            self._stderr.close()


class Log:
    """Reserve calls atomically before dispatch and emit evidence before/after each call.

    A provider adapter must bound its own complete() transport. Python cannot forcibly cancel an arbitrary provider function;
    an unfinished invocation is persisted as call_started and prevents the runner from returning a successful result.
    """

    def __init__(self, max_calls: int = MAX_CALLS, evidence: Evidence | None = None, deadline: float | None = None):
        if max_calls < 0:
            raise ValueError("call cap cannot be negative")
        self.calls: list[Call] = []
        self.lock = threading.RLock()
        self.events: list[dict] = []
        self.max_calls, self.evidence, self.deadline = max_calls, evidence, deadline
        self.budget: Budget | None = None
        self.stopped: str | None = None
        self.releases: dict[str, int] = {}
        self.observes: dict[str, dict] = {}
        self.started = 0
        self.phase_calls: dict[int, int] = {}
        self.in_flight: dict[str, dict] = {}
        # the owner's export window between a terminal phase and the next withdrawal (EXPORT_POLL_S); a new generation wakes
        # every idle agent at once when the next phase begins
        self.exporting = threading.Event()
        self.wake_gen = 0
        self.policy = RUN_HOOK.policy()

    def preview_model(self, model, arm, role, phase, context):
        with self.lock:
            return self.policy.select(model,arm,role,phase,context,ANSWER_TIMEOUT_S)[0]

    def after_call(self, arm, role, phase, context, call=None, reply=None):
        with self.lock:
            for event in self.policy.after_call(arm,role,phase,context,call,reply):
                self.event(**event)

    def _emit(self, kind: str, payload: dict) -> None:
        if self.evidence:
            try:
                self.evidence(kind, payload)
            except Exception:
                self.stopped = "EVIDENCE_ERROR: durable sink failed"
                raise

    def active(self) -> bool:
        with self.lock:
            if self.deadline is not None and time.monotonic() >= self.deadline and not self.stopped:
                self.stopped = "TIMEOUT: phase deadline expired"
            return not self.stopped

    def invoke(self, model: Model, prompt: str, *, call_id: str, arm: str, role: str, phase: int, context: dict | None = None) -> Call | None:
        with self.lock:
            if not self.active():
                return None
            snapshot = dict(context or {})
            model, policy_meta = self.policy.select(model,arm,role,phase,snapshot,ANSWER_TIMEOUT_S)
            if self.started >= self.max_calls or (phase >= 2 and self.phase_calls.get(phase, 0) >= PHASE2_MAX_CALLS):
                self.stopped = f"CALL_CAP: total={self.max_calls}, per withdrawal phase={PHASE2_MAX_CALLS}"
                return None
            # a model the brake does not bill (a subscription builder next to a paid swarm) reserves and settles nothing: the brake
            # bounds the money of the paid calls only (a DeepSeek swarm with a Sonnet builder)
            billed = getattr(model, "billed", True)
            reserve = model.estimate(prompt) if self.budget is not None and hasattr(model, "estimate") and billed else 0.0
            if self.budget is not None and not self.budget.reserve(reserve):
                self.stopped = f"BUDGET_CAP: ${self.budget.cap} (spent {self.budget.state()['spent_usd_estimate']})"
                return None
            self.started += 1
            self.phase_calls[phase] = self.phase_calls.get(phase, 0) + 1
            snapshot.update({k:v for k,v in policy_meta.items() if v is not None})
            snapshot["model"] = getattr(model,"name","unknown")
            if role in ("BUILD","BUILDER"):
                snapshot["builder_model"] = getattr(model,"name","unknown")
            ref = f"{arm}:{call_id}"
            digest = hashlib.sha256(prompt.encode("utf-8")).hexdigest()
            meta = dict(call_id=call_id, arm=arm, role=role, phase=phase, sequence=self.started, context_id=ref,
                        context_rev=snapshot.get("notes_revision"), prompt_chars=len(prompt), prompt_bytes=len(prompt.encode("utf-8")),
                        prompt_sha256=digest, started_at=time.time(), cost_usd=None, reserve=reserve, billed=billed)
            meta.update({k: snapshot[k] for k in ("circle", "circle_phase") if k in snapshot})
            meta.update(policy_meta)
            meta["model"] = getattr(model,"name","unknown")
            meta["work_context"] = {k:v for k,v in (context or {}).items() if k in ("card_id","key","rq_id","task_id","report","section","agent","ontology_anomaly","ontology_review","hint_kinds")}
            self._emit("context", dict(snapshot, call_id=call_id, context_id=ref, arm=arm, phase=phase, prompt=prompt, prompt_sha256=digest))
            self._emit("call_started", dict(meta))
            self.in_flight[call_id] = meta

        def reserve_retry() -> bool:
            # one more physical attempt of this call reserves its own estimate: one call's reservation does not bound the sum of
            # several billed attempts (Codex's review of 06a578c, R04: two attempts of 0.30 settled 0.60 under a cap of 0.35)
            if self.budget is None or not billed:
                return True
            extra = model.estimate(prompt)
            with self.lock:
                if not self.budget.reserve(extra):
                    self.stopped = self.stopped or f"BUDGET_CAP: ${self.budget.cap} (spent {self.budget.state()['spent_usd_estimate']})"
                    return False
                meta["reserve"] += extra
            return True

        try:
            retries = {"reserve_retry": reserve_retry} if getattr(model, "reserves_retries", False) else {}
            token = _stub_about.set(tuple(snapshot.get("stub_about", ()))) if isinstance(model, StubModel) else None
            try:
                c = call_model(model, prompt, call_id=call_id, arm=arm, role=role, phase=phase, **retries)
            finally:
                if token is not None:
                    _stub_about.reset(token)
        except BaseException as exc:
            c = Call(call_id=call_id, arm=arm, role=role, phase=phase, prompt_chars=len(prompt), ok=False,
                     error=f"{type(exc).__name__}: {exc}", model=getattr(model,"name","unknown"))
            self._finish(c, meta, policy_meta)
            raise
        return self._finish(c, meta, policy_meta)

    def _finish(self, c: Call, meta: dict, policy_meta: dict) -> Call:
        if self.budget is not None and meta.get("billed", True):
            self.budget.settle(meta.get("reserve", 0.0), c.cost_usd)
        for key in ("sequence", "context_id", "context_rev", "prompt_bytes", "prompt_sha256", "started_at"):
            setattr(c, key, meta[key])
        for key in ("circle", "circle_phase"):
            if key in meta:
                setattr(c, key, meta[key])
        for key, value in policy_meta.items():
            if hasattr(c, key):
                setattr(c, key, value)
            else:
                c.extra[key] = value
        c.finished_at = time.time()
        with self.lock:
            self.calls.append(c)
            self.in_flight.pop(c.call_id, None)
            self._emit("call", call_record(c))
            self.after_call(c.arm,c.role,c.phase,meta.get("work_context") or {},call=c)
        return c

    def add(self, c: Call) -> Call:
        """Compatibility for already completed dependency fixtures; production uses invoke() before dispatch."""
        with self.lock:
            self.started += 1
            c.sequence = self.started
            self.calls.append(c)
            self._emit("call", call_record(c))
            if self.started >= self.max_calls and not self.stopped:
                self.stopped = f"CALL_CAP: {self.max_calls} model calls"
        return c

    def fail(self, reason: str, **details) -> None:
        with self.lock:
            if not self.stopped:
                self.stopped = reason
            event = dict(details, outcome="ERROR", error=reason)
            self.events.append(event)
            self._emit("event", event)

    def released(self, key: str) -> None:
        with self.lock:
            self.releases[key] = self.releases.get(key, 0) + 1
            if self.releases[key] >= MAX_RELEASES and not self.stopped:
                self.stopped = f"STUCK: {key} was given back {MAX_RELEASES} times"

    def event(self, **e) -> None:
        with self.lock:
            self.events.append(e)
            self._emit("event", e)

    def reply(self, r: dict, **where) -> dict:
        """The answer of the kernel or of the runner's own check to one submission, the refusal of a task's last attempt too: the
        whole reply as it came (up to REPLY_MAX_CHARS of its JSON, else a marked prefix) with the SHA-256 of all of it, and beside it
        search fields (rule, failed line, problems). The store's WAL holds no line a dispatcher rule refused (the B1 side session's
        check of 10A-13); this journal is the runner's record of what the agent was told, not that audit (Codex's review of deb7fe2,
        RJ-01: an index alone lost the hint bytes and a format refusal's lines)."""
        e = r.get("error") if isinstance(r.get("error"), dict) else {}
        problems = r.get("problems") or (e.get("expected_by_kernel") or {}).get("lines") or []
        rules = ("missing_identifiers", "negation_before", "ends_mid_clause", "observe_ends", "exact_bytes_in_section")
        raw = json.dumps(r, ensure_ascii=False, sort_keys=True)
        whole = len(raw) <= REPLY_MAX_CHARS
        with self.lock:
            self._emit("reply", dict(where, status=r.get("status"), local=bool(r.get("local")), failed_index=r.get("failed_index"),
                                     repair_scope=r.get("repair_scope"), accepted=len(r.get("accepted") or []), code=e.get("code") or r.get("code"),
                                     field=e.get("field"), message=str(e.get("message") or "")[:300],
                                     refused=len(r.get("refused") or []), excluded=len(r.get("excluded") or []), extended=len(r.get("extended") or []),
                                     # the word that made S0 refuse the quote (the consilium of 10A-17 read only the rule's name here)
                                     problems=[{"line": p.get("line"), "local_id": p.get("local_id"), "rules": [k for k in rules if k in p],
                                                "trigger": str(p.get("negation_before") or p.get("trailing_word") or "")[:120],
                                                "needs": str(p.get("needs") or "")[:120]} for p in problems if isinstance(p, dict)],
                                     reply=r if whole else None, reply_prefix=None if whole else raw[:REPLY_MAX_CHARS],
                                     reply_chars=len(raw), reply_sha256=hashlib.sha256(raw.encode("utf-8")).hexdigest()))
        return r

    def result(self) -> dict:
        with self.lock:
            if self.in_flight:
                raise RuntimeError(f"unfinished model invocations: {sorted(self.in_flight)}")
            return {"calls": [call_record(c) for c in sorted(self.calls, key=lambda c: c.sequence)], "events": list(self.events), "stopped": self.stopped}


def model_refused(c: "Call") -> bool:
    """The model's safeguards declined the call (Claude Code: "safeguards flagged this message"), unlike a transport or provider
    failure: the task closes and the run goes on (live run 10A-8)."""
    return not c.ok and MODEL_REFUSED in (c.error or "")


def json_lines_only(text: str) -> str:
    """The lines of an answer that start a JSON object. Prose, tags and leaked reasoning are not sent back to the model: echoed in a
    repair prompt, Sonnet 5.5's own leaked <think> text was declined by its safeguards (live run 10A-8)."""
    return "\n".join(ln for ln in text.splitlines() if ln.lstrip().startswith("{"))


def repair_prompt(prompt: str, refusal: dict, what: str, previous: str = "", accepted: list[dict] | None = None) -> str:
    previous = json_lines_only(previous)
    if (refusal.get("error") or {}).get("code") == "OUTPUT_LIMIT":
        # the cut answer is not shown again: a model shown its long answer writes it again (live run 10A-2); what earlier
        # submissions got accepted is (Codex's review of 4381fe7, finding 1: the repair lost the accepted local references)
        return (f"{prompt}\n\nALREADY ACCEPTED IN EARLIER SUBMISSIONS:\n{json.dumps(accepted or [])}\n"
                f"YOUR PREVIOUS ANSWER WAS NOT ACCEPTED: {refusal['error']['message']}. Nothing of it was stored. Keep earlier accepted "
                f"local references; do not repeat their records.")
    bound = ((refusal.get("error") or {}).get("expected_by_kernel") or {}).get("max_lines")
    if isinstance(bound, int):
        # an answer over the line bound is not shown again either: shown its 54 lines, a summary sent the same 54 lines four times
        # and its question ended unknown (DeepSeek check run 10A-11, phase 3)
        # told only to merge, DeepSeek wrote 34, 45 and 36 lines again and three sections of a report lost every line (check run
        # 10A-12): where merging is not enough, the least important records go
        return (f"{prompt}\n\nALREADY ACCEPTED IN EARLIER SUBMISSIONS:\n{json.dumps(accepted or [])}\n"
                f"YOUR PREVIOUS ANSWER WAS NOT ACCEPTED: {refusal['error']['message']}. Nothing of it was stored. Write the answer "
                f"again in at most {bound} lines: merge related records into fewer, broader lines (each still resting on all their "
                f"quotes); where that is not enough, leave out the least important records and the lines that rest on them. Count "
                f"your lines before you answer: more than {bound} and nothing is stored again. Do not copy your earlier answer.")
    error = refusal.get("error") or {}
    whole = (error.get("expected_by_kernel") or {}).get("lines")
    scope = refusal.get("repair_scope")
    # New dispatcher replies say whether this attempt reached storage. Older whole-summary preflights have this exact shape;
    # a lines list on another refusal must not turn an accepted prefix into a whole-answer retry.
    legacy_whole = (scope is None and what == "lines" and not refusal.get("local") and refusal.get("failed_index") == 0
                    and error.get("code") == "BAD_FIELD" and error.get("field") == "lines" and isinstance(whole, list))
    if scope == "whole_answer" or legacy_whole:
        # a summary is checked whole and nothing of it is stored: it is sent again whole, the listed lines corrected. Told the
        # prefix rule below instead, DeepSeek sent 7 and 10 of its 40 claims again, one of them faulty in each (check run 10A-12)
        return (f"{prompt}\n\nPREVIOUS MODEL OUTPUT:\n{previous}\n\nALREADY ACCEPTED IN EARLIER SUBMISSIONS:\n{json.dumps(accepted or [])}\n"
                f"YOUR ANSWER WAS REFUSED AS A WHOLE: {json.dumps(refusal)}. Nothing of it was stored. Send the whole answer again: "
                f"correct the reported error and any lines listed in expected_by_kernel, keeping every other line unchanged. "
                f"Add any required missing line. Leave out a line only when you cannot correct it, and then remove its local id "
                f"where another line names it.")
    if refusal.get("local"):
        return (f"{prompt}\n\nPREVIOUS MODEL OUTPUT:\n{previous}\n\nALREADY ACCEPTED IN EARLIER SUBMISSIONS:\n{json.dumps(accepted or [])}\n"
                f"FORMAT REFUSAL: {json.dumps(refusal)}. Nothing from PREVIOUS MODEL OUTPUT was submitted. Send the whole corrected "
                f"response, keeping earlier accepted local references; do not repeat their records.")
    if scope == "rejected_items_only":
        # the kernel stored every valid line of the answer and left out the refused ones with what rests on them (the consilium of
        # 10A-17, Gemini's plan step 1): only those come back
        return (f"{prompt}\n\nPREVIOUS MODEL OUTPUT:\n{previous}\n\nALREADY ACCEPTED IN EARLIER SUBMISSIONS:\n{json.dumps(accepted or [])}\n"
                f"YOUR ANSWER WAS STORED EXCEPT SOME LINES: {json.dumps(refusal)}. Every line whose local id is not in not_stored was "
                f"stored and keeps its local id: do not send it again. Send only the lines of not_stored: correct each refused line "
                f"(its error's expected_by_kernel and problems name what it needs; where exact_bytes_in_section is given, send those "
                f"bytes as its exact_quote, unchanged) or leave it out together with the lines resting on it, and send the excluded "
                f"lines again as they were. Nothing else.")
    if what == "operations" and isinstance(refusal.get("refused"), list):
        return (f"{prompt}\n\nPREVIOUS MODEL OUTPUT:\n{previous}\n\nYOUR OPERATIONS WERE PARTLY REFUSED: {json.dumps(refusal)}. "
                "Every valid operation was committed. Resend refused operations, corrected, plus any needed propose_concept "
                "prerequisites BEFORE their map_term in this same repair. Choose a shown candidate @id or an exact accepted "
                "concept name; a term string does not create a concept. Use shown observe ids for proposal basis. "
                "Do not resend accepted operations. Leave out unsupported operations; when no grounded repair remains, reply exactly [] with no words.")
    if isinstance(refusal.get("refused"), list):
        # the builder commits every valid operation of an answer: only the refused ones come back, corrected. Dropping a refused
        # link, the builder explained it in a sentence before [] and failed the format (live run 10A-9)
        return (f"{prompt}\n\nPREVIOUS MODEL OUTPUT:\n{previous}\n\nYOUR ANSWER WAS PARTLY REFUSED: {json.dumps(refusal)}. Every other "
                f"{what[:-1]} was committed and stays. Send only the refused {what} (their index is in your previous output), corrected, "
                f"nothing else. Leave out one you cannot correct; when you correct none, reply exactly [] with no words.")
    return (f"{prompt}\n\nPREVIOUS MODEL OUTPUT:\n{previous}\n\nACCEPTED PREFIX AND LOCAL REFERENCES:\n{json.dumps(accepted or [])}\n"
            f"YOUR ANSWER WAS REFUSED: {json.dumps(refusal)}. The {what} before the failed index were accepted and stay. "
            f"Send only the corrected {what[:-1]} and the {what} after it, nothing else. Earlier accepted local ids remain valid.")


def fallback(t: dict, stored: set[str] | None = None) -> list[dict] | None:
    """Honest closure after refused answers; link checks have no fallback. A summary whose repairs are used up delivers the lines
    the kernel stored, marked partial (the consilium of 10A-17, Gemini's plan step 1: one claim of 249 characters cost a summary of
    48 lines); with none stored its answer is unknown."""
    if t["kind"] in ("EXTEND", "INVESTIGATE", "REQUEST"):
        return []
    if t["kind"] == "SUMMARIZE":
        done = {"kind": "done", "local_id": f"{t['local_id_prefix']}d9", "rq_id": t["key"][3:], "directive_id": t["task_id"], "outcome": "unknown",
                "answer_ids": []}
        delivered = set(stored or ()) | set(t.get("retained_answer_ids") or ())
        if delivered:
            done.update(outcome="answered", answer_ids=sorted(delivered),
                        text=f"Partial answer: {len(delivered)} lines retained; the lines still refused after the repairs are left out.")
        return [done]
    return None


def note_observes(log: Log, lines: list[dict], r: dict) -> list[dict]:
    accepted = []
    recs = [x for x in lines if x.get("kind") != "verdict"]
    by_local = r.get("accepted_locals")
    if isinstance(by_local, dict):
        # the dispatcher drops exact resends of accepted lines: map by local id, not by position (Codex review 6d6bcf9, P2)
        pairs = [(x, by_local[x["local_id"]]) for x in recs if isinstance(x.get("local_id"), str) and x["local_id"] in by_local]
    else:
        pairs = list(zip(recs, r.get("accepted") or []))
    # a quote cut where its line ends is stored with the rest of its clause (the consilium of 10A-17): the stored bytes are the quote
    extended = {e.get("local_id"): e.get("stored") for e in r.get("extended") or [] if isinstance(e, dict)}
    with log.lock:
        for x, rid in pairs:
            accepted.append({"local_id": x.get("local_id"), "record_id": rid, "record": x})
            quote = extended.get(x.get("local_id")) or x.get("exact_quote")
            if x.get("kind") == "observe" and isinstance(quote, str):
                log.observes[rid] = {"quote": quote, "doc_id": x.get("doc_id")}
    return accepted


def model_timed_out(call: Call) -> bool:
    return not call.ok and any(word in (call.error or "") for word in ("TimeoutExpired", "TimeoutError", "AGY_TIMEOUT", "timed out", "deadline expired"))


def agent_failed(call: Call) -> bool:
    return not call.ok and (model_timed_out(call) or any(word in (call.error or "") for word in
        ("AGY_ASKED_HUMAN:","AGY_STREAM_ERROR:","BrokenPipeError","Broken pipe","agy did not return a successful text result",
         f"{OUTPUT_OVERRUN}:")))


def report_agent_timeout(rpc: Rpc, call: Call, task: str | None, log: Log, *, agent: str, phase: int, context: dict) -> bool:
    asked = not call.ok and "AGY_ASKED_HUMAN:" in (call.error or "")
    overrun = not call.ok and f"{OUTPUT_OVERRUN}:" in (call.error or "")
    if not agent_failed(call) or (not CIRCLES and AGENT_ATTEMPTS is None):
        return False
    if task:
        reply = rpc.call("audit_release", task_id=task, timed_out=True)
    elif AGENT_ATTEMPTS is not None and context.get("card_id"):
        reply = rpc.call("audit_builder_failure",card_id=context["card_id"],attempt_id=call.call_id,reason="AGY_HUMAN_REQUEST" if asked else "AGY_TIMEOUT" if model_timed_out(call) else OUTPUT_OVERRUN if overrun else "AGY_STREAM_FAILURE")
    else:return False
    log.event(arm="C", agent=agent, phase=phase, task=task, outcome="AGENT_HUMAN_REQUEST" if asked else "AGENT_TIMEOUT" if model_timed_out(call) else "AGENT_OUTPUT_OVERRUN" if overrun else "AGENT_STREAM_FAILURE", call_id=call.call_id,
              error=call.error, reply=reply, **{k: context[k] for k in ("circle","circle_phase","sync_step") if k in context})
    if reply.get("status") not in ("RELEASED", "STALE_TASK","CARD_RETRY","CARD_UNRESOLVED"):
        raise RuntimeError(f"agent timeout was not recorded: {reply}")
    if not CIRCLES:time.sleep(AGENT_RETRY_PAUSE_S)
    return True


def idle_pause(log: Log, pause: float) -> float:
    """An idle agent's next pause: the usual `pause`, or EXPORT_POLL_S while the owner exports (the window opens only on a
    terminal phase, so nothing is waiting for the agent; the next withdrawal wakes it at once)."""
    return min(EXPORT_POLL_S, AGENT_TIMEOUT_S / 2.5) if log.exporting.is_set() else pause


def idle_wait(log: Log, stop: threading.Event, pause: float) -> None:
    """Sleep the idle pause (idle_pause) in short slices: a stop, or the owner's signal that the next phase began, wakes at once.
    The generation is read before the pause is chosen, so a window that closes in between still wakes the agent (Codex review
    EXPORT-01 of 7284c65: read after, it was the new one, and a 120 s pause chosen in the window ran into the next phase)."""
    gen = log.wake_gen
    end = time.monotonic() + idle_pause(log, pause)
    while not stop.is_set() and log.wake_gen == gen:
        left = end - time.monotonic()
        if left <= 0:
            return
        stop.wait(min(0.25, left))


def c_worker(k: Kernel, agent: str, model: Model, log: Log, phase: list[int], stop: threading.Event) -> None:
    rpc = k.connect(agent)

    def cycle() -> bool:
        """One acquire of the agent and the task it got: a step of the executor that drives the agent (executors.drive; the
        threads, LangGraph or Temporal). False ends the agent."""
        waiting = time.time()
        t = rpc.call("audit_acquire", max_wait_ms=ACQUIRE_WAIT_MS)
        if CIRCLES:
            # why the kernel had no task for the agent, as its answer says it (the shift barrier, one lease per circle agent, a
            # pending checkpoint, or no open work for this agent), and how long it held the long poll: the idle time of a run is
            # then explained by its causes, not guessed from 30 s status samples (02.11.2026)
            why = {f"kernel_{k}": t[k] for k in ("message", "open_work", "leases", "builder_caught_up", "waited_ms") if k in t}
            log.event(arm="C", agent=agent, kind="IDLE_WAIT", outcome=t.get("status"),
                      start_unix_s=waiting, end_unix_s=time.time(), reason="acquire", **why)
        if t.get("status") != "DIRECTIVE":
            # the owner closed the run: no more work will come (R27 package 2)
            if t.get("status") == "DONE":
                return False
            if t.get("status") not in ("WAIT", "COMPLETE"):
                raise RuntimeError(f"audit_acquire failed: {t}")
            waiting = time.time()
            pause = 0.05 if t.get("status") == "WAIT" else 0.2
            idle_wait(log, stop, pause)
            if CIRCLES:
                log.event(arm="C", agent=agent, kind="IDLE_WAIT", outcome=t.get("status"),
                          start_unix_s=waiting, end_unix_s=time.time(), reason="poll_backoff")
            return True
        circle_context = {k: t[k] for k in ("circle", "circle_phase", "sync_step", "ring_batch") if k in t}
        if circle_context:
            log.event(**circle_context, arm="C", phase=phase[0], agent=agent, task=t["task_id"], kind=t["kind"],
                      outcome="TASK_ASSIGNED", at_unix_s=time.time())
        if t["kind"] == "BUILD":
            closed = build_card(rpc, t["card"], model, log, phase[0], stop, agent=agent, task_id=t["task_id"], circle_context=circle_context)
            if closed is False and log.active() and not stop.is_set():
                rpc.call("audit_release", task_id=t["task_id"])
            return True
        allow_empty = t["kind"] in ("EXTEND", "CHANGE", "INVESTIGATE", "REQUEST")
        prompt = t["prompt"] + (EMPTY_RESPONSE_RULE if allow_empty else "\nReturn the required done or verdict record; [] cannot close this task.")
        task, ph = t["task_id"], phase[0]
        context = {"task_id": task, "key": t.get("key"), "kind": t["kind"], "link_authors": t.get("link_authors"), **circle_context}
        repairs = SUMMARY_REPAIRS if t["kind"] == "SUMMARIZE" else REPAIRS

        def submit(lines: list[dict], call_id: str | None) -> dict:
            try:
                return log.reply(rpc.call("audit_submit", task_id=task, lines=lines), **circle_context, arm="C", phase=ph, agent=agent, task=task,
                                 kind=t["kind"], call_id=call_id, lines_submitted=len(lines))
            except Exception as exc:
                # the kernel may have stored the lines before its answer was lost: their fate is unknown until the WAL receipt is
                # read, not "refused"; the task gets this outcome, the stop reason stays the first one (Codex's review of 77a803e, R02)
                log.event(**circle_context, arm="C", phase=ph, agent=agent, task=task, kind=t["kind"], key=t.get("key"), call_id=call_id,
                          outcome="ACK_UNKNOWN", error=f"{type(exc).__name__}: {exc}", lines_submitted=len(lines), after_stop=stop.is_set())
                raise

        c = log.invoke(model, prompt, call_id=f"C{ph}-{task}-0", arm="C", role=t["kind"], phase=ph, context=context)
        if c is None:
            return False
        if report_agent_timeout(rpc,c,task,log,agent=agent,phase=ph,context=context):
            return True
        refused = model_refused(c)
        if not c.ok and not refused:
            log.fail(f"MODEL_ERROR: {c.error}", **circle_context, arm="C", phase=ph, agent=agent, task=task)
            return False
        if refused:
            # the model's safeguards declined the task: it closes like an unrepaired answer and the run goes on (live run 10A-8:
            # one refusal stopped the whole run)
            log.event(**circle_context, arm="C", phase=ph, agent=agent, task=task, kind=t["kind"], key=t.get("key"), call_id=c.call_id, outcome="MODEL_REFUSED",
                      error=c.error)
            lines, local, explicit_empty, broken, accepted, r = [], None, False, 0, [], {"status": "MODEL_REFUSED"}
        else:
            lines, local, explicit_empty = check_answer(c, allow_empty=allow_empty, bound=t.get("max_lines"))
            broken = len(local["error"]["lines"]) if local else 0
            r = log.reply(local, **circle_context, arm="C", phase=ph, agent=agent, task=task, kind=t["kind"], call_id=c.call_id,
                          lines_submitted=0) if local else submit(lines, c.call_id)
            accepted = [] if r.get("local") else note_observes(log, lines, r)
        # the measure: of the lines the agent offered, how many the graph got
        offered = {ln["local_id"] for ln in lines if isinstance(ln.get("local_id"), str)}
        stored = set(r.get("accepted_locals") or {})
        tries = 0
        timed_out = False
        relate_open = False
        # the lines of a RELATE turn are claims of a change, not lines of the section: the reading measure keeps its own
        relate_offered: set[str] = set()
        relate_stored: set[str] = set()
        # the reading's refusal when its repairs ran out and it closed on the lines the kernel stored
        abandoned_reading: dict | None = None
        # the reading's own measures, kept when a RELATE turn opens: the turn's go to relate_* (claude-reviewer's RV-01 of d8ab1a74:
        # the turn wrote its repairs over the reading's, and a hints run showed almost none beside an honest count in none)
        reading: dict = {}
        for relate_turn in (False, True):
            if relate_turn:
                if (r.get("status") not in ("COMMITTED", "RELATE") and fallback(t) is not None and not (r.get("local") and not refused)
                        and not timed_out and log.active() and not stop.is_set()):
                    # the closure comes before the RELATE turn, so such a reading gets its turn as any stored reading does (the hints
                    # pre-flight of 8d771feb: it came after this loop, and the turn the kernel opened was released unasked)
                    abandoned_reading = r
                    r = submit(fallback(t, stored), None)
                # the hint profile: the kernel stored the reading answer and shows each of its claims with the
                # claims of other report dates that share its words; one more call may write the change on both quotes
                if r.get("status") != "RELATE" or timed_out or stop.is_set() or not log.active():
                    break
                reading = {"repairs": tries, "broken_lines": broken, "explicit_empty": explicit_empty}
                tries, broken, explicit_empty = 0, 0, False
                relate_open = True
                prompt = r["prompt"] + EMPTY_RESPONSE_RULE
                next_call = log.invoke(model, prompt, call_id=f"C{ph}-{task}-r0", arm="C", role=t["kind"], phase=ph, context=dict(context, relate=True))
                if next_call is None:
                    break
                c = next_call
                if report_agent_timeout(rpc,c,task,log,agent=agent,phase=ph,context=context):
                    timed_out = True
                    break
                if not c.ok:
                    refused = model_refused(c)
                    if refused:
                        log.event(**circle_context, arm="C", phase=ph, agent=agent, task=task, kind=t["kind"], key=t.get("key"), call_id=c.call_id,
                                  outcome="MODEL_REFUSED", error=c.error)
                    else:
                        log.fail(f"MODEL_ERROR: {c.error}", **circle_context, arm="C", phase=ph, agent=agent, task=task)
                    break
                lines, local, explicit_empty = check_answer(c, allow_empty=True, bound=t.get("max_lines"))
                broken += len(local["error"]["lines"]) if local else 0
                r = log.reply(local, **circle_context, arm="C", phase=ph, agent=agent, task=task, kind=t["kind"], call_id=c.call_id,
                              lines_submitted=0) if local else submit(lines, c.call_id)
                relate_offered |= {ln["local_id"] for ln in lines if isinstance(ln.get("local_id"), str)}
                relate_stored |= set(r.get("accepted_locals") or {})
                tries = 0
            while r.get("status") == "REPAIR_REQUIRED" and tries < repairs and not stop.is_set() and log.active():
                tries += 1
                if CIRCLES:
                    renewed=rpc.call("audit_renew",task_id=task)
                    if renewed.get("status") != "RENEWED":
                        log.event(**circle_context,arm="C",phase=ph,agent=agent,task=task,outcome="TASK_LEASE_LOST",reply=renewed)
                        if renewed.get("status") != "STALE_TASK":
                            raise RuntimeError(f"task renewal failed: {renewed}")
                        timed_out=True
                        break
                log.after_call("C",t["kind"],ph,context,reply=r)
                next_call = log.invoke(model, repair_prompt(prompt, r, "lines", c.text, accepted), call_id=f"C{ph}-{task}-{'r' if relate_turn else ''}{tries}",
                               arm="C", role=t["kind"], phase=ph, context=dict(context, repair=tries))
                if next_call is None:
                    break
                c = next_call
                if report_agent_timeout(rpc,c,task,log,agent=agent,phase=ph,context=context):
                    timed_out = True
                    break
                if not c.ok:
                    refused = model_refused(c)
                    if refused:
                        log.event(**circle_context, arm="C", phase=ph, agent=agent, task=task, kind=t["kind"], key=t.get("key"), call_id=c.call_id,
                                  outcome="MODEL_REFUSED", error=c.error)
                    else:
                        log.fail(f"MODEL_ERROR: {c.error}", **circle_context, arm="C", phase=ph, agent=agent, task=task)
                    break
                lines, local, explicit_empty = check_answer(c, allow_empty=allow_empty, bound=t.get("max_lines"))
                broken += len(local["error"]["lines"]) if local else 0
                r = log.reply(local, **circle_context, arm="C", phase=ph, agent=agent, task=task, kind=t["kind"], call_id=c.call_id,
                              lines_submitted=0) if local else submit(lines, c.call_id)
                if not r.get("local"):
                    accepted.extend(note_observes(log, lines, r))
                (relate_offered if relate_turn else offered).update(ln["local_id"] for ln in lines if isinstance(ln.get("local_id"), str))
                (relate_stored if relate_turn else stored).update(r.get("accepted_locals") or {})
        measures = {"repairs": tries, "broken_lines": broken, "explicit_empty": explicit_empty}
        if relate_open:
            measures = dict(reading, relate_repairs=tries, relate_broken_lines=broken, relate_explicit_empty=explicit_empty,
                            relate_lines_offered=len(relate_offered), relate_lines_stored=len(relate_stored & relate_offered))
        if relate_open and r.get("status") != "COMMITTED" and not timed_out and log.active() and not stop.is_set():
            # a RELATE turn that ended without a stored answer closes empty: the reading answer is stored, the section is not read again
            r = submit([], None)
        def code_of(refusal: dict) -> str | None:
            return (refusal.get("error") or {}).get("code") if isinstance(refusal.get("error"), dict) else refusal.get("code")

        if timed_out and relate_open:
            # the reading is stored and only its RELATE turn timed out: the task's event keeps the reading's lines (claude-reviewer's
            # note 2 on 8509eb18)
            # with the fields of every task event, so measures() counts the stored reading (it skipped events without `abandoned`);
            # a reading closed on its stored lines keeps its refusal code (claude-reviewer's note 1 on 055fd50)
            log.event(**circle_context, arm="C", phase=ph, agent=agent, task=task, kind=t["kind"], key=t.get("key"), outcome="RELATE_TIMED_OUT",
                      **measures, parse_failure=False, error=code_of(abandoned_reading) if abandoned_reading else None,
                      abandoned=abandoned_reading is not None, lines_offered=len(offered), lines_stored=len(stored & offered), model=c.model)
            return True
        if timed_out:
            return True
        # an answer still unreadable after its repairs: nothing of it is submitted and the run stops visibly (Codex's 469438a, kept
        # in its first integration as Codex chose in his reply of 20:02; continuing through a failed lease is a separate proposal)
        parse_failure = bool(r.get("local")) and not refused
        if parse_failure:
            log.fail("PARSE_FAILURE: response format was not repaired", **circle_context, arm="C", phase=ph, agent=agent, task=task, parse_failure=True)
            stop.set()
        error = code_of(abandoned_reading or r)
        abandoned = abandoned_reading is not None or (r.get("status") != "COMMITTED" and fallback(t) is not None)
        if abandoned and abandoned_reading is None and not parse_failure and log.active() and not stop.is_set():
            r = submit(fallback(t, stored), None)
        elif refused and abandoned_reading is None and r.get("status") != "COMMITTED" and log.active() and not stop.is_set():
            # a link task has no honest empty closure: its refused empty answer counts as a failed lease, and three give it up
            r = submit([], None)
        log.event(**circle_context, arm="C", phase=ph, agent=agent, task=task, kind=t["kind"], key=t.get("key"), outcome=r.get("status"),
                  **measures, parse_failure=parse_failure, error=error, abandoned=abandoned,
                  lines_offered=len(offered), lines_stored=len(stored & offered),
                  model=c.model, model_family=c.model_family, **c.extra, link_authors=t.get("link_authors"), verdict=r.get("verdict"))
        if r.get("status") != "COMMITTED" and log.active() and not stop.is_set():
            rpc.call("audit_release", task_id=task)
            log.released(t.get("key", task))
        return True

    try:
        executors.drive(f"C-{agent}", cycle, stop, log)
    finally:
        rpc.close()


def build_card(rpc: Rpc, card: dict, model: Model, log: Log, phase: int, stop: threading.Event,
               *, agent: str = "gb", task_id: str | None = None, circle_context: dict | None = None) -> bool | None:
    """The same card, parsing and repairs for dedicated and leased builders."""
    role = "BUILD" if task_id else "REFINER" if CIRCLES_REFINER is not None and agent == "gb" else "BUILDER"
    circle_context = circle_context or {}
    attempt_id = f"{card['card_id']}-{task_id}" if task_id else card["card_id"]
    if not task_id and AGENT_ATTEMPTS is not None:attempt_id+=f"-agent{card.get('agent_attempt',1)}-{secrets.token_hex(16)}"
    submitted_ops = 0
    hint_kinds=sorted({h.get("kind") for h in (card.get("ontology_revision") or {}).get("hints") or [] if h.get("kind")})
    card_signal={"card_id":card["card_id"],"agent":agent,"ontology_anomaly":bool(hint_kinds),"hint_kinds":hint_kinds,
                 "ontology_review":card.get("kind")=="ONTOLOGY_REVIEW_CARD"}
    actual_model = getattr(log.preview_model(model,"C",role,phase,{**circle_context,**card_signal}),"name","unknown")

    def submit_ops(cid: str, ph: int, ops: list[dict], call_id: str | None, annotate: Callable | None = None) -> dict:
        nonlocal submitted_ops
        submitted_ops += sum(op.get("op") != "request" for op in ops)
        try:
            r = (rpc.call("audit_submit", task_id=task_id, lines=ops) if task_id else
                 rpc.call("audit_submit_ops", card_id=cid, ops=ops))
        except Exception as exc:
            log.event(**circle_context,arm="C", phase=ph, agent=agent, card=cid, task=task_id, kind=role, call_id=call_id, outcome="ACK_UNKNOWN",
                      error=f"{type(exc).__name__}: {exc}", ops_submitted=len(ops), after_stop=stop.is_set())
            raise
        extra={}
        if CIRCLES:
            from .agent_matrix import operation_decisions
            extra["operation_decisions"]=operation_decisions(card,ops,r)
        if annotate is not None:
            annotate(extra)
        log.event(**circle_context,arm="C", phase=ph, agent=agent, card=cid, task=task_id, kind=role, call_id=call_id,
                  ontology_anomaly=bool(hint_kinds),ontology_review=card_signal["ontology_review"],builder_model=actual_model, outcome="CARD_SUBMITTED", operation_results=r.get("results") or [], operations=ops, **extra)
        if r.get("requests"):
            log.event(**circle_context,arm="C", phase=ph, agent=agent, card=cid, builder_requests=r["requests"])
        return r

    response_rule = "\nAn explicit grounded review is required; [] leaves this review open." if card.get("kind")=="ONTOLOGY_REVIEW_CARD" else ("" if card.get("kind")=="EVOLUTION_LINK_CARD" else EMPTY_RESPONSE_RULE)
    def card_prompt(shown: dict) -> str:
        return shown["prompt"] + response_rule + "\nCARD:\n" + json.dumps({k_: v for k_, v in shown.items() if k_ != "prompt"})

    prompt = card_prompt(card)
    cid, ph = card["card_id"], phase
    context = {**card_signal,"task_id":task_id,"builder_model":getattr(model,"name",None),**circle_context}
    log.event(**circle_context,arm="C", phase=ph, agent=agent, card=cid, task=task_id, kind=role, outcome="CARD_ASSIGNED",
              builder_model=actual_model, card_authors=sorted({x["author"] for x in card["records"] if x.get("author")}),
              records=len(card["records"]),ontology_anomaly=bool(hint_kinds),ontology_review=card_signal["ontology_review"],hint_kinds=hint_kinds)
    def renew() -> bool:
        if not task_id:
            return True
        r = rpc.call("audit_renew", task_id=task_id)
        if r.get("status") == "RENEWED":
            return True
        log.event(**circle_context,arm="C", phase=ph, agent=agent, card=cid, task=task_id, kind=role,
                  builder_model=actual_model, outcome="BUILD_LEASE_LOST", reply=r)
        return False

    if (PAIRS_ONLY and card.get("kind") not in ("PAIR_CARD","EVOLUTION_LINK_CARD") or WHOLE_READER) and card["records"]:
        # the strong-reader comparison: the builder judges the pairs the kernel finds, not a window of records; a record card
        # is closed without a model, as a stretch of link-check evidence is (run S1.2: every card, the agent relates its own
        # records)
        r = submit_ops(cid, ph, [], None)
        closed = r.get("status") == "CARD_DONE"
        log.event(**circle_context,arm="C", phase=ph, agent=agent, card=cid, task=task_id, kind=role, card_authors=sorted({x["author"] for x in card["records"] if x.get("author")}), builder_model=actual_model, records=len(card["records"]), outcome=r.get("status"), repairs=0,
                  abandoned=not closed, first_try=closed, model_invoked=False, empty=True, pairs_only=True)
        if not closed:
            log.fail(f"RECORD_CARD_REFUSED: {r.get('code') or (r.get('error') or {}).get('code')}", arm="C", phase=ph, agent=agent, card=cid)
            return False
        return True
    if not card["records"] and card.get("kind") not in ("REVISION_CARD","ONTOLOGY_REVIEW_CARD"):
        # a stretch of link-check evidence only: nothing to build, closed without a model. A refused close is a visible stop:
        # the same card would come back at once (Codex's analysis of 831bbac, A3)
        r = submit_ops(cid, ph, [], None)
        closed = r.get("status") == "CARD_DONE"
        log.event(**circle_context,arm="C", phase=ph, agent=agent, card=cid, task=task_id, kind=role, card_authors=sorted({x["author"] for x in card["records"] if x.get("author")}), builder_model=actual_model, records=0, outcome=r.get("status"), repairs=0, abandoned=not closed,
                  first_try=closed, model_invoked=False, empty=True)
        if not closed:
            log.fail(f"EMPTY_CARD_REFUSED: {r.get('code') or (r.get('error') or {}).get('code')}", arm="C", phase=ph, agent=agent, card=cid)
            return False
        return True
    def card_event(**fields) -> None:
        log.event(**circle_context,arm="C",phase=ph,agent=agent,card=cid,builder_model=actual_model,**fields)

    def card_call(called: Model, text: str, *, call_id: str, role: str) -> Call | None:
        return log.invoke(called, text, call_id=call_id, arm="C", role=role, phase=ph, context=context)

    ctx = SimpleNamespace(phase=ph, attempt_id=attempt_id, role=role, renew=renew, render=card_prompt, event=card_event, invoke=card_call)
    prepared = RUN_HOOK.before(card, ctx)
    if prepared is None:
        return False
    prompt, card_fields = prepared
    if not renew():
        return False
    c = log.invoke(model, prompt, call_id=f"B{ph}-{attempt_id}-0", arm="C", role=role, phase=ph, context=context)
    if c is None:
        return False
    if report_agent_timeout(rpc,c,task_id,log,agent=agent,phase=ph,context=context):
        return None
    actual_model = c.model
    refused = model_refused(c)
    if not c.ok and not refused:
        log.fail(f"MODEL_ERROR: {c.error}", arm="C", phase=ph, agent=agent, card=cid)
        return False
    if refused:
        log.event(**circle_context,arm="C", phase=ph, agent=agent, card=cid, call_id=c.call_id, outcome="MODEL_REFUSED", error=c.error)
    accepted = []

    def submit_answer(call: Call) -> tuple[list[dict], dict, str, bool]:
        text = call.text
        operations, local, empty = check_answer(call, allow_empty=True, bound=card.get("max_ops"))
        if local:
            return [], local, text, empty
        operations, result, previous = RUN_HOOK.after(card, operations, lambda ops, annotate=None: submit_ops(cid, ph, ops, call.call_id, annotate), ctx)
        return operations, result, previous or text, empty

    if refused:
        operations, r, previous, explicit_empty = [], {"status": "MODEL_REFUSED"}, "", False
    else:
        operations, r, previous, explicit_empty = submit_answer(c)
    broken = len(r["error"]["lines"]) if r.get("local") else 0
    tries = 0
    while r.get("status") == "REPAIR_REQUIRED" and tries < REPAIRS and not stop.is_set() and log.active():
        n = r.get("failed_index")
        if isinstance(n, int) and not r.get("local"):
            accepted.extend(operations[:n])
        tries += 1
        if not renew():
            return False
        log.after_call("C",role,ph,context,reply=r)
        c = log.invoke(model, repair_prompt(prompt, r, "operations", previous, accepted), call_id=f"B{ph}-{attempt_id}-{tries}",
                       arm="C", role=role, phase=ph, context=dict(context, repair=tries))
        if c is None:
            break
        if report_agent_timeout(rpc,c,task_id,log,agent=agent,phase=ph,context=context):
            return None
        if not c.ok:
            refused = model_refused(c)
            if refused:
                log.event(**circle_context,arm="C", phase=ph, agent=agent, card=cid, call_id=c.call_id, outcome="MODEL_REFUSED", error=c.error)
            else:
                log.fail(f"MODEL_ERROR: {c.error}", arm="C", phase=ph, agent=agent, card=cid)
            break
        actual_model = c.model
        operations, r, previous, explicit_empty = submit_answer(c)
        broken += len(r["error"]["lines"]) if r.get("local") else 0
    parse_failure = bool(r.get("local")) and not refused
    if parse_failure:
        log.fail("PARSE_FAILURE: builder response format was not repaired", arm="C", phase=ph, agent=agent, card=cid, parse_failure=True)
        stop.set()
    abandoned = r.get("status") != "CARD_DONE"
    if abandoned and not parse_failure and log.active() and not stop.is_set():
        r = submit_ops(cid, ph, [], None)
    log.event(**circle_context,arm="C", phase=ph, agent=agent, card=cid, task=task_id, kind=role, card_authors=sorted({x["author"] for x in card["records"] if x.get("author")}), builder_model=actual_model, records=len(card["records"]), outcome=r.get("status"), repairs=tries,
              broken_lines=broken, parse_failure=parse_failure, explicit_empty=explicit_empty, model_invoked=True,
              abandoned=abandoned, first_try=(tries == 0 and not abandoned),
              **card_fields,
              operations_submitted=submitted_ops, closed_without_operations=r.get("status") == "CARD_DONE" and submitted_ops == 0)
    return r.get("status") == "CARD_DONE"


def c_builder(k: Kernel, model: Model, log: Log, phase: list[int], stop: threading.Event) -> None:
    rpc = k.connect("gb")
    try:
        while not stop.is_set() and log.active():
            card = rpc.call("audit_next_card")
            if card.get("status") != "CARD":
                if card.get("status") == "DONE":
                    return
                if card.get("status") not in ("IDLE", "CAUGHT_UP", "WAIT"):
                    raise RuntimeError(f"audit_next_card failed: {card}")
                # a refiner outside REFINE waits for the swarm's circle: a slower poll keeps the coordinator lock free
                pause = 1.0 if card.get("status") == "WAIT" else 0.1
                idle_wait(log, stop, pause)
                continue
            circle_context={k:card[k] for k in ("circle","circle_phase","sync_step") if k in card}
            closed=build_card(rpc, card, model, log, phase[0], stop, circle_context=circle_context or None)
            if closed is None:continue
            if not closed:break
    finally:
        rpc.close()


def guarded_worker(fn, log: Log, stop: threading.Event, **details) -> None:
    try:
        fn()
    except Exception as exc:
        if not stop.is_set():
            try:
                log.fail(f"WORKER_ERROR: {type(exc).__name__}: {exc}", **details)
            finally:
                stop.set()
        else:
            # after a stop the error does not replace its reason, but it is not silent either (Codex's review of 77a803e, R02)
            log.event(**details, outcome="ERROR_AFTER_STOP", error=f"{type(exc).__name__}: {exc}")


def finish_threads(threads: list[threading.Thread], log: Log, stop: threading.Event) -> None:
    stop.set()
    # a model call already sent is waited for (live run 10B: a strong builder's call of up to 85 s was cut at the phase deadline, and
    # the whole run failed for an unfinished thread); its own transport bounds it
    with log.lock:
        busy = bool(log.in_flight)
    # a thread may also be inside a kernel call: an acquire's whole wait and one call's bound (claude-reviewer's RV-01 of 84d7e6b4:
    # with RPC_TIMEOUT_S at 300 s, a reader queued behind the kernel's lock was given 10 s and the phase's export was lost)
    deadline = time.monotonic() + SHUTDOWN_TIMEOUT_S + max(CALL_DRAIN_S if busy else 0, ACQUIRE_WAIT_MS / 1000 + RPC_TIMEOUT_S)
    for thread in threads:
        if thread.ident is not None:
            thread.join(timeout=max(0, deadline - time.monotonic()))
    alive = [thread.name for thread in threads if thread.is_alive()]
    if alive:
        log.fail(f"UNFINISHED_THREADS: {alive}")
        raise RuntimeError(f"runner has unfinished threads: {alive}; call_started evidence remains pending")


def best_effort(own: Rpc, tool: str, **args) -> dict:
    """A call made after a phase timed out: the kernel may still be busy, and what it cannot answer in time is recorded, not raised
    (Codex's analysis of 831bbac, A2: a status call right after the timeout could still crash the run)."""
    try:
        return own.call(tool, **args)
    except (TimeoutError, OSError, RuntimeError) as e:
        return {"status": "UNAVAILABLE", "tool": tool, "error": f"{type(e).__name__}: {e}"}


def c_until_terminal(own: Rpc, log: Log, timeout_s: float) -> dict:
    started = time.monotonic()
    deadline = started + timeout_s
    own.set_deadline(deadline)
    sampled, slow = 0.0, 0
    try:
        while time.monotonic() < deadline:
            if not log.active():
                return {"status": "STOPPED", "reason": log.stopped}
            if (BACKPRESSURE_RECORDS or ARM_A_MODE == "team") and time.monotonic() - sampled >= STATUS_SAMPLE_S:
                # the backlog curve of backpressure: what the kernel holds and what the builder has carded, over time
                sampled = time.monotonic()
                st = best_effort(own, "audit_status")
                d, guard = st.get("dispatch") or {}, st.get("stall_guard") or {}
                log.event(arm="C", phase=getattr(log, "phase_number", 1), agent="owner", status_sample=True,
                          elapsed_s=round(sampled - started, 3), t=round(time.time(), 3), records=st.get("records"),
                          circle_state=st.get("circles"), open_builder_cards=st.get("open_builder_cards"),
                          builder_cursor=st.get("builder_cursor"), reading_done=st.get("reading_done"),
                          builder_caught_up=st.get("builder_caught_up"), builder_backlog=st.get("builder_backlog"), leases=st.get("leases"),
                          wait_ms=d.get("wait_ms"),
                          extend_leases=d.get("extend_leases"), paced_skips=d.get("paced_skips"), requests_accepted=d.get("requests_accepted"),
                          stall_open=guard.get("open"), stall_lifts=guard.get("lifts"), stall_reengages=guard.get("reengages"))
            try:
                r = own.call("audit_terminal_receipt")
            except TimeoutError:
                # the deadline came while the kernel was busy with the call (live run 10A): a timeout of the phase, not a crash
                if time.monotonic() >= deadline:
                    break
                # before it, a kernel still busy with the swarm's calls is asked again; its late answer is skipped by id (live run
                # MCPsfun_r1: one timed-out poll failed the run at the last circle's FINAL)
                slow += 1
                log.event(arm="C", phase=getattr(log, "phase_number", 1), agent="owner", kind="KERNEL_SLOW", outcome="RPC_TIMEOUT",
                          polls=slow, at_unix_s=time.time())
                if slow >= KERNEL_SLOW_POLLS:
                    raise
                continue
            slow = 0
            if r.get("status") == "TERMINAL":
                return r
            # the owner shares the kernel's lock with the swarm: poll rarely (live run 7)
            time.sleep(min(2.0, max(0, deadline - time.monotonic())))
        log.fail("TIMEOUT: terminal receipt deadline expired", arm="C")
        return {"status": "TIMEOUT", "reason": log.stopped}
    finally:
        own.set_deadline(None)


def source_document_paths(manifest: bytes, docs: dict[str, str]) -> dict[str, str]:
    """The exact string-only JCS tuple used by audit/sources.rs::document_id; no substring inference."""
    metadata = json.loads(manifest)
    source = metadata["source"]
    commit = source["commit"].lower()
    if not re.fullmatch(r"[0-9a-f]{40}", commit):
        raise ValueError("manifest requires a full commit")
    entries = {e["path"]: e for e in metadata["entries"]}
    result = {}
    for path, text in docs.items():
        raw = text.encode("utf-8")
        digest = hashlib.sha256(raw).hexdigest()
        entry = entries[path]
        if digest != entry["raw_sha256"].lower() or len(raw) != entry["size_bytes"]:
            raise ValueError(f"source bytes do not match manifest: {path}")
        fields = ["R2R-AUDIT-GIT-DOCUMENT/1", source["origin_recorded"], commit, path, digest]
        identity = "d_" + hashlib.sha256(json.dumps(fields, ensure_ascii=False, separators=(",", ":")).encode("utf-8")).hexdigest()
        result[identity] = path
    return result


def c_answers(own: Rpc, receipt: dict, docs: dict[str, str], document_paths: dict[str, str] | None = None) -> dict:
    """Each research question's outcome and answer records as the user and the grader get them: a record by its kind (a claim
    with its stance and date, a relation with its ends, an observe with its own quote), the quotes it rests on, and the summary's
    own words on what stays unsettled (Codex review c78060e, F06: a superseded claim read as a live one)."""
    paths = document_paths if document_paths is not None else {p: p for p in docs}

    def quote_of(ob: dict) -> dict:
        path = paths.get(ob.get("doc_id"))
        if path not in docs or not ob.get("quote") or ob["quote"] not in docs[path]:
            raise ValueError("answer observation has no matching bound source document")
        return {"id": ob["id"], "short": ob["short"], "quote": ob["quote"], "report": path, "doc_id": ob["doc_id"]}

    def quotes_under(rec: dict) -> list[dict]:
        """The quotes a record rests on: its own, its observe bases', and for a relation those of its ends, nested relations to any
        depth (Codex review d7d9a49, D08; review of 4381fe7, finding 2: a depth bound hid quotes). Records only reference earlier
        records, so the walk ends; each record is visited once."""
        out: dict[str, dict] = {}
        stack, seen = [rec], set()
        while stack:
            r = stack.pop()
            key = r.get("id") or r.get("short")
            if key in seen:
                continue
            seen.add(key)
            if r.get("kind") == "observe":
                q = quote_of(r)
                out[q["id"]] = q
                continue
            stack += [ob for ob in (own.call("audit_record", record=b) for b in r.get("based_on", [])) if ob.get("kind") == "observe"]
            if r.get("kind") == "relation" and r.get("ends"):
                stack += [own.call("audit_record", record=r["ends"][0]), own.call("audit_record", record=r["ends"][2])]
        return list(out.values())

    def text_of(rec: dict) -> str | None:
        """What a record says: an observe its quote, a relation its ends with nested relations spelled out to any depth, anything else
        its text."""
        if rec.get("kind") == "observe":
            return rec.get("quote")
        if rec.get("kind") == "relation" and rec.get("ends"):
            a, b = (text_of(own.call("audit_record", record=x)) for x in (rec["ends"][0], rec["ends"][2]))
            return f"{a} -- {rec['ends'][1]} -> {b}"
        return rec.get("text")

    out = {}
    for rq, outcome in (receipt.get("outcomes") or {}).items():
        claims = []
        # each answer record once, in its first place: a summary may name a record twice, as its own line and by its id (run
        # MCPpair_r1, RQ2: 67 entries of 40 records), and a repeated statement would count twice in the grading
        for answer in dict.fromkeys(outcome.get("answer_ids", [])):
            rec = own.call("audit_record", record=answer)
            text, quotes = text_of(rec), quotes_under(rec)
            status=rec.get("answer_status") or {}
            # the evidence under the claim, not a verdict on its text: its quotes hold a state that a standing later one replaced
            # (registry R34a; Codex's check of bc7cf23; Codex review of 40f97e0: one quote may hold several states)
            # each state by its text too, so the reader sees which fact was replaced (Gemini's audit of R34a)
            # the text in quotation marks is what that record states, not a quote of a report: "rests on a quote of @e ("...")"
            # read as the quote itself (run MCPpair_r1); the date is the latest of the reports the record rests on, not the time of
            # its state (Codex review of 729eda8, N1)
            dated=lambda r,side: f"{r[side]} stating {json.dumps(text_of(own.call('audit_record', record=r[side])))} (latest report date {r.get(side+'_date') or 'unknown'})"  # noqa: E731
            cited=[f"CITES A REPLACED STATE: one of its quotes grounds {dated(r,'earlier')}, a state that {dated(r,'later')} replaced; it may state the earlier state."
                   for r in status.get("replaced") or []]
            cited+=[f"CITES EARLIER AND LATER: its quotes ground both {dated(r,'earlier')} and the state that replaced it, {dated(r,'later')}."
                    for r in status.get("earlier_and_later") or []]
            warnings=rec.get("temporal_warnings") or []
            notes=warnings+cited
            authored_text=text
            if notes:text=" ".join(notes)+(" Historical statement: " if warnings else " Statement: ")+text
            claims.append({**({"authored_text":authored_text,"temporal_warnings":notes} if notes else {}),**({"temporal_status":status["temporal_status"]} if status else {}),"id": rec.get("short"), "kind": rec.get("kind"), "text": text, "stance": rec.get("stance"),
                           "as_of": (rec.get("body") or {}).get("as_of"), "quotes": quotes})
        done = own.call("audit_record", record=outcome["done"]) if outcome.get("done") else {}
        out[rq] = {"outcome": outcome.get("outcome"), "claims": claims, "unsettled": (done.get("body") or {}).get("text") or done.get("text"),
                   "reason": outcome.get("reason")}
        for field in ("partial", "requires_repair", "source_done", "delivery_audit"):
            if outcome.get(field) is not None:
                out[rq][field] = outcome[field]
    return out


def withdrawal_steps(withdraw: dict) -> list[dict]:
    """The pre-registered withdrawal steps; a plain {quote, report} is one step whose anchor is the quote."""
    if "steps" in withdraw:
        return withdraw["steps"]
    return [{"name": "2", "report": withdraw["report"], "candidates": [{"anchor": withdraw["quote"], "quote": withdraw["quote"]}]}]


def anchor_hits(observes: dict[str, dict], report: str, cand: dict, document_paths: dict[str, str]) -> list[str]:
    """Accepted observes of the report that quote the candidate's anchor, or a span of its text."""
    return sorted(rid for rid, ob in observes.items() if document_paths.get(ob["doc_id"]) == report
                  and (cand["anchor"] in ob["quote"] or (len(ob["quote"]) >= 12 and ob["quote"] in cand["quote"])))


def choose_candidate(step: dict, observes: dict[str, dict], answers: dict, document_paths: dict[str, str]) -> tuple[dict, list[str], str]:
    resting = {q["short"] for a in answers.values() for cl in a.get("claims", []) for q in cl.get("quotes", [])}
    hits = [(cand, anchor_hits(observes, step["report"], cand, document_paths)) for cand in step["candidates"]]
    for cand, hit in hits:
        if resting & set(hit):
            return cand, hit, "an answer rests on it"
    for cand, hit in hits:
        if hit:
            return cand, hit, "quoted in C, no answer rests on it"
    return hits[0][0], [], "not quoted in C"


def withdrawal_hits(observes: dict[str, dict], withdraw: dict, document_paths: dict[str, str]) -> list[str]:
    quote, report = withdraw["quote"], withdraw["report"]
    return sorted(rid for rid, ob in observes.items()
                  if document_paths.get(ob["doc_id"]) == report and (quote in ob["quote"] or ob["quote"] in quote))


PARTIAL_ANSWERS = "accepted before the run stopped; the run is not terminal"


def skipped_phase(reason: str) -> dict:
    return {"status": "SKIPPED", "reason": reason, "receipt": {"status": "SKIPPED", "reason": reason}, "answers": {}}


def frozen_arm_a() -> dict:
    """Arm A of a run that froze it: no calls, every phase skipped."""
    return {"arm": "A", "mode": "frozen", "calls": [], "events": [], "phase1": skipped_phase("ARM_A_FROZEN"), "stopped": None}


def run_arm_c(model: Model, builder_model: Model, work: pathlib.Path, manifest: pathlib.Path, repo: pathlib.Path, reports: list[str],
              docs: dict[str, str], withdraw: dict, workers: int = WORKERS, timeout_s: float = 1800, *,
              evidence: Evidence | None = None, max_calls: int = MAX_CALLS, budget: Budget | None = None,
              builder_card: dict | None = None, team: list[Model] | None = None) -> dict:
    """`team`: the readers' models, one agent each (w1 the lead, who alone summarizes; the link checker reads with `model`); else
    `workers` agents of `model`."""
    document_paths = source_document_paths(manifest.read_bytes(), docs)
    log, phase, res = Log(max_calls, evidence, time.monotonic() + timeout_s), [1], {"arm": "C"}
    log.budget = budget
    stop, threads, own, k, drained = threading.Event(), [], None, None, False
    agents = {}
    try:
        readers = team or [model] * workers
        # with --build-scope none the readers keep BUILD among their kinds (the kernel wants it of every circle reader) and are given
        # none: the kernel offers no builder work
        kinds = {f"w{i}": TEAM_READER_KINDS + (["BUILD"] if DYNAMIC_ROLES else []) for i in range(2, len(readers) + 1)} if team else {"w1": WHOLE_KINDS} if WHOLE_READER else None
        k = Kernel(work, manifest, repo, reports, f"pilot-c-{time.time_ns()}", len(readers), builder_card=builder_card, kinds=kinds)
        res["server"] = k.hello
        own = k.connect("own")
        if CIRCLES and evidence is not None:
            def circle_telemetry():
                rpc=k.connect("own")
                try: return rpc.call("audit_status",telemetry=True).get("circle_telemetry") or {}
                finally: rpc.close()
            snapshot=circle_telemetry()
            if snapshot.get("format")!="r2r-circle-telemetry/1" or snapshot.get("complete") is not True:
                raise RuntimeError("kernel committed circle telemetry unavailable; no model work started")
            evidence.circle_telemetry=circle_telemetry
        if GRAPH_QUALITY:
            # every graph option asked for is one the kernel took (31.10: the server dropped --evolution-pairing, and the strongest
            # graph's run would have paired by concepts)
            taken=(own.call("audit_status").get("graph_quality") or {}).get("config") or {}
            dropped=sorted(k for k in GRAPH_QUALITY if k not in taken)
            if dropped:
                raise RuntimeError(f"kernel did not take the graph options {dropped}; no model work started")
        if ONTOLOGY_REVISIONS:
            initial=own.call("audit_status",ontology=True).get("ontology_revision")
            if not isinstance(initial,dict) or (initial.get("policy") or {}).get("rule")!="next_nonproposer/1":
                raise RuntimeError("kernel did not expose the requested pinned ontology revision policy; no model work started")
        agents = {f"w{i}": m for i, m in enumerate(readers, start=1)} | ({LINK_CHECKER_ID: CHECKER_MODEL or model} if LINK_CHECKER else {})
        whole: dict = {"document_paths": document_paths}
        res["whole"] = whole if WHOLE_READER else None
        for agent, agent_model in agents.items():
            if WHOLE_READER and agent == "w1":
                fn = lambda a=agent, m=agent_model: c_whole_worker(k, a, m, log, phase, stop, whole)
            else:
                fn = lambda a=agent, m=agent_model: c_worker(k, a, m, log, phase, stop)
            threads.append(threading.Thread(target=guarded_worker, args=(fn, log, stop), kwargs={"arm": "C", "agent": agent},
                                            name=f"audit-{agent}", daemon=True))
        if not DYNAMIC_ROLES and BUILD_SCOPE not in ("none", "hints", "versions"):
            fn = lambda: c_builder(k, builder_model, log, phase, stop)
            threads.append(threading.Thread(target=guarded_worker, args=(fn, log, stop), kwargs={"arm": "C", "agent": "gb"}, name="audit-gb", daemon=True))
        elif CIRCLES_REFINER is not None:
            fn = lambda: c_builder(k, CIRCLES_REFINER, log, phase, stop)
            threads.append(threading.Thread(target=guarded_worker, args=(fn, log, stop), kwargs={"arm": "C", "agent": "gb"}, name="audit-gb", daemon=True))
        t0 = time.monotonic()
        log.deadline = t0 + timeout_s
        for thread in threads:
            thread.start()
        last_phase = 1 + len(withdrawal_steps(withdraw))

        def settle(receipt: dict, n: int) -> tuple[dict, bool]:
            """What a phase's answers are exported from. A phase that did not end TERMINAL starts no new work, but what the models
            already answered (and was paid for) is submitted while the kernel still runs, then what the store accepted is exported,
            marked partial (Codex's analysis of 10A-4, F02: four paid answers met a closed kernel; F01: the accepted RQ1 was lost to
            the export; his review of 77a803e, R01: every phase, the withdrawal phases too). The phase keeps its own receipt.
            After the last phase the owner closes the run: the agents are told DONE and leave by themselves, within one poll, before
            the answers are exported (R27 package 2); the ones still polling after the shutdown timeout are named. After an earlier
            phase the agents stay until the next withdrawal and poll rarely meanwhile (EXPORT_POLL_S). The phase's deadline bounds its
            work, which ended here: the export runs without it, and the next withdrawal sets its own (run MCPpair_r1: a phase-1
            deadline counted the stalled export and would have stopped the run before its withdrawals)."""
            nonlocal drained
            if receipt.get("status") == "TERMINAL":
                with log.lock:
                    log.deadline = None
                if n != last_phase:
                    log.exporting.set()
                    log.event(arm="C", phase=n, agent="owner", kind="EXPORT_WINDOW", outcome="OPEN", at_unix_s=time.time())
                if n == last_phase:
                    res["close"] = best_effort(own, "audit_close")
                    if res["close"].get("status") == "CLOSED":
                        deadline = time.monotonic() + SHUTDOWN_TIMEOUT_S
                        for thread in threads:
                            if thread.ident is not None:
                                thread.join(timeout=max(0, deadline - time.monotonic()))
                        res["close"]["still_polling"] = [thread.name for thread in threads if thread.is_alive()]
                return receipt, False
            stop.set()
            finish_threads(threads, log, stop)
            drained = True
            now = best_effort(own, "audit_terminal_receipt")
            if now.get("status") == "TERMINAL":
                return now, False
            return {"outcomes": now.get("accepted_outcomes") or {}}, True

        receipt = c_until_terminal(own, log, timeout_s)
        wall = time.monotonic() - t0
        answers_from, partial = settle(receipt, 1)
        res["phase1"] = {"receipt": receipt, "wall_s": wall, "status": best_effort(own, "audit_status")}
        res["phase1"]["answers"] = c_answers(own, answers_from, docs, document_paths)
        if ARM_A_MODE == "team":
            from .blind_links import capture_links
            res["phase1"]["link_sample"] = capture_links(own.call, document_paths)
        if partial:
            res["phase1"]["answers_partial"] = PARTIAL_ANSWERS
        # the withdrawal steps (phase 2, 3, ...), each on the answers the previous one left
        res["withdrawals"], res["revoke"], answers = [], [], res["phase1"]["answers"]
        for n, step in enumerate(withdrawal_steps(withdraw), start=2):
            key = f"phase{n}"
            if receipt.get("status") != "TERMINAL":
                res[key] = skipped_phase("PREVIOUS_PHASE_NOT_TERMINAL")
                continue
            with log.lock:
                cand, hit, reason = choose_candidate(step, log.observes, answers, document_paths)
            res["withdrawals"].append({"step": step["name"], "phase": n, "report": step["report"], **cand, "observes": hit, "reason": reason})
            phase[0] = n
            log.phase_number = n
            log.deadline = time.monotonic() + timeout_s
            t1 = time.monotonic()
            if WHOLE_READER:
                # the summaries of run S1.3 restate what rested on these observes as well as on others
                whole.setdefault("revoked", []).extend(hit)
                whole.setdefault("withdrawn_quotes", []).append({"quote": cand.get("quote"), "report": step["report"]})
            revoked = [own.call("audit_revoke", record=rid) for rid in hit]
            res["revoke"] += revoked
            # two observes quoting the same span share one evidence node: the second revoke finds it already revoked (run 5)
            withdrawn_ok = lambda r: r.get("status") == "REVOKED" or ((r.get("error") or {}).get("code") == "ALREADY_REVOKED")  # noqa: E731
            if not all(withdrawn_ok(r) for r in revoked):
                log.fail("WITHDRAWAL_REFUSED", arm="C", phase=n)
                res[key] = skipped_phase("WITHDRAWAL_REFUSED")
                break
            # the export window closes: the rereads of this withdrawal are taken at once, as before the slow polling
            log.exporting.clear()
            with log.lock:
                log.wake_gen += 1
            log.event(arm="C", phase=n, agent="owner", kind="EXPORT_WINDOW", outcome="CLOSED", at_unix_s=time.time())
            receipt = c_until_terminal(own, log, timeout_s)
            wall = time.monotonic() - t1
            answers_from, partial = settle(receipt, n)
            res[key] = {"step": step["name"], "receipt": receipt, "wall_s": wall, "status": best_effort(own, "audit_status"),
                        "nothing_quoted": not hit}
            res[key]["answers"] = answers = c_answers(own, answers_from, docs, document_paths)
            if partial:
                res[key]["answers_partial"] = PARTIAL_ANSWERS
        res["withdrawn"] = res["withdrawals"]
    finally:
        stop.set()
        # an export window left open by a refused withdrawal, a phase that did not end terminal or a failed export: the stop
        # ends every pause anyway, and the window is closed with it
        if log.exporting.is_set():
            log.exporting.clear()
            log.event(arm="C", phase=phase[0], agent="owner", kind="EXPORT_WINDOW", outcome="CLOSED", at_unix_s=time.time())
        try:
            # the threads finish their calls against a running kernel; it closes after them (F02)
            if not drained:
                finish_threads(threads, log, stop)
        finally:
            if evidence is not None: evidence.circle_telemetry=None
            if own is not None:
                if ONTOLOGY_REVISIONS or UNATTESTED_AT_END:
                    try:
                        snapshot=own.call("audit_status",ontology=True).get("ontology_revision")
                        if not isinstance(snapshot,dict) or (ONTOLOGY_REVISIONS and (snapshot.get("policy") or {}).get("rule")!="next_nonproposer/1"):
                            raise RuntimeError("kernel ontology snapshot unavailable or policy mismatched")
                        events=snapshot.get("events") or []
                        confirmations=sum(e.get("status")=="confirmed" for e in events)
                        rejections=sum(e.get("status")=="rejected" for e in events)
                        snapshot["metrics"]={"proposals":sum(e.get("status")=="pending" for e in events),"confirmed":confirmations,"rejected":rejections,
                            "pending":len(snapshot.get("pending") or []),"invalidated":len(snapshot.get("invalidated") or []),
                            "confirmation_fraction_of_reviews":confirmations/(confirmations+rejections) if confirmations+rejections else None,
                            "interpretation":"Protocol acceptance, not evidence of semantic correctness"}
                        snapshot["models"]={agent:{"model":m.name,"nature":getattr(m,"model_family",m.name)} for agent,m in agents.items()}
                        for event in snapshot.get("events") or []:
                            event["agent_model"]=(snapshot["models"].get(event.get("subject")) or {}).copy()
                        from .ontology_evolution import enrich
                        if CIRCLES_REFINER is not None:
                            snapshot["models"]["gb"]={"model":CIRCLES_REFINER.name,"nature":getattr(CIRCLES_REFINER,"model_family",CIRCLES_REFINER.name)}
                        if not DYNAMIC_ROLES and not WHOLE_READER:
                            snapshot["models"]["gb"]={"model":builder_model.name,"nature":getattr(builder_model,"model_family",builder_model.name)}
                            snapshot["models"]["builder"]=snapshot["models"]["gb"].copy()
                        snapshot=enrich(snapshot,snapshot["models"])
                        from .atomic_output import write_text
                        write_text(work.parent/"ontology_evolution.json",json.dumps(snapshot,ensure_ascii=False,indent=2))
                        res["ontology_evolution"]={"status":"EXPORTED","path":"ontology_evolution.json"}
                    except Exception as exc:
                        res["ontology_evolution"]={"status":"UNAVAILABLE","error":f"{type(exc).__name__}: {exc}"}
                own.close()
            if k is not None:
                k.stop()
    res.update(log.result())
    return res


def default_withdrawal(docs: dict[str, str]) -> dict:
    """A quote fixed before the run, the same for both arms: the first unique keyword line of the first report."""
    for path, text in docs.items():
        for line in found_lines(text):
            return {"quote": line, "report": path, "chosen": "before the run (first unique keyword line of the first report)"}
    raise ValueError("no keyword line to withdraw")


# ------------------------------------------------------------------ arm A: shared notes and a task queue

A_RULES = ("Record what this section establishes, qualifies, revokes or leaves open for the research questions. Write Markdown bullets "
           "`- [<report>] \"<exact quote>\" - <finding>`, quoting byte-exactly. Do not repeat what the notes already hold.")


def notes_context(notes: list[str]) -> dict:
    shared = "\n".join(notes)
    digest = hashlib.sha256(shared.encode("utf-8")).hexdigest()
    return {"notes_revision": f"{len(notes)}:{digest}", "notes_sha256": digest, "notes_lines": len(notes), "notes": shared}


def call_life_s(models: list, *timeouts: float) -> float:
    """The longest life of one model call of a run: each model's own adapter (its longest_s: every transport attempt and the pauses
    between them) at the longest timeout in play (the answer timeout, the agy timeout, each model's own). A model that declares no
    such life cannot bound a Temporal step and is refused (Codex review of c24763f, EXEC-03: the Gemini CLI pauses 4..64 s, not
    2..32 s, so one shared formula fell short of its life)."""
    longest = max([*timeouts, *(getattr(m, "timeout_s", None) or 0.0 for m in models)])
    lives = []
    for m in models:
        if not callable(getattr(m, "longest_s", None)):
            raise ValueError(f"{type(m).__name__} ({getattr(m, 'name', '?')}) declares no longest call life (longest_s)")
        lives.append(m.longest_s(longest))
    return max(lives, default=0.0)


# A step that ends after its phase's deadline still makes at most this many kernel calls (the answer's submit, a timed-out release,
# a fallback submit, a release), each bounded by RPC_TIMEOUT_S
CYCLE_RPCS = 4


def step_overrun_s(models: list, *timeouts: float) -> float:
    """How long an agent's step may outlive its phase's deadline: the longest life of a model call sent before it (call_life_s), the
    whole wait of an audit_acquire begun before it (ACQUIRE_WAIT_MS) and the kernel calls the step still makes (Codex review of
    d80910c, ACQUIRE-01: a 10 s acquire outlived a 0.3 s phase of the stub under Temporal)."""
    return call_life_s(models, *timeouts) + ACQUIRE_WAIT_MS / 1000 + CYCLE_RPCS * RPC_TIMEOUT_S


def invoke_answer(log,model,prompt,*,call_id,arm,role,phase,context=None):
    """ANSWER_TIMEOUT_RETRIES visible retries of an A answer after timeout/human wait; each attempt keeps its own receipt and budget
    reservation."""
    first=call=log.invoke(model,prompt,call_id=call_id,arm=arm,role=role,phase=phase,context=context)
    for n in range(1,ANSWER_TIMEOUT_RETRIES+1):
        if not (arm=="A" and call is not None and agent_failed(call) and f"{OUTPUT_OVERRUN}:" not in (call.error or "") and log.active()):
            break
        retry_id=f"{call_id}-timeout-retry-{n}"
        log.event(arm=arm,phase=phase,kind=role,outcome="ANSWER_TIMEOUT_RETRY",call_id=call.call_id,retry_call_id=retry_id,
                  model=call.model,error=call.error,partial_answer_kept=False)
        call=log.invoke(model,prompt,call_id=retry_id,arm=arm,role=role,phase=phase,
                        context=dict(context or {},timeout_retry=n,retry_of=first.call_id))
    return call


def worker_call(w: int, notes: list[str], docs: dict[str, str], path: str, rng: tuple[int, int]) -> tuple[str, dict, str]:
    """Agent w of arm A reading one section with the team's notes so far: its prompt, the call's context and its call id (the
    runner's queue and the LangGraph-native team send the same call)."""
    qtext = "\n".join(f"  {q['id']}: {q['text']}" for q in QUESTIONS)
    context = notes_context(notes)
    context.update(report=path, section=list(rng))
    prompt = (f"ARM A WORKER {w}\nRESEARCH QUESTIONS:\n{qtext}\n{A_RULES}\nNOTES:\n{context['notes'] or '(empty)'}\n"
              f"SECTION OF {path}:\n<<<\n{section_text(docs[path], rng)}\n>>>")
    path_id = hashlib.sha256(path.encode("utf-8")).hexdigest()
    return prompt, context, f"A1-{path_id}-{rng[0]}"


def read_notes(log: Log, models: list[Model], docs: dict[str, str], by_report: dict | None = None) -> list[str]:
    """Arm A's reading: the agents take the report sections from one queue and add their notes to one shared list, each reading with
    the notes so far (agent i with models[i - 1])."""
    notes: list[str] = []
    lock, stop = threading.Lock(), threading.Event()
    tasks: queue.Queue = queue.Queue()
    for path, text in docs.items():
        for rng in sections(text, SECTION_BYTES):
            tasks.put((path, rng))

    def worker(w: int) -> None:
        model = models[w - 1]

        def step() -> bool:
            """One section of the queue read by agent w: a step of the executor that drives the agent (executors.drive). False
            ends the agent."""
            try:
                path, rng = tasks.get_nowait()
            except queue.Empty:
                return False
            with lock:
                prompt, context, call_id = worker_call(w, notes, docs, path, rng)
            c = log.invoke(model, prompt, call_id=call_id, arm="A", role="WORKER", phase=1, context=context)
            if c is None:
                return False
            if not c.ok:
                log.fail(f"MODEL_ERROR: {c.error}", arm="A", phase=1, agent=f"w{w}")
                return False
            with lock:
                lines=[ln for ln in c.text.splitlines() if ln.strip()]
                notes.extend(lines)
                if by_report is not None:by_report.setdefault(path,[]).extend(lines)
            return True

        executors.drive(f"A-w{w}", step, stop, log)

    threads = []
    for i in range(1, len(models) + 1):
        fn = lambda w=i: worker(w)
        threads.append(threading.Thread(target=guarded_worker, args=(fn, log, stop), kwargs={"arm": "A", "phase": 1, "agent": f"w{i}"},
                                        name=f"notes-w{i}", daemon=True))
    try:
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=max(0, log.deadline - time.monotonic()))
    finally:
        finish_threads(threads, log, stop)
    return notes


def run_arm_a(model: Model, docs: dict[str, str], withdraw: dict, workers: int = WORKERS, timeout_s: float = 1800, *,
              evidence: Evidence | None = None, max_calls: int = MAX_CALLS, budget: Budget | None = None,
              chosen: list[dict] | None = None) -> dict:
    """`chosen`: the withdrawn text of each step as arm C resolved it by the pre-registered rule (else each step's first candidate)."""
    if workers <= 0 or timeout_s <= 0:
        raise ValueError("workers and phase timeout must be positive")
    log = Log(max_calls, evidence, time.monotonic() + timeout_s)
    log.budget = budget
    t0 = time.monotonic()
    notes = read_notes(log, [model] * workers, docs)
    # The worker stop event is local to phase 1; budgets and failure reasons remain shared across all phases.
    res = {"arm": "A", "phase1": {"answers": {}, "notes_lines": len(notes)}}
    for q in QUESTIONS:
        if not log.active():
            break
        context = notes_context(notes)
        context["rq_id"] = q["id"]
        if isinstance(model, StubModel):
            context["stub_about"] = tuple(q["about"])
        prompt = (f"ARM A SUMMARY {q['id']}: {q['text']}\n"
                  f"Answer only from the notes; say what they do not settle.\n{G.TEXT}\nNOTES:\n" + context["notes"])
        c = invoke_answer(log,model, prompt, call_id=f"A1-summary-{q['id']}", arm="A", role="SUMMARIZE", phase=1, context=context)
        if c is None:
            break
        if not c.ok:
            log.fail(f"MODEL_ERROR: {c.error}", arm="A", phase=1, rq_id=q["id"])
            break
        res["phase1"]["answers"][q["id"]] = c.text
    phase1_complete = len(res["phase1"]["answers"]) == len(QUESTIONS) and not log.stopped
    res["phase1"].update(wall_s=time.monotonic() - t0, status="COMPLETE" if phase1_complete else "STOPPED", reason=log.stopped)
    if not phase1_complete:
        res["phase2"] = skipped_phase("PHASE1_NOT_COMPLETE")
    elif not withdraw:
        res["phase2"] = skipped_phase("NO_WITHDRAWAL")
    else:
        steps = withdrawal_steps(withdraw)
        texts = chosen or [{"step": s["name"], "report": s["report"], **s["candidates"][0]} for s in steps]
        previous, so_far = res["phase1"]["answers"], []
        for n, (step, text) in enumerate(zip(steps, texts), start=2):
            key = f"phase{n}"
            if so_far and res[f"phase{n - 1}"].get("status") != "COMPLETE":
                res[key] = skipped_phase("PREVIOUS_PHASE_NOT_COMPLETE")
                continue
            log.deadline = time.monotonic() + timeout_s
            t1 = time.monotonic()
            res[key] = {"step": step["name"], "answers": {}}
            earlier = "".join(f"EARLIER WITHDRAWN QUOTE: \"{w['quote']}\" (report {w['report']})\n" for w in so_far)
            so_far.append(text)
            for q in QUESTIONS:
                context = notes_context(notes)
                context.update(rq_id=q["id"], withdrawal=text, previous_answer=previous[q["id"]])
                if isinstance(model, StubModel):
                    context["stub_about"] = tuple(q["about"])
                prompt = (f"ARM A UPDATE {q['id']}: {q['text']}\nWITHDRAWN QUOTE: \"{text['quote']}\" "
                          f"(report {text['report']}): a later revision withdraws it.\n{earlier}Update the answer: drop what rests only on "
                          "withdrawn text, keep valid support from elsewhere.\n"
                          f"{G.TEXT}\nPREVIOUS ANSWER:\n{context['previous_answer']}\nNOTES:\n{context['notes']}")
                c = invoke_answer(log,model, prompt, call_id=f"A{n}-update-{q['id']}", arm="A", role="UPDATE", phase=n, context=context)
                if c is None:
                    break
                if not c.ok:
                    log.fail(f"MODEL_ERROR: {c.error}", arm="A", phase=n, rq_id=q["id"])
                    break
                res[key]["answers"][q["id"]] = c.text
            complete = len(res[key]["answers"]) == len(QUESTIONS) and not log.stopped
            res[key].update(wall_s=time.monotonic() - t1, status="COMPLETE" if complete else "STOPPED", reason=log.stopped)
            previous = res[key]["answers"] if complete else previous
    res.update(log.result())
    return res


# ------------------------------------------------------------------ arm A, single: one strong agent without the kernel

# The bounds of an answer, the kernel's for a summary (directives.rs SUMMARY_CLAIMS, SUMMARY_TEXT_CHARS): the same task for both.
SINGLE_CLAIMS, SINGLE_TEXT_CHARS = 40, 240
CUT_MARK = " [cut]"
SINGLE_RESPONSE_CHARS = 32000  # arm A JSON response characters, not the provider token allowance
SINGLE_RULES = G.append_to(
    "Answer only from the reports above. Write JSON lines only, no prose and no code fences:\n"
    f'  {{"kind":"claim","local_id":"a1","text":"<at most {G.TARGET_CLAIM_CHARACTERS} characters>","quotes":[{{"report":"<report path as given>","exact_quote":'
    '"<copied byte for byte from that report>"}]}\n'
    f'  then exactly one {{"kind":"done","text":"<at most {G.TARGET_CLAIM_CHARACTERS} characters: what the reports do not settle>"}}\n'
    f"At most {SINGLE_CLAIMS} claim lines, each a short text that merges related findings and rests on all their quotes. A quote is "
    "copied byte for byte from the named report and occurs exactly once in it: extend it when its words repeat. Cover every report "
    "that bears on the question.")
# A continuation line that is not one paragraph with the line before: the kernel's soft wrap does not join it (directives.rs).
SINGLE_BLOCK_STARTS = ("#", "- ", "* ", "```", "+++", "|")


def single_corpus(docs: dict[str, str]) -> str:
    """The reports in one prompt, the same for every call of the arm (a cached prefix)."""
    return "ARM A SINGLE\n" + "".join(f"=== REPORT {path} ===\n{text}\n=== END OF {path} ===\n" for path, text in docs.items())


def resolve_quote(text: str, quote: str) -> tuple[tuple[int, int] | None, str]:
    """Where a quote stands in a report by the kernel's rule: exactly one occurrence; failing that, exactly one occurrence when a
    space of the quote may be one soft line break of the report inside a paragraph (the kernel's soft wrap). The span, or why not."""
    if not quote.strip():
        return None, "the quote is empty"
    n = text.count(quote)
    if n == 1:
        i = text.index(quote)
        return (i, i + len(quote)), ""
    if n > 1:
        return None, f"occurs {n} times in the report: extend it until it occurs once"
    gap = r"(?:[ \t]+|[ \t]*\n[ \t]*)"
    hits = [m for m in re.finditer(gap.join(re.escape(w) for w in quote.split()), text)
            if not any(ln.lstrip().startswith(SINGLE_BLOCK_STARTS) or re.match(r"\s*\d+\. ", ln) for ln in m.group(0).split("\n")[1:])]
    if len(hits) == 1:
        return (hits[0].start(), hits[0].end()), ""
    if hits:
        return None, f"occurs {len(hits)} times in the report: extend it until it occurs once"
    return None, "not found byte for byte in the report"


def check_single(lines: list[dict], docs: dict[str, str], withdrawn: list[dict], kept: dict[str, dict], *,
                 max_claims: int = SINGLE_CLAIMS) -> tuple[dict[str, dict], list[dict], dict | None]:
    """The checked claims of an answer by local id (each quote as the report's bytes), the lines refused with why, and the done line.
    A line under a local id already kept is a resend and changes nothing; a quote overlapping withdrawn text is refused."""
    spans = []
    for w in withdrawn:
        span, _ = resolve_quote(docs.get(w["report"], ""), w["quote"])
        if span:
            spans.append((w["report"], span))
    new, refused, done = {}, [], None
    for v in lines:
        kind, local = v.get("kind"), v.get("local_id")
        if kind == "done":
            text = v.get("text") if isinstance(v.get("text"), str) else ""
            if done is not None:
                refused.append({"local_id": local, "kind": "done", "why": "a second done line"})
            elif len(text) <= SINGLE_TEXT_CHARS:
                done = {"text": text}
            else:
                # The closing line says what the reports leave open. It backs no claim, so an over-long one is cut, not refused: refused, it
                # marked the whole answer incomplete and the page was done again at the next stage, calls that had nothing to do with a
                # withdrawal. It goes into the answer, so a reader sees the mark and the run counts the cut.
                done = {"text": text[:SINGLE_TEXT_CHARS - len(CUT_MARK)] + CUT_MARK, "cut_from_chars": len(text)}
            continue
        if kind != "claim" or not isinstance(local, str) or not local:
            refused.append({"local_id": local, "kind": kind, "why": "a line is a claim with a local_id or the done line"})
            continue
        if local in kept:
            continue
        if local in new:
            refused.append({"local_id": local, "kind": kind, "why": "the local_id is given twice"})
            continue
        text = v.get("text") if isinstance(v.get("text"), str) else ""
        why = None if 0 < len(text) <= SINGLE_TEXT_CHARS else f"text of 1..{SINGLE_TEXT_CHARS} characters ({len(text)})"
        quotes = []
        for q in v.get("quotes") if isinstance(v.get("quotes"), list) else []:
            report, exact = (q.get("report"), q.get("exact_quote")) if isinstance(q, dict) else (None, None)
            if report not in docs or not isinstance(exact, str):
                why = why or f"unknown report {report!r}: name a report as given"
                break
            span, reason = resolve_quote(docs[report], exact)
            if span is None:
                why = why or f"quote {exact[:80]!r}: {reason}"
                break
            if any(r == report and span[0] < b and a < span[1] for r, (a, b) in spans):
                why = why or f"quote {exact[:80]!r} rests on withdrawn text"
                break
            quotes.append({"report": report, "quote": docs[report][span[0]:span[1]]})
        if not quotes:
            why = why or "a claim rests on at least one quote"
        if why is None and len(kept) + len(new) >= max_claims:
            why = f"over the bound of {max_claims} claims"
        if why:
            refused.append({"local_id": local, "kind": kind, "why": why})
        else:
            new[local] = {"id": local, "kind": "claim", "text": text, "stance": None, "as_of": None, "quotes": quotes}
    return new, refused, done


def single_output_contract(claims: int, chars: int) -> str:
    """Arm A's local envelope; the common A/C guidance and the provider allowance stay unchanged."""
    return (f"LOCAL OUTPUT LIMIT: at most {claims} claim lines and exactly one done line; at most {chars} characters in the entire "
            "response, including quotes and JSON. JSON objects on separate lines only; no discussion or code fences. "
            'A claim is {"kind":"claim","local_id":"a1","text":"a short finding","quotes":[{"report":"given path",'
            '"exact_quote":"source bytes"}]}. The last line is {"kind":"done","text":"what the supplied material leaves unsettled"}. '
            "Use short supporting quotes. If a quote cannot be made unique using the source bytes supplied, omit that claim and "
            "state the missing support in done. Do not reconstruct unseen source text.")


def single_answer(log: "Log", model: Model, prompt: str, docs: dict[str, str], withdrawn: list[dict], *, phase: int, rq: str,
                  role: str, name: str = "single", context: dict | None = None, first: str | None = None,
                  stop_on_model_error: bool = True, max_response_chars: int | None = None, allowed_quotes: set | None = None,
                  max_claims: int = SINGLE_CLAIMS, repair_context: str | None = None) -> dict | None:
    """A bounded answer and targeted repairs. Accepted lines stay; a repair gets only the refused lines, the original evidence,
    and a local output contract, rather than another full answer task and every accepted line. A failed/cut response contributes
    no new lines. An OUTPUT_OVERRUN is terminal for this answer, never a timeout retry: keep prior validated lines as INCOMPLETE.
    `repair_context` contains the original task's evidence/question/withdrawals, with no new source access or answer instructions.
    `first` supplies an already given initial answer, whose validation is identical."""
    cap = SINGLE_RESPONSE_CHARS if max_response_chars is None else max_response_chars
    if not 1 <= max_claims <= SINGLE_CLAIMS or cap <= 0:
        raise ValueError("invalid arm A answer limits")
    material = repair_context if repair_context is not None else prompt.replace(G.TEXT, "")
    kept: dict[str, dict] = {}
    done, refused, repairs, previous, whole = None, [], 0, "", False
    repair_ids: set[str] | None = None
    for attempt in range(SUMMARY_REPAIRS + 1):
        allowed_ids = repair_ids
        remaining = max_claims - len(kept)
        limit = remaining if allowed_ids is None else min(remaining, len(allowed_ids))
        if attempt == 0:
            ask = f"{prompt}\n{single_output_contract(limit, cap)}"
        else:
            again = ("Nothing of your previous answer was kept: send the whole answer again, JSON lines only. Earlier KEPT IDs "
                     "remain accepted; do not repeat them." if whole and repair_ids is None else
                     "Repair only the REFUSED IDs, or omit them if the supplied evidence cannot support a correction. Do not add "
                     "other claims or answer the question again. Always send one done line, even if every refused claim is omitted.")
            ask = (f"ARM A ANSWER REPAIR\nREFERENCE MATERIAL AND QUESTION:\n{material}\nEND REFERENCE MATERIAL\n{G.TEXT}\n"
                   f"KEPT: {sorted(kept)}\nREFUSED: {json.dumps(refused, ensure_ascii=False)}\n"
                   f"YOUR PREVIOUS ANSWER:\n{previous}\nPREVIOUS DONE TEXT: {json.dumps((done or {}).get('text'))}\n"
                   f"{again}\n{single_output_contract(limit, cap)}")
        if attempt == 0 and first is not None:
            c = Call(call_id=f"A{phase}-{name}-{rq}-given", arm="A", role=role, phase=phase, prompt_chars=len(ask), text=first, model="given")
        else:
            c = invoke_answer(log,model, ask, call_id=f"A{phase}-{name}-{rq}-{attempt}", arm="A", role=role, phase=phase,
                              context=dict(context or {}, rq_id=rq, attempt=attempt))
        if c is None:
            return None
        repairs = attempt
        if not c.ok:
            overrun = f"{OUTPUT_OVERRUN}:" in (c.error or "")
            if stop_on_model_error and not overrun:
                log.fail(f"MODEL_ERROR: {c.error}", arm="A", phase=phase, rq_id=rq)
                return None
            # Do not let a native node retry the same overrun as a transient model outage. With validated claims it is a partial
            # answer; without them it is unknown. The error and incomplete status remain visible in both cases.
            return {"outcome": ("answered" if kept else "unknown") if overrun else "not_answered", "claims": list(kept.values()),
                    "unsettled": (done or {}).get("text"), "refused_at_end": refused, "repairs": repairs,
                    "complete": False, "error": c.error}
        lines, local, _ = check_answer(c, allow_empty=False, bound=limit + 1)
        if len(c.text or "") > cap:
            local={"error":{"code":"ANSWER_PARTIAL_TOO_LONG","message":f"Answer must fit {cap} characters; send it again shorter."}}
        elif local is None and len(lines) > limit + 1:
            local={"error":{"code":"ANSWER_TOO_MANY_LINES","message":f"Send at most {limit} claim lines and one done line."}}
        whole = local is not None
        if whole:
            refused = [{"local_id": None, "kind": None, "why": local["error"]["message"], "lines": local["error"].get("lines")}]
            # Never put a cut or oversized response back into the next prompt; malformed examples are not useful repair input.
            previous = "(cut at the output limit)" if local["error"].get("code") in ("OUTPUT_LIMIT","ANSWER_PARTIAL_TOO_LONG") else "(invalid response omitted)"
            continue
        new, refused, got = check_single(lines, docs, withdrawn, kept, max_claims=max_claims)
        for local_id, claim in list(new.items()):
            why = ("repair may only correct a refused local_id" if allowed_ids is not None and local_id not in allowed_ids else
                   "quote is not among the validated per-report partial answers" if allowed_quotes is not None and
                   any((q["report"], q["quote"]) not in allowed_quotes for q in claim["quotes"]) else None)
            if why:
                refused.append({"local_id":local_id,"kind":"claim","why":why})
                del new[local_id]
        kept.update(new)
        done = got or done
        if got and got.get("cut_from_chars"):
            log.event(arm="A", phase=phase, kind="CLOSING_LINE_CUT", rq_id=rq, name=name, chars=got["cut_from_chars"])
        if got is None:
            refused.append({"local_id": None, "kind": "done", "why": "one done line is required, including after a repair"})
        refused_ids = {r["local_id"] for r in refused if isinstance(r.get("local_id"), str)}
        if repair_ids is None:
            repair_ids = refused_ids
        previous = "\n".join(json.dumps(v, ensure_ascii=False) for v in lines if v.get("local_id") in refused_ids)
        if not refused and done is not None:
            break
    claims = list(kept.values())
    return {"outcome": "answered" if claims else "unknown", "claims": claims, "unsettled": (done or {}).get("text"),
            "refused_at_end": refused, "repairs": repairs, "complete": done is not None and not refused,
            "unsettled_cut_from_chars": (done or {}).get("cut_from_chars")}


def answers_status(answers: dict, log: "Log") -> tuple[str, str | None]:
    """A phase of arm A answers is COMPLETE when every research question has a complete answer (single_answer), STOPPED when the log
    stopped the arm, else INCOMPLETE; the reason beside it."""
    if log.stopped:
        return "STOPPED", log.stopped
    if len(answers) == len(QUESTIONS) and all(a.get("complete") for a in answers.values()):
        return "COMPLETE", None
    if any(a.get("partial_reports_missing") for a in answers.values()):return "INCOMPLETE","one or more per-report partial answers are incomplete"
    return "INCOMPLETE", "an answer ended without its done line or with lines refused after its repairs"


def answer_phases(log: "Log", model: Model, docs: dict[str, str], withdraw: dict, corpus: str, rules: str, res: dict, t0: float,
                  timeout_s: float, chosen: list[dict] | None, *, name: str, role: str, context: dict | None = None,
                  first: dict[str, str] | None = None, notes_by_report: dict | None = None) -> None:
    """Phase 1 and each withdrawal step of an arm A agent that answers from `corpus` with claims and quotes (the single agent, the
    team's lead), into `res`: the quotes checked by the kernel's byte rule after each answer; each step told to it and its update
    checked."""
    rules = G.append_to(rules)
    if ARM_A_ANSWER=="map-reduce":
        if first is not None:raise ValueError("map-reduce needs its own report/notes inputs; precomputed answers are not allowed")
        res["answer_strategy"]=ARM_A_ANSWER
    for q in QUESTIONS:
        prompt = f"{corpus}\nQUESTION {q['id']}: {q['text']}\n{rules}"
        if ARM_A_ANSWER=="map-reduce":
            from .answer_map_reduce import answer
            sink=res["phase1"].setdefault("partials",{}).setdefault(q["id"],[])
            ans=answer(log,model,docs,[],q,1,rules,name,role,context,notes_by_report,sink)
        else:ans = single_answer(log, model, prompt, docs, [], phase=1, rq=q["id"], role=role, name=name, context=context, first=(first or {}).get(q["id"]),
                                  repair_context=f"{corpus}\nQUESTION {q['id']}: {q['text']}")
        if ans is None:
            break
        res["phase1"]["answers"][q["id"]] = ans
    status, reason = answers_status(res["phase1"]["answers"], log)
    res["phase1"].update(wall_s=time.monotonic() - t0, status=status, reason=reason)
    # an answer with a gap (INCOMPLETE: a partial answer of a report or a line still refused after its repairs) is still the
    # arm's answer, and the withdrawals test how the arm updates it, as arm C goes on from a TERMINAL phase with unsettled
    # questions; only a stopped arm skips them (run MCPpair2_r1: one refused quote in two of 44 partial answers skipped both
    # withdrawals of arm A). The INCOMPLETE status stays in the record.
    if status == "STOPPED":
        res["phase2"] = skipped_phase("PHASE1_STOPPED")
    elif withdraw:
        steps = withdrawal_steps(withdraw)
        texts = chosen or [{"step": s["name"], "report": s["report"], **s["candidates"][0]} for s in steps]
        previous, so_far = res["phase1"]["answers"], []
        for n, (step, text) in enumerate(zip(steps, texts), start=2):
            key = f"phase{n}"
            if so_far and res[f"phase{n - 1}"].get("status") == "STOPPED":
                res[key] = skipped_phase("PREVIOUS_PHASE_STOPPED")
                continue
            log.deadline = time.monotonic() + timeout_s
            t1 = time.monotonic()
            so_far.append(text)
            res[key] = {"step": step["name"], "answers": {}}
            told = "".join(f"WITHDRAWN QUOTE: \"{w['quote']}\" (report {w['report']}): a later revision withdraws it.\n" for w in so_far)
            for q in QUESTIONS:
                before = "\n".join(json.dumps({"kind": "claim", "local_id": cl["id"], "text": cl["text"],
                                               "quotes": [{"report": x["report"], "exact_quote": x["quote"]} for x in cl["quotes"]]})
                                   for cl in previous[q["id"]]["claims"])
                prompt = (f"{corpus}\nQUESTION {q['id']}: {q['text']}\n{told}"
                          f"YOUR ANSWER BEFORE THE WITHDRAWAL:\n{before or '(no claims)'}\nAnswer again: drop what rests only on withdrawn "
                          f"text, keep valid support from elsewhere.\n{rules}")
                if ARM_A_ANSWER=="map-reduce":
                    from .answer_map_reduce import answer
                    sink=res[key].setdefault("partials",{}).setdefault(q["id"],[])
                    ans=answer(log,model,docs,so_far,q,n,rules,name,"UPDATE",context,notes_by_report,sink)
                else:ans = single_answer(log, model, prompt, docs, so_far, phase=n, rq=q["id"], role="UPDATE", name=name, context=context,
                                          repair_context=f"{corpus}\nQUESTION {q['id']}: {q['text']}\n{told}")
                if ans is None:
                    break
                res[key]["answers"][q["id"]] = ans
            status, reason = answers_status(res[key]["answers"], log)
            res[key].update(wall_s=time.monotonic() - t1, status=status, reason=reason)
            previous = res[key]["answers"] if status != "STOPPED" else previous
    else:
        res["phase2"] = skipped_phase("NO_WITHDRAWAL")


def run_arm_single(model: Model, docs: dict[str, str], withdraw: dict, timeout_s: float = 1800, *, evidence: Evidence | None = None,
                   max_calls: int = MAX_CALLS, budget: Budget | None = None, chosen: list[dict] | None = None) -> dict:
    """Arm A as one agent of the same model without the kernel: every report in one prompt, an answer with quotes per research
    question, the quotes checked by the kernel's byte rule after the answer; each withdrawal step told to it and its update checked."""
    if timeout_s <= 0:
        raise ValueError("phase timeout must be positive")
    log = Log(max_calls, evidence, time.monotonic() + timeout_s)
    log.budget = budget
    res = {"arm": "A", "mode": "single", "phase1": {"answers": {}}}
    answer_phases(log, model, docs, withdraw, single_corpus(docs), SINGLE_RULES, res, time.monotonic(), timeout_s, chosen,
                  name="single", role="SINGLE")
    res.update(log.result())
    return res


# ------------------------------------------------------------------ arm A, team: the same agents without the kernel

# The lead answers from the team's notes, not from the reports: the single agent's rules with the notes as the source.
TEAM_RULES = SINGLE_RULES.replace("Answer only from the reports above.", "Answer only from the notes above; their quotes are copied from the "
                                  "reports.", 1)


def team_corpus(notes: list[str], docs: dict[str, str]) -> str:
    """The team's shared notes in one prompt, the same for every answer of a phase, under the reports' paths: a note may name its
    report short, an answer names it as given (live run S2: without the paths every claim of the lead's first answer was refused)."""
    return ("ARM A TEAM\nREPORTS (name a report by its path as given here):\n" + "".join(f"  {path}\n" for path in docs)
            + "NOTES OF THE TEAM (each agent's notes on the reports it read, with their quotes):\n" + "\n".join(notes) + "\n")


def run_arm_team(team: list[Model], docs: dict[str, str], withdraw: dict, timeout_s: float = 1800, *, evidence: Evidence | None = None,
                 max_calls: int = MAX_CALLS, budget: Budget | None = None, chosen: list[dict] | None = None) -> dict:
    """Arm A as the same team without the kernel: the agents read the report sections from one queue into one
    shared notes file, each with the notes so far, as a team shares a document; then the lead (the team's first agent, who alone
    summarizes in the kernel's arm too) answers each research question from the notes alone, its quotes checked by the kernel's byte
    rule as the single agent's are; each withdrawal step told to the lead."""
    if ARM_A_ORCHESTRATION in ("langgraph-native", "temporal-native"):
        # the same team, prompts and checks as one LangGraph graph or one Temporal workflow with their own checkpoints, retries and
        # native means
        if ARM_A_ORCHESTRATION == "langgraph-native":
            from .arm_a_langgraph import run as run_native
        else:
            from .arm_a_temporal import run as run_native
        return run_native(team, docs, withdraw, timeout_s, evidence=evidence, max_calls=max_calls, budget=budget, chosen=chosen)
    if not team or timeout_s <= 0:
        raise ValueError("a team and a positive phase timeout are needed")
    log = Log(max_calls, evidence, time.monotonic() + timeout_s)
    log.budget = budget
    t0 = time.monotonic()
    notes_by_report={} if ARM_A_ANSWER=="map-reduce" else None
    notes = read_notes(log, team, docs) if notes_by_report is None else read_notes(log, team, docs,by_report=notes_by_report)
    res = {"arm": "A", "mode": "team", "team": [m.name for m in team], "phase1": {"answers": {}, "notes_lines": len(notes)}}
    context = {k: v for k, v in notes_context(notes).items() if k != "notes"}
    # the lead answers alone, question after question: one step of the executor
    executors.once("A-lead", lambda: answer_phases(log, team[0], docs, withdraw, team_corpus(notes, docs), TEAM_RULES, res, t0, timeout_s, chosen,
                                                 name="lead", role="LEAD", context=context, notes_by_report=notes_by_report))
    res.update(log.result())
    return res


# ------------------------------------------------------------------ run S1.2: one strong agent hands in its whole reading

def whole_read(rpc: Rpc, t: dict, agent: str, model: Model, log: Log, ph: int, whole: dict, stop: threading.Event) -> None:
    """The zone task of run S1.2: one call reads every report and answers with records, relations and the answers to the research
    questions. The records and relations go to the kernel, its refusals repaired as a reader's are; the answers wait for the
    summaries. Whatever the kernel stored closes the task. Run S1.3 (WHOLE_STEPS): the records are atomic and the answers come in a
    call of their own after the zone (whole_answers)."""
    task = t["task_id"]
    change = t["kind"] == "CHANGE"
    prompt = t["prompt"] + (EMPTY_RESPONSE_RULE if change else WHOLE_STEP_RULES if WHOLE_STEPS else WHOLE_RULES)
    context = {"task_id": task, "key": t.get("key"), "kind": t["kind"]}

    def submit(lines: list[dict], call_id: str | None) -> dict:
        return log.reply(rpc.call("audit_submit", task_id=task, lines=lines), arm="C", phase=ph, agent=agent, task=task, kind=t["kind"],
                         call_id=call_id, lines_submitted=len(lines))

    def ask(text: str, n: int) -> "Call | None":
        return log.invoke(model, text, call_id=f"C{ph}-{task}-{n}", arm="C", role="CHANGE" if change else "ZONE", phase=ph, context=dict(context, repair=n))

    tries, c = 0, ask(prompt, 0)
    lines, local = [], None
    while c is not None and c.ok:
        lines, local, _ = check_answer(c, allow_empty=change, bound=t.get("max_lines") if change else None)
        if not local or tries >= REPAIRS:
            break
        tries += 1
        c = ask(repair_prompt(prompt, local, "lines", c.text), tries)
    if c is None:
        return
    if not c.ok or local:
        log.fail(f"MODEL_ERROR: {c.error}" if not c.ok else "PARSE_FAILURE: the zone answer was not repaired", arm="C", phase=ph, agent=agent,
                 task=task, parse_failure=bool(local))
        stop.set()
        return
    graph = [v for v in lines if v.get("kind") in WHOLE_GRAPH]
    if not WHOLE_LINKS:
        whole["relations_kept_aside"] = [v for v in graph if v.get("kind") == "relation"]
        graph = [v for v in graph if v.get("kind") != "relation"]
    whole.update(answer_call=c.call_id, answers=[v for v in lines if v.get("kind") in WHOLE_ANSWERS], graph_lines=list(graph),
                 left_out=[v for v in lines if v.get("kind") not in WHOLE_GRAPH + WHOLE_ANSWERS])
    r = submit(graph, c.call_id)
    accepted = note_observes(log, graph, r)
    stored = dict(r.get("accepted_locals") or {})
    while r.get("status") == "REPAIR_REQUIRED" and tries < REPAIRS and log.active() and not stop.is_set():
        tries += 1
        c = ask(repair_prompt(prompt, r, "lines", c.text, accepted), tries)
        if c is None or not c.ok:
            break
        fixed, local, _ = check_answer(c, allow_empty=change, bound=t.get("max_lines") if change else None)
        if local:
            continue
        fixed = [v for v in fixed if v.get("kind") in WHOLE_GRAPH and (WHOLE_LINKS or v.get("kind") != "relation")]
        r = submit(fixed, c.call_id)
        accepted.extend(note_observes(log, fixed, r))
        stored.update(r.get("accepted_locals") or {})
        # the records as the kernel took them: a repaired line replaces the one it repairs (the answers rest on these)
        by_local = {v.get("local_id"): v for v in fixed}
        whole["graph_lines"] = [by_local.pop(v.get("local_id"), v) for v in whole["graph_lines"]] + list(by_local.values())
    if r.get("status") != "COMMITTED" and log.active() and not stop.is_set():
        r = submit([], None)
    whole["locals"] = stored
    log.event(arm="C", phase=ph, agent=agent, task=task, kind=t["kind"], key=t.get("key"), outcome=r.get("status"), repairs=tries, broken_lines=0,
              parse_failure=False, explicit_empty=False, error=None, abandoned=False, lines_offered=len(graph), lines_stored=len(stored))
    if WHOLE_STEPS and not change and log.active() and not stop.is_set():
        whole_answers(t, model, log, ph, whole, stop)


def whole_answers(t: dict, model: Model, log: Log, ph: int, whole: dict, stop: threading.Event) -> None:
    """Run S1.3: the answers in a call of their own after the zone: the same reports, the records the agent wrote as the kernel took
    them, and answer lines asked for on its observes. Arm A takes the same answers."""
    stored = whole.get("locals") or {}
    records = "\n".join(json.dumps(v, ensure_ascii=False) for v in whole.get("graph_lines") or [] if v.get("local_id") in stored)
    prompt = f"{t['prompt']}\n\nANSWER FROM YOUR RECORDS. These are the records you wrote for the reports above, as the kernel stored them:\n{records}\n{WHOLE_ANSWER_RULES}"
    tries = 0
    c = log.invoke(model, prompt, call_id=f"C{ph}-{t['task_id']}-answers-0", arm="C", role="ANSWER", phase=ph, context={"task_id": t["task_id"]})
    lines, local = [], None
    while c is not None and c.ok:
        lines, local, _ = check_answer(c, allow_empty=False, bound=None)
        if not local or tries >= REPAIRS:
            break
        tries += 1
        c = log.invoke(model, repair_prompt(prompt, local, "lines", c.text), call_id=f"C{ph}-{t['task_id']}-answers-{tries}", arm="C", role="ANSWER",
                       phase=ph, context={"task_id": t["task_id"], "repair": tries})
    if c is None:
        return
    if not c.ok or local:
        log.fail(f"MODEL_ERROR: {c.error}" if not c.ok else "PARSE_FAILURE: the answers were not repaired", arm="C", phase=ph, agent="w1",
                 parse_failure=bool(local))
        stop.set()
        return
    whole.update(answers=[v for v in lines if v.get("kind") in WHOLE_ANSWERS], answers_call=c.call_id)


def whole_observes(whole: dict) -> dict:
    """The agent's observe lines by local id, as the kernel took them."""
    return {v.get("local_id"): v for v in whole.get("graph_lines") or [] if v.get("kind") == "observe"}


# the stances the kernel takes in a claim (records.rs STANCES)
WHOLE_STANCES = ("reported", "confirmed", "refuted", "qualified", "superseded", "open", "unknown")
# the line the hint and the restatement ask for
WHOLE_LINE = ('{"kind":"answer","rq_id":"<RQ id>","local_id":"<its local_id>","text":"<at most 240 characters>","subject":"...",'
              '"stance":"...","based_on":["<observe local_ids>"]}')


def whole_lines(text: str) -> list[dict]:
    """The answer lines of a hint or a restatement: JSON objects one per line, or a JSON array of them on a line (live run S1.3: the
    agent sent its three restatements as an array without "kind", and all three were dropped); the kernel checks what is handed in."""
    out = []
    for ln in (text or "").splitlines():
        ln = ln.strip()
        if not ln.startswith(("{", "[")):
            continue
        try:
            v = json.loads(ln)
        except json.JSONDecodeError:
            continue
        out.extend(x | {"kind": x.get("kind") or "answer"} for x in (v if isinstance(v, list) else [v]) if isinstance(x, dict))
    return out


def whole_hint(model: Model, log: Log, ph: int, whole: dict, rq: str, refused: list[dict], problems: list) -> list[dict]:
    """Run S1.3: answer lines the kernel refused go back to the agent once, with the kernel's reasons and its observes, instead of
    being left out silently. The corrected answer lines, as the agent wrote them."""
    observes = whole_observes(whole)
    shown = "\n".join(json.dumps(observes[o], ensure_ascii=False) for o in observes if o in (whole.get("locals") or {}))
    prompt = (f"FIX THESE ANSWER LINES of research question {rq}. The kernel refused them; its reasons:\n{json.dumps(problems, ensure_ascii=False)}\n"
              "LINES:\n" + "\n".join(json.dumps(a, ensure_ascii=False) for a in refused) + f"\nYOUR OBSERVES:\n{shown}\n"
              "Send each line corrected under the same local_id: cite observes that hold what its text names, or take out of the text what "
              f"no observe holds; leave a line out when it cannot be fixed. One answer line per JSON line, nothing else:\n{WHOLE_LINE}")
    c = log.invoke(model, prompt, call_id=f"C{ph}-hint-{rq}", arm="C", role="HINT", phase=ph, context={"rq_id": rq})
    if c is None or not c.ok:
        return []
    return [v for v in whole_lines(c.text) if v.get("kind") == "answer"]


def whole_restate(model: Model, log: Log, ph: int, whole: dict, rq: str, lost: list[dict]) -> list[dict]:
    """Run S1.3: after a withdrawal the kernel keeps the answer rows that do not rest on withdrawn text; each row it took out that
    still has quotes goes back to the agent with those quotes and its other observes that stand (not the reports): restated on them,
    narrower, or left out. A row may rest on another of its observes (replicate S1.3-R1: restated on its remaining quotes only, a
    supersession lost the newer state the reports held elsewhere). The restated answer lines, as the agent wrote them."""
    observes = whole_observes(whole)
    revoked = {r.lstrip("@")[:16] for r in whole.get("revoked") or []}
    standing = {o for o, rid in (whole.get("locals") or {}).items() if o in observes and rid.lstrip("@")[:16] not in revoked}
    withdrawn = "".join(f"WITHDRAWN QUOTE: \"{w['quote']}\" (report {w['report']}): a later revision withdraws it.\n" for w in whole.get("withdrawn_quotes") or [])
    blocks = "\n".join("CANDIDATE " + json.dumps({"local_id": x["agent_id"], "rq_id": rq, "text": x["text"], "subject": x.get("subject"),
                                                  "remaining": x["remaining"], "quotes": [observes[o] for o in x["remaining"] if o in observes]},
                                                 ensure_ascii=False) for x in lost)
    others = "\n".join(json.dumps(observes[o], ensure_ascii=False) for o in sorted(standing) if all(o not in x["remaining"] for x in lost))
    prompt = (f"RESTATE AFTER A WITHDRAWAL, research question {rq}.\n{withdrawn}Each candidate below was an answer line resting on withdrawn "
              f"text as well as on other quotes; its remaining quotes are shown.\n{blocks}\nYOUR OTHER OBSERVES THAT STAND:\n{others or '(none)'}\n"
              "For each candidate write one answer line under its local_id when quotes that stand still prove it (restated on them, "
              "narrower if only part of it holds; based_on: its remaining observes and any of your other observes that stand), or leave "
              f"it out. One answer line per JSON line, nothing else; reply [] when none holds:\n{WHOLE_LINE}")
    c = log.invoke(model, prompt, call_id=f"C{ph}-restate-{rq}", arm="C", role="RESTATE", phase=ph, context={"rq_id": rq})
    if c is None or not c.ok:
        return []
    allowed = {x["agent_id"]: set(x["remaining"]) | standing for x in lost}
    return [v for v in whole_lines(c.text) if v.get("kind") == "answer" and v.get("local_id") in allowed
            and isinstance(v.get("based_on"), list) and v["based_on"] and set(v["based_on"]) <= allowed[v["local_id"]]]


def whole_summary(rpc: Rpc, t: dict, agent: str, log: Log, ph: int, whole: dict, model: Model | None = None) -> None:
    """A summary of run S1.2, handed in from the agent's answer lines without a model: its answer lines for the question as claims
    on the observes the kernel stored (a line on an observe it did not store is left out and counted), then the done line; a line
    the kernel refuses is left out and the rest handed in again. A summary reopened by a withdrawal hands in its done line alone:
    the kernel keeps the rows that do not rest on the withdrawn text. Run S1.3 (WHOLE_STEPS) asks the agent once about the refused
    lines (whole_hint) and, after a withdrawal, about the rows taken out that still have quotes (whole_restate)."""
    task, rq, p = t["task_id"], t["key"][3:], t["local_id_prefix"]
    locals_ = whole.get("locals") or {}
    retained = set(t.get("retained_answer_ids") or [])
    records = whole.setdefault("answer_records", {})
    claims, origin, left_out, unsettled, asked = [], {}, [], None, []

    def claim_of(a: dict, local: str | None = None) -> dict | None:
        names = a.get("based_on") if isinstance(a.get("based_on"), list) else []
        based = [locals_.get(b) for b in names]
        if not based or None in based:
            left_out.append({"local_id": a.get("local_id"), "why": "rests on an observe the kernel did not store"})
            return None
        # an answer line's stance outside the kernel's list is handed in as reported (live run S1.3, bcd3840: a restatement said
        # "supports", a relation's name, and the kernel refused the whole row)
        stance = a.get("stance") if a.get("stance") in WHOLE_STANCES else "reported"
        cl = {"kind": "claim", "local_id": local or f"{p}c{len(claims) + 1}", "text": a.get("text"), "subject": a.get("subject") or rq,
              "stance": stance, "based_on": based}
        origin[cl["local_id"]] = a
        return cl

    if ph == 1:
        for a in whole.get("answers") or []:
            if a.get("rq_id") != rq:
                continue
            if a.get("kind") == "answer_done":
                unsettled = a.get("text") if isinstance(a.get("text"), str) and a.get("text") else None
                continue
            cl = claim_of(a)
            if cl:
                claims.append(cl)
    elif WHOLE_STEPS and model is not None:
        revoked = {r.lstrip("@")[:16] for r in whole.get("revoked") or []}
        lost = []
        for x in records.get(rq, []):
            if x["short"] in retained:
                continue
            remaining = [o for o in x["based_on"] if (locals_.get(o) or "@").lstrip("@")[:16] not in revoked]
            if remaining:
                lost.append(dict(x, remaining=remaining))
        if lost:
            asked.append("restate")
            for a in whole_restate(model, log, ph, whole, rq, lost):
                cl = claim_of(dict(a, rq_id=rq))
                if cl:
                    claims.append(cl)

    def done(ids: list[str]) -> dict:
        line = {"kind": "done", "local_id": f"{p}d1", "rq_id": rq, "directive_id": task, "outcome": "answered" if ids else "unknown", "answer_ids": ids}
        return line | ({"text": unsettled} if unsettled else {})

    def submit(lines: list[dict]) -> dict:
        return log.reply(rpc.call("audit_submit", task_id=task, lines=lines), arm="C", phase=ph, agent=agent, task=task, kind="SUMMARIZE",
                         call_id=None, lines_submitted=len(lines))

    r = submit(claims + [done([cl["local_id"] for cl in claims])])
    stored = dict(r.get("accepted_locals") or {})
    tries = 0
    while r.get("status") == "REPAIR_REQUIRED" and tries < SUMMARY_REPAIRS:
        tries += 1
        refused = {x.get("local_id") for x in r.get("refused") or []} - {None, f"{p}d1"}
        if WHOLE_STEPS and model is not None and refused and "hint" not in asked:
            asked.append("hint")
            # every reason the kernel gave: its S0 problems and the error of each refused line (a field's enum too)
            reasons = (r.get("problems") or []) + [{"local_id": x.get("local_id"), "error": x.get("error")} for x in r.get("refused") or []]
            fixed = whole_hint(model, log, ph, whole, rq, [origin[n] for n in sorted(refused) if n in origin], reasons)
            by_agent = {origin[n].get("local_id"): n for n in refused if n in origin}
            for a in fixed:
                n = by_agent.get(a.get("local_id"))
                cl = claim_of(dict(a, rq_id=rq), local=n) if n else None
                if cl:
                    claims = [cl if x["local_id"] == n else x for x in claims]
                    refused.discard(n)
        left_out += [{"local_id": n, "why": "refused by the kernel"} for n in sorted(refused)]
        keep = [cl for cl in claims if cl["local_id"] not in stored and cl["local_id"] not in refused]
        claims = [cl for cl in claims if cl["local_id"] not in refused]
        r = submit(keep + [done([stored[cl["local_id"]] if cl["local_id"] in stored else cl["local_id"] for cl in claims])])
        stored.update(r.get("accepted_locals") or {})
    # the answer rows of this question, for the next withdrawal: the kept ones and the ones handed in now
    rows = [x for x in records.get(rq, []) if x["short"] in retained] if ph > 1 else []
    for cl in claims:
        if cl["local_id"] in stored and cl["local_id"] in origin:
            a = origin[cl["local_id"]]
            rows.append({"short": stored[cl["local_id"]], "agent_id": a.get("local_id"), "text": a.get("text"), "subject": a.get("subject"),
                         "based_on": list(a.get("based_on") or [])})
    records[rq] = rows
    whole.setdefault("summaries", []).append({"phase": ph, "rq": rq, "status": r.get("status"), "handed_in": len(claims), "left_out": left_out,
                                              "retained": len(retained), "asked": asked})
    log.event(arm="C", phase=ph, agent=agent, task=task, kind="SUMMARIZE", key=t.get("key"), outcome=r.get("status"), repairs=tries, broken_lines=0,
              parse_failure=False, explicit_empty=False, error=None, abandoned=False, lines_offered=len(claims) + 1, lines_stored=len(stored),
              left_out=len(left_out))
    if r.get("status") != "COMMITTED":
        rpc.call("audit_release", task_id=task)
        log.released(t.get("key", task))


def c_whole_worker(k: Kernel, agent: str, model: Model, log: Log, phase: list[int], stop: threading.Event, whole: dict) -> None:
    """The strong agent of run S1.2 (kinds EXTEND and SUMMARIZE): its zone in one call, the summaries from that answer."""
    rpc = k.connect(agent)
    try:
        while not stop.is_set() and log.active():
            t = rpc.call("audit_acquire", max_wait_ms=ACQUIRE_WAIT_MS)
            if t.get("status") != "DIRECTIVE":
                if t.get("status") == "DONE":
                    return
                if t.get("status") not in ("WAIT", "COMPLETE"):
                    raise RuntimeError(f"audit_acquire failed: {t}")
                pause = 0.05 if t.get("status") == "WAIT" else 0.2
                idle_wait(log, stop, pause)
                continue
            if t["kind"] == "EXTEND":
                whole_read(rpc, t, agent, model, log, phase[0], whole, stop)
            elif t["kind"] == "CHANGE":
                changes = whole.setdefault("version_changes", {}).setdefault(t["task_id"], {})
                whole_read(rpc, t, agent, model, log, phase[0], changes, stop)
            elif t["kind"] == "SUMMARIZE":
                whole_summary(rpc, t, agent, log, phase[0], whole, model)
            else:
                rpc.call("audit_release", task_id=t["task_id"])
    finally:
        rpc.close()


def run_arm_whole(model: Model, docs: dict[str, str], withdraw: dict, whole: dict, timeout_s: float = 1800, *, evidence: Evidence | None = None,
                  max_calls: int = MAX_CALLS, budget: Budget | None = None, chosen: list[dict] | None = None) -> dict:
    """Arm A of run S1.2: the same zone answer without the kernel. Its answer lines for each question become the single agent's
    claims, each quote the bytes of an observe it rests on, checked by the kernel's byte rule and repaired as the single agent's
    are; each withdrawal step is answered again by the same model, as in S1."""
    if timeout_s <= 0:
        raise ValueError("phase timeout must be positive")
    log = Log(max_calls, evidence, time.monotonic() + timeout_s)
    log.budget = budget
    paths = whole.get("document_paths") or {}
    observes = {v.get("local_id"): v for v in whole.get("graph_lines") or [] if v.get("kind") == "observe"}
    first = {}
    for q in QUESTIONS:
        out = []
        for a in whole.get("answers") or []:
            if a.get("rq_id") != q["id"]:
                continue
            if a.get("kind") == "answer_done":
                out.append(json.dumps({"kind": "done", "text": a.get("text") or ""}))
                continue
            names = a.get("based_on") if isinstance(a.get("based_on"), list) else []
            quotes = [{"report": paths.get(observes[b].get("doc_id"), observes[b].get("doc_id")), "exact_quote": observes[b].get("exact_quote")}
                      for b in names if b in observes]
            out.append(json.dumps({"kind": "claim", "local_id": a.get("local_id"), "text": a.get("text"), "quotes": quotes}))
        first[q["id"]] = "\n".join(out)
    res = {"arm": "A", "mode": "whole", "phase1": {"answers": {}}}
    answer_phases(log, model, docs, withdraw, single_corpus(docs), SINGLE_RULES, res, time.monotonic(), timeout_s, chosen, name="whole", role="WHOLE",
                  first=first)
    res.update(log.result())
    return res


# ------------------------------------------------------------------ the five measures

def cost_of(calls: list[dict]) -> dict:
    known = [c["cost_usd"] for c in calls if c["cost_usd"] is not None]
    tok = lambda k: sum((c["usage"] or {}).get(k) or 0 for c in calls)  # noqa: E731
    return {"calls": len(calls), "failed_calls": sum(1 for c in calls if not c["ok"]), "cost_usd_known": round(sum(known), 6),
            "cost_unknown_calls": sum(1 for c in calls if c["cost_usd"] is None), "input_tokens": tok("input"), "output_tokens": tok("output"),
            "reasoning_tokens": tok("reasoning"), "truncated_calls": sum(1 for c in calls if (c["usage"] or {}).get("finish_reason") == "length"),
            "prompt_chars": sum(c["prompt_chars"] for c in calls), "prompt_bytes": sum(c.get("prompt_bytes", 0) for c in calls),
            "latency_s": round(sum(c["latency_s"] for c in calls), 3)}


# The shortest quote that counts for the coverage of either arm: a shorter double-quoted span in a free-text answer is mostly a word.
QUOTE_MIN_CHARS = 15


def reports_quoted(answer, docs: dict[str, str]) -> list[str]:
    """The reports an answer cites by a quote found in their bytes, by one definition for both arms (Codex review d7d9a49, D09):
    arm C the quotes of its answer records, arm A every double-quoted span in its text; for both, a quote of at least
    QUOTE_MIN_CHARS characters (review of 4381fe7, finding 3: the same short quote counted for C only)."""
    if isinstance(answer, dict):
        quotes = [x["quote"] for cl in answer.get("claims", []) for x in cl.get("quotes", [])]
    elif isinstance(answer, str):
        quotes = re.findall(r'"([^"\n]+)"', answer)
    else:
        return []
    quotes = [q for q in quotes if len(q) >= QUOTE_MIN_CHARS]
    return sorted({path for path, text in docs.items() for q in quotes if q in text})


# What each withdrawal step tests (Gemini's review of e2464d8): 2A withdraws text the swarm has not quoted in any run so far, so arm C
# should spend no call on it; 2B withdraws a quote an answer rests on, so arm C reopens only what rests on it.
# 2A was chosen as text no earlier run had quoted; a run may quote it all the same (S1, S2: Codex's review of S1), and the step's
# observes in arm C's withdrawals say whether this one did.
WITHDRAWAL_ROLES = {"2A": "chosen as unquoted in earlier runs (a control: unquoted, it costs arm C no call); whether this run quoted it is "
                          "in the withdrawal's observes",
                    "2B": "quoted support: the first candidate an answer rests on, else one quoted in C"}


def graph_shape(wal: pathlib.Path) -> dict | None:
    """How far the builder's concepts join the swarm's records, from the WAL (`concepts_reused` counts only a proposed name the
    ontology already held, not a map_term to an earlier concept: Codex's and Gemini's reviews of 10A-12). A record's reports are its
    own document or those of the quotes it rests on."""
    if not wal.exists():
        return None
    records, maps, concepts, locals_ = {}, defaultdict(set), {}, {}
    for line in wal.read_text(encoding="utf-8").splitlines():
        p = json.loads(line).get("payload") or {}
        cmd, res = p.get("command") or {}, (p.get("outcome") or {}).get("result") or {}
        actor = str(p.get("actor", ""))
        if cmd.get("kind") == "submit" and actor.startswith("w"):
            for ln, rid in zip(cmd.get("lines") or [], res.get("accepted") or []):
                rid = rid.lstrip("@")[:16]
                locals_[(actor, cmd.get("directive"), ln.get("local_id"))] = rid
                based = [b[1:17] if b.startswith("@") else locals_.get((actor, cmd.get("directive"), b), "") for b in ln.get("based_on") or []]
                records[rid] = (ln.get("kind"), ln.get("doc_id"), based)
        elif actor.startswith("bu"):
            ops, results = cmd.get("operations") or [], res.get("results") or []
            for i, op in enumerate(ops[:res.get("accepted_operations") or 0]):
                if op.get("kind") == "map_term":
                    maps[op["concept"]].add(op["record"][:16])
                elif op.get("kind") == "propose_concept" and i < len(results) and results[i].get("id"):
                    concepts[results[i]["id"]] = op.get("name")

    def reports(rid: str) -> set:
        kind, doc, based = records.get(rid, (None, None, []))
        return {doc} if doc else {d for b in based for d in ([records[b][1]] if b in records and records[b][1] else [])}

    snapshot=wal.parent.parent/"ontology_evolution.json"
    current_inventory=False
    if snapshot.is_file():
        ontology=json.loads(snapshot.read_text(encoding="utf-8"))
        for concept in (ontology.get("ontology") or {}).get("concepts") or []:
            if isinstance(concept.get("id"),str) and isinstance((concept.get("definition") or {}).get("name"),str):
                concepts[concept["id"]]=concept["definition"]["name"]
        if isinstance(ontology.get("current_mappings"),list):
            current_inventory=True
            maps=defaultdict(set)
            for m in ontology["current_mappings"]:maps[m["concept"]].add(m["record"][:16])
    mapped = set().union(*maps.values()) if maps else set()
    sizes = sorted(((len(v),concepts.get(k),k) for k,v in maps.items()),key=lambda row:(row[0],row[1] is not None,row[1] or "",row[2]),reverse=True)
    return {"records": len(records), "records_with_concept": len(mapped & set(records)), "concepts_used": len(maps),
            "concepts_on_2_records": sum(1 for v in maps.values() if len(v) >= 2),
            "concepts_across_reports": sum(1 for v in maps.values() if len(set().union(*(reports(r) for r in v))) >= 2),
            "largest_concepts": [{"records":n,"name":name} for n,name,cid in sizes[:3]],
            "concept_names_unresolved":sum(concepts.get(cid) is None for cid in maps),
            "definition": "current stored associations from the kernel snapshot, after confirmed mapping moves" if current_inventory else "map_term operations the store accepted; a concept far larger than the rest may be a catch-all (10A-12, 10A-13)"}


def measures(a: dict, c: dict, docs: dict[str, str] | None = None) -> dict:
    def growth(calls: list[dict], roles: set[str]) -> dict:
        ordered = sorted(enumerate(calls), key=lambda pair: pair[1].get("sequence", pair[0]))
        seq = [x["prompt_chars"] for _, x in ordered if x["role"] in roles and x["phase"] == 1]
        return {f"call_{n}": (seq[n - 1] if len(seq) >= n else "N/A") for n in (1, 15, 30)} | {"max": max(seq, default="N/A"), "calls": len(seq)}

    def phase_cost(arm: dict, n: int = 2) -> dict:
        ph = arm.get(f"phase{n}")
        if not ph or ph.get("status") == "SKIPPED":
            return {"status": "SKIPPED", "reason": (ph or {}).get("reason", f"PHASE{n}_NOT_RUN"), "calls": None,
                    "cost_usd_known": None, "cost_unknown_calls": None, "input_tokens": None, "output_tokens": None,
                    "prompt_chars": None, "prompt_bytes": None, "latency_s": None}
        status = ph.get("status") if isinstance(ph.get("status"), str) else (ph.get("receipt") or {}).get("status")
        return dict(cost_of([x for x in arm["calls"] if x["phase"] == n]), status=status, step=ph.get("step"))

    phase2_cost = phase_cost

    def cited(arm: dict) -> dict:
        """How many of the run's reports each answer cites by a quote in their bytes (Gemini's checklist v2: all reports covered)."""
        out = {}
        for ph in sorted(k for k in arm if re.fullmatch(r"phase\d", k)):
            answers = (arm.get(ph) or {}).get("answers") or {}
            out[ph] = {q["id"]: (len(reports_quoted(answers[q["id"]], docs or {})) if q["id"] in answers else None) for q in QUESTIONS}
        return out

    # cards with records only: a stretch of link-check evidence is closed without a model and says nothing of the builder
    cards = [e for e in c["events"] if e.get("card") and "repairs" in e and "abandoned" in e and not e.get("empty")]
    tasks = [e for e in c["events"] if e.get("task") and e.get("kind") not in ("BUILD", "BUILDER") and "repairs" in e and "abandoned" in e]
    st = (c.get("phase1") or {}).get("status") or {}
    return {
        "builder": {"cards": len(cards), "empty_cards": sum(1 for e in c["events"] if e.get("card") and e.get("empty")),
                    "first_try": sum(1 for e in cards if e["first_try"]), "repairs": sum(e["repairs"] for e in cards),
                    "abandoned": sum(1 for e in cards if e["abandoned"]), "parse_failures": sum(1 for e in cards if e.get("parse_failure")),
                    **RUN_HOOK.measures(cards),
                    "by_model": {name: {"cards": sum(e.get("builder_model") == name for e in cards),
                                       "first_try": sum(e.get("builder_model") == name and e["first_try"] for e in cards),
                                       "repairs": sum(e["repairs"] for e in cards if e.get("builder_model") == name)}
                                 for name in sorted({e.get("builder_model") for e in cards if e.get("builder_model")})},
                    "stats": st.get("builder"), "links": st.get("links"),
                    "verify": {k: (st.get("dispatch") or {}).get(k) for k in ("confirmed", "rejected")}},
        "graph_timing": {"definition": "first observed reading_done and builder_caught_up in phase 1; may precede later investigations",
                         "sample_interval_s": STATUS_SAMPLE_S,
                         "first_observed_s": min((e["elapsed_s"] for e in c["events"] if e.get("status_sample")
                                                and e.get("phase") == 1 and e.get("reading_done") and e.get("builder_caught_up")),
                                               default=((c.get("phase1") or {}).get("wall_s") if st.get("reading_done") and st.get("builder_caught_up") else None)),
                         "terminal_s": (c.get("phase1") or {}).get("wall_s") if ((c.get("phase1") or {}).get("receipt") or {}).get("status") == "TERMINAL" else None},
        # a reading whose RELATE turn timed out is stored and checkpointed: committed
        "swarm_tasks": {"committed": sum(1 for e in tasks if e["outcome"] in ("COMMITTED", "RELATE_TIMED_OUT") and not e["abandoned"]),
                        "abandoned": [e["key"] for e in tasks if e["abandoned"]], "repairs": sum(e["repairs"] for e in tasks),
                        "refusals": sorted({e["error"] for e in tasks if e["error"]}), "parse_failures": sum(1 for e in tasks if e.get("parse_failure")),
                        "stopped": c.get("stopped")},
        # structural retention for the owner's aim of a graph built from as many correct lines as possible (2026-10-23): distinct
        # local ids per task offered and stored; stored is not shown correct or sufficient (Codex)
        "lines_stored": {kind: {"offered": sum(e.get("lines_offered") or 0 for e in tasks if e.get("kind") == kind),
                                "stored": sum(e.get("lines_stored") or 0 for e in tasks if e.get("kind") == kind)}
                         for kind in sorted({e.get("kind") for e in tasks if e.get("kind")})},
        "reports_cited": {"of": len(docs) if docs is not None else None, "definition": "reports whose bytes hold a quote the answer cites",
                          "A": cited(a), "C": cited(c)},
        "context_growth_chars": {"A": growth(a["calls"], {"WORKER", "SINGLE"}), "C": growth(c["calls"], {"EXTEND", "INVESTIGATE", "VERIFY_LINK", "RESOLVE_CONFLICT", "REQUEST"})},
        "phase2": {"A": phase2_cost(a), "C": phase2_cost(c)},
        **{f"phase{n}": {"A": phase_cost(a, n), "C": phase_cost(c, n)} for n in range(3, 6) if f"phase{n}" in a or f"phase{n}" in c},
        "total": {"A": cost_of(a["calls"]), "C": cost_of(c["calls"])},
        "worker_errors": [e for e in c["events"] + a["events"] if e.get("outcome") == "ERROR"],
        # submissions whose answer was lost (stored or not: read the WAL receipt) and errors after a stop (Codex's review of 77a803e, R02)
        "ack_unknown": [e for e in c["events"] if e.get("outcome") == "ACK_UNKNOWN"],
        "closing_lines_cut": sum(1 for e in a.get("events") or [] if e.get("kind") == "CLOSING_LINE_CUT"), "model_refusals": [e for e in c["events"] if e.get("outcome") == "MODEL_REFUSED"],
        "errors_after_stop": [e for e in c["events"] + a["events"] if e.get("outcome") == "ERROR_AFTER_STOP"],
        "semantic_check": "manual and blind: answers_blind.md by checklist.md; the variant key is in answers_key.json",
        "strategies": STRATEGIES,
        "withdrawal_roles": WITHDRAWAL_ROLES,
        "phase2_max_calls": PHASE2_MAX_CALLS,
        "phase2_cap_rule": PHASE2_CAP_RULE,
        "acquire_wait_ms": ACQUIRE_WAIT_MS,
        "repairs": {"submission": REPAIRS, "answer": SUMMARY_REPAIRS},
    }


def answers_md(a: dict, c: dict) -> tuple[str, dict]:
    """The answers of both arms under neutral labels in a random order (blind grading), and the key to the labels. Against a single
    agent or a team without the kernel both arms are written alike, claims and quotes only: a stance or an outcome line would tell
    the kernel's arm."""
    plain = a.get("mode") in ("single", "team", "whole")

    def text_c(ans: dict | str | None) -> str:
        if isinstance(ans, str):
            return ans
        if not ans:
            return "(none)"
        out = [] if plain else [f"outcome: {ans['outcome']}"] + ([f"reason: {ans['reason']}"] if ans.get("reason") else [])
        for cl in ans["claims"]:
            tags = [f"stance: {cl['stance']}"] if cl.get("stance") and not plain else []
            tags += [f"as of: {cl['as_of']}"] if cl.get("as_of") and not plain else []
            out.append(f"- {cl['text']}" + (f" [{'; '.join(tags)}]" if tags else ""))
            out += [f"  - [{x['report']}] \"{x['quote']}\"" for x in cl["quotes"]]
        if ans.get("unsettled"):
            out.append(f"Not settled: {ans['unsettled']}")
        return "\n".join(out)

    order = ["A", "C"]
    if secrets.randbelow(2):
        order.reverse()
    key = {"Variant 1": order[0], "Variant 2": order[1]}
    if a.get("mode") == "frozen":
        key = {"Variant 1": "C"}
    out = ["# Pilot: answers for the blind manual check (grade by checklist.md)", ""]
    w = c.get("withdrawn")
    for x in (w if isinstance(w, list) else [w] if w else []):
        out += [f"Withdrawn in phase {x.get('phase', 2)} ({x.get('step', '2')}): \"{x['quote']}\" ({x['report']})", ""]
    phases = ["phase1"] + sorted({k for k in list(a) + list(c) if re.fullmatch(r"phase[2-9]", k)})
    for ph in phases:
        for q in QUESTIONS:
            out += [f"## {ph}, {q['id']}: {q['text']}", ""]
            for label, arm in key.items():
                body = text_c(((a if arm == "A" else c).get(ph) or {}).get("answers", {}).get(q["id"]))
                out += [f"### {label}", "", body, ""]
    return "\n".join(out), key
