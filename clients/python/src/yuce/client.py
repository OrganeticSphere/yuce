"""One authenticated connection to `sbgk audit-serve`, its MCP tools as methods. Standard library only.

The server speaks newline-delimited JSON-RPC over TCP. An agent is whoever holds a token from the server's subjects file: the role of
that token decides which tools answer, and the server, not the client, fixes the agent's identity.

What a tool answers comes back as a dict, a refusal of the kernel included: `audit_submit` answering `REPAIR_REQUIRED` is an ordinary
reply, not an exception. An exception means the call itself failed: the token, the role, the connection or the time.
"""
from __future__ import annotations

import json
import socket
import time
from typing import Any, Callable, Iterable

PROTOCOL_VERSION = "2025-06-18"
UNAUTHORIZED = -32001
FORBIDDEN = -32003
# the longest wait the server grants one audit_acquire
MAX_WAIT_MS = 30_000
DEFAULT_TIMEOUT_S = 60.0
MAX_RESPONSE_BYTES = 16 * 1024 * 1024


class YuceError(Exception):
    """A call that failed. Refusals of the kernel are replies, see the module's text."""


class RpcError(YuceError):
    """The server answered with a JSON-RPC error: `code` is UNAUTHORIZED, FORBIDDEN or a standard JSON-RPC code."""

    def __init__(self, code: int, message: str):
        super().__init__(f"{code}: {message}")
        self.code, self.message = code, message


class ConnectionClosed(YuceError):
    """The connection ended, or its answers stopped making sense. Open a new `Client`."""


def _split(address: str) -> tuple[str, int]:
    host, colon, port = address.rpartition(":")
    if not colon or not host or not port.isdigit():
        raise ValueError(f"an address is host:port, not {address!r}")
    return host.strip("[]"), int(port)


class Client:
    """One agent's connection. Use one per agent and one thread at a time; `with Client(...) as agent:` closes it.

    `timeout_s` bounds each call. A call that times out raises `TimeoutError` and may still have reached the server, so do not assume
    it did nothing: the client skips its late answer, and `audit_acquire` tells what is left to do.
    """

    def __init__(self, address: str, token: str, *, timeout_s: float = DEFAULT_TIMEOUT_S):
        if timeout_s <= 0:
            raise ValueError("timeout_s must be positive")
        self.timeout_s = timeout_s
        self._buffer = b""
        self._next_id = 0
        self._socket: socket.socket | None = socket.create_connection(_split(address), timeout=timeout_s)
        try:
            hello = self._rpc("initialize", {"protocolVersion": PROTOCOL_VERSION, "capabilities": {}, "auth_token": token}, timeout_s)
        except BaseException:
            self.close()
            raise
        self.subject: dict = hello.get("subject") or {}
        self.server: dict = hello.get("serverInfo") or {}
        self.instructions: str = hello.get("instructions") or ""

    def __enter__(self) -> "Client":
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    def close(self) -> None:
        """Close the connection. The run goes on; `close_run` is what ends a run."""
        sock, self._socket = self._socket, None
        if sock is None:
            return
        try:
            sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        sock.close()

    def _rpc(self, method: str, params: dict, timeout_s: float) -> dict:
        if self._socket is None:
            raise ConnectionClosed("this client is closed")
        deadline = time.monotonic() + timeout_s

        def remaining() -> float:
            seconds = deadline - time.monotonic()
            if seconds <= 0:
                raise TimeoutError(f"{method}: no answer in {timeout_s} s")
            return min(seconds, timeout_s)  # the sum can round above the bound when the clock has not moved

        self._next_id += 1
        request = json.dumps({"jsonrpc": "2.0", "id": self._next_id, "method": method, "params": params})
        try:
            self._socket.settimeout(remaining())
            self._socket.sendall((request + "\n").encode("utf-8"))
            reply = self._read_reply(remaining)
        except TimeoutError:  # socket.timeout is this class since Python 3.10
            raise TimeoutError(f"{method}: no answer in {timeout_s} s") from None
        except OSError as error:
            self.close()
            raise ConnectionClosed(f"{method}: {error}") from None
        if "error" in reply:
            error = reply["error"] or {}
            raise RpcError(error.get("code", 0), error.get("message", ""))
        return reply.get("result") or {}

    def _read_reply(self, remaining: Callable[[], float]) -> dict:
        while True:
            reply = self._read_line(remaining)
            answered = reply.get("id")
            # the late answer to an earlier call that timed out is skipped, not taken for this one
            if isinstance(answered, int) and answered < self._next_id:
                continue
            # the server answers a message it cannot read with no id
            if answered != self._next_id and not (answered is None and "error" in reply):
                self.close()
                raise ConnectionClosed("the answer has another id")
            return reply

    def _read_line(self, remaining: Callable[[], float]) -> dict:
        while b"\n" not in self._buffer:
            self._socket.settimeout(remaining())
            chunk = self._socket.recv(65536)
            if not chunk:
                self.close()
                raise ConnectionClosed("the server closed the connection")
            self._buffer += chunk
            if len(self._buffer) > MAX_RESPONSE_BYTES:
                self.close()
                raise ConnectionClosed(f"an answer over {MAX_RESPONSE_BYTES} bytes")
        line, self._buffer = self._buffer.split(b"\n", 1)
        try:
            reply = json.loads(line.decode("utf-8"))
        except ValueError:
            self.close()
            raise ConnectionClosed("the server sent something that is not JSON") from None
        if not isinstance(reply, dict):
            self.close()
            raise ConnectionClosed("the server's answer is not an object")
        return reply

    def call(self, tool: str, *, timeout_s: float | None = None, **arguments: Any) -> dict:
        """Any tool by its name, for example `call("audit_status")`: what the methods below do."""
        result = self._rpc("tools/call", {"name": tool, "arguments": arguments}, timeout_s or self.timeout_s)
        return result.get("structuredContent") or {}

    def tools(self) -> list[dict]:
        """The tools this agent's role may call, with their input schemas."""
        return self._rpc("tools/list", {}, self.timeout_s).get("tools") or []

    def ping(self) -> None:
        self._rpc("ping", {}, self.timeout_s)

    # ---- a reader (role swarm)

    def acquire(self, max_wait_ms: int = 0, *, compact: bool = False) -> dict:
        """The most urgent free work. `status` is DIRECTIVE (with `task_id`, `prompt`, `local_id_prefix`), WAIT, COMPLETE or DONE."""
        if not 0 <= max_wait_ms <= MAX_WAIT_MS:
            raise ValueError(f"max_wait_ms is 0 to {MAX_WAIT_MS}")
        return self.call("audit_acquire", timeout_s=self.timeout_s + max_wait_ms / 1000, max_wait_ms=max_wait_ms, compact=compact)

    def submit(self, task_id: str, lines: Iterable[dict], *, compact: bool = False) -> dict:
        """The lines of a directive. `status` is COMMITTED, STALE_TASK, or REPAIR_REQUIRED: send only the lines after the accepted ones."""
        return self.call("audit_submit", task_id=task_id, lines=list(lines), compact=compact)

    def renew(self, task_id: str) -> dict:
        return self.call("audit_renew", task_id=task_id)

    def release(self, task_id: str, *, timed_out: bool = False) -> dict:
        """Give a task back unfinished. `timed_out=True` reports that the model ran out of time."""
        return self.call("audit_release", task_id=task_id, timed_out=timed_out)

    # ---- a builder (role builder)

    def next_card(self) -> dict:
        return self.call("audit_next_card")

    def submit_ops(self, card_id: str, ops: Iterable[dict]) -> dict:
        return self.call("audit_submit_ops", card_id=card_id, ops=list(ops))

    def builder_failure(self, card_id: str, attempt_id: str, reason: str) -> dict:
        return self.call("audit_builder_failure", card_id=card_id, attempt_id=attempt_id, reason=reason)

    # ---- the owner (role owner)

    def status(self, *, ontology: bool = False, telemetry: bool = False) -> dict:
        """Counters and the roots of the run."""
        return self.call("audit_status", ontology=ontology, telemetry=telemetry)

    def record(self, record: str) -> dict:
        """One record with its basis and whether it is still grounded."""
        return self.call("audit_record", record=record)

    def dependents(self, record: str | None = None, *, doc_id: str | None = None, start: int | None = None, end: int | None = None,
                   limit: int | None = None) -> dict:
        """Every record resting on a record, or on the quotes of a document (in a byte range of its current version), by depth."""
        return self.call("audit_dependents", **_given(record=record, doc_id=doc_id, start=start, end=end, limit=limit))

    def active_claims(self, doc_id: str | None = None, *, limit: int | None = None) -> dict:
        """The claims that stand now; claims of equal text are one row, with the documents of the quotes under them."""
        return self.call("audit_active_claims", **_given(doc_id=doc_id, limit=limit))

    def diff(self, from_point: int, to_point: int | None = None, *, limit: int | None = None) -> dict:
        """What changed between two points of the journal (a point = a number of frames): records added, fallen, risen; texts withdrawn."""
        return self.call("audit_diff", **_given(**{"from": from_point, "to": to_point, "limit": limit}))

    def fallen(self, since: int | None = None, *, limit: int | None = None) -> dict:
        """What fell, and on what it stood: the gone quotes without their text, the quotes that stand, twins, what to reread.
        `since` is the point a withdrawal answered: only what stood then."""
        return self.call("audit_fallen", **_given(since=since, limit=limit))

    def revoke(self, record: str) -> dict:
        """Withdraw an observation: its source no longer holds, and what rested on it loses that ground. The answer names the
        point before it (`since`) and how many records fell: `fallen(since)` gives the report."""
        return self.call("audit_revoke", record=record)

    def withdraw_text(self, doc_id: str, exact_quote: str) -> dict:
        """Withdraw text of a document, quoted or not: stored quotes overlapping it go with it, and new ones are refused."""
        return self.call("audit_withdraw_text", doc_id=doc_id, exact_quote=exact_quote)

    def links(self, status: str | None = None) -> dict:
        return self.call("audit_links", **({} if status is None else {"status": status}))

    def link_status(self, link: str, status: str, basis: Iterable[str]) -> dict:
        return self.call("audit_link_status", link=link, status=status, basis=list(basis))

    def concept_status(self, concept: str, status: str) -> dict:
        return self.call("audit_concept_status", concept=concept, status=status)

    def terminal_receipt(self) -> dict:
        """The receipt of a finished run, to keep where the journal's writer cannot change it. NOT_COMPLETE until then."""
        return self.call("audit_terminal_receipt")

    def close_run(self) -> dict:
        """End a finished run: agents are told DONE and nothing more is accepted. It is not the same as `close`."""
        return self.call("audit_close")

    def shutdown(self) -> None:
        """Stop the server."""
        self._rpc("shutdown", {}, self.timeout_s)


def _given(**arguments: Any) -> dict:
    """The arguments that were given: a tool reads a missing one as its default."""
    return {k: v for k, v in arguments.items() if v is not None}


def observe(local_id: str, doc_id: str, exact_quote: str, *, terms: Iterable[str] | None = None) -> dict:
    """A quote from a document, to be found there byte for byte."""
    line = {"kind": "observe", "local_id": local_id, "doc_id": doc_id, "exact_quote": exact_quote}
    return line if terms is None else {**line, "terms": list(terms)}


def claim(local_id: str, text: str, subject: str, based_on: Iterable[str], *, stance: str = "reported", **fields: Any) -> dict:
    """A claim resting on quotes, all of them required."""
    return {"kind": "claim", "local_id": local_id, "text": text, "subject": subject, "stance": stance, "based_on": list(based_on), **fields}
