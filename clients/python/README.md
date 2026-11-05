# yuce

A thin Python client of the YuCe audit server (`sbgk audit-serve`): one authenticated connection per agent, the server's tools as methods.
Standard library only, Python 3.10 or newer.

It talks to a running server. The kernel, its checks and its journal stay in the server: see the
[main README](https://github.com/OrganeticSphere/yuce#an-audit-server-on-the-open-corpus) for how to start one.

## Install

From a clone of the repository:

```bash
pip install ./clients/python
```

Or from the wheel attached to a [release](https://github.com/OrganeticSphere/yuce/releases). The package is not on PyPI.

## A reader

```python
import yuce

with yuce.Client("127.0.0.1:8787", token="replace-with-a-secret-1") as agent:
    task = agent.acquire(max_wait_ms=10_000)
    if task["status"] == "DIRECTIVE":
        p = task["local_id_prefix"]
        reply = agent.submit(task["task_id"], [
            yuce.observe(p + "o1", "the document id", "a quote, byte for byte", terms=["a term"]),
            yuce.claim(p + "c1", "What the quote says.", "a subject", [p + "o1"]),
        ])
        print(reply["status"])
```

`task["prompt"]` is the directive to give a model: it holds the section to read and the form of the lines to send back.
[examples/reader.py](examples/reader.py) is the whole loop with your model in one function.

## The owner

```python
with yuce.Client("127.0.0.1:8787", token="replace-with-a-secret-4") as owner:
    print(owner.status())
    owner.revoke(quote_id)                     # the source no longer holds
    print(owner.record(claim_id)["grounded"])  # False: the claim rested on that quote
```

## What comes back

A tool's answer is a dict, and a refusal of the kernel is an answer: `submit` gives `REPAIR_REQUIRED` with the reason, and you send only the
lines after the accepted ones. An exception means the call itself failed:

| Exception | Meaning |
|---|---|
| `yuce.RpcError` | the server refused the call: `code` is `yuce.UNAUTHORIZED` (the token), `yuce.FORBIDDEN` (the role's tools) or a JSON-RPC code |
| `TimeoutError` | no answer within `timeout_s`, 60 s by default. The call may still have reached the server |
| `yuce.ConnectionClosed` | the connection ended. Open a new `Client` |

Use one `Client` per agent and one thread at a time. Every tool has its method; `agent.call("audit_status")` calls one by name, and
`agent.tools()` lists what this agent's role may call. The role comes from the token, and the server decides it: `agent.subject` shows it.

The connection is plain TCP, as the server has no TLS: the token travels unencrypted, so keep the server on loopback or inside a network
you trust.
