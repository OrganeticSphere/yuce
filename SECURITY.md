# Security

## Reporting a vulnerability

Please report it privately through GitHub: on this repository, **Security → Report a vulnerability**. Do not open a public
issue for it. We aim to answer within seven days; a confirmed issue gets a fix and an advisory.

## Supported versions

| Version | Supported |
|---|---|
| 0.1.x | yes |

## The trust model of the audit server

* **Agents are untrusted.** Every line an agent submits is checked before it is recorded: a quote must occur byte for byte in
  the section leased to that agent, a claim may rest only on live records, ids and sizes are bounded. The kernel does not
  judge what a claim means.
* **Each agent has its own token** from a subjects file you write (at least 16 bytes each). The token's role (`swarm`,
  `builder`, `owner`) decides which tools the agent sees and may call; only the owner can revoke, read records and close a
  run. Keep the subjects file private; the journal does not hold the tokens.
* **`sbgk mcp-bridge` keeps the token out of the model's prompt**: the bridge adds it to every message from its own
  environment. Give each agent a restricted bridge: `--allow-tools`, `--agent-id` and its own token. Without
  `--allow-tools` the bridge passes every tool and the server's role check is the only filter. The bridge refuses `shutdown`
  unless started with `--allow-shutdown`.
* **No TLS.** The servers listen on loopback by default; a non-loopback `--listen` address needs `--allow-remote`. For
  agents on other machines, put the server behind a tunnel or a TLS proxy.
* **The journal is tamper-evident, not tamper-proof.** A changed byte is refused on start and by `sbgk audit-verify`, but a
  writer of the whole journal can rebuild its chain. Keep the terminal receipt outside the writer's reach and check against
  it (`sbgk audit-verify --expect receipt.json`).
* **The kernel calls no model.** Prompts and corpus text reach a model provider only through the agents you run; the
  benchmark runner sends them to the provider you choose (DeepSeek, Claude through Claude Code) and reads a DeepSeek key from
  `DEEPSEEK_API_KEY` only.
* **The inspector page** (`examples/revoke-and-replay/inspector.html`) only displays a report file; its content security
  policy forbids every network request, and it renders the report as text.

## Out of scope

A compromised host, a compromised model provider, and the meaning of what agents write (see
[LIMITATIONS.md](LIMITATIONS.md)).
