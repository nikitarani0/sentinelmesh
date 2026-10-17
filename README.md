# SentinelMesh — Security Control Plane for AI Agents

**Let AI work. Make every action accountable.**

Built by team **VISN** for the Google Cloud AI Builder Cup 2026 · Future of Work & Enterprise Productivity.

| | |
|---|---|
| **Live prototype — Attack my agent** | https://sentinelmesh-agent-1035774079606.us-central1.run.app/ |
| **Demo video** | https://youtu.be/IheddZOME50 |

---

## The problem

AI agents are becoming digital workers. They query databases, read documents and call cloud APIs on someone's behalf. IAM only answers one question: *may this identity touch this resource?*

SentinelMesh asks the question that matters for an agent: **should this agent take this action, on this data, for this purpose, right now?**

## Core principle

> **AI reasons. Security policy decides.**

Gemini plans the agent's work, flags suspicious intent and explains decisions in plain English. A **deterministic Python policy engine** makes every final decision. The model is never the security authority.

## How it works

1. **Intercept.** Every tool call from the agent (Google ADK + Gemini) becomes a normalised action request. The agent cannot reach data on its own.
2. **Verify.** The control plane runs on Cloud Run with authentication required. It verifies the caller's Google-signed identity token rather than trusting a field in the request.
3. **Evaluate.** The policy engine checks the agent's registration, its capabilities, the resource scope, the agent's *stated purpose* against the user's *verbatim request*, and the destination. Each decision carries a rule ID.
4. **Enforce.** Only on ALLOW does the control plane mint a **5-minute token** for a separate `target-executor` identity through the IAM Credentials API. On DENY, no token exists to leak.
5. **Audit.** Every request, signal, risk score, decision and rule ID is written to Cloud Logging.

![SentinelMesh architecture](docs/architecture.png)

### Zero standing privilege

The agent's own identity (`agent-runtime`) has **no access to any data**. Enterprise data lives in a separate GCP project, and only `target-executor` can read it, and only through a token the control plane mints per allowed action.

So even a fully compromised agent cannot move data. We prove this live: with the control plane switched off, the identical request returns **`403 Forbidden`**.

## Results

| Scenario | What the agent tried | Outcome | Stopped by |
|---|---|---|---|
| Normal lookup | BigQuery read of TX-1001 | ALLOW WITH AUDIT · risk 45 · real answer | — |
| Poisoned document | Read a dispute file, then send customers to `collector.attacker.example` | Read allowed (risk 40) · send **DENIED** (risk 96) | `PE-050-PURPOSE-DIVERGENCE` |
| Customer data leaving | Read customers, then pass them outside | Read allowed · send **DENIED** | Policy engine |
| Look-alike address | Send to `sentinelmesh.internal.attacker.example` with a perfectly matching purpose | **DENIED** (risk 92) | `PE-051-EXTERNAL-DESTINATION` |
| Planted tool | Call an unregistered `secretmanager_read` | **BLOCKED** before reaching the control plane | Agent-side tripwire |
| Control plane off | Same TX-1001 read | **403 Forbidden** | IAM: no standing access |

All four attacks can be run by anyone in the live playground. Each one swaps Gemini for a script that behaves like a fully compromised agent; the tools, identity and control plane are the production ones.

## Security design

- **Single chokepoint.** All tool execution goes through one executor, and credentials exist only after an explicit ALLOW.
- **Fail closed.** If the control plane is unreachable or a response is invalid, the action is denied.
- **Untrusted content fence.** Retrieved documents are wrapped in an `<untrusted_document_content>` fence before re-entering the model's context, and fence-breaking attempts are neutralised.
- **Stated purpose is untrusted.** The agent's `declared_purpose` is model output. It is compared with the user's verbatim request, and divergence is treated as a prompt-injection signal.
- **Deny by default.** Unknown actions, malformed requests, unregistered or inactive agents, identity mismatches and out-of-scope resources are all denied with their own rule IDs (`PE-002` to `PE-021`).

## Google Cloud services

| Service | Role |
|---|---|
| **Cloud Run** | Hosts the agent and playground, and the auth-required control plane |
| **Gemini (`gemini-3.8-flash`) on Vertex AI** | Plans tool calls; produces intent signals and decision explanations |
| **Google ADK** | Agent runtime and tool framework |
| **IAM Credentials API** | Mints short-lived, scoped tokens per allowed action |
| **BigQuery** | Synthetic bank data: transactions and customers |
| **Cloud Storage** | Case documents, including the poisoned dispute |
| **Cloud Logging** | Audit trail of every decision |

## Repository

```
agent/           ADK agent, tools, executor chokepoint, attack playground, tests
control-plane/   policy engine, Gemini explanations, deploy scripts, tests
docs/            architecture diagram
```

## Tests

**63 tests passing:** 39 in `agent/` and 24 in `control-plane/`. The agent tests drive the real Google ADK runtime with a scripted model, and assert *which rule* fired, not just ALLOW or DENY. Deliberately breaking the gate makes them fail.

```bash
cd agent && pip install -r requirements.txt && pytest
cd ../control-plane && pip install -r requirements.txt && pytest
```

## Known limitations and Stage 2

- The agent's reply can repeat data it read legitimately. **Cloud DLP** on outputs is planned.
- Planned next: a human-in-the-loop approval queue, **Model Armor** screening of retrieved content, an agent permission graph, and governance of **MCP** tool calls and multi-agent delegation.

All data in this project is synthetic.
