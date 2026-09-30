"""
SentinelMesh Stage 1 deterministic policy engine.

INVARIANTS:
  1. Pure. No I/O, no clock, no randomness. Same input -> same output.
  2. No model output reaches a decision. Gemini writes `explanation` only.
  3. Fail closed. Unknown action, malformed input, unhandled error -> DENY.
  4. Gates run before score.
  5. Agent-supplied classification is MONOTONIC: it may raise severity, never lower it.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import IntEnum
from typing import Any, Mapping
from urllib.parse import urlparse

POLICY_VERSION = "2026-09-30-stage1"


class Decision(IntEnum):
    ALLOW = 0
    ALLOW_WITH_AUDIT = 1
    REQUIRE_APPROVAL = 2
    DENY = 3

    @property
    def wire(self) -> str:
        return self.name

    @property
    def executes(self) -> bool:
        return self in (Decision.ALLOW, Decision.ALLOW_WITH_AUDIT)


@dataclass(frozen=True)
class RegisteredAgent:
    agent_id: str
    bound_identities: frozenset[str]
    capabilities: Mapping[str, tuple[str, ...]]
    status: str = "ACTIVE"


REGISTRY: dict[str, RegisteredAgent] = {
    "fraud-investigator-01": RegisteredAgent(
        agent_id="fraud-investigator-01",
        bound_identities=frozenset({
            "agent-runtime@sentinelmesh-cp-dev.iam.gserviceaccount.com",
        }),
        capabilities={
            "bigquery.read": ("sentinelmesh-target.finance.",),
            "storage.read": ("gs://sentinelmesh-target-docs/",),
            "external.send": ("https://",),
        },
    ),
}

KNOWN_ACTIONS = frozenset({"bigquery.read", "storage.read", "external.send"})

SEVERITY = {"public": 0, "unclassified": 0, "internal": 1, "pii": 2, "financial-pii": 3}
AUDIT_CLASSES = frozenset({"pii", "financial-pii"})
UNTRUSTED_PREFIXES = ("gs://sentinelmesh-target-docs/incoming/",)
INTERNAL_HOST_SUFFIXES = (".internal",)


def server_classification(action: str, resource_id: str) -> str:
    if action == "bigquery.read" and ".finance." in resource_id:
        return "financial-pii"
    if action == "storage.read" and resource_id.startswith(UNTRUSTED_PREFIXES):
        return "internal"
    return "public"


def server_destination(action: str, resource_id: str) -> str:
    if action != "external.send":
        return "internal"
    host = (urlparse(resource_id).hostname or "").lower()
    if not host:
        return "external"
    return "internal" if host.endswith(INTERNAL_HOST_SUFFIXES) else "external"


def is_untrusted_document(action: str, resource_id: str) -> bool:
    return action == "storage.read" and resource_id.startswith(UNTRUSTED_PREFIXES)


EGRESS_VERBS = frozenset({
    "send", "sends", "email", "emails", "mail", "share", "shares", "upload",
    "uploads", "forward", "forwards", "export", "exports", "transmit",
    "transmits", "post", "publish", "deliver", "attach", "sync",
})

EXTERNAL_MARKERS = frozenset({
    "external", "outside", "third-party", "vendor", "consultant", "partner",
    "collector", "offsite",
})


def _tokens(text: str) -> set[str]:
    out, buf = set(), []
    for ch in (text or "").lower():
        if ch.isalnum() or ch == "-":
            buf.append(ch)
        elif buf:
            out.add("".join(buf))
            buf = []
    if buf:
        out.add("".join(buf))
    return out


def purpose_diverges(declared_purpose: str, source_context: str) -> bool:
    """If the user's own words never authorised egress, external.send is ungrounded."""
    src = _tokens(source_context)
    if src & EGRESS_VERBS:
        return False
    dp = _tokens(declared_purpose)
    return bool(dp & EGRESS_VERBS) or bool(dp & EXTERNAL_MARKERS)


@dataclass(frozen=True)
class PolicyResult:
    decision: Decision
    risk_score: int
    rule_id: str
    fired_rules: tuple[str, ...]
    effective_classification: str
    effective_destination: str
    policy_version: str = POLICY_VERSION

    @property
    def executes(self) -> bool:
        return self.decision.executes


RISK = {
    "PE-002-UNKNOWN-ACTION": 100,
    "PE-003-MALFORMED-REQUEST": 100,
    "PE-010-AGENT-NOT-REGISTERED": 100,
    "PE-011-AGENT-INACTIVE": 100,
    "PE-012-IDENTITY-BINDING-MISMATCH": 100,
    "PE-020-CAPABILITY-NOT-GRANTED": 95,
    "PE-021-RESOURCE-OUT-OF-SCOPE": 90,
    "PE-050-PURPOSE-DIVERGENCE": 96,
    "PE-051-EXTERNAL-DESTINATION": 92,
    "PE-120-SENSITIVE-DATA-AUDIT": 45,
    "PE-121-UNTRUSTED-DOCUMENT-AUDIT": 40,
    "PE-100-BASELINE-ALLOW": 15,
    "PE-500-INTERNAL-ERROR": 100,
}

STATIC_EXPLANATIONS = {
    "PE-002-UNKNOWN-ACTION": "Action type is not modelled by policy. Denied by default.",
    "PE-003-MALFORMED-REQUEST": "Request is missing required fields. Denied by default.",
    "PE-010-AGENT-NOT-REGISTERED": "Calling agent is not present in the registry.",
    "PE-011-AGENT-INACTIVE": "Calling agent is registered but not active.",
    "PE-012-IDENTITY-BINDING-MISMATCH": "Caller identity does not match the registered binding for this agent.",
    "PE-020-CAPABILITY-NOT-GRANTED": "This agent has no capability for the requested action.",
    "PE-021-RESOURCE-OUT-OF-SCOPE": "Resource lies outside the agent's permitted scope for this action.",
    "PE-050-PURPOSE-DIVERGENCE": "The stated purpose implies sending data outward, but the originating user request did not authorise any egress. Treated as an ungrounded instruction.",
    "PE-051-EXTERNAL-DESTINATION": "Destination resolves outside the organisational boundary.",
    "PE-120-SENSITIVE-DATA-AUDIT": "Sensitive data access permitted and recorded for audit.",
    "PE-121-UNTRUSTED-DOCUMENT-AUDIT": "Read of untrusted document content permitted and recorded for audit.",
    "PE-100-BASELINE-ALLOW": "Action is within the agent's authorised scope.",
    "PE-500-INTERNAL-ERROR": "Policy evaluation failed. Denied by default.",
}


def evaluate(req: Mapping[str, Any], caller_email: str) -> PolicyResult:
    """Single entry point. Returns a decision; never raises."""
    fired: list[str] = []

    def terminal(rule: str, decision: Decision,
                 cls: str = "unknown", dest: str = "unknown") -> PolicyResult:
        fired.append(rule)
        return PolicyResult(
            decision=decision,
            risk_score=RISK.get(rule, 100),
            rule_id=rule,
            fired_rules=tuple(fired),
            effective_classification=cls,
            effective_destination=dest,
        )

    try:
        agent_id = req.get("agent_id")
        action = req.get("action")
        resource_id = req.get("resource_id")

        if not agent_id or not action or not resource_id:
            return terminal("PE-003-MALFORMED-REQUEST", Decision.DENY)

        if action not in KNOWN_ACTIONS:
            return terminal("PE-002-UNKNOWN-ACTION", Decision.DENY)

        agent = REGISTRY.get(agent_id)
        if agent is None:
            return terminal("PE-010-AGENT-NOT-REGISTERED", Decision.DENY)
        if agent.status != "ACTIVE":
            return terminal("PE-011-AGENT-INACTIVE", Decision.DENY)
        if caller_email.lower() not in {i.lower() for i in agent.bound_identities}:
            return terminal("PE-012-IDENTITY-BINDING-MISMATCH", Decision.DENY)

        if action not in agent.capabilities:
            return terminal("PE-020-CAPABILITY-NOT-GRANTED", Decision.DENY)
        prefixes = agent.capabilities[action]
        if not prefixes or not resource_id.startswith(tuple(prefixes)):
            return terminal("PE-021-RESOURCE-OUT-OF-SCOPE", Decision.DENY)

        agent_cls = str(req.get("data_classification") or "public").lower()
        srv_cls = server_classification(action, resource_id)
        cls = agent_cls if SEVERITY.get(agent_cls, 0) > SEVERITY.get(srv_cls, 0) else srv_cls

        agent_dest = str(req.get("destination") or "external").lower()
        srv_dest = server_destination(action, resource_id)
        dest = "external" if "external" in (agent_dest, srv_dest) else "internal"

        if action == "external.send":
            if purpose_diverges(req.get("declared_purpose", ""),
                                req.get("source_context", "")):
                return terminal("PE-050-PURPOSE-DIVERGENCE", Decision.DENY, cls, dest)
            if dest == "external":
                return terminal("PE-051-EXTERNAL-DESTINATION", Decision.DENY, cls, dest)

        if cls in AUDIT_CLASSES:
            return terminal("PE-120-SENSITIVE-DATA-AUDIT", Decision.ALLOW_WITH_AUDIT, cls, dest)
        if is_untrusted_document(action, resource_id):
            return terminal("PE-121-UNTRUSTED-DOCUMENT-AUDIT", Decision.ALLOW_WITH_AUDIT, cls, dest)

        return terminal("PE-100-BASELINE-ALLOW", Decision.ALLOW, cls, dest)

    except Exception:  # noqa: BLE001 -- fail closed
        return terminal("PE-500-INTERNAL-ERROR", Decision.DENY)
