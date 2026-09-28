"""
The enforcement chokepoint. The ONLY path from a tool to a GCP resource.

Invariant: handlers RECEIVE credentials; they never create them.
Credentials are created in exactly one place, _credentials_for(), which is
reached only after the control plane returns a decision that executes.
Every failure — exception, malformed response, wrong request_id,
missing token — ends in DENY.
"""
from __future__ import annotations

import logging
from typing import Any, Callable, Optional

import config
import control_plane as cp
from contracts import Decision, DecisionRequest, DecisionResponse

log = logging.getLogger("sentinelmesh.exec")

_SCOPES = ["https://www.googleapis.com/auth/cloud-platform"]

Handler = Callable[[dict[str, Any], Any], dict[str, Any]]
HANDLERS: dict[str, Handler] = {}


def register(action: str):
    """Decorator: handlers.py registers each GCP call against an action."""
    def deco(fn: Handler) -> Handler:
        HANDLERS[action] = fn
        return fn
    return deco


def _credentials_for(token: Optional[str]):
    if not token:
        raise RuntimeError("no access token: execution attempted without ALLOW")
    if token == "stub":
        # A real control plane must never be able to unlock local ADC by
        # returning the magic string. Stub tokens only work in stub mode.
        if config.CONTROL_PLANE_MODE != "stub":
            raise RuntimeError("stub token received outside stub mode")
        import google.auth
        creds, _ = google.auth.default(scopes=_SCOPES)
        return creds
    from google.oauth2.credentials import Credentials
    return Credentials(token=token)


def _refusal(decision: DecisionResponse) -> dict[str, Any]:
    return {
        "executed": False,
        "decision": decision.decision.value,
        "risk_score": decision.risk_score,
        "reason": decision.explanation or "Blocked by SentinelMesh policy.",
        "guidance": ("Do not retry a variation of this action. "
                     "Report the refusal and its reason to the user."),
    }


def execute(*, action: str, resource_type: str, resource_id: str,
            declared_purpose: str, source_context: str, user_id: str,
            trace_id: str, data_classification: str, destination: str,
            args: dict[str, Any], client: cp.ControlPlaneClient,
            delegated_by: Optional[str] = None,
            ) -> tuple[dict[str, Any], DecisionResponse]:

    req = DecisionRequest(
        agent_id=config.AGENT_ID,
        user_id=user_id,
        declared_purpose=declared_purpose,
        action=action,
        resource_type=resource_type,
        resource_id=resource_id,
        source_context=source_context,
        data_classification=data_classification,
        destination=destination,
        parameters=dict(args),
        delegated_by=delegated_by,
        **({"trace_id": trace_id} if trace_id else {}),
    )

    # Outside the capability boundary: denied before the control plane is
    # even asked. This is where secretmanager.read ends up.
    handler = HANDLERS.get(action)
    if handler is None:
        d = cp.deny(req.request_id, f"action '{action}' is not in this agent's capability set")
        return _refusal(d), d

    try:
        decision = client.decide(req)
    except Exception as e:
        decision = cp.deny(req.request_id, f"control plane error ({type(e).__name__})")

    if decision.decision is Decision.REQUIRE_APPROVAL:
        resolved = (cp.await_approval(client, decision.approval_id)
                    if decision.approval_id else None)
        decision = resolved or cp.deny(req.request_id, "human approval not granted in time")

    # A decision about some other request authorises nothing here.
    if decision.request_id != req.request_id:
        decision = cp.deny(req.request_id, "response request_id mismatch")

    log.info("%s %s -> %s (risk=%s)", action, resource_id,
             decision.decision.value, decision.risk_score)

    if not decision.decision.executes:
        return _refusal(decision), decision

    try:
        creds = _credentials_for(decision.access_token)
    except RuntimeError as e:
        d = cp.deny(req.request_id, str(e))
        return _refusal(d), d

    try:
        result = dict(handler(dict(args), creds))
    except Exception as e:
        log.exception("handler failed for %s", action)
        return ({"executed": False, "decision": decision.decision.value,
                 "error": f"{type(e).__name__}: {e}"[:400]}, decision)

    result.update(executed=True, decision=decision.decision.value,
                  risk_score=decision.risk_score)
    return result, decision
