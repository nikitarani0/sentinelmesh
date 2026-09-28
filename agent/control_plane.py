"""
Client for the SentinelMesh control plane.

Swap stub -> real service with one env var: SM_CONTROL_PLANE_MODE=http
Every failure path in this file returns DENY. Nothing here can produce
an implicit ALLOW.
"""
from __future__ import annotations

import logging
import time
from typing import Optional, Protocol

import config
from contracts import Decision, DecisionRequest, DecisionResponse

log = logging.getLogger("sentinelmesh.cp")


def deny(request_id: str, why: str) -> DecisionResponse:
    """The one way to construct a fail-closed decision."""
    return DecisionResponse(
        request_id=request_id,
        decision=Decision.DENY,
        risk_score=100,
        explanation=f"Fail-closed: {why}",
    )


class ControlPlaneClient(Protocol):
    def decide(self, req: DecisionRequest) -> DecisionResponse: ...
    def poll_approval(self, approval_id: str) -> Optional[DecisionResponse]: ...


class StubControlPlane:
    """Dev stand-in. Always allows. Logs at WARNING so a stub left on
    during the demo is impossible to miss in Cloud Logging."""

    def decide(self, req: DecisionRequest) -> DecisionResponse:
        log.warning("STUB CONTROL PLANE auto-allowing %s on %s",
                    req.action, req.resource_id)
        return DecisionResponse(
            request_id=req.request_id,
            decision=Decision.ALLOW,
            risk_score=0,
            explanation="Stub control plane: no evaluation performed.",
            access_token="stub",
        )

    def poll_approval(self, approval_id: str) -> Optional[DecisionResponse]:
        return None


class HttpControlPlane:
    """Real client for the Cloud Run control plane."""

    def __init__(self, base_url: Optional[str] = None):
        self.base_url = (base_url or config.CONTROL_PLANE_URL).rstrip("/")
        if not self.base_url:
            raise ValueError("http mode but SM_CONTROL_PLANE_URL is empty")

    def _headers(self) -> dict[str, str]:
        # ID token audience-scoped to the control plane: the body's agent_id
        # is a claim, this token is evidence of which runtime is calling.
        import google.auth.transport.requests
        import google.oauth2.id_token
        token = google.oauth2.id_token.fetch_id_token(
            google.auth.transport.requests.Request(), self.base_url)
        return {"Authorization": f"Bearer {token}",
                "Content-Type": "application/json"}

    def decide(self, req: DecisionRequest) -> DecisionResponse:
        import requests
        try:
            r = requests.post(f"{self.base_url}/v1/decide",
                              json=req.to_dict(),
                              headers=self._headers(),
                              timeout=config.CONTROL_PLANE_TIMEOUT_S)
        except Exception as e:
            log.error("control plane unreachable: %s", type(e).__name__)
            return deny(req.request_id, "control plane unreachable")

        if r.status_code != 200:
            return deny(req.request_id, f"control plane returned HTTP {r.status_code}")

        try:
            return DecisionResponse.from_dict(r.json())
        except Exception as e:
            # Malformed JSON, missing keys, or a decision value we don't
            # recognise (e.g. REDACT before it's agreed) all land here.
            return deny(req.request_id, f"unparseable response ({type(e).__name__})")

    def poll_approval(self, approval_id: str) -> Optional[DecisionResponse]:
        import requests
        try:
            r = requests.get(f"{self.base_url}/v1/approvals/{approval_id}",
                             headers=self._headers(),
                             timeout=config.CONTROL_PLANE_TIMEOUT_S)
            if r.status_code != 200:
                return None
            body = r.json()
            if body.get("status") == "pending":
                return None
            return DecisionResponse.from_dict(body)
        except Exception:
            return None  # treated as still pending; timeout then denies


def get_client() -> ControlPlaneClient:
    if config.CONTROL_PLANE_MODE == "http":
        return HttpControlPlane()
    if config.CONTROL_PLANE_MODE == "stub":
        return StubControlPlane()
    raise ValueError(f"unknown SM_CONTROL_PLANE_MODE: {config.CONTROL_PLANE_MODE}")


def await_approval(client: ControlPlaneClient,
                   approval_id: str) -> Optional[DecisionResponse]:
    """Block until a human decides. Returns None on timeout (caller denies)."""
    deadline = time.time() + config.APPROVAL_TIMEOUT_S
    while time.time() < deadline:
        result = client.poll_approval(approval_id)
        if result is not None:
            return result
        time.sleep(config.APPROVAL_POLL_INTERVAL_S)
    return None
