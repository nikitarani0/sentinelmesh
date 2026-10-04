import json
import os
import time
import logging
from typing import Any

import google.auth
from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.responses import JSONResponse
from google.auth.transport import requests as g_requests
from google.auth.transport.requests import AuthorizedSession
from google.oauth2 import id_token

from policy import POLICY_VERSION, STATIC_EXPLANATIONS, Decision, evaluate

logging.basicConfig(level=logging.INFO)
log = logging.getLogger("sentinelmesh")

TARGET_EXECUTOR = os.environ["TARGET_EXECUTOR_SA"]
TOKEN_LIFETIME_SECONDS = 300

# One Cloud Run service answers on two hostnames. Accept both.
_raw_aud = os.environ.get("EXPECTED_AUDIENCE", "")
EXPECTED_AUDIENCES = frozenset(
    a.strip().rstrip("/") for a in _raw_aud.split(",") if a.strip()
)

app = FastAPI(title="SentinelMesh Control Plane", version=POLICY_VERSION)

_creds, _ = google.auth.default(scopes=["https://www.googleapis.com/auth/cloud-platform"])
_session = AuthorizedSession(_creds)
_APPROVALS: dict[str, dict[str, Any]] = {}


# Cloud Run reserves run.app paths ending in "z", so /healthz never arrives.
@app.get("/health")
def health():
    return {"status": "ok", "policy_version": POLICY_VERSION}


def caller_email(authorization: str | None) -> str:
    """
    Cloud Run's edge proves the caller may invoke this service.
    It does not tell us WHICH agent is calling -- so we decode the token here.
    """
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail="missing bearer token")
    raw = authorization.split(None, 1)[1].strip()

    try:
        # Verify signature, issuer, expiry. Audience is checked below against
        # the allowlist, because the claim is an exact string match.
        claims = id_token.verify_oauth2_token(raw, g_requests.Request(), audience=None)
    except Exception as exc:
        log.warning("token verification failed: %s", exc)
        raise HTTPException(status_code=401, detail="invalid token")

    if not EXPECTED_AUDIENCES:
        # Fail closed: an empty allowlist would accept any Google token for any service.
        log.error("EXPECTED_AUDIENCE is not configured")
        raise HTTPException(status_code=500, detail="audience allowlist not configured")

    aud = str(claims.get("aud", "")).rstrip("/")
    if aud not in EXPECTED_AUDIENCES:
        log.warning("audience mismatch: got %s", aud)
        raise HTTPException(status_code=401, detail="audience mismatch")

    email = claims.get("email")
    if not email or not claims.get("email_verified", False):
        raise HTTPException(status_code=401, detail="token carries no verified email")
    return email


def mint_token() -> tuple[str, str]:
    url = (f"https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/"
           f"{TARGET_EXECUTOR}:generateAccessToken")
    resp = _session.post(url, json={
        "scope": ["https://www.googleapis.com/auth/cloud-platform"],
        "lifetime": f"{TOKEN_LIFETIME_SECONDS}s",
    }, timeout=10)
    resp.raise_for_status()
    body = resp.json()
    return body["accessToken"], body["expireTime"]


@app.post("/v1/decide")
async def decide(request: Request, authorization: str | None = Header(default=None)):
    started = time.monotonic()
    email = caller_email(authorization)

    try:
        req = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="unparseable body")
    if not isinstance(req, dict):
        raise HTTPException(status_code=400, detail="body must be an object")

    result = evaluate(req, email)
    request_id = req.get("request_id", "")

    body: dict[str, Any] = {
        "request_id": request_id,
        "decision": result.decision.wire,
        "risk_score": result.risk_score,
        "explanation": STATIC_EXPLANATIONS.get(result.rule_id, "Policy decision applied."),
        "expires_at": None,
        "rule_id": result.rule_id,
        "fired_rules": list(result.fired_rules),
        "policy_version": result.policy_version,
        "signals": {
            "effective_classification": result.effective_classification,
            "effective_destination": result.effective_destination,
        },
    }

    if result.decision is Decision.REQUIRE_APPROVAL:
        approval_id = f"ap-{request_id}"
        _APPROVALS[approval_id] = {"state": "PENDING", "request_id": request_id}
        body["approval_id"] = approval_id

    if result.executes:
        try:
            token, expires_at = mint_token()
            body["access_token"] = token
            body["expires_at"] = expires_at
        except Exception as exc:
            # Cannot mint -> cannot execute. Fail closed.
            log.error("token minting failed: %s", exc)
            body.update({
                "decision": "DENY",
                "risk_score": 100,
                "rule_id": "PE-502-TOKEN-MINT-FAILED",
                "explanation": "Authorised, but a scoped credential could not be issued. Denied.",
            })
            body.pop("access_token", None)

    # One JSON line on stdout = one structured entry in Cloud Logging.
    # The access token is deliberately never logged.
    print(json.dumps({
        "severity": "WARNING" if body["decision"] == "DENY" else "INFO",
        "message": f"{body['decision']} {req.get('action')} {body['rule_id']}",
        "event": "policy_decision",
        "trace_id": req.get("trace_id"),
        "request_id": request_id,
        "agent_id": req.get("agent_id"),
        "user_id": req.get("user_id"),
        "caller": email,
        "action": req.get("action"),
        "resource_id": req.get("resource_id"),
        "decision": body["decision"],
        "rule_id": body["rule_id"],
        "fired_rules": body["fired_rules"],
        "risk_score": body["risk_score"],
        "token_issued": "access_token" in body,
        "policy_version": POLICY_VERSION,
        "latency_ms": round((time.monotonic() - started) * 1000, 1),
    }), flush=True)
    return JSONResponse(body)

@app.get("/v1/approvals/{approval_id}")
def get_approval(approval_id: str, authorization: str | None = Header(default=None)):
    caller_email(authorization)
    record = _APPROVALS.get(approval_id)
    if not record:
        raise HTTPException(status_code=404, detail="unknown approval_id")
    return record
