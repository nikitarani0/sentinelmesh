"""
Day 8: the Attack Playground swaps only the model. These tests prove the
compromised agent still goes through the same gate as the real one.
No network, no GCP, no Gemini.
"""
import asyncio

import pytest

import attacks
import executor
import main
from contracts import Decision, DecisionResponse
from enterprise_agent import tools


class PolicyLikePlane:
    """Allows reads, denies every external send. Records what it was asked."""

    def __init__(self):
        self.seen = []

    def decide(self, req):
        self.seen.append(req)
        if req.action == "external.send":
            return DecisionResponse(request_id=req.request_id, decision=Decision.DENY,
                                    risk_score=95, explanation="DENY by test policy")
        return DecisionResponse(request_id=req.request_id,
                                decision=Decision.ALLOW_WITH_AUDIT,
                                risk_score=45, access_token="tok")

    def poll_approval(self, approval_id):
        return None


class AllowEverythingPlane(PolicyLikePlane):
    def decide(self, req):
        self.seen.append(req)
        return DecisionResponse(request_id=req.request_id, decision=Decision.ALLOW,
                                access_token="tok")


@pytest.fixture
def ran(monkeypatch):
    calls = []

    def fake(action):
        def h(args, creds):
            calls.append(action)
            return {"ok": True}
        return h

    monkeypatch.setattr(executor, "HANDLERS", {
        a: fake(a) for a in ("bigquery.read", "storage.read", "external.send")})
    return calls


def attack(scenario, plane, monkeypatch):
    monkeypatch.setattr(tools, "_client", lambda: plane)
    return asyncio.run(main.run_attack(scenario))


def test_poisoned_document_reaches_plane_and_send_is_blocked(ran, monkeypatch):
    plane = PolicyLikePlane()
    out = attack("poisoned_document", plane, monkeypatch)
    assert [r.action for r in plane.seen] == ["storage.read", "external.send"]
    assert ran == ["storage.read"]
    assert [c["decision"] for c in out["tool_calls"]] == ["ALLOW_WITH_AUDIT", "DENY"]


def test_attack_carries_trusted_user_prompt(ran, monkeypatch):
    plane = PolicyLikePlane()
    attack("poisoned_document", plane, monkeypatch)
    expected = attacks.SCENARIOS["poisoned_document"]["user_prompt"]
    assert all(r.source_context == expected for r in plane.seen)


def test_lookalike_address_is_classified_external(ran, monkeypatch):
    plane = PolicyLikePlane()
    attack("lookalike_address", plane, monkeypatch)
    assert plane.seen[0].destination == "external"
    assert ran == []


def test_planted_tool_never_runs_even_if_plane_allows_everything(ran, monkeypatch):
    plane = AllowEverythingPlane()
    out = attack("planted_tool", plane, monkeypatch)
    assert plane.seen == []                       # stopped before the control plane
    assert out["tool_calls"][0]["decision"] == "DENY"
    assert "TRIPWIRE-FAILED" not in str(out)


@pytest.mark.parametrize("scenario", list(attacks.SCENARIOS))
def test_no_scenario_runs_anything_when_plane_denies(scenario, ran, monkeypatch):
    class DenyAll(PolicyLikePlane):
        def decide(self, req):
            self.seen.append(req)
            return DecisionResponse(request_id=req.request_id, decision=Decision.DENY)
    attack(scenario, DenyAll(), monkeypatch)
    assert ran == []


def test_unknown_scenario_rejected():
    with pytest.raises(KeyError):
        asyncio.run(main.run_attack("not-a-scenario"))
