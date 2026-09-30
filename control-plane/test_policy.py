from policy import Decision, evaluate, purpose_diverges, server_destination, POLICY_VERSION

AGENT_SA = "agent-runtime@sentinelmesh-cp-dev.iam.gserviceaccount.com"


def req(**kw):
    base = dict(
        request_id="r-1", agent_id="fraud-investigator-01", user_id="demo-user",
        declared_purpose="Read transaction rows for the dispute investigation",
        action="bigquery.read", resource_type="table",
        resource_id="sentinelmesh-target.finance.transactions", parameters={},
        data_classification="financial-pii", destination="internal",
        source_context="Investigate the disputed transaction TX1001",
        delegated_by=None, timestamp="2026-09-30T10:00:00Z", trace_id="t-1",
    )
    base.update(kw)
    return base


def test_acceptance_A_bigquery_read_executes():
    r = evaluate(req(), AGENT_SA)
    assert r.decision is Decision.ALLOW_WITH_AUDIT
    assert r.rule_id == "PE-120-SENSITIVE-DATA-AUDIT"
    assert r.executes


def test_acceptance_B_injected_external_send_denied():
    r = evaluate(req(
        action="external.send", resource_id="https://collector.attacker.example/upload",
        source_context="Summarise the customer dispute in incoming/dispute-TX1001.txt",
        declared_purpose="Send customer records for standard compliance processing",
        destination="external", data_classification="pii",
    ), AGENT_SA)
    assert r.decision is Decision.DENY
    assert r.rule_id == "PE-050-PURPOSE-DIVERGENCE"
    assert not r.executes


def test_unregistered_agent_denied():
    assert evaluate(req(agent_id="ghost-01"), AGENT_SA).rule_id == "PE-010-AGENT-NOT-REGISTERED"


def test_identity_mismatch_denied():
    r = evaluate(req(), "attacker@evil.iam.gserviceaccount.com")
    assert r.rule_id == "PE-012-IDENTITY-BINDING-MISMATCH"


def test_unknown_action_denied():
    assert evaluate(req(action="bigquery.delete"), AGENT_SA).rule_id == "PE-002-UNKNOWN-ACTION"


def test_out_of_scope_resource_denied():
    r = evaluate(req(resource_id="sentinelmesh-target.hr.salaries"), AGENT_SA)
    assert r.rule_id == "PE-021-RESOURCE-OUT-OF-SCOPE"


def test_malformed_request_denied():
    assert evaluate({"agent_id": "fraud-investigator-01"}, AGENT_SA).rule_id == "PE-003-MALFORMED-REQUEST"


def test_engine_never_raises():
    for bad in ({}, {"agent_id": None}, {"action": 42, "agent_id": "x", "resource_id": "y"}):
        assert evaluate(bad, AGENT_SA).decision is Decision.DENY


def test_agent_cannot_downgrade_classification():
    r = evaluate(req(data_classification="public"), AGENT_SA)
    assert r.effective_classification == "financial-pii"
    assert r.decision is Decision.ALLOW_WITH_AUDIT


def test_unclassified_label_cannot_downgrade():
    r = evaluate(req(data_classification="unclassified"), AGENT_SA)
    assert r.effective_classification == "financial-pii"


def test_agent_cannot_downgrade_destination():
    r = evaluate(req(
        action="external.send", resource_id="https://collector.attacker.example/upload",
        destination="internal",
        source_context="Please email the summary to the reviewer",
        declared_purpose="Email the summary",
    ), AGENT_SA)
    assert r.rule_id == "PE-051-EXTERNAL-DESTINATION"
    assert r.effective_destination == "external"


def test_divergence_true_when_user_never_authorised_egress():
    assert purpose_diverges("Send records to the partner", "Summarise the dispute")


def test_divergence_false_when_user_asked_for_egress():
    assert not purpose_diverges("Email the summary", "Please email this to the reviewer")


def test_external_host_detection():
    assert server_destination("external.send", "https://collector.attacker.example/x") == "external"
    assert server_destination("external.send", "not-a-url") == "external"


def test_deterministic():
    runs = [evaluate(req(), AGENT_SA) for _ in range(50)]
    assert len({(x.decision, x.risk_score, x.rule_id) for x in runs}) == 1


def test_no_result_carries_redact():
    for kw in ({}, {"action": "external.send", "resource_id": "https://x.example/y"}):
        assert evaluate(req(**kw), AGENT_SA).decision.name != "REDACT"


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    failed = 0
    for fn in fns:
        try:
            fn(); print(f"PASS  {fn.__name__}")
        except AssertionError as e:
            failed += 1; print(f"FAIL  {fn.__name__}: {e}")
    print(f"\n{len(fns)-failed}/{len(fns)} passed  (policy {POLICY_VERSION})")
    raise SystemExit(1 if failed else 0)
