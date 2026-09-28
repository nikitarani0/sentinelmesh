from __future__ import annotations
import uuid
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional


class Decision(str, Enum):
    ALLOW = "ALLOW"
    ALLOW_WITH_AUDIT = "ALLOW_WITH_AUDIT"
    REQUIRE_APPROVAL = "REQUIRE_APPROVAL"
    DENY = "DENY"

    @property
    def executes(self) -> bool:
        return self in (Decision.ALLOW, Decision.ALLOW_WITH_AUDIT)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass
class DecisionRequest:
    agent_id: str
    user_id: str
    declared_purpose: str        # model-generated. UNTRUSTED.
    action: str                  # "bigquery.read"
    resource_type: str           # coarse class: "table", "object", "endpoint"
    resource_id: str             # fully-qualified path
    source_context: str          # verbatim user turn. TRUSTED.
    data_classification: str     # computed agent-side, never model-supplied
    destination: str             # "internal" | "external", computed agent-side
    parameters: dict[str, Any] = field(default_factory=dict)
    delegated_by: Optional[str] = None
    request_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    trace_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: str = field(default_factory=_now)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class DecisionResponse:
    request_id: str
    decision: Decision
    risk_score: int = 0
    explanation: str = ""
    access_token: Optional[str] = None
    approval_id: Optional[str] = None
    expires_at: Optional[str] = None

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "DecisionResponse":
        return cls(
            request_id=d["request_id"],
            decision=Decision(d["decision"]),
            risk_score=int(d.get("risk_score", 0)),
            explanation=d.get("explanation", ""),
            access_token=d.get("access_token"),
            approval_id=d.get("approval_id"),
            expires_at=d.get("expires_at"),
        )
