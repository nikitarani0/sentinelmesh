"""
Deterministic policy inputs. NEVER model-supplied.

The model cannot see or set anything in this file. data_classification and
destination are computed from the action itself, so a prompt-injected agent
cannot declare its own exfiltration "internal".
Stage 2 replaces the classification table with Cloud DLP.
"""
from __future__ import annotations
from urllib.parse import urlparse

_CLASSIFICATION = {
    ("bigquery.read", "finance", "transactions"): "financial-pii",
    ("bigquery.read", "finance", "customers"): "pii",
}

# Exact hostnames only. Suffix matching would classify
# "sentinelmesh.internal.attacker.example" as internal.
_INTERNAL_HOSTS = frozenset({"sentinelmesh.internal"})


def classify(action: str, parts: tuple[str, ...]) -> str:
    return _CLASSIFICATION.get((action, *parts), "unclassified")


def storage_classification(bucket: str, object_path: str) -> str:
    # Anything a customer or third party could have written is untrusted.
    if object_path.startswith("incoming/"):
        return "untrusted-document"
    return "internal-document"


def destination_for(action: str, args: dict) -> str:
    if action != "external.send":
        return "internal"
    try:
        host = (urlparse(str(args.get("destination_url", ""))).hostname or "").lower()
    except ValueError:
        return "external"
    return "internal" if host in _INTERNAL_HOSTS else "external"
