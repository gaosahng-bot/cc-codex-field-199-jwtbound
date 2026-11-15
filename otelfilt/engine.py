from __future__ import annotations
from typing import Any

def inspect_span(obj: dict) -> dict:
    return {
        "kid": obj.get("kid"),
        "service": obj.get("service"),
        "resource": obj.get("resource"),
        "attrs": obj.get("attrs"),
        "nonce": obj.get("nonce"),
    }

def admit_span(obj: dict, keys: dict, policy: dict, store: dict, now_unix: int) -> dict:
    return {"decision": "deny", "reason_codes": ["not_implemented"], "service": obj.get("service")}
