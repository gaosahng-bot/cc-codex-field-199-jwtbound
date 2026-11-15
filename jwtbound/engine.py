from __future__ import annotations
from typing import Any

def inspect_tok(obj: dict) -> dict:
    return {
        "kid": obj.get("kid"),
        "aud": obj.get("aud"),
        "azp": obj.get("azp"),
        "sub": obj.get("sub"),
        "cnf_jkt": obj.get("cnf_jkt"),
        "nonce": obj.get("nonce"),
    }

def admit_tok(obj: dict, keys: dict, policy: dict, store: dict, now_unix: int) -> dict:
    return {"decision": "deny", "reason_codes": ["not_implemented"], "sub": obj.get("sub")}
