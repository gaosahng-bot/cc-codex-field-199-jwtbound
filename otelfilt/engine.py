from __future__ import annotations
import base64
import hashlib
import hmac
from typing import Any

def inspect_span(obj: dict) -> dict:
    return {
        "kid": obj.get("kid"),
        "service": obj.get("service"),
        "resource": obj.get("resource"),
        "attrs": obj.get("attrs"),
        "nonce": obj.get("nonce"),
    }

def _signing_line(kid: str, service: str, resource: str, attrs: dict, iat: int, nonce: str) -> str:
    attrs_sorted = ";".join(f"{k}={attrs[k]}" for k in sorted(attrs))
    return f"v1|{kid}|{service}|{resource}|{attrs_sorted}|{iat}|{nonce}"

def _b64url_hmac_sha256(secret_hex: str, message: str) -> str:
    digest = hmac.new(bytes.fromhex(secret_hex), message.encode("utf-8"), hashlib.sha256).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")

def admit_span(obj: dict, keys: dict, policy: dict, store: dict, now_unix: int) -> dict:
    reasons: list[str] = []
    service = obj.get("service")
    resource = obj.get("resource")
    attrs = obj.get("attrs") if isinstance(obj.get("attrs"), dict) else {}
    kid = obj.get("kid")
    nonce = obj.get("nonce")
    iat = obj.get("iat")
    sig = obj.get("sig")

    svc = policy.get("services", {}).get(service)
    if svc is None:
        reasons.append("service_unknown")
    else:
        if resource != svc.get("resource_exact"):
            reasons.append("resource_mismatch")
        attr_allow = set(svc.get("attr_allow", []))
        if any(k not in attr_allow for k in attrs):
            reasons.append("attr_key_denied")

    if len(attrs) > policy.get("attr_count_max", 0):
        reasons.append("attr_count_exceeded")
    max_len = policy.get("attr_value_max_len", 0)
    if any(not isinstance(v, str) or len(v) > max_len for v in attrs.values()):
        reasons.append("attr_value_too_long")

    key_entry = keys.get("keys", {}).get(kid)
    if key_entry is None:
        reasons.append("key_unknown")
    elif key_entry.get("status") != "active":
        reasons.append("key_revoked")
    else:
        line = _signing_line(kid, service, resource, attrs, iat, nonce)
        expected = _b64url_hmac_sha256(key_entry["secret"], line)
        if not isinstance(sig, str) or not hmac.compare_digest(expected, sig):
            reasons.append("bad_signature")

    if not isinstance(iat, int):
        reasons.append("iat_invalid")
    else:
        if iat > now_unix + policy.get("clock_skew_seconds", 0):
            reasons.append("iat_future")
        if now_unix - iat > policy.get("max_age_seconds", 0):
            reasons.append("iat_expired")

    items = store.setdefault("items", {})
    if nonce in items:
        reasons.append("nonce_replay")

    if reasons:
        return {"decision": "deny", "reason_codes": reasons, "service": service}
    items[nonce] = {"ts": now_unix}
    return {"decision": "allow", "reason_codes": [], "service": service}
