from __future__ import annotations
import base64
import hashlib
import hmac
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
    codes: list[str] = []
    sub = obj.get("sub")

    aud_cfg = (policy.get("audiences") or {}).get(obj.get("aud"))
    if aud_cfg is None:
        codes.append("aud")
    else:
        if obj.get("azp") not in (aud_cfg.get("azp_allow") or []):
            codes.append("azp")
        if not any(isinstance(sub, str) and sub.startswith(p) for p in (aud_cfg.get("sub_prefixes") or [])):
            codes.append("sub")
        if policy.get("require_cnf_jkt"):
            jkt = obj.get("cnf_jkt")
            if (not isinstance(jkt, str) or not jkt
                    or jkt not in (aud_cfg.get("jkt_allow") or [])
                    or len(jkt) < int(policy.get("jkt_hexish_min_len") or 0)):
                codes.append("jkt")

    key = (keys.get("keys") or {}).get(obj.get("kid"))
    if key is None:
        codes.append("sig")
    elif key.get("status") != "active":
        codes.append("revoked")
    else:
        line = "v1|{kid}|{aud}|{azp}|{sub}|{cnf_jkt}|{iat}|{exp}|{nonce}".format(
            kid=obj.get("kid"), aud=obj.get("aud"), azp=obj.get("azp"),
            sub=obj.get("sub"), cnf_jkt=obj.get("cnf_jkt"),
            iat=obj.get("iat"), exp=obj.get("exp"), nonce=obj.get("nonce"))
        expect = hmac.new(bytes.fromhex(key["secret"]), line.encode("utf-8"), hashlib.sha256).digest()
        got = _b64url_decode(obj.get("sig"))
        if got is None or not hmac.compare_digest(expect, got):
            codes.append("sig")

    skew = int(policy.get("clock_skew_seconds") or 0)
    max_age = policy.get("max_age_seconds")
    iat, exp = obj.get("iat"), obj.get("exp")
    if (not isinstance(iat, int) or not isinstance(exp, int)
            or now_unix > exp + skew
            or iat > now_unix + skew
            or (max_age is not None and now_unix - iat > int(max_age))):
        codes.append("time")

    nonce = obj.get("nonce")
    items = store.setdefault("items", {})
    if not isinstance(nonce, str) or not nonce or nonce in items:
        codes.append("replay")

    if codes:
        return {"decision": "deny", "reason_codes": codes, "sub": sub}
    items[nonce] = {"ts": now_unix}
    return {"decision": "allow", "reason_codes": [], "sub": sub}


def _b64url_decode(s: Any) -> bytes | None:
    if not isinstance(s, str):
        return None
    try:
        return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))
    except Exception:
        return None
