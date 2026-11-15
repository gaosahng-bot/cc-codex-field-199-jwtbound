# jwtbound admit rules

## Signing input
`v1|{kid}|{aud}|{azp}|{sub}|{cnf_jkt}|{iat}|{exp}|{nonce}`

## Bind
aud ∈ audiences; azp ∈ audiences[aud].azp_allow; sub startswith one of sub_prefixes;
if require_cnf_jkt: cnf_jkt non-empty and ∈ jkt_allow and len >= jkt_hexish_min_len;
HMAC+revoke; time; nonce allow-only.
