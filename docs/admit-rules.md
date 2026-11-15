# otelfilt admit rules

## Signing input
`v1|{kid}|{service}|{resource}|{attrs_sorted_k=v_joined_by_;}|{iat}|{nonce}`

attrs_sorted: sort keys, join `k=v` with `;`.

## Gates
service ∈ services; resource == resource_exact; every attr key ∈ attr_allow;
len(attrs) <= attr_count_max; every value len <= attr_value_max_len;
HMAC+revoke; time; nonce allow-only.
