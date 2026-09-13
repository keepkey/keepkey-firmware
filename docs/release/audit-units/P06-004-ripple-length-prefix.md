# P06-004: 192-byte memo length prefix

Base: cecf1ea20239d140cb43dc0629219fd9179ae452.

XRPL's length prefix uses one byte for lengths 0 through 192 inclusive, and
two bytes from 193. ripple_serializeVarint used `< 192`, producing two bytes
for length 192. This boundary is reachable through 7.15's memo[200] field,
which accepts up to 199 content bytes. The extra prefix byte shifts the memo
payload and produces incorrect serialized transaction bytes.

Change the first comparison to `<= 192`. Native boundary vectors 191, 192,
193 and 199 reproduce failure only at 192 before the fix and all pass after.
The four Ripple native tests pass. Full native results are recorded centrally
when complete. Reference: https://xrpl.org/docs/references/protocol/binary-format#length-prefixing

The older release serializers have no memo implementation, so their fixed
address/public-key/signature lengths do not reach 192; broader helper-domain
review remains pending. No other prefix ranges were changed. Combined ARM/host
integration and complete Ripple review remain open.
