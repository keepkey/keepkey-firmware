# T3 — Uniswap clear-sign and authenticator wipe honour a cancel (#421, #422)

Device: 7.14.2, fw_hash fd7b3901…, mnemonic12, no PIN, no passphrase.

## VERDICT: PASS (8/8 wire checks; photo checks with the tester)

### Leg A — authenticator (#421)

| check | result |
|---|---|
| authdata reset | PASS |
| account added | PASS |
| **account readable BEFORE cancel** | PASS `'keepkey.com:alice'` |
| wipe cancel produced Failure | PASS `Action cancelled` |
| **account survived the cancelled wipe** | PASS `'keepkey.com:alice'` |

The before/after pair is the evidence: the account is provably present, the wipe
is cancelled, and it is still readable. On the old firmware the host's own abort
executed as a commit and destroyed every authenticator secret.

Text change `5bccac024` verified in source: the wipe body is now only
`"Do you want to PERMANENTLY delete all authenticator accounts?"`. The sentence
`"If not, unplug Keepkey now."` is absent from `lib/` repo-wide — it existed only
while Cancel was inert.

### Leg B — Uniswap approve (#422)

| check | result |
|---|---|
| uniswap raised a confirm screen | PASS |
| uniswap cancel produced Failure | PASS `Signing cancelled by user` |
| **no signature returned** | PASS |

`fd99fa75a` changes no text at all — every `confirm()` title and format string is
byte-identical. The diff only wraps them in `if (!confirm(...)) return false;`.
Before it, the handler walked forward to `return true` and signed a MAX_ALLOWANCE
approval to the Uniswap V2 router with zero button presses.

Calldata is verbatim from `test_msg_ethereum_erc20_uniswap_liquidity.py::
test_sign_uni_approve_liquidity_ETH` — `approve(0x7a250d56…, 0xffff…ff)` to the
FOX pool `0x470e8de2ebaef52014a47cb5e6af86884947f08c`.

## First attempt was INVALID — precondition, not firmware

Leg A initially failed with `Failure code=4 'passphrase incorrect for authdata'`,
not `Account not found`. Authdata is encrypted under a key derived from the seed;
T3's step 0 reloads the seed, so authdata left from the previous wallet
(`ceremony-B`) could not be decrypted and `initializeAuth` never ran.

**Correct ordering, now in `t3_legA_authenticator.py`:** complete a wipe first
(hold it — `storage_wipeAuthData()` resets the encryption flag), then add the
account, then run the cancel test. Also added the A1b read-back so the test
proves the account exists before claiming it survived.

Note the failure mode was loud, not silent — the prefix bytes were correct.
Verified against `fsm_msg_common.h:205-225`:
`\x15 initializeAuth:` `\x16 generateOTPFrom:` `\x17 getAccount:`
`\x18 removeAccount:` `\x19 wipeAuthdata:`

## Coverage caveat — state it in the release record

This exercises **2 of the 5** `confirm()` calls gated by `fd99fa75a`, and
**1 of the 3** authenticator mutations gated by `5bccac024`. The remaining paths
are argued-by-symmetry, not measured. See plan §4.

## Device left as

mnemonic12, no PIN, no passphrase, authenticator holds `keepkey.com:alice`.
