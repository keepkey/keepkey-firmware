# T2 — a cancelled passphrase confirmation must not cache (#428a)

Device: 7.14.2, fw_hash fd7b3901…, mnemonic12, passphrase ON, no PIN, label `test`.

## VERDICT: PASS (8/8)

| check | result |
|---|---|
| passphrase requested | PASS |
| confirmation screen raised for `topsecret` | PASS |
| host Cancel produced `Failure code=4 'Ping cancelled'` | PASS |
| **re-asked after cancel (the #428a fix)** | **PASS** |
| confirmation screen raised for `secondtry` | PASS |
| second ping succeeded | PASS |
| control: cached passphrase not re-requested | PASS |

Before `b286dc009`, `passphrase_request()` discarded `review()`'s verdict and did
`ret = true`, so `session_cachePassphrase()` cached a passphrase whose
confirmation screen the host had just suppressed. The next passphrase-protected
request drew nothing and derived keys from it — the user was in a different
wallet than the one they believed they had opened. `passphrase_sm.c:158-161` now
propagates the verdict.

The step-5 control matters: after a *successful* confirmation the passphrase IS
cached and is not re-requested. The fix cancels correctly without disabling
caching.

## First run was INVALID — procedure, not firmware

The first attempt reported 4 failures. It had a 3-second "photograph now" pause
between the ButtonAck and the Cancel; the tester held the button during it, the
confirmation completed (`Success`, message `cancel-probe`), and `topsecret` was
then cached entirely legitimately. All four failures followed from that one press.

**Rule reinforced (see T5):** never leave a human window inside a test whose
premise is that no press occurs. The Cancel is now sent with no pause at all, so
there is no window to press in. Photo 2 is captured in a separate deliberate pass.

`Initialize` calls `session_clear(false)` (`fsm_msg_common.h:9`) — drops a cached
passphrase, keeps the PIN. The script uses it to reset state between probes
instead of requiring a replug.

## Device left as

`mnemonic12`, passphrase ON, no PIN, label `test`.
