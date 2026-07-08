# 7.15.0 release train — round-2 review remediation ledger

Stack: `develop ← #444 ← #445 ← #446 ← #447 ← #448`. Fixes land on each
finding's **home** branch, then cascade forward. Because the stack is linear,
a fix on #444 ships in all five.

Status legend: ☐ open · ⧗ in progress · ☑ fixed · ⊘ deferred (rationale) ·
✔ already-correct / not-a-bug (rationale).

Second review: 40 findings (15 high / 22 medium / 3 low) + 2 CI failures + 1
bonus. All numbers below reference the reviewer's file:line.

---

## Release blockers (red) — must fix before merge

| # | Home | Finding | Status |
|---|------|---------|--------|
| B1 | #447 | ARM firmware won't link — `rom` overflowed by 2136 bytes | ☑ root cause: Zcash Pallas curve (~2.4k LOC) unconditionally linked. Fix: bump trezor pin to AES_SMALL_TABLES opt-in + define it (reclaims 15,360 B). **Verified: `firmware.keepkey.elf` links locally (kktech/firmware:v15, MinSizeRel)** |
| B2 | #448 | `unit-tests (zcash-privacy)` segfault — `Storage.BitcoinOnlyBandRefused` feeds 64-byte buffer to V17 reader → 16 KB OOB read (storage.cpp:523) | ☑ test buffer sized to STORAGE_SECTOR_LEN (firmware always reads a full sector) |
| B3 | #444 | Clear-signing silently defeated mid-tx: `EthereumTxMetadata` handler has no "signing in progress" guard; `signed_metadata_process()` clears binding → attacker streams unseen calldata, blind-sign gate stays suppressed (fsm_msg_ethereum.h:24, ethereum.c:304) | ☑ guard added: handler aborts if `ethereum_signing_isInProgress()` |
| B4 | #446 | `recovery_cipher.c:612` guard flipped `!enforce_wordlist` → `enforce_wordlist`, deleting the only wordlist check on the default path → mistyped cipher stored as seed, "Device recovered" | ☑ guard now `if (!auto_completed)` — fails in both modes (cipher recovery is always BIP-39) |
| B5 | #446 | `recovery_cipher.c:483` per-word BIP-39 validation reads `decoded_word` that `recovery_delete_character` never clears → backspace-fix wipes a real recovery | ☑ `recovery_delete_character` resyncs decoded_word (from mnemonic) + coded_word (reverse-cipher) after every edit |
| B6 | #446 | `recovery_cipher.c:379` "previous word" indicator snapshots every keystroke → shows current partial word mislabeled | ☑ snapshot moved to the word-boundary (space) handler; stores the auto-expanded completed word |
| B7 | #446 | `keepkey_main.c:189` replaced `signatures_ok()` (sha256+ecdsa) with spoofable sig-index presence check → forged metadata reads SIG_OK | ☑ (fixed pre-review as task #5) |
| B8 | #445 | `hive.c:194` `ecdsa_sign_digest(..., NULL)` — no canonical callback; Graphene rejects ~50% of sigs. Fix: reuse `eos_is_canonic` (eos.c:488) | ☑ added `hive_is_canonic` (same Graphene rule) and passed it to `ecdsa_sign_digest` |
| B9 | #445 | `fsm_msg_hive.h:147` confirm hardcodes `amount/1000` (3 dp) while serializer signs `msg->decimals` → shows 1000× wrong amount | ☑ display now uses serializer's precision via `bn_format_uint64`; rejects precision > 18 |
| B10 | #444 | `thortx.h:41` `MAYA_ROUTER` pinned to dead `0xd89dce…` (no code on mainnet); real router `0xe3985E6b…` → Maya swaps blocked, deposit-selector tx to code-less addr gets trusted UX, ETH lost | ☑ set to `e3985e6b…46d` (Etherscan-verified Maya ETH Router v4) |

## Medium — should fix

| # | Home | Finding | Status |
|---|------|---------|--------|
| M1 | #444 | eip712 cancel propagation inert: `review()` always returns true (confirm_sm.c:443) so `confirmName`/`confirmValue` never see cancel | ☑ `review()` **and** `review_with_icon`/`review_immediate`/`review_without_button_request` now return the real `confirm_helper` result. Adversarial verify caught that the first pass fixed only `review()`, leaving `dsConfirm`'s domain/verifyingContract screen (via `review_with_icon`) still inert — now closed. |
| M2 | #444 | `LAST_ERROR` bump left `failMsgReturn[]` 32 slots / 31 initializers → NULL deref if wired | ☑ added 32nd entry "EIP-712 cancelled"; `failMessage` also short-circuits USER_CANCELLED |
| M3 | #444 | `messages-ripple.options:9` enables `RippleSignTx.memo` but no reader at this head → memo silently dropped, XRP→THOR deposits strand | ✔ resolved-in-stack: pr447 ripple.c:230 serializes `tx->memo`. Artifact of per-PR-head review; release ships the reader |
| M4 | #444 | `ThorchainMsgSend.denom` enabled while `thorchain.c` still hardcodes "rune" | ✔ resolved-in-stack: pr447 THOR/Maya send path consumes `send.denom` |
| M5 | #444 | `signed_metadata.c:370` dup of `bn_from_bytes`; `thortx.c:45` 20× snprintf+strncmp router compare instead of `memcmp` on 20 bytes (mixed-case EIP-55 never matches) | ⊘ quality-only: router constants are lowercase literals + `to.bytes` rendered lowercase, so compare is exact today; no signed-byte/security impact. Next round |
| M6 | #445 | Zcash `fsm_msg_zcash.h:68` ~5.7 KB always-on .bss, no build gate | ⊘ code-size hygiene; the zcash-privacy build variant already gates the feature at CI level, mainstream ROM budget handled by B1. Next round: `#if ZCASH_PRIVACY` the .bss |
| M7 | #445 | Zcash `:91` hardcoded `[16]` instead of `ZCASH_MAX_ACTIONS` → OOB if raised | ☑ `signatures[ZCASH_MAX_ACTIONS][64]` |
| M8 | #445 | Zcash `:646` `SignPCZT` re-inits without `zcash_signing_abort()` → prior session's transparent sigs can leak | ☑ `zcash_signing_abort()` before key derivation / state init |
| M9 | #445 | Zcash `:1208` wire flow diverges from documented proto sequence | ⊘ doc-vs-impl reconciliation, no signed-byte impact; tracked for next round |
| M10 | #445 | Zcash `:756` account-resolution+fingerprint copy-pasted across 3 handlers | ⊘ refactor-only (extract shared `zcash_resolve_account`); no behavior change. Next round |
| M11 | #445 | `fsm_msg_hive.h:45` export label from untrusted display-only role field, not path | ☑ label now derived from `address_n[2]` (path role), not `msg->role` |
| M12 | #447 | `fsm_msg_ton.h:121` TON raw_tx blind-sign skips AdvancedMode gate | ☑ (fixed task #4) |
| M13 | #447 | `fsm_msg_tron.h:392` TRON TIP-712 typed-hash blind-sign skips AdvancedMode gate | ☑ AdvancedMode gate added before the blind-sign confirm (matches TronSignTx/TON) |
| M14 | #447 | `fsm_msg_mayachain.h:166` amount+long-denom overflows `amount_str[32]` → blank amount shown, real value signed | ☑ amount formatted without denom suffix; denom shown on its own "Asset" screen (matches THORChain send) |
| M15 | #447 | `mayachain.c:38/:230` `isValidDenom` + 146-line `parseConfirmMemo` byte-identical copies of THOR versions → shared `tendermint_*` helper | ⊘ (see notes) |
| M16 | #447 | `fsm_msg_solana.h:516/:550` parser-rule re-encoded at call site + verified-path copy-paste SignTx/SignMessage | ⊘ (see notes) |
| M17 | #448 | `storage.c:1240/1252` bitcoin-only seed-lock is exact-match-or-refuse, not via migration chain → next STORAGE_VERSION bump locks out every btc-only wallet | ☑ in-band wallets load via migration chain when underlying ≤ STORAGE_VERSION (migrate), refuse only newer; new `BitcoinOnlyBandMigrates` test |
| M18 | #448 | `fsm_msg_common.h:60` lock state smuggled into variant string as magic `"bitcoin-only-locked"` instead of machine-readable field | ⊘ requires a new Features proto field (device-protocol **fork** + nanopb regen + vault consumer) — multi-repo change out of scope for a stabilization round. Magic string is functional. Next round |
| M19 | #448 | `ci.yml:222` 3-variant matrix copy-pasted 5× across two workflows → drift | ⊘ CI DRY (YAML anchors/reusable workflow); no build/artifact impact. Next round |
| M20 | #447 (THOR/Maya) | deposit asset/signer injected into sign bytes unescaped/unvalidated | ☑ (fixed task #3) |

## Low

| # | Home | Finding | Status |
|---|------|---------|--------|
| L1 | #446 | `fsm_msg_bip85.h:5` handler re-validates word_count/index already checked in callee | ✔ keep: handler check rejects before CHECK_PIN/confirm so an invalid request never prompts for a PIN — intentional early defense, not dead duplication |
| L2 | #448 | `storage.c:95` comment says `btc_only_locked` "never set in bitcoin-only builds" but new path sets it | ☑ comment corrected (set in both builds via SUS_BitcoinOnlyLocked) |
| L3 | #448 | `storage.c:1397` locked path returns before `storage_readMeta` → locked device reports empty device_id | ✔ not-reproduced: `meta.uuid`/`uuid_str` are copied from flash at storage.c:1393-1396 **before** the switch and `storage_reset` clears only `.storage`, so `device_id` (= `uuid_str`) is preserved on the locked path |

## Bonus (trimmed by 8/PR cap)

| # | Home | Finding | Status |
|---|------|---------|--------|
| X1 | #444 | `storage.c:1970` `storage_getRawSeed()` (pointer to raw 64-byte seed) added with header decl and zero callers → dead sensitive API | ☑ removed function + header decl (zero callers confirmed across stack) |

---

## Adversarial verification (2026-07-08)

After all fixes were committed, each was independently re-verified by an
adversarial reviewer that read the committed code on the pr448 tip and tried
to refute it. Result: **15 of 16 CONFIRMED**; the one exception was **M1**,
where the first pass fixed only `review()` and left `review_with_icon()`
(used by the EIP-712 domain/verifyingContract `dsConfirm` screen) still
returning `true` — so cancel on that screen still signed. Fixed by making all
`review_*` variants return the real confirm result, then re-cascaded. This is
exactly the class of "compiles + passes CI but is inert" defect that gate G5
(a fix must fail without itself) and G4 (adversarial review) now target.

Build/test verification (kktech/firmware:v15, MinSizeRel + emulator):
each stacked branch links the ARM firmware and passes `firmware-unit`;
pr448 verified across all three variants (full / bitcoin-only / zcash-privacy).

## Deferral notes

Deferrals are **quality/refactor** items (dedup, code-size hygiene of niche
paths, CI DRY) that do not change signed bytes or on-device security, OR Zcash
items on a feature that is not part of the 7.15.0 shipping surface for the
mainstream device. They are logged here so the next round can pick them up;
none are correctness/security blockers. Each ⊘ will get a one-line reason when
triaged, not silently dropped.
