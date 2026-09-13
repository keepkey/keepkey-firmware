# Full-diff audit of the 7.15 candidate

Every changed file of this candidate was reviewed against its base, in
subsystem-sized chunks, by reviewers that had the base version, the current
file and the ability to grep callers. Findings rated P1 or P2 were then
re-checked by three independent reviewers along separate lines of attack --
is the path reachable, does the consequence matter on a shipped release, is it
already covered -- and a finding survived only when at least two of the three
failed to refute it.

Status of each finding below:

- **FIXED** -- corrected on this line, with a test where a seam exists. Where
  a control build was possible, the unfixed code was built and the test
  confirmed to fail against it; where no seam exists, the test or the commit
  message says so rather than implying coverage.
- **refuted on re-check** -- the re-check found the claim does not hold on
  this head. No change made.
- **open** -- real, not addressed in this pass. Each is named so a reader can
  weigh it rather than discover it.
- **triaged by reading** -- P3, read and judged not to warrant a change in a
  release pass. Not individually re-checked by the three-reviewer process.


Counts: 78 fixed, 11 refuted on re-check, 0 open, 77 triaged by reading (166 findings touching this line).


## Fixed

- **F028** (P3, `lib/rand/rng_health.c`) — random_buffer_checked() ignores a hardware seed/clock error latched during the draw itself (raised on 7.14.3; this line carried the same code)
- **F033** (P3, `lib/firmware/eip712.c`) — int value "-0" is shown as zero but encoded as -2^64 (sign-extension keyed on the '-' character, not the value)
- **F035** (P3, `lib/firmware/ethereum.c`) — TRANSFER amount screen can show a stale WAN ticker left by an earlier request (raised on 7.14.3; this line carried the same code)
- **F044** (P3, `lib/firmware/eip712.c`) — EIP-712 refuses any domain whose chainId exceeds 2^32, on a value it never uses
- **F047** (P1, `lib/firmware/fsm_msg_bip85.h`) — BIP-85 seed pages use the UNPAGED confirm_constant_power, so words are silently clipped off the OLED
- **F054** (P3, `lib/firmware/fsm_msg_common.h`) — Two new auth error codes, one new error string: DUPLICATE reports "Action cancelled", AUTH_CANCELLED reports nothing
- **F058** (P2, `lib/firmware/ethereum_contracts/zxappliquid.c`) — Unlimited LP approval: refused after the user consents, or signed outright if the host pads `value`
- **F059** (P3, `lib/firmware/fsm_msg_ethereum.h`) — process_ethereum_xfer() leaves a derived private key in the shared fsm_derived_node scratch on two error returns
- **F067** (P2, `lib/firmware/hive.c`) — HiveSignTx serializes the display symbol ("HIVE") instead of the wire symbol ("STEEM"), so every transfer signature is unverifiable on-chain
- **F072** (P1, `lib/board/confirm_sm.c`) — Render-completeness gate excludes constant-power layouts, so BIP-85 mnemonic pages still drop whole words
- **F073** (P2, `lib/board/confirm_sm.c`) — Seed words copied into an uncleared plain stack buffer in confirm_constant_power_subpage_take()
- **F077** (P1, `lib/firmware/recovery_cipher.c`) — Cipher recovery commits an empty or one-word mnemonic as the seed when enforce_wordlist is omitted (the default)
- **F079** (P2, `lib/firmware/fsm_msg_hive.h`) — HiveGetPublicKey show_display clips ~8 characters off the STM key with no indication
- **F080** (P2, `lib/firmware/fsm_msg_hive.h`) — HiveSignTx defaults to the wrong wire asset symbol and applies no symbol/precision whitelist
- **F082** (P1, `lib/firmware/fsm_msg_mayachain.h`) — MAYAChain MsgSend amount screen scales every host-chosen denom at 10 decimals
- **F085** (P2, `lib/firmware/signed_metadata.c`) — Session signer icon is compiled out of every build that contains this file — per-tx identity screen can never show the logo
- **F086** (P2, `lib/firmware/solana.c`) — KKSOLSC1 schema review describes one instruction while every other fund-moving instruction in the same message is never drawn
- **F090** (P2, `lib/firmware/ethereum_contracts/thortx.c`) — 7.14.2's ABI memo tail-padding zero check is missing on 7.15 (up to 31 signed-but-never-displayed bytes)
- **F091** (P2, `lib/firmware/fsm_msg_mayachain.h`) — 7.14.2 MayachainSignTx envelope hardening (msg_count + chain_id safe-text) never landed on 7.15
- **F092** (P2, `lib/firmware/fsm_msg_mayachain.h`) — 7.14.2's fee/gas disclosure on the MAYAChain sign screen is absent on 7.15
- **F093** (P2, `lib/firmware/fsm_msg_mayachain.h`) — 7.15 MAYAChain send screen scales every denom by 10^10; 7.14.2's denom-aware formatter was not adopted
- **F094** (P2, `lib/firmware/ethereum_contracts/thortx.c`) — 7.14.2's ABI memo tail-padding zero check is missing on 7.15 — up to 31 signed-but-never-displayed bytes
- **F099** (P1, `lib/board/confirm_sm.c`) — 7.14.2's "route consent screens through the measured renderer" hunk is absent on 7.15 — the comment was propagated, the code was not
- **F102** (P1, `lib/board/confirm_sm.c`) — 7.15 confirm_with_custom_layout still honors the custom layout, so the Bitcoin output screen gets no completeness check
- **F103** (P3, `lib/firmware/authenticator.c`) — 7.15 authenticator cancel paths do not revoke the decrypted TOTP cache
- **F120** (P2, `lib/board/confirm_sm.c`) — 7.15 keeps the >99-page truncation confirm_sm fixed on 7.14.2: page 100 is labelled "100/100" and its hold approves a prefix
- **F121** (P2, `lib/board/confirm_sm.c`) — 7.15 lets the user hold to approve a body vsnprintf() already cut; 7.14.2/7.14.3 refuse before any ButtonRequest
- **F122** (P3, `lib/board/confirm_sm.c`) — 7.15 emits per-page ButtonRequests from the *_without_button_request() entry points (7.14.2's notify_host gate is missing)
- **F124** (P2, `docs/release/7.15-COMBINED-CANDIDATE.md`) — Acceptance receipt claims "documentation only" over a head carrying 1,670 lines of firmware change
- **F125** (P3, `docs/security/clearsign-provider-tier.md`) — Provider-tier doc says Solana has no per-transaction provider field and no firmware LUT path; head ships both
- **F131** (P2, `lib/firmware/mayachain.c`) — 7.14.2's MAYAChain signTxInit envelope validation + msg-separator/underflow guards are absent on 7.15
- **F132** (P2, `lib/firmware/fsm_msg_thorchain.h`) — 7.14.2's THORChain msg_count/chain_id envelope gate is absent on 7.15 (same underflow/separator exposure as MAYAChain)
- **F133** (P2, `lib/firmware/fsm_msg_thorchain.h`) — THORChain (and MAYAChain) final sign screen omits the signed fee_amount/gas on 7.15, which 7.14.2 and 7.15's own Cosmos/Osmosis/Tendermint screens show
- **F136** (P2, `include/keepkey/transport/messages-hive.options`) — Hive account-name nanopb bounds are one byte short; a legal 16-character account is rejected at decode
- **F137** (P2, `docs/release/7.15-COMBINED-CANDIDATE.md`) — Release-candidate "Dependency pins" sections do not match the gitlinks at head, in all three releases
- **F138** (P3, `.gitmodules`) — .gitmodules branch keys name branches that are not what is pinned, for both dependency submodules
- **F140** (P2, `lib/firmware/solana.c`) — 7.15 never propagated the 7.14.2 "decimals > 18" token-amount fix: high-decimal SPL amounts render with the scale silently dropped
- **F142** (P3, `lib/firmware/signing.c`) — 7.15 applied only the multisig half of the 7.14.2 sighash-suffix hunk; the single-signature segwit branch still writes into the protobuf field and lost the memzero
- **F143** (P2, `lib/firmware/solana.c`) — 7.14.2's "scale never dropped" fix for decimals > 18 did not propagate to 7.15 (and its test was deleted)
- **F144** (P2, `lib/firmware/thorchain.c`) — 7.14.2 ThorchainSignTx envelope validation + msgs_remaining guards absent on 7.15; msgs_remaining underflows
- **F147** (P2, `lib/firmware/mayachain.c`) — 7.14.2's msgs[] comma separator (has_message) never landed on 7.15 — a 2-message MAYAChain tx is signed over invalid JSON
- **F148** (P2, `lib/firmware/mayachain.c`) — 7.14.2's fail-closed mayachain_signTxInit and the msgs_remaining==0 guards are absent on 7.15 — msg_count=0 arms the session and underflows the counter
- **F150** (P3, `.github/workflows/ci.yml`) — publish-emulator-libs ships a rolling public release gated on one job, not the graph
- **F154** (P1, `lib/board/confirm_sm.c`) — 7.15 pager truncates at the 99-page cap instead of refusing; 7.14.2's fix is not propagated
- **F158** (P2, `unittests/firmware/thorchain.cpp`) — 7.14.2's chain_id safe-text refusal (and its test) never reached 7.15; unvalidated chain_id is rendered on the sign screen
- **F163** (P3, `tools/merge_direction_gate.py`) — Merge-direction gate exits 0 and reports "0 files" when git fails or the SHAs are absent
- **F166** (P2, `include/keepkey/firmware/ripple.h`) — RIPPLE_MAX_DROPS is ~7 orders of magnitude too small; XRP payments over 100,000 XRP that 7.14.x signed correctly are now hard-refused
- **F167** (P3, `lib/firmware/zcash.c`) — Wire-supplied rho is silently truncated to 255 bits instead of rejected as non-canonical
- **F173** (P2, `tools/merge_symbol_gate.py`) — merge_symbol_gate.py reports a clean green run and exits 0 when it has read nothing
- **F177** (P2, `lib/emulator/libkkemu.c`) — kkemu_get_display() still thresholds at >0 while every other 1-bit renderer moved to the dither helper
- **F178** (P3, `lib/emulator/libkkemu.c`) — Poll thread can wedge forever in delay_ms(); kkemu_stop()/kkemu_shutdown() then join with no deadline
- **F181** (P2, `include/keepkey/transport/messages-hive.options`) — Hive account-name fields capped at 15 characters; a legal 16-char account cannot be signed for
- **F186** (P2, `include/keepkey/board/confirm_sm.h`) — confirm_with_custom_layout() does not do the measured routing its header contract promises; transaction-consent screens stay unmeasured and unpaged
- **F187** (P3, `include/keepkey/firmware/authenticator.h`) — Two new AUTH_ERR_TYPE values, one new string: authenticator errors are off by one and AUTH_CANCELLED reports nothing
- **F188** (P2, `unittests/firmware/hive.cpp`) — hived golden vectors never reach the on-device serializer, which still writes the display symbol "HIVE" instead of the wire symbol "STEEM"
- **F192** (P3, `lib/firmware/fsm_msg_zcash.h`) — P2SH accepted as a transparent input scriptPubKey, then signed with a P2PKH key and the wrong scriptCode
- **F195** (P2, `lib/firmware/fsm_msg_solana.h`) — Attested-schema review renders one instruction in full detail and never shows the transaction's other, fully-decoded instructions
- **F196** (P3, `lib/firmware/signing.c`) — sig_with_hashtype[73] is one byte too small for the size it is written for, so the OOB write it was added to remove is only prevented by the separate cap
- **F197** (P3, `unittests/firmware/signed_metadata.cpp`) — key_id=256 aliasing regression assertion passes with or without the production guard
- **F198** (P3, `unittests/firmware/signed_metadata.cpp`) — Icon width cap (review finding 2) is asserted as a constant, never exercised against the code that enforces it
- **F200** (P3, `unittests/firmware/ethereum.cpp`) — LiquiditySelectorChecksDeclaredCalldataLength never reaches the calldata-length guard it is named for
- **F201** (P2, `unittests/firmware/thorchain.cpp`) — ConfirmThorTx memo tests never assert a screen count, so the disclosure they name is untested
- **F208** (P3, `unittests/firmware/solana.cpp`) — New Solana tests are the only callers of the recipient-owner / known-token helpers; no signing path uses them
- **F215** (P3, `lib/firmware/ethereum_contracts/thortx.c`) — 7.14.2's THORChain ABI tail-padding zero check is missing on 7.15 (and on the new Maya path)
- **F217** (P2, `lib/firmware/fsm_msg_mayachain.h`) — 7.14.2's denom-aware MAYAChain amount exponent is bypassed on 7.15's MsgSend path
- **F218** (P2, `lib/firmware/ethereum_contracts/thortx.c`) — 7.14.2's THORChain memo ABI tail-padding zero check is missing on 7.15
- **F222** (P2, `lib/firmware/fsm_msg_mayachain.h`) — 7.14.2's fee/gas disclosure on the MAYAChain (and THORChain) sign screen is missing on 7.15
- **F223** (P3, `lib/firmware/fsm_msg_mayachain.h`) — 7.14.2's MAYAChain msg_count hardening (non-zero check + msgs_remaining guards) is absent on 7.15, leaving an unterminated MsgAck loop
- **F224** (P2, `lib/firmware/mayachain.c`) — 7.14.2's `has_message` comma separator between MAYAChain StdSignDoc msgs is not on 7.15
- **F226** (P2, `lib/board/confirm_sm.c`) — 7.15 lets the 100-page cap truncate a confirmation body; 7.14.2/7.14.3 refuse
- **F227** (P2, `lib/firmware/signing.c`) — Input-side multisig quorum check missing on 7.15 (present on 7.14.2 and 7.14.3)
- **F228** (P3, `lib/board/confirm_sm.c`) — 7.15 downgrades 7.14.2's refuse-on-source-truncation to warn-and-continue
- **F229** (P3, `lib/board/confirm_sm.c`) — `notify_host` suppression for *_without_button_request() paging not propagated to 7.15
- **F237** (P3, `lib/firmware/fsm_msg_common.h`) — 7.15 inserts DUPLICATE into AUTH_ERR_TYPE without extending errMsgStr[]: cancel reports no reason, duplicate reports "Action cancelled"
- **F239** (P2, `docs/release/7.14.3-COMBINED-CANDIDATE.md`) — Recorded dependency pins predate the release's own dice protocol commits
- **F241** (P3, `include/keepkey/transport/messages-hive.options`) — Hive account-name fields sized 16, so a valid 16-character account name fails to decode
- **F243** (P2, `docs/release/7.15-COMBINED-CANDIDATE.md`) — Acceptance receipt certifies a code head 43 non-doc files behind the release head, with two wrong submodule pins
- **F247** (P3, `docs/security/clearsign-provider-tier.md`) — Provider-tier doc says Solana tags 5-8 are reserved and no firmware work exists, but head assigns them to the ALT attestation it implements


## Refuted on re-check

- **F045** (P2, `lib/firmware/eip712.c`) — Aborted domain pass leaves dsname/dsversion/dschainId/dsverifyingContract armed; next domain screen shows fields that are not in the hash
- **F065** (P2, `lib/board/usb.c`) — msg_write() acquiring the shared frame arena destroys RAW-dispatch continuation state, breaking the bootloader's FirmwareUpload abort path
- **F074** (P2, `lib/board/confirm_sm.c`) — Backup subpages emit extra ButtonRequests only under DEBUG_LINK, so CI never exercises the shipping protocol
- **F135** (P3, `deps/device-protocol`) — device-protocol pinned to an unreviewed fork branch when the reviewed twin (PR #122) exists
- **F162** (P2, `tools/check_pallas_ct_disassembly.py`) — CT gate proves "backward", claims "fixed": a secret-dependent loop count or a table branch passes green
- **F168** (P3, `lib/firmware/solana.c`) — KKSOLSC1 schema review describes one instruction while sibling instructions are never displayed
- **F172** (P3, `unittests/board/board.cpp`) — Confirm-pagination round-trip property is uncovered — the shipped pager has no test at all
- **F190** (P3, `lib/firmware/fsm_msg_zcash.h`) — Entire transparent shielding path ships with zero device-level test coverage
- **F211** (P2, `unittests/firmware/zcash.cpp`) — The rk-binding fix has no regression guard at the call site, and the test named for the PCZT path asserts the UNBOUND API still signs
- **F213** (P2, `unittests/firmware/zcash.cpp`) — ZIP-244/ZIP-229 sighash, header-digest and note-commitment vectors carry no provenance and have no differential assertion on the fields they must commit to
- **F231** (P2, `lib/firmware/authenticator.c`) — 7.15 drops 7.14.2's authenticator cache revocation on confirmation refusal

## Triaged by reading (P3)

- F032 (`lib/firmware/eip712.c`) — Domain statics (dsname/dsversion/dschainId/dsverifyingContract) survive every parseVals error path, so a later domain screen shows fields from an aborted request
- F046 (`lib/firmware/eip712.c`) — Struct type names of 33+ chars are re-registered on each use, duplicating their definition in encodeType
- F048 (`lib/firmware/fsm_msg_common.h`) — errMsgStr[] gained one string while the AUTH_ERR_TYPE enum gained two, shifting every new code by one
- F049 (`lib/firmware/fsm_msg_common.h`) — Authenticator writes in fsm_msgPing were missed by CHECK_NOT_BITCOIN_ONLY_LOCKED, so they report Success for a write flash refuses
- F055 (`lib/firmware/app_layout.c`) — Recovery-cipher previous-word indicator wraps onto the "Recovery Cipher:" prompt and both render superimposed
- F056 (`unittests/firmware/signed_metadata.cpp`) — The attestor's only native test re-implements the issuer instead of calling it, so an issuer-side digest change stays green
- F057 (`lib/firmware/authenticator.c`) — removeAuthAccount now validates the identity it is asked to delete, making pre-7.15 non-ASCII accounts undeletable
- F060 (`lib/firmware/ethereum.c`) — Unmapped-chain native amounts now render as an 18-digit Wei integer instead of a scaled decimal
- F061 (`lib/firmware/ethereum_contracts/thortx.c`) — Maya Protocol deposits are narrated to the user as THORChain on every memo screen
- F068 (`lib/firmware/hive.c`) — append_asset() silently truncates a host asset symbol to 6 bytes, so the transfer confirm screen can show a symbol the device did not sign
- F075 (`lib/board/confirm_sm.c`) — confirm_with_custom_layout() does not route consent screens through the measured renderer, contrary to its own contract
- F076 (`lib/board/confirm_sm.c`) — The "Cut Off" warning consumes the caller's only ButtonRequest, leaving the following body page unannounced
- F078 (`lib/firmware/recovery_cipher.c`) — Backspace rebuilds coded_word with the current cipher, but the cipher is re-randomised on every keystroke
- F081 (`lib/firmware/fsm_msg_hive.h`) — bn_format_uint64 return ignored: the transfer screen can show no amount at all
- F083 (`lib/firmware/mayachain.c`) — mayachain_formatAmount keys scaling on the denom "cacao", but its only production caller passes an ASSET name
- F084 (`lib/firmware/mayachain.c`) — Rewritten mayachain_parseConfirmMemo has no firmware caller; its 13 unit tests exercise an unreachable path
- F087 (`lib/firmware/solana.c`) — Signed Solana token attestation and ATA-owner derivation are shipped, documented and unit-tested but have no firmware call site
- F088 (`lib/firmware/thorchain.c`) — Exact-match op tokens drop lowercase "swap"/"add" memos; on the EVM router path that is a hard refusal
- F089 (`lib/firmware/fsm_msg_thorchain.h`) — Deposit asset is screened with a looser predicate than the one that gates signing, so approval precedes rejection
- F095 (`lib/firmware/ethereum_contracts/zxliquidtx.c`) — 7.14.2's "format every amount before the first approval" ordering not carried to 7.15 Uniswap liquidity confirm
- F101 (`include/keepkey/firmware/authenticator.h`) — 7.15 inserted DUPLICATE into AUTH_ERR_TYPE without extending errMsgStr[], so the cancel string now belongs to the wrong code and AUTH_CANCELLED maps to a NULL entry
- F104 (`lib/emulator/libkkemu.c`) — 7.15 kkemu_get_display still thresholds at >0, contradicting the frame ring it is meant to mirror
- F123 (`lib/firmware/signing.c`) — 7.15 dropped the input-side multisig quorum check that 7.14.2 added alongside the output-side one
- F126 (`docs/security/storage-version-downgrade-policy.md`) — Release doc records an already-fixed storage_writeV17 bounds defect as still open, and misquotes the shipped guard
- F127 (`docs/coin-integration/README.md`) — New contributor guide documents a CI system and job that do not exist in this repo
- F128 (`docs/release/SRS-7.15.md`) — SRS publishes an SRAM reserve 1.3-1.8 KB larger than the candidate receipt in the same release, and neither was measured at head
- F129 (`docs/security/pin-kdf-v19-migration.md`) — PIN-KDF doc describes v19 behavior as live without mentioning the compile-time gate that makes all of it dead at head
- F130 (`docs/release/REHEARSAL-SOP.md`) — Canonical SOP anchors the whole release program to a manifest file that is not in the tree
- F134 (`lib/firmware/mayachain.c`) — mayachain_parseConfirmMemo has no production caller on 7.15, but its unit tests still assert clear-signing screen counts
- F139 (`deps/python-keepkey`) — python-keepkey's checked-in _pb2 bindings were generated from a device-protocol revision the firmware does not pin
- F141 (`lib/firmware/signing.c`) — 7.15's signing_validate_input() dropped the 7.14.2 input-side multisig quorum refusal while keeping its sibling signature-length bound
- F145 (`lib/firmware/thorchain.c`) — 7.14.2 multi-message comma separator (has_message) not propagated to 7.15
- F149 (`unittests/firmware/ethereum.cpp`) — 7.15 drops the only tests that pin the chain-scoped 0xeee…ee sentinel and zx_tokenLabelsThisChain, while 7.15 has more live callers of that guard than 7.14.2
- F151 (`.github/workflows/ci.yml`) — secret-scan reverts to a full-history scan on the first push of any new branch
- F152 (`.github/workflows/ci.yml`) — Presign evidence bundle is assembled from the full leg only; the bitcoin-only section renders as all-skips
- F153 (`scripts/release/hash-manifest.sh`) — Release signing-gate self-tests exist but are never executed by any workflow
- F159 (`unittests/firmware/thorchain.cpp`) — msg_count==0 / missing has_msg_count is still accepted on 7.15, and the Update* serializers have no armed-state guard
- F160 (`unittests/firmware/thorchain.cpp`) — Multi-message THORChain StdSignDoc has no ',' separator on 7.15; the 7.14.2 test that pins it is absent
- F161 (`unittests/firmware/usb_rx.cpp`) — PacketStorageIsWipedAfterCallback is compiled out of 7.15's bitcoin-only build by a #if !BITCOIN_ONLY that 7.14.3 proves is unnecessary
- F164 (`tools/check_pallas_ct_disassembly.py`) — bitcoin-only "privacy code absent" check misses the ct_* core it elsewhere requires, and passes a symbol-less image
- F165 (`.github/workflows/release.yml`) — Release build runs the SRAM gate but not the Pallas constant-time gate, and CI does not trigger on tags
- F169 (`lib/firmware/solana.c`) — Five new/retained Solana metadata functions have no firmware caller; unit tests assert behavior no signing screen can produce
- F170 (`lib/firmware/thorchain.c`) — Memo op matching lost case-insensitivity; lowercase "swap"/"add" memos are now unsignable on the ETH router path
- F171 (`lib/firmware/tendermint.c`) — New JSON control-character escaper emits \b and \f, which the chain's canonical encoder never produces
- F174 (`unittests/firmware/CMakeLists.txt`) — authenticator.cpp is excluded from the bitcoin-only unit build although authenticator.c ships in that image
- F175 (`unittests/crypto/CMakeLists.txt`) — zcash-crypto-unit is built and ctest-registered but never executed by CI or release
- F176 (`unittests/board/board.cpp`) — ConfirmBodiesThatOverflowAreDetected asserts on the retired line-count model, not on the shipped overflow guard
- F179 (`lib/emulator/libkkemu.c`) — kkemu_stop() leaves an unconsumed Cancel in rb_main_in whenever no confirm was parked
- F180 (`lib/firmware/signed_metadata.c`) — metadata_schema_moves_value is never computed for v1 blobs, so the pinned-signer branch suppresses the native-value screen unconditionally
- F182 (`include/keepkey/transport/messages-hive.options`) — HiveSignTx.asset_symbol admits 9 characters but only the first 6 are signed
- F183 (`lib/firmware/storage.c`) — storage_getAuthData() leaves decrypted TOTP secrets and the passphrase-derived authdata key live on the stack
- F184 (`lib/firmware/storage.h`) — 912 bytes of permanently-zero CONFIDENTIAL SRAM for the retired V18 clear-sign identity records
- F185 (`lib/firmware/storage.c`) — storage_writeStorageV18/V19 require 3435 bytes but storage_commit()'s only buffer is 2572; the guard is a silent no-op, and the tests never see it
- F189 (`unittests/firmware/hive.cpp`) — The asset symbol NUL-padding check has zero coverage; the two cases labelled as covering it are routed away by wire_symbol()
- F191 (`lib/firmware/fsm_msg_zcash.h`) — Orchard spending key cached in a non-CONFIDENTIAL static for the whole signing session
- F193 (`lib/firmware/fsm_msg_ton.h`) — TonSignTx gate comment asserts TonSignMessage is ungated; the gate is right there
- F194 (`lib/firmware/fsm_msg_tron.h`) — Rationale for dropping the TRON message-signing gate states AdvancedMode is persistent; it is session-scoped
- F199 (`unittests/firmware/signed_metadata.cpp`) — RELAY_ROUTER bytes disagree with the on-chain address the comment claims they were captured from
- F202 (`unittests/firmware/thorchain.cpp`) — Refusal assertions run with an empty decision queue: a regression hangs CI instead of failing
- F203 (`unittests/firmware/thorchain.cpp`) — The end-to-end THORChain signing vector was deleted, not regenerated, in the same commit that changed the signed MsgSend document
- F204 (`unittests/firmware/usb_rx.cpp`) — PacketStorageIsWipedAfterCallback can leave a malformed datagram queued that latches tiny_handler_rejected and hangs firmware-unit
- F205 (`unittests/firmware/usb_rx.cpp`) — New tiny-message poll loops drop the `volatile` guard the rest of the harness uses for MSG_TINY_TYPE_ERROR
- F206 (`unittests/firmware/mayachain.cpp`) — New Mayachain memo tests call parseConfirmMemo with no confirm decisions queued, so a regression hangs firmware-unit instead of failing it
- F207 (`unittests/firmware/ripple.cpp`) — Ripple's two new display-binding fixes and the new memo serializer have zero unit coverage; only the varint arithmetic was tested
- F209 (`unittests/firmware/signing.cpp`) — ScriptTypeChecksumEncodingIsAbiIndependent restates the implementation and never touches the two call sites the fix changed
- F210 (`unittests/firmware/storage.cpp`) — AdvancedMode write-side guard arms the global shadow, not the struct the writer actually serializes from
- F212 (`unittests/firmware/zcash.cpp`) — EmptyBundleDigests_MatchZip244AndZip229 compares the test's own hex to the test's own BLAKE2b and never touches the pinned firmware constants
- F214 (`CMakeLists.txt`) — zcash-crypto-unit, whose only test source is this chunk's file, is built and registered with ctest but never executed by the xunit target CI runs
- F225 (`lib/firmware/fsm_msg_mayachain.h`) — MAYAChain chain_id is never validated as safe text on 7.15, though every sibling Tendermint chain on the same branch validates it
- F232 (`lib/emulator/libkkemu.c`) — 7.15 kkemu_get_display() still thresholds at `> 0`; only the frame-ring path got the dithering fix
- F233 (`lib/firmware/ethereum.c`) — 7.15 keeps the tightened MAX_CHAIN_ID but not 7.14.2's chain-id gate that enforces it at signing init
- F242 (`docs/release/7.15-COMBINED-CANDIDATE.md`) — Shipped protocol pin re-publishes NEAR as supported with the display fields canonical removed as a display-binding hazard
- F244 (`docs/coin-integration/zcash-on-device-ua.md`) — Zcash UA doc claims the shipped flow displays a host-supplied address; head derives it on-device
- F245 (`docs/security/storage-version-downgrade-policy.md`) — Downgrade-policy doc reports an open storage bounds defect that head has already fixed
- F246 (`docs/coin-integration/README.md`) — Coin-integration guide's wire-ID allocation table is wrong and would guide a new coin into occupied IDs
- F248 (`docs/release/SRS-7.15.md`) — SRS verification reference names a storage-version test that does not exist in the pinned host suite
- F249 (`docs/release/REHEARSAL-SOP.md`) — Release SOP and roadmap cite canonical documents that do not exist in the release

## Re-checked at head

The triaged list above records each finding as it was raised. Some of those
were overtaken by another finding's fix, and some were read again and found
unreachable. Both are recorded here so a reader does not mistake the triaged
list for a list of live defects.

Verified already fixed by another finding's change:

- F048, F101 — the authenticator error table now uses a designated initialiser
  per enumerator, so no code can shift and no slot is NULL
- F104, F232 — the emulator dylib adopted the ordered-dither lit-pixel
  predicate the device uses; the `> 0` threshold is gone from both paths
- F123, F141 — `signing_input_multisig_quorum_is_valid()` gates inputs
- F145, F160 — the `has_message` comma separator is emitted
- F225 — the MAYAChain envelope gate validates `chain_id` as safe text

Verified unreachable on this build:

- F068, F081 — `cur_asset()` bounds the symbol to STEEM/SBD/VESTS and pins each
  one's precision, so the formatter can neither truncate a symbol nor overflow
  the amount buffer
- F180 — no firmware-pinned signer exists: `metadata_pubkey_for()` resolves
  runtime-loaded keys only, so the branch that would suppress the native-value
  screen cannot be entered. It is a trap for whoever adds the first pinned
  signer, not a defect at this head
- F185 — `storage_commit()` serialises through `storage_writeV17()`; the
  V18/V19 writers have no caller, and their guards fail closed rather than
  overrun
