#ifndef KEEPKEY_FIRMWARE_HIVE_H
#define KEEPKEY_FIRMWARE_HIVE_H

#include "trezor/crypto/bip32.h"
#include "messages-hive.pb.h"

// ── Hive mainnet chain ID ─────────────────────────────────────────────────
#define HIVE_CHAIN_ID                                \
  "\xbe\xea\xb0\xde\x00\x00\x00\x00\x00\x00\x00\x00" \
  "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" \
  "\x00\x00\x00\x00\x00\x00\x00\x00"

#define HIVE_CHAIN_ID_LEN 32

// ── STM public key prefix (Hive inherited from Steem / Graphene) ──────────
#define HIVE_PUBKEY_PREFIX "STM"

// ── SLIP-0048 derivation constants (all hardened) ─────────────────────────
// Path: m/48'/13'/role'/account_index'/0'
// 13' is the de-facto Hive network index shipped by Ledger (LedgerHQ/app-hive)
// and hive-ledger-cli, NOT the slip-0048.md registry entry (0xbee = 3054',
// which no wallet implements). Chosen deliberately for seed-level key
// compatibility with the existing hardware-wallet ecosystem.
#define HIVE_SLIP48_PURPOSE (0x80000030u)  // 48'
#define HIVE_SLIP48_NETWORK (0x8000000Du)  // 13'
#define HIVE_ROLE_OWNER \
  (0x80000000u)  // 0'  — account recovery, authority changes
#define HIVE_ROLE_ACTIVE (0x80000001u)   // 1'  — transfers, staking
#define HIVE_ROLE_MEMO (0x80000003u)     // 3'  — memo field encryption
#define HIVE_ROLE_POSTING (0x80000004u)  // 4'  — votes, posts, follows

/**
 * Validate a complete Hive SLIP-0048 path:
 * m/48'/13'/role'/account'/0'. The role must be one of owner, active, memo,
 * or posting; every component is hardened.
 */
bool hive_slip48_path_valid(const uint32_t* address_n, size_t count);

/** Validate a complete Hive SLIP-0048 path for one required role. */
bool hive_slip48_path_valid_for_role(const uint32_t* address_n, size_t count,
                                     uint32_t required_role);

// ── Graphene operation type IDs ───────────────────────────────────────────
#define HIVE_OP_VOTE 0
#define HIVE_OP_COMMENT 1
#define HIVE_OP_TRANSFER 2
#define HIVE_OP_TRANSFER_TO_VESTING 3
#define HIVE_OP_WITHDRAW_VESTING 4
#define HIVE_OP_LIMIT_ORDER_CREATE 5
#define HIVE_OP_LIMIT_ORDER_CANCEL 6
#define HIVE_OP_CONVERT 8
#define HIVE_OP_ACCOUNT_CREATE 9
#define HIVE_OP_ACCOUNT_UPDATE 10
#define HIVE_OP_CUSTOM_JSON 18
#define HIVE_OP_COMMENT_OPTIONS 19
#define HIVE_OP_TRANSFER_TO_SAVINGS 32
#define HIVE_OP_TRANSFER_FROM_SAVINGS 33
#define HIVE_OP_CLAIM_REWARD_BALANCE 39
#define HIVE_OP_DELEGATE_VESTING_SHARES 40
#define HIVE_OP_ACCOUNT_UPDATE2 43

// ── Protocol limits ───────────────────────────────────────────────────────
#define HIVE_DECIMALS 3  // HIVE and HBD both use 3 decimal places
// Maximum memo length that fits safely in the signer's tx_buf[512] with all
// other fields. Non-memo overhead: header(12) + from(17) + to(17) + asset(16)
// + footer(1) = ~63 bytes. 512 - 63 - 3 (varint) = 446; 440 is conservative.
#define HIVE_MAX_MEMO_LEN 440
// Maximum signable message length. MUST match HiveSignMessage.message
// max_size in messages-hive.options (proto cap and code cap kept in sync).
#define HIVE_MAX_MESSAGE_LEN 1024
// Maximum host-serialized transaction length for HiveSignOperations. MUST
// match HiveSignOperations.serialized_tx max_size in messages-hive.options.
#define HIVE_MAX_OPS_TX_LEN 2048
// Maximum operations per HiveSignOperations transaction.
#define HIVE_MAX_TX_OPS 4
// Graphene asset: int64 LE amount + uint8 precision + 7-byte NUL-padded
// symbol (append_asset layout).
#define HIVE_ASSET_LEN 16
// Most assets carried by a single op in the table (claim_reward_balance
// carries three: HIVE, HBD, VESTS).
#define HIVE_MAX_OP_ASSETS 3
// Most comment_payout_beneficiaries entries accepted on a comment_options op.
// Matches the host serializer's cap; hived itself allows more, but eight is
// all that can be reviewed on the OLED before approval fatigue sets in.
#define HIVE_MAX_BENEFICIARIES 8
// Maximum custom_json authorization accounts accepted per operation. Every
// account is confirmed individually; bounding the set prevents an unreviewable
// approval loop and keeps the parsed transaction's static RAM use predictable.
#define HIVE_MAX_CUSTOM_JSON_AUTHS 4

// Symbol whitelist bits for the asset parser. Every asset field in the op
// table pins an explicit set — an op that accepts HIVE must never silently
// accept VESTS, since the two differ by 1000x in displayed magnitude.
#define HIVE_SYM_HIVE (1u << 0)
#define HIVE_SYM_HBD (1u << 1)
#define HIVE_SYM_VESTS (1u << 2)

// ── Public API ────────────────────────────────────────────────────────────
/**
 * Encode a 33-byte compressed public key in Hive/Steem STM-prefix base58
 * format. Uses RIPEMD checksum (Graphene convention, not SHA256d).
 */
bool hive_getPublicKey(const uint8_t public_key[33], char* out, size_t out_len);

/**
 * Derive one SLIP-0048 role key for a given account index to raw 33 bytes.
 * role_hardened: HIVE_ROLE_OWNER | HIVE_ROLE_ACTIVE | HIVE_ROLE_MEMO |
 * HIVE_ROLE_POSTING account_index_hardened: account_index | 0x80000000u Returns
 * false if derivation fails.
 */
bool hive_deriveRawKey(const HDNode* root, uint32_t role_hardened,
                       uint32_t account_index_hardened, uint8_t out[33]);

/**
 * Derive all four SLIP-0048 role keys for a given account index and encode
 * each as an STM-prefixed string. All output buffers must be >= 64 bytes.
 * Returns false if any derivation or encoding step fails.
 */
bool hive_getPublicKeys(const HDNode* root, uint32_t account_index,
                        char* owner_out, size_t owner_len, char* active_out,
                        size_t active_len, char* memo_out, size_t memo_len,
                        char* posting_out, size_t posting_len);

/**
 * Sign a Hive transfer transaction (op type 2).
 * Rejects memos longer than HIVE_MAX_MEMO_LEN (440 bytes).
 */
void hive_signTx(const HDNode* node, const HiveSignTx* msg, HiveSignedTx* resp);

// ── Parsed operations (HiveSignOperations) ────────────────────────────────

typedef struct {
  uint32_t op_type;
  bool needs_active;  // custom_json with required_auths; false = posting tier
  // Borrowed slices into the request's serialized_tx (NOT NUL-terminated):
  const uint8_t* acct;  // vote: voter / comment: author / cj: first auth name
  uint16_t acct_len;
  const uint8_t* target;  // vote: author / comment: title / cj: id
  uint16_t target_len;
  const uint8_t* detail;  // vote: permlink / comment: body / cj: json
  uint16_t detail_len;
  const uint8_t* parent_author;  // comment only
  uint16_t parent_author_len;
  const uint8_t*
      parent_permlink;  // comment only (category for a top-level post)
  uint16_t parent_permlink_len;
  const uint8_t* permlink;  // comment only: this post/reply's permlink
  uint16_t permlink_len;
  const uint8_t* json_metadata;  // comment only
  uint16_t json_metadata_len;
  int16_t weight;     // vote (-10000..10000), or a 0..10000 basis-point
                      // percent (comment_options percent_hbd,
                      // set_withdraw_vesting_route percent)
  bool is_top_level;  // comment only: parent_author empty
  uint8_t n_auths;    // custom_json only: total auth account names
  const uint8_t* auth_acct[HIVE_MAX_CUSTOM_JSON_AUTHS];
  uint16_t auth_acct_len[HIVE_MAX_CUSTOM_JSON_AUTHS];

  // ── Phase-3 op fields ───────────────────────────────────────────────────
  // Borrowed HIVE_ASSET_LEN-byte asset slices in the op's own field order:
  //   transfer_to_vesting/convert/claim_account/savings: [0] = amount
  //   withdraw_vesting/delegate_vesting_shares:          [0] = vesting_shares
  //   limit_order_create:      [0] = amount_to_sell, [1] = min_to_receive
  //   claim_reward_balance:    [0] = HIVE, [1] = HBD, [2] = VESTS
  //   comment_options:         [0] = max_accepted_payout
  const uint8_t* assets[HIVE_MAX_OP_ASSETS];
  uint8_t n_assets;
  uint32_t req_id;      // convert requestid / savings request_id / order id
  uint32_t expiration;  // limit_order_create only
  bool flag;            // fill_or_kill / approve / auto_vest / allow_votes
  bool flag2;           // comment_options: allow_curation_rewards
  uint8_t n_benef;      // comment_options: beneficiary count (0 = none)
  const uint8_t* benef_acct[HIVE_MAX_BENEFICIARIES];
  uint16_t benef_acct_len[HIVE_MAX_BENEFICIARIES];
  uint16_t benef_weight[HIVE_MAX_BENEFICIARIES];  // basis points
} HiveTxOp;

typedef struct {
  uint8_t num_ops;
  bool needs_active;  // tx tier: active' path required, else posting'
  HiveTxOp ops[HIVE_MAX_TX_OPS];
} HiveParsedTx;

/**
 * Parse and validate a host-serialized Graphene transaction against the
 * device clear-sign op table. Returns NULL on success or a static error
 * message. Slices in `out` borrow from `tx` — keep it alive.
 *
 * Ops 2 (transfer), 9 (account_create) and 10 (account_update) are
 * permanently excluded; everything not in the table is refused outright —
 * there is no blind-sign fallback.
 */
const char* hive_parseOperations(const uint8_t* tx, size_t len,
                                 HiveParsedTx* out);

/**
 * Accessors for a HIVE_ASSET_LEN-byte asset slice stored in HiveTxOp.assets.
 * The parser has already validated the symbol/precision pair, so the symbol
 * is always a NUL-terminated "HIVE" / "HBD" / "VESTS" and the amount is
 * non-negative.
 */
uint64_t hive_assetAmount(const uint8_t* asset);
uint8_t hive_assetPrecision(const uint8_t* asset);
const char* hive_assetSymbol(const uint8_t* asset);

/**
 * Sign a parsed HiveSignOperations transaction: digest is
 * SHA256(chain_id || serialized_tx), identical to HiveSignTx. The caller
 * (FSM handler) is responsible for parsing, display, and role checks.
 */
void hive_signOperations(const HDNode* node, const HiveSignOperations* msg,
                         HiveSignedOperations* resp);

/**
 * Sign an arbitrary message per the Hive Keychain signBuffer contract:
 * signature over SHA256(message bytes) only — no chain_id prepend, no
 * message prefix. Emits the 65-byte compact recoverable signature plus the
 * signing key's 33-byte compressed public key.
 */
void hive_signMessage(const HDNode* node, const HiveSignMessage* msg,
                      HiveSignedMessage* resp);

/**
 * True iff every byte is printable ASCII (0x20-0x7e). Hive message signing
 * requires this: a transaction digest is SHA256(chain_id || serialized_tx)
 * whose chain_id and serialized fields are binary, so a printable-only message
 * domain can never collide with a transaction preimage on ANY chain id. This
 * closes the cross-chain message→transaction signature oracle that a
 * mainnet-only prefix reject cannot. Empty (len == 0) returns true.
 */
bool hive_message_is_printable(const uint8_t* message, size_t len);

/**
 * Sign a Hive account_create transaction (op type 9).
 * owner/active/posting/memo_raw must be device-derived 33-byte compressed keys.
 * The firmware uses these directly; host-supplied key strings in msg are
 * ignored.
 */
void hive_signAccountCreate(const HDNode* signing_node,
                            const HiveSignAccountCreate* msg,
                            const uint8_t owner_raw[33],
                            const uint8_t active_raw[33],
                            const uint8_t posting_raw[33],
                            const uint8_t memo_raw[33],
                            HiveSignedAccountCreate* resp);

/**
 * Sign a Hive account_update transaction (op type 10).
 * owner/active/posting/memo_raw must be device-derived 33-byte compressed keys.
 * The firmware uses these directly; host-supplied new_*_key strings in msg are
 * ignored.
 */
void hive_signAccountUpdate(const HDNode* signing_node,
                            const HiveSignAccountUpdate* msg,
                            const uint8_t owner_raw[33],
                            const uint8_t active_raw[33],
                            const uint8_t posting_raw[33],
                            const uint8_t memo_raw[33],
                            HiveSignedAccountUpdate* resp);

#endif  // KEEPKEY_FIRMWARE_HIVE_H
