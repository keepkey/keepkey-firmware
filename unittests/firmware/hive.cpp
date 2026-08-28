extern "C" {
#include "keepkey/board/font.h"
#include "keepkey/board/layout.h"
#include "keepkey/firmware/hive.h"
}

#include "gtest/gtest.h"

#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

namespace {

void append_varint(std::vector<uint8_t>& out, uint32_t value) {
  do {
    uint8_t byte = static_cast<uint8_t>(value & 0x7f);
    value >>= 7;
    if (value != 0) byte |= 0x80;
    out.push_back(byte);
  } while (value != 0);
}

void append_u16_le(std::vector<uint8_t>& out, uint16_t value) {
  out.push_back(static_cast<uint8_t>(value));
  out.push_back(static_cast<uint8_t>(value >> 8));
}

void append_u32_le(std::vector<uint8_t>& out, uint32_t value) {
  for (int i = 0; i < 4; i++) {
    out.push_back(static_cast<uint8_t>(value >> (8 * i)));
  }
}

void append_string(std::vector<uint8_t>& out, const std::string& value) {
  append_varint(out, static_cast<uint32_t>(value.size()));
  out.insert(out.end(), value.begin(), value.end());
}

std::string slice(const uint8_t* value, uint16_t len) {
  return std::string(reinterpret_cast<const char*>(value), len);
}

std::vector<uint8_t> comment_tx(const std::string& parent_author,
                                const std::string& parent_permlink,
                                const std::string& author,
                                const std::string& permlink,
                                const std::string& title,
                                const std::string& body,
                                const std::string& json_metadata) {
  std::vector<uint8_t> tx;
  append_u16_le(tx, 12345);
  append_u32_le(tx, 67890);
  append_u32_le(tx, 1700000000);
  append_varint(tx, 1);
  append_varint(tx, HIVE_OP_COMMENT);
  append_string(tx, parent_author);
  append_string(tx, parent_permlink);
  append_string(tx, author);
  append_string(tx, permlink);
  append_string(tx, title);
  append_string(tx, body);
  append_string(tx, json_metadata);
  append_varint(tx, 0);
  return tx;
}

// Call sites pass DISPLAY symbols ("HIVE"/"HBD") because that is what the test
// is about; this helper writes what the chain actually serializes. Verified
// against hived itself via condenser_api.get_transaction_hex — see
// Hive.SerializationMatchesHived.
std::string wire_symbol(const std::string& display) {
  if (display == "HIVE") return "STEEM";
  if (display == "HBD") return "SBD";
  return display;
}

void append_asset(std::vector<uint8_t>& out, int64_t amount, uint8_t precision,
                  const std::string& symbol) {
  const std::string wire = wire_symbol(symbol);
  uint64_t raw = static_cast<uint64_t>(amount);
  for (int i = 0; i < 8; i++) {
    out.push_back(static_cast<uint8_t>(raw >> (8 * i)));
  }
  out.push_back(precision);
  for (size_t i = 0; i < 7; i++) {
    out.push_back(i < wire.size() ? static_cast<uint8_t>(wire[i]) : 0);
  }
}

// Wrap already-serialized ops in the 10-byte TaPoS header, op count and the
// empty extensions varint that hive_parseOperations expects.
std::vector<uint8_t> wrap_ops(const std::vector<std::vector<uint8_t>>& ops) {
  std::vector<uint8_t> tx;
  append_u16_le(tx, 12345);
  append_u32_le(tx, 67890);
  append_u32_le(tx, 1700000000);
  append_varint(tx, static_cast<uint32_t>(ops.size()));
  for (const std::vector<uint8_t>& op : ops) {
    tx.insert(tx.end(), op.begin(), op.end());
  }
  append_varint(tx, 0);
  return tx;
}

std::vector<uint8_t> limit_order_create_op(
    const std::string& owner, uint32_t orderid, int64_t sell,
    const std::string& sell_symbol, int64_t receive,
    const std::string& receive_symbol, bool fill_or_kill, uint32_t expiration) {
  std::vector<uint8_t> op;
  append_varint(op, HIVE_OP_LIMIT_ORDER_CREATE);
  append_string(op, owner);
  append_u32_le(op, orderid);
  append_asset(op, sell, 3, sell_symbol);
  append_asset(op, receive, 3, receive_symbol);
  op.push_back(fill_or_kill ? 1 : 0);
  append_u32_le(op, expiration);
  return op;
}

// A limit order priced in VESTS at its CORRECT precision (6), so the
// rejection comes from the symbol whitelist rather than the precision check.
std::vector<uint8_t> limit_order_vests_op() {
  std::vector<uint8_t> op;
  append_varint(op, HIVE_OP_LIMIT_ORDER_CREATE);
  append_string(op, "alice");
  append_u32_le(op, 1);
  append_asset(op, 100, 6, "VESTS");
  append_asset(op, 100, 3, "HBD");
  op.push_back(0);
  append_u32_le(op, 1);
  return op;
}

// transfer_to_vesting with a caller-chosen symbol/precision, so the asset
// validator can be probed with values a correct host would never send.
std::vector<uint8_t> power_up_op(int64_t amount, uint8_t precision,
                                 const std::string& symbol) {
  std::vector<uint8_t> op;
  append_varint(op, HIVE_OP_TRANSFER_TO_VESTING);
  append_string(op, "alice");
  append_string(op, "bob");
  append_asset(op, amount, precision, symbol);
  return op;
}

std::vector<uint8_t> comment_op(const std::string& author,
                                const std::string& permlink) {
  std::vector<uint8_t> op;
  append_varint(op, HIVE_OP_COMMENT);
  append_string(op, "");
  append_string(op, "hive-100");
  append_string(op, author);
  append_string(op, permlink);
  append_string(op, "Title");
  append_string(op, "Body");
  append_string(op, "{}");
  return op;
}

// beneficiaries: (account, basis-point weight) pairs; empty = no extension.
std::vector<uint8_t> comment_options_op(
    const std::string& author, const std::string& permlink,
    const std::vector<std::pair<std::string, uint16_t>>& beneficiaries) {
  std::vector<uint8_t> op;
  append_varint(op, HIVE_OP_COMMENT_OPTIONS);
  append_string(op, author);
  append_string(op, permlink);
  append_asset(op, 1000000, 3, "HBD");
  append_u16_le(op, 10000);
  op.push_back(1);
  op.push_back(1);
  if (beneficiaries.empty()) {
    append_varint(op, 0);
  } else {
    append_varint(op, 1);
    append_varint(op, 0);
    append_varint(op, static_cast<uint32_t>(beneficiaries.size()));
    for (const auto& b : beneficiaries) {
      append_string(op, b.first);
      append_u16_le(op, b.second);
    }
  }
  return op;
}

std::vector<uint8_t> account_update2_op(const std::string& json_metadata,
                                        const std::string& posting_metadata,
                                        bool authority_present) {
  std::vector<uint8_t> op;
  append_varint(op, HIVE_OP_ACCOUNT_UPDATE2);
  append_string(op, "alice");
  op.push_back(authority_present ? 1 : 0);
  op.push_back(0);
  op.push_back(0);
  op.push_back(0);
  append_string(op, json_metadata);
  append_string(op, posting_metadata);
  append_varint(op, 0);
  return op;
}

std::vector<uint8_t> custom_json_op(
    const std::vector<std::string>& active_auths,
    const std::vector<std::string>& posting_auths, const std::string& id,
    const std::string& json) {
  std::vector<uint8_t> op;
  append_varint(op, HIVE_OP_CUSTOM_JSON);
  append_varint(op, static_cast<uint32_t>(active_auths.size()));
  for (const std::string& auth : active_auths) append_string(op, auth);
  append_varint(op, static_cast<uint32_t>(posting_auths.size()));
  for (const std::string& auth : posting_auths) append_string(op, auth);
  append_string(op, id);
  append_string(op, json);
  return op;
}

}  // namespace

TEST(Hive, Slip48PathValidation) {
  uint32_t path[5] = {HIVE_SLIP48_PURPOSE, HIVE_SLIP48_NETWORK,
                      HIVE_ROLE_ACTIVE, 0x80000007u, 0x80000000u};

  EXPECT_TRUE(hive_slip48_path_valid(path, 5));
  EXPECT_TRUE(hive_slip48_path_valid_for_role(path, 5, HIVE_ROLE_ACTIVE));
  EXPECT_FALSE(hive_slip48_path_valid_for_role(path, 5, HIVE_ROLE_OWNER));
  EXPECT_FALSE(hive_slip48_path_valid(path, 4));

  path[0] = 0x8000002cu;
  EXPECT_FALSE(hive_slip48_path_valid(path, 5));
  path[0] = HIVE_SLIP48_PURPOSE;
  path[1] = 0x8000003cu;
  EXPECT_FALSE(hive_slip48_path_valid(path, 5));
  path[1] = HIVE_SLIP48_NETWORK;
  path[2] = 0x80000002u;
  EXPECT_FALSE(hive_slip48_path_valid(path, 5));
  path[2] = HIVE_ROLE_ACTIVE;
  path[3] = 7;
  EXPECT_FALSE(hive_slip48_path_valid(path, 5));
  path[3] = 0x80000007u;
  path[4] = 0;
  EXPECT_FALSE(hive_slip48_path_valid(path, 5));
}

TEST(Hive, CommentParserRetainsEveryDisplayedField) {
  std::vector<uint8_t> tx = comment_tx(
      "parent-author", "parent-permlink", "reply-author", "reply-permlink",
      "Reply title", "Complete reply body", "{\"tags\":[\"keepkey\"]}");

  HiveParsedTx parsed;
  ASSERT_EQ(nullptr, hive_parseOperations(tx.data(), tx.size(), &parsed));
  ASSERT_EQ(1, parsed.num_ops);
  const HiveTxOp& op = parsed.ops[0];
  EXPECT_FALSE(op.is_top_level);
  EXPECT_EQ("reply-author", slice(op.acct, op.acct_len));
  EXPECT_EQ("parent-author", slice(op.parent_author, op.parent_author_len));
  EXPECT_EQ("parent-permlink",
            slice(op.parent_permlink, op.parent_permlink_len));
  EXPECT_EQ("reply-permlink", slice(op.permlink, op.permlink_len));
  EXPECT_EQ("Reply title", slice(op.target, op.target_len));
  EXPECT_EQ("Complete reply body", slice(op.detail, op.detail_len));
  EXPECT_EQ("{\"tags\":[\"keepkey\"]}",
            slice(op.json_metadata, op.json_metadata_len));
}

// Message signing is restricted to printable ASCII so a message can never be a
// binary transaction preimage (chain_id || serialized_tx) on any chain id.
TEST(Hive, MessagePrintableAcceptsAsciiRejectsBinary) {
  const char* login = "keepkey-login-challenge:1700000000";
  EXPECT_TRUE(hive_message_is_printable(reinterpret_cast<const uint8_t*>(login),
                                        strlen(login)));

  // Empty message is trivially printable.
  EXPECT_TRUE(
      hive_message_is_printable(reinterpret_cast<const uint8_t*>(""), 0));

  // Any non-printable byte (control char / high bit) is refused.
  const uint8_t withNul[] = {'h', 'i', 0x00, 'x'};
  EXPECT_FALSE(hive_message_is_printable(withNul, sizeof(withNul)));
  const uint8_t highBit[] = {'o', 'k', 0x80};
  EXPECT_FALSE(hive_message_is_printable(highBit, sizeof(highBit)));

  // The oracle vector: a "message" that begins with the binary mainnet chain id
  // (beeab0de00...) followed by a serialized tx. The leading 0xbe/0xea/0x00
  // bytes are non-printable, so this can never be signed as a message.
  const uint8_t chainIdPrefixed[] = {0xbe, 0xea, 0xb0, 0xde, 0x00,
                                     0x00, 0x00, 't',  'x'};
  EXPECT_FALSE(
      hive_message_is_printable(chainIdPrefixed, sizeof(chainIdPrefixed)));
}

TEST(Hive, TopLevelCommentRetainsCategoryAndEmptyTitle) {
  std::vector<uint8_t> tx = comment_tx("", "hive-123456", "post-author",
                                       "post-permlink", "", "Post body", "{}");

  HiveParsedTx parsed;
  ASSERT_EQ(nullptr, hive_parseOperations(tx.data(), tx.size(), &parsed));
  const HiveTxOp& op = parsed.ops[0];
  EXPECT_TRUE(op.is_top_level);
  EXPECT_EQ(0, op.parent_author_len);
  EXPECT_EQ("hive-123456", slice(op.parent_permlink, op.parent_permlink_len));
  EXPECT_EQ("post-permlink", slice(op.permlink, op.permlink_len));
  EXPECT_EQ(0, op.target_len);
  EXPECT_EQ("{}", slice(op.json_metadata, op.json_metadata_len));
}

TEST(Hive, RejectsNonCanonicalVarints) {
  std::vector<uint8_t> op;
  append_varint(op, HIVE_OP_VOTE);
  append_string(op, "alice");
  append_string(op, "bob");
  append_string(op, "post");
  append_u16_le(op, 10000);

  HiveParsedTx parsed;

  // Operation count 1 encoded as 0x81 0x00 instead of canonical 0x01.
  std::vector<uint8_t> overlong_count = wrap_ops({op});
  overlong_count[10] = 0x81;
  overlong_count.insert(overlong_count.begin() + 11, 0x00);
  EXPECT_NE(nullptr, hive_parseOperations(overlong_count.data(),
                                          overlong_count.size(), &parsed));

  // The voter string length 5 encoded as 0x85 0x00.
  std::vector<uint8_t> overlong_string = wrap_ops({op});
  overlong_string[12] = 0x85;
  overlong_string.insert(overlong_string.begin() + 13, 0x00);
  EXPECT_NE(nullptr, hive_parseOperations(overlong_string.data(),
                                          overlong_string.size(), &parsed));
}

TEST(Hive, RejectsAccountNamesThatCanSpoofTheDisplay) {
  HiveParsedTx parsed;
  const std::vector<std::string> invalid = {
      "al\nice", std::string("ali\0ce", 6), "Alice", "alice-", ".alice", "a"};
  for (const std::string& account : invalid) {
    std::vector<uint8_t> op;
    append_varint(op, HIVE_OP_TRANSFER_TO_SAVINGS);
    append_string(op, account);
    append_string(op, "bob");
    append_asset(op, 1000, 3, "HIVE");
    append_string(op, "");
    std::vector<uint8_t> tx = wrap_ops({op});
    EXPECT_NE(nullptr, hive_parseOperations(tx.data(), tx.size(), &parsed));
  }
}

TEST(Hive, CustomJsonRetainsAndBoundsEveryAuthorization) {
  HiveParsedTx parsed;
  std::vector<uint8_t> tx =
      wrap_ops({custom_json_op({}, {"alice", "bob", "carol"}, "follow", "[]")});
  ASSERT_EQ(nullptr, hive_parseOperations(tx.data(), tx.size(), &parsed));
  const HiveTxOp& op = parsed.ops[0];
  ASSERT_EQ(3, op.n_auths);
  EXPECT_EQ("alice", slice(op.auth_acct[0], op.auth_acct_len[0]));
  EXPECT_EQ("bob", slice(op.auth_acct[1], op.auth_acct_len[1]));
  EXPECT_EQ("carol", slice(op.auth_acct[2], op.auth_acct_len[2]));
  EXPECT_FALSE(parsed.needs_active);

  std::vector<uint8_t> too_many = wrap_ops({custom_json_op(
      {}, {"alice", "bob", "carol", "dave", "erin"}, "follow", "[]")});
  EXPECT_NE(nullptr,
            hive_parseOperations(too_many.data(), too_many.size(), &parsed));

  std::vector<uint8_t> unsorted =
      wrap_ops({custom_json_op({}, {"bob", "alice"}, "follow", "[]")});
  EXPECT_NE(nullptr,
            hive_parseOperations(unsorted.data(), unsorted.size(), &parsed));

  std::vector<uint8_t> duplicate =
      wrap_ops({custom_json_op({}, {"alice", "alice"}, "follow", "[]")});
  EXPECT_NE(nullptr,
            hive_parseOperations(duplicate.data(), duplicate.size(), &parsed));
}

TEST(Hive, DisplayPaginationUsesRenderedBodyRows) {
  const std::string payload =
      "%%%%%%%%%%%%%%%% %%%%%%%%%%%%%%%% %%%%%%%%%%%%%%%% %%%%%%%%%%%%%%%%";
  ASSERT_GT(calc_str_line(get_body_font(), payload.c_str(), BODY_WIDTH),
            BODY_ROWS);

  std::string reconstructed;
  size_t offset = 0;
  unsigned pages = 0;
  while (offset < payload.size()) {
    size_t take = calc_str_page(get_body_font(), payload.data() + offset,
                                payload.size() - offset, BODY_WIDTH, BODY_ROWS);
    ASSERT_GT(take, 0u);
    const std::string page = payload.substr(offset, take);
    EXPECT_LE(calc_str_line(get_body_font(), page.c_str(), BODY_WIDTH),
              BODY_ROWS);
    reconstructed += page;
    offset += take;
    pages++;
  }

  EXPECT_GT(pages, 1u);
  EXPECT_EQ(payload, reconstructed);
}

// ── Phase-3 op table ────────────────────────────────────────────────────────

// The op that started this: a HIVE->HBD internal-market swap. Every field the
// approval screen shows must survive the parse.
TEST(Hive, LimitOrderCreateRetainsEveryDisplayedField) {
  std::vector<uint8_t> tx = wrap_ops({limit_order_create_op(
      "alice", 42, 1500, "HIVE", 400, "HBD", true, 1700003600)});

  HiveParsedTx parsed;
  ASSERT_EQ(nullptr, hive_parseOperations(tx.data(), tx.size(), &parsed));
  ASSERT_EQ(1, parsed.num_ops);
  const HiveTxOp& op = parsed.ops[0];
  EXPECT_EQ(HIVE_OP_LIMIT_ORDER_CREATE, op.op_type);
  EXPECT_EQ("alice", slice(op.acct, op.acct_len));
  EXPECT_EQ(42u, op.req_id);
  EXPECT_EQ(1700003600u, op.expiration);
  EXPECT_TRUE(op.flag);  // fill_or_kill
  ASSERT_EQ(2, op.n_assets);
  EXPECT_EQ(1500u, hive_assetAmount(op.assets[0]));
  EXPECT_STREQ("HIVE", hive_assetSymbol(op.assets[0]));
  EXPECT_EQ(3, hive_assetPrecision(op.assets[0]));
  EXPECT_EQ(400u, hive_assetAmount(op.assets[1]));
  EXPECT_STREQ("HBD", hive_assetSymbol(op.assets[1]));
  // Trading needs the active key.
  EXPECT_TRUE(parsed.needs_active);
}

TEST(Hive, LimitOrderRejectsDegenerateOrders) {
  HiveParsedTx parsed;

  // A same-symbol pair is a no-op trade on screen but still burns the fill.
  std::vector<uint8_t> same = wrap_ops(
      {limit_order_create_op("alice", 1, 100, "HIVE", 100, "HIVE", false, 1)});
  EXPECT_NE(nullptr, hive_parseOperations(same.data(), same.size(), &parsed));

  std::vector<uint8_t> zero_sell = wrap_ops(
      {limit_order_create_op("alice", 1, 0, "HIVE", 100, "HBD", false, 1)});
  EXPECT_NE(nullptr,
            hive_parseOperations(zero_sell.data(), zero_sell.size(), &parsed));

  std::vector<uint8_t> zero_recv = wrap_ops(
      {limit_order_create_op("alice", 1, 100, "HIVE", 0, "HBD", false, 1)});
  EXPECT_NE(nullptr,
            hive_parseOperations(zero_recv.data(), zero_recv.size(), &parsed));

  // VESTS never trades on the internal market.
  std::vector<uint8_t> vests = wrap_ops({limit_order_vests_op()});
  EXPECT_NE(nullptr, hive_parseOperations(vests.data(), vests.size(), &parsed));
}

TEST(Hive, LimitOrderCancelParses) {
  std::vector<uint8_t> op;
  append_varint(op, HIVE_OP_LIMIT_ORDER_CANCEL);
  append_string(op, "alice");
  append_u32_le(op, 42);
  std::vector<uint8_t> tx = wrap_ops({op});

  HiveParsedTx parsed;
  ASSERT_EQ(nullptr, hive_parseOperations(tx.data(), tx.size(), &parsed));
  EXPECT_EQ("alice", slice(parsed.ops[0].acct, parsed.ops[0].acct_len));
  EXPECT_EQ(42u, parsed.ops[0].req_id);
  EXPECT_TRUE(parsed.needs_active);
}

// The asset validator is what stops a host from moving the decimal point or
// swapping a ~2000x-more-valuable symbol behind an identical-looking number.
TEST(Hive, AssetValidatorPinsSymbolAndPrecision) {
  HiveParsedTx parsed;

  std::vector<uint8_t> ok = wrap_ops({power_up_op(1000, 3, "HIVE")});
  EXPECT_EQ(nullptr, hive_parseOperations(ok.data(), ok.size(), &parsed));

  // transfer_to_vesting is HIVE-only; HBD and VESTS are out of the whitelist.
  std::vector<uint8_t> hbd = wrap_ops({power_up_op(1000, 3, "HBD")});
  EXPECT_NE(nullptr, hive_parseOperations(hbd.data(), hbd.size(), &parsed));
  std::vector<uint8_t> vests = wrap_ops({power_up_op(1000, 6, "VESTS")});
  EXPECT_NE(nullptr, hive_parseOperations(vests.data(), vests.size(), &parsed));

  // Right symbol, wrong precision: 1000 would render as 0.001 vs 1.000.
  std::vector<uint8_t> prec = wrap_ops({power_up_op(1000, 6, "HIVE")});
  EXPECT_NE(nullptr, hive_parseOperations(prec.data(), prec.size(), &parsed));

  // A negative int64 would print as an enormous positive number.
  std::vector<uint8_t> negative = wrap_ops({power_up_op(-1000, 3, "HIVE")});
  EXPECT_NE(nullptr,
            hive_parseOperations(negative.data(), negative.size(), &parsed));

  // Unknown symbol, and a longer symbol sharing an accepted prefix.
  std::vector<uint8_t> unknown = wrap_ops({power_up_op(1000, 3, "SBD")});
  EXPECT_NE(nullptr,
            hive_parseOperations(unknown.data(), unknown.size(), &parsed));
  std::vector<uint8_t> prefixed = wrap_ops({power_up_op(1000, 3, "HIVEX")});
  EXPECT_NE(nullptr,
            hive_parseOperations(prefixed.data(), prefixed.size(), &parsed));
}

// Zero is a real instruction for some ops and nonsense for others; the parser
// must not apply one blanket rule.
TEST(Hive, ZeroAmountSemanticsDifferPerOp) {
  HiveParsedTx parsed;

  // Zero HIVE power-up: nothing to do, reject.
  std::vector<uint8_t> power_up = wrap_ops({power_up_op(0, 3, "HIVE")});
  EXPECT_NE(nullptr,
            hive_parseOperations(power_up.data(), power_up.size(), &parsed));

  // Zero VESTS withdraw_vesting: cancels an in-progress power-down, accept.
  std::vector<uint8_t> stop_pd;
  {
    std::vector<uint8_t> op;
    append_varint(op, HIVE_OP_WITHDRAW_VESTING);
    append_string(op, "alice");
    append_asset(op, 0, 6, "VESTS");
    stop_pd = wrap_ops({op});
  }
  EXPECT_EQ(nullptr,
            hive_parseOperations(stop_pd.data(), stop_pd.size(), &parsed));

  // Zero VESTS delegation: removes an existing delegation, accept.
  std::vector<uint8_t> undelegate;
  {
    std::vector<uint8_t> op;
    append_varint(op, HIVE_OP_DELEGATE_VESTING_SHARES);
    append_string(op, "alice");
    append_string(op, "bob");
    append_asset(op, 0, 6, "VESTS");
    undelegate = wrap_ops({op});
  }
  EXPECT_EQ(nullptr, hive_parseOperations(undelegate.data(), undelegate.size(),
                                          &parsed));

  // claim_reward_balance with all three at zero: nothing to claim, reject.
  std::vector<uint8_t> empty_claim;
  {
    std::vector<uint8_t> op;
    append_varint(op, HIVE_OP_CLAIM_REWARD_BALANCE);
    append_string(op, "alice");
    append_asset(op, 0, 3, "HIVE");
    append_asset(op, 0, 3, "HBD");
    append_asset(op, 0, 6, "VESTS");
    empty_claim = wrap_ops({op});
  }
  EXPECT_NE(nullptr, hive_parseOperations(empty_claim.data(),
                                          empty_claim.size(), &parsed));
}

TEST(Hive, ClaimRewardBalanceKeepsAssetOrder) {
  std::vector<uint8_t> op;
  append_varint(op, HIVE_OP_CLAIM_REWARD_BALANCE);
  append_string(op, "alice");
  append_asset(op, 1234, 3, "HIVE");
  append_asset(op, 5678, 3, "HBD");
  append_asset(op, 90123456, 6, "VESTS");
  std::vector<uint8_t> tx = wrap_ops({op});

  HiveParsedTx parsed;
  ASSERT_EQ(nullptr, hive_parseOperations(tx.data(), tx.size(), &parsed));
  ASSERT_EQ(3, parsed.ops[0].n_assets);
  EXPECT_EQ(1234u, hive_assetAmount(parsed.ops[0].assets[0]));
  EXPECT_STREQ("HIVE", hive_assetSymbol(parsed.ops[0].assets[0]));
  EXPECT_EQ(5678u, hive_assetAmount(parsed.ops[0].assets[1]));
  EXPECT_STREQ("HBD", hive_assetSymbol(parsed.ops[0].assets[1]));
  EXPECT_EQ(90123456u, hive_assetAmount(parsed.ops[0].assets[2]));
  EXPECT_STREQ("VESTS", hive_assetSymbol(parsed.ops[0].assets[2]));
  // Claiming rewards is a posting-tier action.
  EXPECT_FALSE(parsed.needs_active);
}

// SECURITY: comment_options redirects a post's payout. Detached from its
// comment it could retarget a post the user published earlier and is not
// reviewing on screen.
TEST(Hive, CommentOptionsMustBindToItsComment) {
  HiveParsedTx parsed;

  std::vector<uint8_t> alone =
      wrap_ops({comment_options_op("alice", "my-post", {})});
  EXPECT_NE(nullptr, hive_parseOperations(alone.data(), alone.size(), &parsed));

  std::vector<uint8_t> wrong_permlink =
      wrap_ops({comment_op("alice", "my-post"),
                comment_options_op("alice", "other-post", {})});
  EXPECT_NE(nullptr, hive_parseOperations(wrong_permlink.data(),
                                          wrong_permlink.size(), &parsed));

  std::vector<uint8_t> wrong_author =
      wrap_ops({comment_op("alice", "my-post"),
                comment_options_op("mallory", "my-post", {})});
  EXPECT_NE(nullptr, hive_parseOperations(wrong_author.data(),
                                          wrong_author.size(), &parsed));

  std::vector<uint8_t> ok =
      wrap_ops({comment_op("alice", "my-post"),
                comment_options_op("alice", "my-post", {})});
  ASSERT_EQ(nullptr, hive_parseOperations(ok.data(), ok.size(), &parsed));
  EXPECT_EQ(2, parsed.num_ops);
  EXPECT_EQ(10000, parsed.ops[1].weight);  // percent_hbd
  EXPECT_FALSE(parsed.needs_active);
}

TEST(Hive, CommentOptionsBeneficiaryRules) {
  HiveParsedTx parsed;

  std::vector<uint8_t> ok =
      wrap_ops({comment_op("alice", "my-post"),
                comment_options_op("alice", "my-post",
                                   {{"aaron", 1000}, {"zoe", 500}})});
  ASSERT_EQ(nullptr, hive_parseOperations(ok.data(), ok.size(), &parsed));
  ASSERT_EQ(2, parsed.ops[1].n_benef);
  EXPECT_EQ("aaron", slice(parsed.ops[1].benef_acct[0],
                           parsed.ops[1].benef_acct_len[0]));
  EXPECT_EQ(1000, parsed.ops[1].benef_weight[0]);
  EXPECT_EQ("zoe", slice(parsed.ops[1].benef_acct[1],
                         parsed.ops[1].benef_acct_len[1]));

  // hived requires strictly ascending names; unsorted is rejected on-chain.
  std::vector<uint8_t> unsorted =
      wrap_ops({comment_op("alice", "my-post"),
                comment_options_op("alice", "my-post",
                                   {{"zoe", 500}, {"aaron", 1000}})});
  EXPECT_NE(nullptr,
            hive_parseOperations(unsorted.data(), unsorted.size(), &parsed));

  // Duplicates are the same violation.
  std::vector<uint8_t> duped =
      wrap_ops({comment_op("alice", "my-post"),
                comment_options_op("alice", "my-post",
                                   {{"aaron", 500}, {"aaron", 500}})});
  EXPECT_NE(nullptr, hive_parseOperations(duped.data(), duped.size(), &parsed));

  // Weights may not add up to more than 100%.
  std::vector<uint8_t> overweight =
      wrap_ops({comment_op("alice", "my-post"),
                comment_options_op("alice", "my-post",
                                   {{"aaron", 6000}, {"zoe", 5000}})});
  EXPECT_NE(nullptr, hive_parseOperations(overweight.data(), overweight.size(),
                                          &parsed));
}

// SECURITY: account_update2 can rotate account keys. Only the profile-metadata
// form is in the table — the op-9/10 exclusion applied field-level.
TEST(Hive, AccountUpdate2RejectsAuthorityChanges) {
  HiveParsedTx parsed;

  std::vector<uint8_t> authority =
      wrap_ops({account_update2_op("{\"profile\":{}}", "", true)});
  EXPECT_NE(nullptr,
            hive_parseOperations(authority.data(), authority.size(), &parsed));

  std::vector<uint8_t> empty = wrap_ops({account_update2_op("", "", false)});
  EXPECT_NE(nullptr, hive_parseOperations(empty.data(), empty.size(), &parsed));

  // json_metadata is an active-key field.
  std::vector<uint8_t> active =
      wrap_ops({account_update2_op("{\"profile\":{}}", "", false)});
  ASSERT_EQ(nullptr,
            hive_parseOperations(active.data(), active.size(), &parsed));
  EXPECT_TRUE(parsed.needs_active);

  // posting_json_metadata alone stays on the posting tier.
  std::vector<uint8_t> posting =
      wrap_ops({account_update2_op("", "{\"profile\":{}}", false)});
  ASSERT_EQ(nullptr,
            hive_parseOperations(posting.data(), posting.size(), &parsed));
  EXPECT_FALSE(parsed.needs_active);
}

TEST(Hive, SavingsWithdrawRetainsDisplayedFields) {
  std::vector<uint8_t> op;
  append_varint(op, HIVE_OP_TRANSFER_FROM_SAVINGS);
  append_string(op, "alice");
  append_u32_le(op, 7);
  append_string(op, "bob");
  append_asset(op, 2500, 3, "HBD");
  append_string(op, "rent");
  std::vector<uint8_t> tx = wrap_ops({op});

  HiveParsedTx parsed;
  ASSERT_EQ(nullptr, hive_parseOperations(tx.data(), tx.size(), &parsed));
  // request_id sits BETWEEN from and to on the wire — the easiest field-order
  // bug to make in this op, and the one that would swap displayed accounts.
  EXPECT_EQ("alice", slice(parsed.ops[0].acct, parsed.ops[0].acct_len));
  EXPECT_EQ(7u, parsed.ops[0].req_id);
  EXPECT_EQ("bob", slice(parsed.ops[0].target, parsed.ops[0].target_len));
  EXPECT_EQ("rent", slice(parsed.ops[0].detail, parsed.ops[0].detail_len));
  EXPECT_EQ(2500u, hive_assetAmount(parsed.ops[0].assets[0]));
  EXPECT_TRUE(parsed.needs_active);
}

TEST(Hive, SavingsDepositRetainsDisplayedFields) {
  std::vector<uint8_t> op;
  append_varint(op, HIVE_OP_TRANSFER_TO_SAVINGS);
  append_string(op, "alice");
  append_string(op, "bob");
  append_asset(op, 1500, 3, "HIVE");
  append_string(op, "");
  std::vector<uint8_t> tx = wrap_ops({op});

  HiveParsedTx parsed;
  ASSERT_EQ(nullptr, hive_parseOperations(tx.data(), tx.size(), &parsed));
  EXPECT_EQ("alice", slice(parsed.ops[0].acct, parsed.ops[0].acct_len));
  EXPECT_EQ("bob", slice(parsed.ops[0].target, parsed.ops[0].target_len));
  EXPECT_EQ(0, parsed.ops[0].detail_len);  // empty memo is legal
  EXPECT_EQ(1500u, hive_assetAmount(parsed.ops[0].assets[0]));
}

// An empty `to` means "power up to self" on Hive, not a malformed field.
TEST(Hive, PowerUpAcceptsEmptyDestination) {
  std::vector<uint8_t> op;
  append_varint(op, HIVE_OP_TRANSFER_TO_VESTING);
  append_string(op, "alice");
  append_string(op, "");
  append_asset(op, 1000, 3, "HIVE");
  std::vector<uint8_t> tx = wrap_ops({op});

  HiveParsedTx parsed;
  ASSERT_EQ(nullptr, hive_parseOperations(tx.data(), tx.size(), &parsed));
  EXPECT_EQ(0, parsed.ops[0].target_len);
}

// Truncating any op body by one byte must be refused, never partially parsed:
// the signature covers the whole buffer, so a short read would mean signing
// bytes the device never looked at.
TEST(Hive, TruncatedOpBodiesRejected) {
  std::vector<std::vector<uint8_t>> bodies;
  bodies.push_back(
      limit_order_create_op("alice", 1, 100, "HIVE", 50, "HBD", false, 9));
  bodies.push_back(power_up_op(1000, 3, "HIVE"));
  {
    std::vector<uint8_t> op;
    append_varint(op, HIVE_OP_CLAIM_REWARD_BALANCE);
    append_string(op, "alice");
    append_asset(op, 1, 3, "HIVE");
    append_asset(op, 1, 3, "HBD");
    append_asset(op, 1, 6, "VESTS");
    bodies.push_back(op);
  }
  {
    std::vector<uint8_t> op;
    append_varint(op, HIVE_OP_TRANSFER_FROM_SAVINGS);
    append_string(op, "alice");
    append_u32_le(op, 7);
    append_string(op, "bob");
    append_asset(op, 2500, 3, "HBD");
    append_string(op, "memo");
    bodies.push_back(op);
  }

  HiveParsedTx parsed;
  for (const std::vector<uint8_t>& body : bodies) {
    ASSERT_EQ(nullptr, hive_parseOperations(wrap_ops({body}).data(),
                                            wrap_ops({body}).size(), &parsed));
    for (size_t cut = 1; cut < body.size(); cut++) {
      std::vector<uint8_t> truncated(body.begin(), body.end() - cut);
      std::vector<uint8_t> tx = wrap_ops({truncated});
      EXPECT_NE(nullptr, hive_parseOperations(tx.data(), tx.size(), &parsed))
          << "op type " << (unsigned)body[0] << " truncated by " << cut;
    }
  }
}

TEST(Hive, CommentOptionsExtensionShapeRejected) {
  HiveParsedTx parsed;
  const std::vector<uint8_t> comment = comment_op("alice", "my-post");

  // More than one extension could split beneficiaries past a per-extension cap.
  {
    std::vector<uint8_t> op;
    append_varint(op, HIVE_OP_COMMENT_OPTIONS);
    append_string(op, "alice");
    append_string(op, "my-post");
    append_asset(op, 1000000, 3, "HBD");
    append_u16_le(op, 10000);
    op.push_back(1);
    op.push_back(1);
    append_varint(op, 2);
    std::vector<uint8_t> tx = wrap_ops({comment, op});
    EXPECT_NE(nullptr, hive_parseOperations(tx.data(), tx.size(), &parsed));
  }
  // Only comment_payout_beneficiaries (tag 0) is in the table.
  {
    std::vector<uint8_t> op;
    append_varint(op, HIVE_OP_COMMENT_OPTIONS);
    append_string(op, "alice");
    append_string(op, "my-post");
    append_asset(op, 1000000, 3, "HBD");
    append_u16_le(op, 10000);
    op.push_back(1);
    op.push_back(1);
    append_varint(op, 1);
    append_varint(op, 1);  // tag != 0
    std::vector<uint8_t> tx = wrap_ops({comment, op});
    EXPECT_NE(nullptr, hive_parseOperations(tx.data(), tx.size(), &parsed));
  }
  // Zero beneficiaries in a present extension is malformed, not "none".
  {
    std::vector<uint8_t> tx =
        wrap_ops({comment, comment_options_op("alice", "my-post", {})});
    ASSERT_EQ(nullptr, hive_parseOperations(tx.data(), tx.size(), &parsed));
    std::vector<uint8_t> op;
    append_varint(op, HIVE_OP_COMMENT_OPTIONS);
    append_string(op, "alice");
    append_string(op, "my-post");
    append_asset(op, 1000000, 3, "HBD");
    append_u16_le(op, 10000);
    op.push_back(1);
    op.push_back(1);
    append_varint(op, 1);
    append_varint(op, 0);
    append_varint(op, 0);  // n_benef = 0
    std::vector<uint8_t> bad = wrap_ops({comment, op});
    EXPECT_NE(nullptr, hive_parseOperations(bad.data(), bad.size(), &parsed));
  }
}

TEST(Hive, AccountUpdate2RejectsNonEmptyExtensions) {
  std::vector<uint8_t> op;
  append_varint(op, HIVE_OP_ACCOUNT_UPDATE2);
  append_string(op, "alice");
  for (int i = 0; i < 4; i++) op.push_back(0);
  append_string(op, "{\"profile\":{}}");
  append_string(op, "");
  append_varint(op, 1);  // extensions must be empty
  std::vector<uint8_t> tx = wrap_ops({op});

  HiveParsedTx parsed;
  EXPECT_NE(nullptr, hive_parseOperations(tx.data(), tx.size(), &parsed));
}

// Graphene bools are one byte; anything but 0/1 is a host serializer bug.
TEST(Hive, RejectsNonCanonicalBool) {
  // limit_order_create's fill_or_kill byte, set to 2.
  std::vector<uint8_t> op;
  append_varint(op, HIVE_OP_LIMIT_ORDER_CREATE);
  append_string(op, "alice");
  append_u32_le(op, 1);
  append_asset(op, 100, 3, "HIVE");
  append_asset(op, 50, 3, "HBD");
  op.push_back(2);
  append_u32_le(op, 9);
  std::vector<uint8_t> tx = wrap_ops({op});

  HiveParsedTx parsed;
  EXPECT_NE(nullptr, hive_parseOperations(tx.data(), tx.size(), &parsed));
}

TEST(Hive, MixedTierOpsRejected) {
  // vote is posting-tier, convert is active-tier; one signature cannot
  // satisfy both post-HF28.
  std::vector<uint8_t> vote;
  append_varint(vote, HIVE_OP_VOTE);
  append_string(vote, "alice");
  append_string(vote, "bob");
  append_string(vote, "a-post");
  append_u16_le(vote, 10000);

  std::vector<uint8_t> convert;
  append_varint(convert, HIVE_OP_CONVERT);
  append_string(convert, "alice");
  append_u32_le(convert, 1);
  append_asset(convert, 1000, 3, "HBD");

  std::vector<uint8_t> tx = wrap_ops({vote, convert});
  HiveParsedTx parsed;
  EXPECT_NE(nullptr, hive_parseOperations(tx.data(), tx.size(), &parsed));
}

TEST(Hive, ExcludedAndUnknownOpsStillRejected) {
  HiveParsedTx parsed;

  // Ops 2/9/10 keep their dedicated message types — never fold them in.
  for (uint32_t excluded : {static_cast<uint32_t>(HIVE_OP_TRANSFER),
                            static_cast<uint32_t>(HIVE_OP_ACCOUNT_CREATE),
                            static_cast<uint32_t>(HIVE_OP_ACCOUNT_UPDATE)}) {
    std::vector<uint8_t> op;
    append_varint(op, excluded);
    append_string(op, "alice");
    std::vector<uint8_t> tx = wrap_ops({op});
    EXPECT_NE(nullptr, hive_parseOperations(tx.data(), tx.size(), &parsed));
  }

  // Anything outside the table is refused; there is no blind-sign fallback.
  // 49 = recurrent_transfer, a real op deliberately not in the table.
  std::vector<uint8_t> unknown;
  append_varint(unknown, 49);
  append_string(unknown, "alice");
  std::vector<uint8_t> tx = wrap_ops({unknown});
  EXPECT_NE(nullptr, hive_parseOperations(tx.data(), tx.size(), &parsed));
}

// Trailing bytes after a well-formed op must not be silently accepted: the
// signature covers them, so what the device displays would be a subset of
// what it signs.
TEST(Hive, TrailingBytesRejected) {
  std::vector<uint8_t> tx = wrap_ops(
      {limit_order_create_op("alice", 1, 100, "HIVE", 50, "HBD", false, 1)});
  tx.push_back(0xff);

  HiveParsedTx parsed;
  EXPECT_NE(nullptr, hive_parseOperations(tx.data(), tx.size(), &parsed));
}

// ---------------------------------------------------------------------------
// Golden vectors produced by hived itself:
//
//   curl -X POST https://api.hive.blog -H 'Content-Type: application/json' \
//     -d '{"jsonrpc":"2.0","method":"condenser_api.get_transaction_hex",
//          "params":[<tx>],"id":1}'
//
// These exist because our serializer and this parser were byte-exact mirrors
// of EACH OTHER while both disagreed with the chain: we wrote "HIVE"/"HBD"
// where hived writes "STEEM"/"SBD". Two wrongs cancelled and every test
// passed, but the device signed bytes hived could not validate — it reported
// "missing required active authority", because signature recovery over
// different bytes yields a key in no authority. A vector the chain generated
// is the only kind that can catch that class of bug.
// ---------------------------------------------------------------------------

std::vector<uint8_t> from_hex(const std::string& hex) {
  std::vector<uint8_t> out;
  for (size_t i = 0; i + 1 < hex.size(); i += 2) {
    out.push_back(
        static_cast<uint8_t>(std::stoul(hex.substr(i, 2), nullptr, 16)));
  }
  return out;
}

// Header shared by both vectors below: ref_block_num 4660 / prefix 0xdeadbeef
// (0/0 for the second) and expiration 2021-01-14T02:19:44.
//
// get_transaction_hex serializes a full transaction, so its output ends with a
// varint count of the `signatures` array. The device is handed the digest
// preimage, which stops after the extensions varint — so the trailing "00"
// from hived's hex is dropped in the goldens below. Everything before it must
// match byte for byte.
TEST(Hive, SerializationMatchesHivedLimitOrderCreate) {
  const std::string golden =
      "3412efbeadde40aaff5f010505616c6963652a000000dc05000000000000035354"
      "45454d00009001000000000000035342440000000001b0f5536500";

  std::vector<uint8_t> tx;
  append_u16_le(tx, 4660);
  append_u32_le(tx, 0xdeadbeef);
  append_u32_le(tx, 0x5fffaa40);
  append_varint(tx, 1);
  std::vector<uint8_t> op = limit_order_create_op("alice", 42, 1500, "HIVE",
                                                  400, "HBD", true, 0x6553f5b0);
  tx.insert(tx.end(), op.begin(), op.end());
  append_varint(tx, 0);  // extensions

  EXPECT_EQ(from_hex(golden), tx);

  // and the parser accepts what the chain produces
  HiveParsedTx parsed;
  ASSERT_EQ(nullptr, hive_parseOperations(tx.data(), tx.size(), &parsed));
  EXPECT_STREQ("HIVE", hive_assetSymbol(parsed.ops[0].assets[0]));
  EXPECT_STREQ("HBD", hive_assetSymbol(parsed.ops[0].assets[1]));
}

TEST(Hive, SerializationMatchesHivedClaimRewardBalance) {
  const std::string golden =
      "00000000000040aaff5f012705616c696365e8030000000000000353544545"
      "4d0000d0070000000000000353424400000000c0c62d0000000000065645535453"
      "000000";

  std::vector<uint8_t> tx;
  append_u16_le(tx, 0);
  append_u32_le(tx, 0);
  append_u32_le(tx, 0x5fffaa40);
  append_varint(tx, 1);
  append_varint(tx, HIVE_OP_CLAIM_REWARD_BALANCE);
  append_string(tx, "alice");
  append_asset(tx, 1000, 3, "HIVE");
  append_asset(tx, 2000, 3, "HBD");
  append_asset(tx, 3000000, 6, "VESTS");
  append_varint(tx, 0);  // extensions

  EXPECT_EQ(from_hex(golden), tx);

  HiveParsedTx parsed;
  ASSERT_EQ(nullptr, hive_parseOperations(tx.data(), tx.size(), &parsed));
  EXPECT_STREQ("VESTS", hive_assetSymbol(parsed.ops[0].assets[2]));
}
