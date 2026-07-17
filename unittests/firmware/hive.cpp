extern "C" {
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
