extern "C" {
#include "keepkey/firmware/tron.h"
}

#include "gtest/gtest.h"
#include <cstring>
#include <vector>

/* ------------------------------------------------------------------ */
/*  Minimal protobuf wire-format writer for building raw_data vectors  */
/* ------------------------------------------------------------------ */

namespace {

void putVarint(std::vector<uint8_t>& out, uint64_t v) {
  while (v >= 0x80) {
    out.push_back(static_cast<uint8_t>(v) | 0x80);
    v >>= 7;
  }
  out.push_back(static_cast<uint8_t>(v));
}

void putKey(std::vector<uint8_t>& out, uint32_t field, uint8_t wire) {
  putVarint(out, (static_cast<uint64_t>(field) << 3) | wire);
}

void putVarintField(std::vector<uint8_t>& out, uint32_t field, uint64_t v) {
  putKey(out, field, 0);
  putVarint(out, v);
}

void putBytesField(std::vector<uint8_t>& out, uint32_t field,
                   const std::vector<uint8_t>& bytes) {
  putKey(out, field, 2);
  putVarint(out, bytes.size());
  out.insert(out.end(), bytes.begin(), bytes.end());
}

void putStringField(std::vector<uint8_t>& out, uint32_t field,
                    const char* str) {
  putBytesField(out, field,
                std::vector<uint8_t>(str, str + strlen(str)));
}

std::vector<uint8_t> tronAddr(uint8_t fill) {
  std::vector<uint8_t> a(21, fill);
  a[0] = 0x41;
  return a;
}

/* protocol.TransferContract { owner=1, to=2, amount=3 } */
std::vector<uint8_t> transferContractValue(const std::vector<uint8_t>& owner,
                                           const std::vector<uint8_t>& to,
                                           uint64_t amount) {
  std::vector<uint8_t> v;
  putBytesField(v, 1, owner);
  putBytesField(v, 2, to);
  putVarintField(v, 3, amount);
  return v;
}

/* TRC-20 transfer(address,uint256) calldata */
std::vector<uint8_t> trc20Calldata(const std::vector<uint8_t>& to21,
                                   uint64_t amount, bool tronStylePrefix) {
  std::vector<uint8_t> d = {0xa9, 0x05, 0x9c, 0xbb};
  /* address word */
  for (int i = 0; i < 11; i++) d.push_back(0);
  d.push_back(tronStylePrefix ? 0x41 : 0x00);
  d.insert(d.end(), to21.begin() + 1, to21.end()); /* low 20 bytes */
  /* amount word: big-endian uint256 */
  for (int i = 0; i < 24; i++) d.push_back(0);
  for (int i = 7; i >= 0; i--)
    d.push_back(static_cast<uint8_t>(amount >> (8 * i)));
  return d;
}

/* protocol.TriggerSmartContract { owner=1, contract=2, call_value=3, data=4 } */
std::vector<uint8_t> triggerContractValue(const std::vector<uint8_t>& owner,
                                          const std::vector<uint8_t>& contract,
                                          const std::vector<uint8_t>& data) {
  std::vector<uint8_t> v;
  putBytesField(v, 1, owner);
  putBytesField(v, 2, contract);
  putBytesField(v, 4, data);
  return v;
}

/* Transaction.Contract { type=1, parameter=2 (Any{type_url=1, value=2}) } */
std::vector<uint8_t> contractMsg(uint64_t type, const char* type_url,
                                 const std::vector<uint8_t>& value) {
  std::vector<uint8_t> any;
  putStringField(any, 1, type_url);
  putBytesField(any, 2, value);

  std::vector<uint8_t> c;
  putVarintField(c, 1, type);
  putBytesField(c, 2, any);
  return c;
}

/* Transaction.raw with typical TronGrid framing */
std::vector<uint8_t> rawTx(const std::vector<uint8_t>& contract,
                           const char* memo, uint64_t fee_limit) {
  std::vector<uint8_t> raw;
  putBytesField(raw, 1, {0xab, 0xcd});                     /* ref_block_bytes */
  putBytesField(raw, 4, std::vector<uint8_t>(8, 0x5a));    /* ref_block_hash */
  putVarintField(raw, 8, 1750000000000ULL);                /* expiration */
  if (memo) putStringField(raw, 10, memo);
  putBytesField(raw, 11, contract);
  putVarintField(raw, 14, 1749999000000ULL);               /* timestamp */
  if (fee_limit) putVarintField(raw, 18, fee_limit);
  return raw;
}

const char* TRANSFER_URL = "type.googleapis.com/protocol.TransferContract";
const char* TRIGGER_URL = "type.googleapis.com/protocol.TriggerSmartContract";

}  // namespace

TEST(Tron, ParseNativeTransfer) {
  auto owner = tronAddr(0x11);
  auto to = tronAddr(0x22);
  auto raw = rawTx(contractMsg(1, TRANSFER_URL,
                               transferContractValue(owner, to, 1000000)),
                   nullptr, 0);

  TronParsedTx parsed;
  EXPECT_EQ(tron_parseRawTx(raw.data(), raw.size(), &parsed),
            TRON_TX_TRANSFER);
  EXPECT_EQ(memcmp(parsed.owner, owner.data(), 21), 0);
  EXPECT_EQ(memcmp(parsed.to, to.data(), 21), 0);
  EXPECT_EQ(parsed.amount, 1000000u);
  EXPECT_FALSE(parsed.has_fee_limit);
  EXPECT_EQ(parsed.memo_len, 0);
}

TEST(Tron, ParseNativeTransferWithSwapMemo) {
  const char* memo = "=:ETH.ETH:0x41e5560054824ea6b0732e656e3ad64e20e94e45:0/1/0:kk:75";
  auto raw = rawTx(contractMsg(1, TRANSFER_URL,
                               transferContractValue(tronAddr(0x11),
                                                     tronAddr(0x22), 5000000)),
                   memo, 0);

  TronParsedTx parsed;
  EXPECT_EQ(tron_parseRawTx(raw.data(), raw.size(), &parsed),
            TRON_TX_TRANSFER);
  ASSERT_EQ(parsed.memo_len, strlen(memo));
  EXPECT_EQ(memcmp(parsed.memo, memo, parsed.memo_len), 0);
}

TEST(Tron, ParseTrc20Transfer) {
  auto owner = tronAddr(0x11);
  auto to = tronAddr(0x22);
  auto token = tronAddr(0x33);
  for (bool tronStyle : {false, true}) {
    auto raw = rawTx(
        contractMsg(31, TRIGGER_URL,
                    triggerContractValue(
                        owner, token, trc20Calldata(to, 123456789, tronStyle))),
        nullptr, 100000000 /* 100 TRX fee_limit */);

    TronParsedTx parsed;
    EXPECT_EQ(tron_parseRawTx(raw.data(), raw.size(), &parsed),
              TRON_TX_TRC20_TRANSFER);
    EXPECT_EQ(memcmp(parsed.owner, owner.data(), 21), 0);
    EXPECT_EQ(memcmp(parsed.to, to.data(), 21), 0);
    EXPECT_EQ(memcmp(parsed.contract, token.data(), 21), 0);
    EXPECT_TRUE(parsed.has_fee_limit);
    EXPECT_EQ(parsed.fee_limit, 100000000u);

    char amount[90];
    ASSERT_TRUE(tron_formatTrc20Amount(parsed.trc20_amount, amount,
                                       sizeof(amount)));
    EXPECT_STREQ(amount, "123456789");
  }
}

TEST(Tron, ParseTrc20TransferWithMemo) {
  /* Vault splices THORChain swap memos into raw_data.data for TRC-20 swaps */
  const char* memo = "=:e:0x1234:0:kk:75";
  auto raw = rawTx(contractMsg(31, TRIGGER_URL,
                               triggerContractValue(
                                   tronAddr(0x11), tronAddr(0x33),
                                   trc20Calldata(tronAddr(0x22), 42, false))),
                   memo, 30000000);

  TronParsedTx parsed;
  EXPECT_EQ(tron_parseRawTx(raw.data(), raw.size(), &parsed),
            TRON_TX_TRC20_TRANSFER);
  ASSERT_EQ(parsed.memo_len, strlen(memo));
  EXPECT_EQ(memcmp(parsed.memo, memo, parsed.memo_len), 0);
}

TEST(Tron, RejectWrongSelector) {
  auto data = trc20Calldata(tronAddr(0x22), 42, false);
  data[0] = 0x09; /* approve(address,uint256) = 0x095ea7b3... not transfer */
  auto raw = rawTx(contractMsg(31, TRIGGER_URL,
                               triggerContractValue(tronAddr(0x11),
                                                    tronAddr(0x33), data)),
                   nullptr, 0);

  TronParsedTx parsed;
  EXPECT_EQ(tron_parseRawTx(raw.data(), raw.size(), &parsed),
            TRON_TX_UNVERIFIED);
}

TEST(Tron, RejectDirtyAddressWord) {
  auto data = trc20Calldata(tronAddr(0x22), 42, false);
  data[4 + 3] = 0x01; /* junk in the high bytes of the address word */
  auto raw = rawTx(contractMsg(31, TRIGGER_URL,
                               triggerContractValue(tronAddr(0x11),
                                                    tronAddr(0x33), data)),
                   nullptr, 0);

  TronParsedTx parsed;
  EXPECT_EQ(tron_parseRawTx(raw.data(), raw.size(), &parsed),
            TRON_TX_UNVERIFIED);
}

TEST(Tron, RejectCalldataLengthMismatch) {
  auto data = trc20Calldata(tronAddr(0x22), 42, false);
  data.push_back(0x00); /* trailing byte — could smuggle params */
  auto raw = rawTx(contractMsg(31, TRIGGER_URL,
                               triggerContractValue(tronAddr(0x11),
                                                    tronAddr(0x33), data)),
                   nullptr, 0);

  TronParsedTx parsed;
  EXPECT_EQ(tron_parseRawTx(raw.data(), raw.size(), &parsed),
            TRON_TX_UNVERIFIED);
}

TEST(Tron, RejectNonzeroCallValue) {
  auto value = triggerContractValue(tronAddr(0x11), tronAddr(0x33),
                                    trc20Calldata(tronAddr(0x22), 42, false));
  std::vector<uint8_t> withCallValue;
  putBytesField(withCallValue, 1, tronAddr(0x11));
  putBytesField(withCallValue, 2, tronAddr(0x33));
  putVarintField(withCallValue, 3, 7 /* nonzero TRX attached */);
  putBytesField(withCallValue, 4, trc20Calldata(tronAddr(0x22), 42, false));
  auto raw = rawTx(contractMsg(31, TRIGGER_URL, withCallValue), nullptr, 0);

  TronParsedTx parsed;
  EXPECT_EQ(tron_parseRawTx(raw.data(), raw.size(), &parsed),
            TRON_TX_UNVERIFIED);

  /* zero call_value explicitly present is fine */
  std::vector<uint8_t> zeroCallValue;
  putBytesField(zeroCallValue, 1, tronAddr(0x11));
  putBytesField(zeroCallValue, 2, tronAddr(0x33));
  putVarintField(zeroCallValue, 3, 0);
  putBytesField(zeroCallValue, 4, trc20Calldata(tronAddr(0x22), 42, false));
  raw = rawTx(contractMsg(31, TRIGGER_URL, zeroCallValue), nullptr, 0);
  EXPECT_EQ(tron_parseRawTx(raw.data(), raw.size(), &parsed),
            TRON_TX_TRC20_TRANSFER);
}

TEST(Tron, RejectTrc10Fields) {
  std::vector<uint8_t> v;
  putBytesField(v, 1, tronAddr(0x11));
  putBytesField(v, 2, tronAddr(0x33));
  putBytesField(v, 4, trc20Calldata(tronAddr(0x22), 42, false));
  putVarintField(v, 5, 1000001); /* call_token_value / token_id territory */
  auto raw = rawTx(contractMsg(31, TRIGGER_URL, v), nullptr, 0);

  TronParsedTx parsed;
  EXPECT_EQ(tron_parseRawTx(raw.data(), raw.size(), &parsed),
            TRON_TX_UNVERIFIED);
}

TEST(Tron, RejectMultipleContracts) {
  auto contract = contractMsg(
      1, TRANSFER_URL,
      transferContractValue(tronAddr(0x11), tronAddr(0x22), 1));
  std::vector<uint8_t> raw;
  putBytesField(raw, 11, contract);
  putBytesField(raw, 11, contract);

  TronParsedTx parsed;
  EXPECT_EQ(tron_parseRawTx(raw.data(), raw.size(), &parsed),
            TRON_TX_UNVERIFIED);
}

TEST(Tron, RejectUnknownTopLevelField) {
  auto raw = rawTx(contractMsg(1, TRANSFER_URL,
                               transferContractValue(tronAddr(0x11),
                                                     tronAddr(0x22), 1)),
                   nullptr, 0);
  putBytesField(raw, 9, {0x01}); /* auths — permission delegation */

  TronParsedTx parsed;
  EXPECT_EQ(tron_parseRawTx(raw.data(), raw.size(), &parsed),
            TRON_TX_UNVERIFIED);
}

TEST(Tron, RejectExtraFieldInTransferContract) {
  auto value = transferContractValue(tronAddr(0x11), tronAddr(0x22), 1);
  putVarintField(value, 4, 99);
  auto raw = rawTx(contractMsg(1, TRANSFER_URL, value), nullptr, 0);

  TronParsedTx parsed;
  EXPECT_EQ(tron_parseRawTx(raw.data(), raw.size(), &parsed),
            TRON_TX_UNVERIFIED);
}

TEST(Tron, RejectPermissionId) {
  std::vector<uint8_t> any;
  putStringField(any, 1, TRANSFER_URL);
  putBytesField(any, 2,
                transferContractValue(tronAddr(0x11), tronAddr(0x22), 1));
  std::vector<uint8_t> c;
  putVarintField(c, 1, 1);
  putBytesField(c, 2, any);
  putVarintField(c, 5, 2); /* Permission_id — multisig account slot */
  auto raw = rawTx(c, nullptr, 0);

  TronParsedTx parsed;
  EXPECT_EQ(tron_parseRawTx(raw.data(), raw.size(), &parsed),
            TRON_TX_UNVERIFIED);
}

TEST(Tron, RejectDuplicateAnyFields) {
  /* Two type_urls in the Any wrapper — last-wins ambiguity, refuse. */
  std::vector<uint8_t> any;
  putStringField(any, 1, TRIGGER_URL);
  putStringField(any, 1, TRANSFER_URL);
  putBytesField(any, 2,
                transferContractValue(tronAddr(0x11), tronAddr(0x22), 1));
  std::vector<uint8_t> c;
  putVarintField(c, 1, 1);
  putBytesField(c, 2, any);
  auto raw = rawTx(c, nullptr, 0);

  TronParsedTx parsed;
  EXPECT_EQ(tron_parseRawTx(raw.data(), raw.size(), &parsed),
            TRON_TX_UNVERIFIED);

  /* Two value fields likewise */
  std::vector<uint8_t> any2;
  putStringField(any2, 1, TRANSFER_URL);
  putBytesField(any2, 2,
                transferContractValue(tronAddr(0x11), tronAddr(0x22), 1));
  putBytesField(any2, 2,
                transferContractValue(tronAddr(0x11), tronAddr(0x33), 2));
  std::vector<uint8_t> c2;
  putVarintField(c2, 1, 1);
  putBytesField(c2, 2, any2);
  raw = rawTx(c2, nullptr, 0);
  EXPECT_EQ(tron_parseRawTx(raw.data(), raw.size(), &parsed),
            TRON_TX_UNVERIFIED);
}

TEST(Tron, RejectTypeUrlEnumMismatch) {
  /* enum says TransferContract, Any says TriggerSmartContract */
  auto raw = rawTx(contractMsg(1, TRIGGER_URL,
                               transferContractValue(tronAddr(0x11),
                                                     tronAddr(0x22), 1)),
                   nullptr, 0);

  TronParsedTx parsed;
  EXPECT_EQ(tron_parseRawTx(raw.data(), raw.size(), &parsed),
            TRON_TX_UNVERIFIED);
}

TEST(Tron, RejectBadOwnerAddress) {
  auto owner = tronAddr(0x11);
  owner[0] = 0x42; /* wrong network prefix */
  auto raw = rawTx(contractMsg(1, TRANSFER_URL,
                               transferContractValue(owner, tronAddr(0x22), 1)),
                   nullptr, 0);

  TronParsedTx parsed;
  EXPECT_EQ(tron_parseRawTx(raw.data(), raw.size(), &parsed),
            TRON_TX_UNVERIFIED);
}

TEST(Tron, RejectTruncated) {
  /* Build with the contract as the LAST field: any truncation then either
   * cuts into a field (parse failure) or drops the contract entirely —
   * both must be UNVERIFIED. (Truncation at a field boundary that only
   * drops benign trailing fields like timestamp is legal protobuf and
   * stays verified — that case is exercised by the parse tests above.) */
  std::vector<uint8_t> raw;
  putBytesField(raw, 1, {0xab, 0xcd});
  putVarintField(raw, 8, 1750000000000ULL);
  putBytesField(raw, 11,
                contractMsg(1, TRANSFER_URL,
                            transferContractValue(tronAddr(0x11),
                                                  tronAddr(0x22), 1000000)));
  TronParsedTx sanity;
  ASSERT_EQ(tron_parseRawTx(raw.data(), raw.size(), &sanity),
            TRON_TX_TRANSFER);

  for (size_t cut = 1; cut < raw.size(); cut++) {
    TronParsedTx parsed;
    EXPECT_EQ(tron_parseRawTx(raw.data(), raw.size() - cut, &parsed),
              TRON_TX_UNVERIFIED)
        << "cut=" << cut;
  }

  TronParsedTx parsed;
  EXPECT_EQ(tron_parseRawTx(nullptr, 0, &parsed), TRON_TX_UNVERIFIED);
}

TEST(Tron, FormatTrc20AmountUint256) {
  uint8_t amount[32] = {0};
  amount[31] = 0x01;
  char buf[90];
  ASSERT_TRUE(tron_formatTrc20Amount(amount, buf, sizeof(buf)));
  EXPECT_STREQ(buf, "1");

  /* 10^18 — an 18-decimals token unit */
  uint8_t big[32] = {0};
  const uint64_t e18 = 1000000000000000000ULL;
  for (int i = 0; i < 8; i++)
    big[24 + i] = static_cast<uint8_t>(e18 >> (8 * (7 - i)));
  ASSERT_TRUE(tron_formatTrc20Amount(big, buf, sizeof(buf)));
  EXPECT_STREQ(buf, "1000000000000000000");
}

TEST(Tron, AddressFromBytes) {
  /* Base58Check of 41 + 20 bytes must round-trip through the display helper */
  uint8_t addr[21];
  memset(addr, 0x11, sizeof(addr));
  addr[0] = 0x41;
  char out[64];
  ASSERT_TRUE(tron_addressFromBytes(addr, out, sizeof(out)));
  EXPECT_EQ(out[0], 'T'); /* mainnet addresses render as T... */
  EXPECT_GE(strlen(out), 33u);
}
