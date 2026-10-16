extern "C" {
#include "keepkey/firmware/ethereum.h"
#include "keepkey/firmware/erc7730_capabilities.h"
#include "keepkey/firmware/erc7730_field.h"
#include "keepkey/firmware/erc7730_workflow.h"
}

#include "gtest/gtest.h"

#include <cstring>
#include <string>
#include <vector>

namespace {

std::vector<uint8_t> hex(const char* text) {
  std::vector<uint8_t> out;
  for (size_t i = 0; text[i] && text[i + 1]; i += 2) {
    unsigned value = 0;
    sscanf(text + i, "%2x", &value);
    out.push_back((uint8_t)value);
  }
  return out;
}

std::vector<uint8_t> word(uint64_t value) {
  std::vector<uint8_t> out(32, 0);
  for (int i = 0; i < 8; i++) out[31 - i] = (uint8_t)(value >> (8 * i));
  return out;
}

std::string amount(const std::vector<uint8_t>& value, const char* token,
                   bool native, uint64_t chain, const char* message = nullptr) {
  char out[600];
  const auto address = hex(token);
  if (!erc7730_format_token_amount(value.data(), address.data(), native, chain,
                                   message, out, sizeof(out)))
    return "<refused>";
  return out;
}

const char* kUsdc = "a0b86991c6218b36c1d19d4a2e9eb0ce3606eb48";
const char* kUnknown = "1111111111111111111111111111111111111111";

}  // namespace

// EIP-55's own test vectors.
TEST(Erc7730Field, AddressIsEip55AndMarksOnlyTheSigner) {
  char out[64];
  const auto a = hex("5aaeb6053f3e94c9b9a09f33669435e7ef1beaed");
  ASSERT_TRUE(erc7730_format_address(a.data(), false, out, sizeof(out)));
  EXPECT_STREQ(out, "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed");
  const auto b = hex("fb6916095ca1df60bb79ce92ce3ea74c37c5d359");
  ASSERT_TRUE(erc7730_format_address(b.data(), true, out, sizeof(out)));
  EXPECT_STREQ(out,
               "0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359\n(this wallet)");
  EXPECT_FALSE(erc7730_format_address(b.data(), true, out, 43));
}

// Ticker and decimals come from the firmware table for the chain; the same
// address on another chain, the zero address and an unlisted address are
// unknown tokens, shown as the exact integer and the address.
TEST(Erc7730Field, TokenAmountUsesOnlyTheFirmwareTokenTable) {
  EXPECT_EQ(amount(word(1500000), kUsdc, false, 1), "1.5 USDC");
  EXPECT_EQ(
      amount(word(1500000), kUsdc, false, 137),
      "1500000\nunknown token\n0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48");
  EXPECT_EQ(amount(word(42), kUnknown, false, 1),
            "42\nunknown token\n0x1111111111111111111111111111111111111111");
  EXPECT_EQ(
      amount(word(42), "0000000000000000000000000000000000000000", false, 1),
      "42\nunknown token\n0x0000000000000000000000000000000000000000");
  // The largest amount still renders exactly.
  const std::vector<uint8_t> max(32, 0xff);
  EXPECT_EQ(amount(max, kUnknown, false, 1),
            "115792089237316195423570985008687907853269984665640564039457584007"
            "913129639935\nunknown token\n"
            "0x1111111111111111111111111111111111111111");
}

// An unknown address called native by the signer must stay visible as a
// signer-supplied interpretation, even when its amount uses native decimals.
TEST(Erc7730Field, NativeAliasDisclosesSignerMappingAndAddress) {
  const std::string prefix =
      "Signer native alias:\n0x1111111111111111111111111111111111111111\n";
  EXPECT_EQ(amount(word(1500000000000000000ull), kUnknown, true, 1),
            prefix + "1.5 ETH");
  EXPECT_EQ(amount(word(1000), kUnknown, true, 1), prefix + "1000 Wei");
  // A chain without a native name here keeps the exact amount in wei.
  EXPECT_EQ(amount(word(1500000000000000000ull), kUnknown, true, 999999),
            prefix + "1500000000000000000 Wei");
  const std::vector<uint8_t> maximum(32, 0xff);
  EXPECT_EQ(
      amount(maximum, kUnknown, true, 999999),
      prefix +
          "115792089237316195423570985008687907853269984665640564039457584007"
          "913129639935 Wei");
}

// The signer's threshold message is shown above the value, never instead.
TEST(Erc7730Field, MessageNeverReplacesTheAmount) {
  EXPECT_EQ(amount(word(1500000), kUsdc, false, 1, "Unlimited"),
            "Signer: Unlimited\n1.5 USDC");
}

// A signer's native alias never overrides the firmware token table, and a
// native amount never inherits a previous Wanchain transaction's asset.
TEST(Erc7730Field, FirmwareTokenTableBeatsTheSignersNativeAlias) {
  EXPECT_EQ(amount(word(1500000), kUsdc, true, 1), "1.5 USDC");
}

namespace {

void beginTokenAmount(Erc7730Workflow* workflow) {
  memset(workflow, 0, sizeof(*workflow));
  Erc7730Formatter formatter = {};
  formatter.kind = 3;
  formatter.argument_count = 3;
  formatter.arguments[0] = {1, 1, 1};
  formatter.arguments[1] = {2, 1, 0};
  formatter.arguments[2] = {7, 2, 0};
  ASSERT_TRUE(erc7730_workflow_field_begin(workflow, &formatter));
}

}  // namespace

TEST(Erc7730Field, TokenAmountArgumentsAreTypedAndOrdered) {
  static Erc7730Workflow workflow;
  beginTokenAmount(&workflow);
  const auto amount_word = word(1500000);
  // The threshold cannot precede the amount.
  workflow.field.pending_role = 7;
  const uint8_t threshold[] = {0x16, 0xe3, 0x60};  // 1,500,000
  EXPECT_FALSE(erc7730_workflow_field_value(&workflow, ERC7730_CLASS_UINT,
                                            threshold, sizeof(threshold)));
  // The amount must be an integer.
  workflow.field.pending_role = 1;
  EXPECT_FALSE(erc7730_workflow_field_value(&workflow, ERC7730_CLASS_ADDRESS,
                                            amount_word.data(), 32));
  EXPECT_TRUE(erc7730_workflow_field_value(&workflow, ERC7730_CLASS_UINT,
                                           amount_word.data(), 32));
  // A token word with a nonzero high byte is not an address.
  workflow.field.pending_role = 2;
  auto dirty = word(0);
  dirty[0] = 1;
  EXPECT_FALSE(erc7730_workflow_field_value(&workflow, ERC7730_CLASS_ADDRESS,
                                            dirty.data(), 32));
  const auto token = hex(kUsdc);
  EXPECT_TRUE(erc7730_workflow_field_value(&workflow, ERC7730_CLASS_ADDRESS,
                                           token.data(), 20));
  EXPECT_EQ(0, memcmp(workflow.field.address, token.data(), 20));
  // amount >= threshold, and one more than the amount is not reached.
  workflow.field.pending_role = 7;
  EXPECT_TRUE(erc7730_workflow_field_value(&workflow, ERC7730_CLASS_UINT,
                                           threshold, sizeof(threshold)));
  EXPECT_TRUE(workflow.field.threshold_reached);
  const uint8_t above[] = {0x16, 0xe3, 0x61};
  EXPECT_TRUE(erc7730_workflow_field_value(&workflow, ERC7730_CLASS_UINT, above,
                                           sizeof(above)));
  EXPECT_FALSE(workflow.field.threshold_reached);
  memset(&workflow, 0, sizeof(workflow));
}

namespace {

std::string render(bool (*format)(const uint8_t*, char*, size_t),
                   const std::vector<uint8_t>& value) {
  char out[600];
  return format(value.data(), out, sizeof(out)) ? out : "<refused>";
}

std::string date(uint64_t seconds, bool block) {
  char out[600];
  const auto value = word(seconds);
  return erc7730_format_date(value.data(), block, out, sizeof(out))
             ? out
             : "<refused>";
}

}  // namespace

// Calendar vectors: the epoch, 2023-11-14T22:13:20Z, the 2000 leap day and
// the last second of year 9999. Anything later is shown, never refused.
TEST(Erc7730Field, DateIsUtcWithTheRawValue) {
  EXPECT_EQ(date(0, false), "1970-01-01 00:00:00 UTC\n(0)");
  EXPECT_EQ(date(1700000000, false), "2023-11-14 22:13:20 UTC\n(1700000000)");
  EXPECT_EQ(date(951782400, false), "2000-02-29 00:00:00 UTC\n(951782400)");
  EXPECT_EQ(date(253402300799ull, false),
            "9999-12-31 23:59:59 UTC\n(253402300799)");
  EXPECT_EQ(date(253402300800ull, false), "253402300800\n(not a date)");
  EXPECT_EQ(date(19000000, true), "Block 19000000");
  std::vector<uint8_t> huge(32, 0);
  huge[0] = 1;  // 2^248
  char out[600];
  ASSERT_TRUE(erc7730_format_date(huge.data(), false, out, sizeof(out)));
  EXPECT_NE(std::string(out).find("(not a date)"), std::string::npos);
}

TEST(Erc7730Field, DurationSplitsDaysHoursMinutesSeconds) {
  EXPECT_EQ(render(erc7730_format_duration, word(93784)),
            "1d 2h 3m 4s\n(93784 s)");
  EXPECT_EQ(render(erc7730_format_duration, word(0)), "0s\n(0 s)");
  EXPECT_EQ(render(erc7730_format_duration, word(3600)), "1h\n(3600 s)");
  std::vector<uint8_t> big = word(0);
  big[23] = 1;  // 2^64
  EXPECT_EQ(render(erc7730_format_duration, big), "18446744073709551616 s");
}

TEST(Erc7730Field, UnitIsExactWithTheRawValue) {
  char out[600];
  const auto value = word(1500);
  // The base is the signer's word: it is marked, and the raw integer is
  // always shown, so "USDC" or a leading digit cannot pass for a fact.
  ASSERT_TRUE(erc7730_format_unit(value.data(), 3, "kg", out, sizeof(out)));
  EXPECT_STREQ(out, "unit set by signer\n1.5 kg\nraw 1500");
  ASSERT_TRUE(
      erc7730_format_unit(value.data(), 0, "000 USDC", out, sizeof(out)));
  EXPECT_STREQ(out, "unit set by signer\n1500 000 USDC\nraw 1500");
  // The widest rendering fits: 77 decimals, a 64-byte base escaped to 256.
  const std::string base(4u * 64u, 'x');
  const auto one = word(1);
  ASSERT_TRUE(
      erc7730_format_unit(one.data(), 77, base.c_str(), out, sizeof(out)));
}

TEST(Erc7730Field, EnumLabelsTheValueAndMarksUnmapped) {
  char out[64];
  ASSERT_TRUE(erc7730_format_enum("1", "Buy", out, sizeof(out)));
  EXPECT_STREQ(out, "label set by signer\nBuy (1)");
  ASSERT_TRUE(erc7730_format_enum("7", nullptr, out, sizeof(out)));
  EXPECT_STREQ(out, "7 (unmapped)");
}

TEST(Erc7730Field, NftShowsTheIdAndTheCollectionAddress) {
  char out[128];
  const auto id = word(42);
  const auto collection = hex("5aaeb6053f3e94c9b9a09f33669435e7ef1beaed");
  ASSERT_TRUE(
      erc7730_format_nft(id.data(), collection.data(), out, sizeof(out)));
  EXPECT_STREQ(out,
               "Token ID 42\nCollection\n"
               "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed");
}

TEST(Erc7730Field, NativeAmountRendersLikeTheOrdinaryReview) {
  char out[128];
  const auto value = word(1500000000000000000ull);
  ASSERT_TRUE(erc7730_format_native_amount(value.data(), 1, out, sizeof(out)));
  EXPECT_STREQ(out, "1.5 ETH");
}

TEST(Erc7730Field, EmbeddedCallShowsCalleeSelectorLengthValueAndAuthority) {
  char out[600];
  const auto callee = hex("5aaeb6053f3e94c9b9a09f33669435e7ef1beaed");
  const auto spender = hex("fb6916095ca1df60bb79ce92ce3ea74c37c5d359");
  const uint8_t selector[4] = {0xa9, 0x05, 0x9c, 0xbb};
  const auto value = word(1500000000000000000ull);
  ASSERT_TRUE(erc7730_format_embedded(callee.data(), selector, 4, 68,
                                      value.data(), 1, spender.data(), out,
                                      sizeof(out)));
  EXPECT_STREQ(out,
               "To 0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed\n"
               "Function 0xa9059cbb\nData 68 bytes\nValue 1.5 ETH\n"
               "As 0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359");
  // Fewer than four bytes hold no selector; none at all is "No data".
  ASSERT_TRUE(erc7730_format_embedded(callee.data(), selector, 3, 3, nullptr, 1,
                                      nullptr, out, sizeof(out)));
  EXPECT_STREQ(out,
               "To 0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed\n"
               "Data 3 bytes");
  ASSERT_TRUE(erc7730_format_embedded(callee.data(), nullptr, 0, 0, nullptr, 1,
                                      nullptr, out, sizeof(out)));
  EXPECT_STREQ(out, "To 0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed\nNo data");
}

// ethereumFormatAmount() names " WAN" from a module global that a previous
// Wanchain transaction may have left set. An ERC-7730 native amount must not.
TEST(Erc7730Field, NativeAmountNeverInheritsAWanchainTransaction) {
  EthereumSignTx wanchain = {};
  wanchain.has_chain_id = true;
  wanchain.chain_id = 1;
  wanchain.has_tx_type = true;
  wanchain.tx_type = 1;
  wanchain.has_value = true;  // 1.5e18: large enough to carry a ticker
  wanchain.value.size = 8;
  memcpy(wanchain.value.bytes, "\x14\xd1\x12\x0d\x7b\x16\x00\x00", 8);
  char primed[64];
  ASSERT_TRUE(ethereumFormatTransferAmount(&wanchain, primed, sizeof(primed)));
  // The global really is primed: the Wanchain transfer itself is WAN.
  ASSERT_NE(strstr(primed, " WAN"), nullptr) << primed;
  char out[64];
  const auto value = word(1500000000000000000ull);
  ASSERT_TRUE(erc7730_format_native_amount(value.data(), 1, out, sizeof(out)));
  EXPECT_STREQ(out, "1.5 ETH");
  // tokenAmount's signer-alias branch must disclose its original address.
  EXPECT_EQ(amount(value, "4444444444444444444444444444444444444444", true, 1),
            "Signer native alias:\n"
            "0x4444444444444444444444444444444444444444\n1.5 ETH");
  // Leave the module global as an ordinary transaction would.
  EthereumSignTx ordinary = wanchain;
  ordinary.has_tx_type = false;
  ASSERT_TRUE(ethereumFormatTransferAmount(&ordinary, primed, sizeof(primed)));
  EXPECT_EQ(strstr(primed, " WAN"), nullptr) << primed;
}
