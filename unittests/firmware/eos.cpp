extern "C" {
#include "keepkey/firmware/eos.h"
#include "messages-eos.pb.h"
}

#include "gtest/gtest.h"

#include <string>

TEST(EOS, FormatNameVec) {
    struct {
        uint64_t value;
        const char *name;
        bool ret;
    } vec[] = {
        { 0x5530ea0000000000, "eosio",        true },
        { 0x0000000000ea3055, nullptr,        true },
        { 0x5530ea031ec65520, "eosio.system", true },
        { 0xb68d3cbb3e000000, "quantity",     true },
        { 0x9ab864229a9e4000, "newaccount",   true },
        { EOS_Transfer,       "transfer",     true },
        { 0xcdcd3c2d57000000, "transfer",     true },
        { 0xd4d2a8a986ca8fc0, "undelegatebw", true },
        { 0xc2b263b800000000, "setabi",       true },
        { 0xa726ab8000000000, "owner",        true },
        { EOS_Owner,          "owner",        true },
        { 0x3232eda800000000, "active",       true },
        { EOS_Active,         "active",       true },
        { 0x5530002eea526920, "eos..freedom", true },
        { 0x5530412eea526920, "eos42freedom", true },
        { 0x0,                "",             true },
    };

    for (const auto &v : vec) {
        char str[EOS_NAME_STR_SIZE];
        ASSERT_EQ(v.ret, eos_formatName(v.value, str));
        if (v.name)
            ASSERT_EQ(v.name, std::string(str));
    }
}

TEST(EOS, FormatAssetVec) {
    struct {
        int64_t amount;
        uint64_t symbol;
        std::string expected;
        bool ret;
    } vec[] = {
        {        7654321L, 0x000000534f4504L, "765.4321 EOS",      true },
        {             42L, 0x004e45584f4600L, "42 FOXEN",          true },
        {             42L, 0x004e45584f4601L, "4.2 FOXEN",         true },
        {             42L, 0x004e45584f4602L, "0.42 FOXEN",        true },
        {             42L, 0x004e45584f4603L, "0.042 FOXEN",       true },
        {             42L, 0x004e45584f4604L, "0.0042 FOXEN",      true },
        {             42L, 0x004e45584f4605L, "0.00042 FOXEN",     true },
        {             42L, 0x004e45584f4606L, "0.000042 FOXEN",    true },
        {             42L, 0x004e45584f4607L, "0.0000042 FOXEN",   true },
        {             42L, 0x004e45584f4608L, "0.00000042 FOXEN",  true },
        {             42L, 0x004e45584f4609L, "0.000000042 FOXEN", true },
        {            -10L, 0x00000053595305L, "-0.00010 SYS",      true },
        {       INT64_MIN, 0x00000053595303L, "-9223372036854775.808 SYS", true },
        {          20000L, 0x000000534f4504L,          "2.0000 EOS", true },
        {         200000L, 0x000000534f4504L,         "20.0000 EOS", true },
        {        2000000L, 0x000000534f4504L,        "200.0000 EOS", true },
        {       20000000L, 0x000000534f4504L,       "2000.0000 EOS", true },
        {      200000000L, 0x000000534f4504L,      "20000.0000 EOS", true },
        {     2000000000L, 0x000000534f4504L,     "200000.0000 EOS", true },
        {    20000000000L, 0x000000534f4504L,    "2000000.0000 EOS", true },
        {   200000000000L, 0x000000534f4504L,   "20000000.0000 EOS", true },
        {  2000000000000L, 0x000000534f4504L,  "200000000.0000 EOS", true },
        { 20000000000000L, 0x000000534f4504L, "2000000000.0000 EOS", true },
        {          10000L, 0x000000534f4504L,          "1.0000 EOS", true },
        {         100000L, 0x000000534f4504L,         "10.0000 EOS", true },
        {        1000000L, 0x000000534f4504L,        "100.0000 EOS", true },
        {       10000000L, 0x000000534f4504L,       "1000.0000 EOS", true },
        {      100000000L, 0x000000534f4504L,      "10000.0000 EOS", true },
        {     1000000000L, 0x000000534f4504L,     "100000.0000 EOS", true },
        {    10000000000L, 0x000000534f4504L,    "1000000.0000 EOS", true },
        {   100000000000L, 0x000000534f4504L,   "10000000.0000 EOS", true },
        {  1000000000000L, 0x000000534f4504L,  "100000000.0000 EOS", true },
        { 10000000000000L, 0x000000534f4504L, "1000000000.0000 EOS", true },
    };

    for (const auto &v : vec) {
        char str[EOS_ASSET_STR_SIZE];
        EosAsset asset;
        asset.has_amount = true;
        asset.amount = v.amount;
        asset.has_symbol = true;
        asset.symbol = v.symbol;
        EXPECT_EQ(v.ret, eos_formatAsset(&asset, str));
        EXPECT_EQ(v.expected, str);
    }
}
