extern "C" {
#include "u2f.h"
#include "u2f_knownapps.h"
}

#include "gtest/gtest.h"

#include <string>

TEST(U2F, WordsFromData) {
    const uint8_t buff1[32] = "123456789012345678901";
    ASSERT_EQ(std::string(words_from_data(buff1, 6)), "couple muscle snack heavy");

    const uint8_t buff2[32] = "keepkeykeepkeykeepkey";
    ASSERT_EQ(std::string(words_from_data(buff2, 6)), "hidden clinic foster strategy");

    ASSERT_EQ(std::string(u2f_well_known[0].appname), "Google");
    ASSERT_EQ(std::string(words_from_data(u2f_well_known[0].appid, 6)), "pipe crime prosper easily");
}
