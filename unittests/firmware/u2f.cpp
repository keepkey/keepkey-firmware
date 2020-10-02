extern "C" {
#include "u2f.h"
#include "u2f_knownapps.h"
}

#include "gtest/gtest.h"

#include <string>

TEST(U2F, WordsFromData) {
  const uint8_t buff1[32] = "123456789012345678901";
  ASSERT_EQ(std::string(words_from_data(buff1, 6)),
            "couple muscle snack heavy");

  const uint8_t buff2[32] = "keepkeykeepkeykeepkey";
  ASSERT_EQ(std::string(words_from_data(buff2, 6)),
            "hidden clinic foster strategy");

  ASSERT_EQ(std::string(u2f_well_known[6].appname), "Bitbucket");
  ASSERT_EQ(std::string(words_from_data(u2f_well_known[6].appid, 6)),
            "bar peace tonight cement");
}

TEST(U2F, ShapeShift) {
  ASSERT_EQ(U2F_SHAPESHIFT_COM->appname, std::string("ShapeShift"));
  ASSERT_EQ(U2F_SHAPESHIFT_IO->appname, std::string("ShapeShift"));
  ASSERT_EQ(U2F_SHAPESHIFT_COM_STG->appname,
            std::string("ShapeShift (staging)"));
  ASSERT_EQ(U2F_SHAPESHIFT_IO_STG->appname,
            std::string("ShapeShift (staging)"));
  ASSERT_EQ(U2F_SHAPESHIFT_COM_DEV->appname, std::string("ShapeShift (dev)"));
  ASSERT_EQ(U2F_SHAPESHIFT_IO_DEV->appname, std::string("ShapeShift (dev)"));
}
