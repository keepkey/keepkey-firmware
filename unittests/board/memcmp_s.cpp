extern "C" {
#include "keepkey/board/memcmp_s.h"
}

#include "gtest/gtest.h"

TEST(Board, Memcmps) {
  struct {
    const char *lhs;
    const char *rhs;
    size_t len;
    int expected;
  } vec[] = {
    { "A1234567890123456789012345678901",
      "A1234567890123456789012345678901", 32, 0 },
    { "B123456789012345678901234567890101234567890123456789012345678901",
      "B123456789012345678901234567890101234567890123456789012345678901", 63, 0 },
    { "C1234567890123456789012345678901",
      "C123456789012345678901234567890A", 32, 1 },
    { "D                               ",
      "D                              F", 32, 1 },
    { "E                               ",
      "E                               ", 32, 0 },
  };

  for (const auto &v : vec) {
    for (size_t i = 0; i < 1000; i++) {
      ASSERT_EQ(memcmp_s(v.lhs, v.rhs, v.len), v.expected)
        << "lhs: " << v.lhs << "\n"
        << "rhs: " << v.rhs << "\n"
        << "len: " << v.len << "\n";
    }
  }
}
