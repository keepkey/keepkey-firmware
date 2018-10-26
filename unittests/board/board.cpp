extern "C" {
#include "keepkey/board/keepkey_board.h"
#include "keepkey/board/u2f.h"
}

#include "gtest/gtest.h"

TEST(Board, Shutdown) {
    EXPECT_EXIT(shutdown(), ::testing::ExitedWithCode(1), "");
}

TEST(Board, U2FChannel) {
    const uint8_t *channel = u2f_get_channel();
    ASSERT_TRUE(memcmp(channel, "\x00\x00\x00\x00", 4) != 0)
        << "Channel should be nonzero after initialization";

    uint8_t c[4];
    memcpy(c, channel, 4);

    channel = u2f_get_channel();
    ASSERT_TRUE(memcmp(c, channel, 4) == 0)
        << "Channel shouldn't change when u2f_get_channel() is called again";
}
