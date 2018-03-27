extern "C" {
#include "keepkey/board/keepkey_board.h"
}

#include "gtest/gtest.h"

TEST(Board, Shutdown) {
    EXPECT_EXIT(shutdown(), ::testing::ExitedWithCode(1), "");
}
