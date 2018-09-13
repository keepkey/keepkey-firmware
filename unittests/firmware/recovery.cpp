extern "C" {
#include "keepkey/firmware/recovery_cipher.h"
}

#include "gtest/gtest.h"

#include <cstring>

TEST(Recovery, ExactStrMatch) {
    char LHS[] = "allow\0";
    char RHS[] = "all\0";

    ASSERT_TRUE(exact_str_match(LHS, RHS, 1));
    ASSERT_TRUE(exact_str_match(LHS, RHS, 2));
    ASSERT_TRUE(exact_str_match(LHS, RHS, 3));
    ASSERT_FALSE(exact_str_match(LHS, RHS, 4));
}

bool attempt_auto_complete(char *partial_word);

#if !defined(__has_feature)
#  define __has_feature(X) 0
#endif

#if !__has_feature(address_sanitizer) && !__SANITIZE_ADDRESS__
// FIXME: the bip32 wordlist needs padding added back.
TEST(Recovery, AutoComplete) {
    char partial_word[] = "all\0\0\0\0\0";
    ASSERT_TRUE(attempt_auto_complete(partial_word));
    ASSERT_TRUE(memcmp(partial_word, "all\0\0\0\0\0", sizeof(partial_word)) == 0);

    memcpy(partial_word, "allo\0\0\0\0", sizeof(partial_word));
    ASSERT_TRUE(attempt_auto_complete(partial_word));
    ASSERT_TRUE(memcmp(partial_word, "allow\0\0\0", sizeof(partial_word)) == 0);

    memcpy(partial_word, "allways\0", sizeof(partial_word));
    ASSERT_FALSE(attempt_auto_complete(partial_word));
    ASSERT_TRUE(memcmp(partial_word, "allways\0", sizeof(partial_word)) == 0);
}
#endif
