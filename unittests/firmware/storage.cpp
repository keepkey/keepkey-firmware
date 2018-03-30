extern "C" {
#include "keepkey/firmware/storage.h"
}

#include "gtest/gtest.h"

#include <iomanip>
#include <iostream>

template<class T, size_t N>
constexpr size_t array_len(T (&)[N]) { return N; }

TEST(Storage, StorageArenaElement) {
    uint32_t pin_fail_arena[32];
    memset(pin_fail_arena, 0xff, sizeof(pin_fail_arena));

    ASSERT_EQ(&pin_fail_arena[0],
              storage_getPinArenaElement(pin_fail_arena,
                                         array_len(pin_fail_arena)));

    pin_fail_arena[0] = 0xfffffffeu;
    ASSERT_EQ(&pin_fail_arena[0],
              storage_getPinArenaElement(pin_fail_arena,
                                         array_len(pin_fail_arena)));

    pin_fail_arena[0] = 0x80000000u;
    ASSERT_EQ(&pin_fail_arena[0],
              storage_getPinArenaElement(pin_fail_arena,
                                         array_len(pin_fail_arena)));

    pin_fail_arena[0] = 0x0u;
    ASSERT_EQ(&pin_fail_arena[1],
              storage_getPinArenaElement(pin_fail_arena,
                                         array_len(pin_fail_arena)));

    uint32_t *expected_arena = pin_fail_arena;
    pin_fail_arena[0] = 0xffffffffu;
    for (size_t i = 0; i < array_len(pin_fail_arena); ++i) {
        for (size_t bit = 0; bit < 32; ++bit) {
            pin_fail_arena[i] = 0xffffffffu << bit;

            ASSERT_EQ(expected_arena,
                      storage_getPinArenaElement(pin_fail_arena,
                                                 array_len(pin_fail_arena)));
        }

        if (i + 1 != array_len(pin_fail_arena)) {
            pin_fail_arena[i] = 0;
            expected_arena++;
            ASSERT_EQ(expected_arena,
                      storage_getPinArenaElement(pin_fail_arena,
                                                 array_len(pin_fail_arena)));
        }
    }

    pin_fail_arena[array_len(pin_fail_arena) - 1] = 0;
    ASSERT_EQ(NULL, storage_getPinArenaElement(pin_fail_arena,
                                               array_len(pin_fail_arena)));
}

TEST(Storage, StorageArenaFailCount) {
    uint32_t arena_elt = 0xffffffffu;
    ASSERT_EQ(0, storage_getPinArenaFailCount(&arena_elt));

    for (int i = 0; i < 32; i++) {
        arena_elt = 0xffffffffu << i;
        ASSERT_EQ(i, storage_getPinArenaFailCount(&arena_elt));
    }
}

TEST(Storage, StorageResetPinArena) {
    uint32_t pin_fail_arena[32];

    // Pin arena with all 1's to begin with.
    memset(pin_fail_arena, 0xff, sizeof(pin_fail_arena));
    ASSERT_EQ(0, storage_getPinArenaFailCount(&pin_fail_arena[0]));
    storage_resetPinArena(&pin_fail_arena[0], array_len(pin_fail_arena));
    ASSERT_EQ(0, storage_getPinArenaFailCount(&pin_fail_arena[0]));
    for (int i = 0; i < array_len(pin_fail_arena); ++i) {
        ASSERT_EQ(pin_fail_arena[i], 0xffffffffu);
    }

    // Partial pin arena, must be partially reset.
    pin_fail_arena[0] = 0xffffffffu << 3;
    ASSERT_EQ(3, storage_getPinArenaFailCount(&pin_fail_arena[0]));
    storage_resetPinArena(&pin_fail_arena[0], array_len(pin_fail_arena));
    ASSERT_EQ(3, storage_getPinArenaFailCount(&pin_fail_arena[0]));
    ASSERT_EQ(pin_fail_arena[0], 0xffffffffu << 3);
    for (int i = 1; i < array_len(pin_fail_arena); ++i) {
        ASSERT_EQ(pin_fail_arena[i], 0xffffffffu);
    }

    // Partial pin arena, must be partially reset.
    pin_fail_arena[0] = 0;
    pin_fail_arena[1] = 0xffffffffu << 4;
    ASSERT_EQ(4, storage_getPinArenaFailCount(&pin_fail_arena[1]));
    storage_resetPinArena(&pin_fail_arena[0], array_len(pin_fail_arena));
    ASSERT_EQ(4, storage_getPinArenaFailCount(&pin_fail_arena[0]));
    ASSERT_EQ(pin_fail_arena[0], 0xffffffffu << 4);
    for (int i = 1; i < array_len(pin_fail_arena); ++i) {
        ASSERT_EQ(pin_fail_arena[i], 0xffffffffu);
    }

    // Partial pin arena, must be partially reset.
    pin_fail_arena[0] = 0;
    pin_fail_arena[1] = 0;
    pin_fail_arena[2] = 0xffffffffu << 5;
    ASSERT_EQ(5, storage_getPinArenaFailCount(&pin_fail_arena[2]));
    storage_resetPinArena(&pin_fail_arena[0], array_len(pin_fail_arena));
    ASSERT_EQ(5, storage_getPinArenaFailCount(&pin_fail_arena[0]));
    ASSERT_EQ(pin_fail_arena[0], 0xffffffffu << 5);
    for (int i = 1; i < array_len(pin_fail_arena); ++i) {
        ASSERT_EQ(pin_fail_arena[i], 0xffffffffu);
    }

    // Empty pin arena, must be fully reset.
    memset(pin_fail_arena, 0, sizeof(pin_fail_arena));
    ASSERT_EQ(0, storage_getPinArenaFailCount(&pin_fail_arena[31]));
    storage_resetPinArena(&pin_fail_arena[0], array_len(pin_fail_arena));
    ASSERT_EQ(0, storage_getPinArenaFailCount(&pin_fail_arena[0]));
    for (int i = 0; i < array_len(pin_fail_arena); ++i) {
        ASSERT_EQ(pin_fail_arena[i], 0xffffffffu) << i;
    }
}
