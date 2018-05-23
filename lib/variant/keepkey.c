#include "keepkey/variant/variant.h"

#if 0 // example
VariantImage frame_0 = { 0, 0 };
VariantImage frame_1 = { 0, 0 };

VariantAnimation screensaver = {
    .count = 5,
    .frames = { &frame_0, &frame_1 },
};

VariantImage home_screen = {
    .width = 2,
    .height = 2,
    .version = 1,
    .len = 4,
    .data = {0x00, 0xff, 0xff, 0x00 },
};

VariantInfo variant_info = {
    .magic = "KPWL",
    .version = 1,
    .name = "KeepKey",
    .home_screen = &home_screen,
    .screensaver = &screensaver
};
#endif
