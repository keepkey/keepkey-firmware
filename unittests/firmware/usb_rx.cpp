extern "C" {
#include "keepkey/board/messages.h"
#include "keepkey/board/usb.h"
#include "keepkey/firmware/fsm.h"
}

#include "gtest/gtest.h"

extern "C" {
void usb_rx_helper(const void *buf, size_t length, MessageMapType type);
}

TEST(USBRX, Overflow) {
    fsm_init();

    char msg[64];
    TrezorFrame *frame = (TrezorFrame *)msg;
    TrezorFrameFragment *frame_fragment = (TrezorFrameFragment *)msg;

    frame->usb_header.hid_type = '?';
    frame->header.pre1 = '#';
    frame->header.pre2 = '#';
    frame->header.id = __builtin_bswap16(MessageType_MessageType_Initialize);
    frame->header.len = __builtin_bswap32(0xffffffff);
    usb_rx_helper(&msg, sizeof(msg), NORMAL_MSG);

    frame->header.pre1 = '0';
    frame->header.pre2 = '0';

#ifndef DEBUG_ON
    // The real test is only in release builds now, since it's stupid slow in debug.
    for (unsigned i=0; i < 69273665; i++)
#else
    for (unsigned i=0; i < 10240; i++)
#endif
        usb_rx_helper(&msg, sizeof(msg), NORMAL_MSG);

    // Boom!
    usb_rx_helper(&msg, sizeof(msg), NORMAL_MSG);
}
