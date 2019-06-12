extern "C" {
#include "keepkey/board/messages.h"
#include "keepkey/board/usb.h"
#include "keepkey/firmware/fsm.h"
}

#include "gtest/gtest.h"

extern "C" {
void usb_rx_helper(const void *buf, size_t length, MessageMapType type);
void set_msg_failure_handler(msg_failure_t failure_func);
}

static int failure_count;
static std::string message;

static void setup() {
    failure_count = 0;

    set_msg_failure_handler(+[](FailureType code, const char *text) {
        failure_count++;
        message = text;
    });
}

TEST(USBRX, Overflow) {
    fsm_init();
    setup();

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

    // Send packets up until the point just before where the buffer internal to
    // usb_rx_helper would overflow. All of these should succeeed.
    for (unsigned i = 0; i < 1039; i++) {
        usb_rx_helper(&msg, sizeof(msg), NORMAL_MSG);
        ASSERT_EQ(failure_count, 0);
    }

    // Then on the last one, check that we detect the overflow before it happens:
    usb_rx_helper(&msg, sizeof(msg), NORMAL_MSG);
    ASSERT_EQ(failure_count, 1);
    ASSERT_EQ(message, "Malformed message");

    // And check that the state got cleared out afterward:
    usb_rx_helper(&msg, sizeof(msg), NORMAL_MSG);
    ASSERT_EQ(failure_count, 2);
    ASSERT_EQ(message, "Malformed packet");
}

TEST(USBRX, ErrorHandling) {
    fsm_init();
    setup();

    char msg[64];
    memset(msg, 0, sizeof(msg));

    // Missing '?'
    usb_rx_helper(&msg, sizeof(msg), NORMAL_MSG);
    ASSERT_EQ(failure_count, 1);
    ASSERT_EQ(message, "Malformed packet");

    msg[0] = '?';

    // Missing '#'
    usb_rx_helper(&msg, sizeof(msg), NORMAL_MSG);
    ASSERT_EQ(failure_count, 2);
    ASSERT_EQ(message, "Malformed packet");

    msg[1] = '#';

    // Missing '#'
    usb_rx_helper(&msg, sizeof(msg), NORMAL_MSG);
    ASSERT_EQ(failure_count, 3);
    ASSERT_EQ(message, "Malformed packet");

    msg[2] = '#';
    msg[3] = 0xff;
    msg[6] = 0xff;

    // Unknown msgId
    usb_rx_helper(&msg, sizeof(msg), NORMAL_MSG);
    ASSERT_EQ(failure_count, 4);
    ASSERT_EQ(message, "Unknown message");
}
