extern "C" {
#include "keepkey/board/layout.h"
#include "keepkey/board/memory.h"
#include "keepkey/board/messages.h"
#include "keepkey/board/usb.h"
#include "keepkey/firmware/fsm.h"
#include "keepkey/firmware/recovery_cipher.h"
#include "keepkey/firmware/reset.h"
#include "keepkey/firmware/storage.h"
#include "keepkey/firmware/u2f.h"
#include "keepkey/firmware/u2f/u2f.h"
#include "u2f.h"
#include "u2f_knownapps.h"
}

#include "gtest/gtest.h"

#include <algorithm>
#include <cstring>
#include <deque>
#include <functional>
#include <string>
#include <vector>

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

extern "C" void set_msg_failure_handler(msg_failure_t failure_func);
bool kkconfirm_preload(int nYes, int nNo);
int kkconfirm_drain(void);
void kkconfirm_capture_start(void);
std::vector<std::string> kkconfirm_capture_finish(void);

namespace {

// Each step runs inside one usbPoll(), as a USB callback would on hardware.
std::deque<std::function<void()>> poll_script;
bool button_up;
std::vector<std::vector<uint8_t>> u2f_replies;
std::vector<uint8_t> u2f_reply_cmds;
size_t u2f_reply_len;

const uint32_t kCid = 0x01020304;

// A U2F_REGISTER APDU is 71 bytes: one init frame and one continuation.
void register_frames(uint8_t challenge, U2FHID_FRAME* init,
                     U2FHID_FRAME* cont) {
  uint8_t apdu[7 + sizeof(U2F_REGISTER_REQ)] = {
      0, U2F_REGISTER, 0, 0, 0, 0, sizeof(U2F_REGISTER_REQ)};
  memset(apdu + 7, challenge, U2F_CHAL_SIZE);
  memset(apdu + 7 + U2F_CHAL_SIZE, 0xa5, U2F_APPID_SIZE);
  *init = {};
  init->cid = kCid;
  init->init.cmd = U2FHID_MSG;
  init->init.bcntl = sizeof(apdu);
  memcpy(init->init.data, apdu, sizeof(init->init.data));
  *cont = {};
  cont->cid = kCid;
  memcpy(cont->cont.data, apdu + sizeof(init->init.data),
         sizeof(apdu) - sizeof(init->init.data));
}

// A request (or retry) arriving during the session, on the tiny U2F path.
void send_register(uint8_t challenge) {
  U2FHID_FRAME init, cont;
  register_frames(challenge, &init, &cont);
  u2fhid_read(1, &init);
  u2fhid_read(1, &cont);
}

void send_main(uint16_t id, const uint8_t* payload, uint8_t len) {
  uint8_t frame[64] = {'?', '#', '#', uint8_t(id >> 8), uint8_t(id & 0xff)};
  frame[8] = len;
  if (len) memcpy(frame + 9, payload, len);
  usb_test_receive(frame, sizeof(frame));
}

void hold(bool up, int polls) {
  for (int i = 0; i < polls; i++)
    poll_script.push_back([=] { button_up = up; });
}

uint16_t status(const std::vector<uint8_t>& reply) {
  return reply.size() < 2 ? 0 : reply[reply.size() - 2] << 8 | reply.back();
}

std::vector<uint16_t> statuses() {
  std::vector<uint16_t> out;
  for (const auto& reply : u2f_replies) out.push_back(status(reply));
  return out;
}

// Splits an APDU into one init frame and its continuations.
std::vector<U2FHID_FRAME> frames_for(const std::vector<uint8_t>& apdu) {
  std::vector<U2FHID_FRAME> out(1);
  out[0] = {};
  out[0].cid = kCid;
  out[0].init.cmd = U2FHID_MSG;
  out[0].init.bcnth = apdu.size() >> 8;
  out[0].init.bcntl = apdu.size() & 0xff;
  size_t off = std::min(apdu.size(), sizeof(out[0].init.data));
  memcpy(out[0].init.data, apdu.data(), off);
  for (uint8_t seq = 0; off < apdu.size(); seq++) {
    U2FHID_FRAME cont = {};
    cont.cid = kCid;
    cont.cont.seq = seq;
    const size_t n = std::min(apdu.size() - off, sizeof(cont.cont.data));
    memcpy(cont.cont.data, apdu.data() + off, n);
    off += n;
    out.push_back(cont);
  }
  return out;
}

const uint8_t kAppId = 0xa5;      // register_frames() uses the same appId
const size_t kPubKeyLen = 65;     // uncompressed P-256 point
const size_t kKeyHandleLen = 64;  // key path + HMAC, as u2f.c builds it

std::vector<uint8_t> auth_apdu(const std::vector<uint8_t>& key_handle) {
  std::vector<uint8_t> apdu = {0, U2F_AUTHENTICATE, U2F_AUTH_ENFORCE, 0, 0, 0,
                               0};
  apdu.insert(apdu.end(), U2F_CHAL_SIZE, 0x11);
  apdu.insert(apdu.end(), U2F_APPID_SIZE, kAppId);
  apdu.push_back(key_handle.size());
  apdu.insert(apdu.end(), key_handle.begin(), key_handle.end());
  apdu[6] = apdu.size() - 7;
  return apdu;
}

// Queues each frame as its own USB callback through the U2F endpoint, so the
// frame sees usb.c's current tiny setting as on hardware.
void push_u2f(const std::vector<U2FHID_FRAME>& frames) {
  for (const auto& f : frames)
    poll_script.push_back([=] { usb_test_receive_u2f(&f); });
}

std::vector<uint8_t> screen() {
  const Canvas* c = layout_get_canvas();
  return std::vector<uint8_t>(c->buffer, c->buffer + c->width * c->height);
}

size_t count(uint8_t cmd, uint8_t err) {
  size_t n = 0;
  for (size_t i = 0; i < u2f_replies.size(); i++)
    if (u2f_reply_cmds[i] == cmd && !u2f_replies[i].empty() &&
        u2f_replies[i][0] == err)
      n++;
  return n;
}

int failures;
std::string failure_text;

struct U2FWait : ::testing::Test {
  std::vector<uint8_t> flash = std::vector<uint8_t>(FLASH_TOTAL_SIZE, 0xff);
  uint8_t* previous_flash = emulator_flash_base;

  void SetUp() override {
    ASSERT_TRUE(kkconfirm_preload(0, 0));
    ASSERT_EQ(0, kkconfirm_drain());
    emulator_flash_base = flash.data();
    storage_init();
    LoadDevice load = {};
    load.has_mnemonic = true;
    strcpy(load.mnemonic, "all all all all all all all all all all all all");
    storage_loadDevice(&load);
    storage_commit();
    usb_set_u2f_rx_callback(u2fhid_read);  // as u2fInit() does
    poll_script.clear();
    u2f_replies.clear();
    u2f_reply_cmds.clear();
    button_up = false;
    failures = 0;
    failure_text.clear();
    set_msg_failure_handler(+[](FailureType, const char* text) {
      failures++;
      failure_text = text;
    });
  }

  void TearDown() override {
    poll_script.clear();
    button_up = false;
    fsm_init();  // restores the real failure handler
    storage_reset();
    emulator_flash_base = previous_flash;
  }

  // Runs one U2F session from the main loop until its wait ends.
  void run(uint8_t challenge) {
    U2FHID_FRAME init, cont;
    register_frames(challenge, &init, &cont);
    poll_script.push_front([=] { u2fhid_read(1, &cont); });
    u2fhid_read(0, &init);
  }
};

}  // namespace

extern "C" void emulatorPoll(void) {
  if (poll_script.empty()) return;
  auto step = poll_script.front();
  poll_script.pop_front();
  step();
}

extern "C" bool emulator_button_up(void) { return button_up; }

extern "C" void emulator_u2f_tx(const U2FHID_FRAME* f) {
  if (f->type & TYPE_INIT) {
    u2f_replies.emplace_back();
    u2f_reply_cmds.push_back(f->init.cmd);
    u2f_reply_len = MSG_LEN(*f);
    const size_t n = std::min(u2f_reply_len, sizeof(f->init.data));
    u2f_replies.back().assign(f->init.data, f->init.data + n);
  } else if (!u2f_replies.empty()) {
    auto& reply = u2f_replies.back();
    const size_t n =
        std::min(u2f_reply_len - reply.size(), sizeof(f->cont.data));
    reply.insert(reply.end(), f->cont.data, f->cont.data + n);
  }
}

// A normal message arriving while U2F waits for presence must not be
// dispatched: its confirm would replace the U2F prompt, and a press held for
// it would then count as U2F presence once the host cancels it.
TEST_F(U2FWait, NormalMessageIsNotDispatched) {
  const uint8_t ping[] = {0x10, 0x01};  // Ping.button_protection = true
  poll_script.push_back(
      [&] { send_main(MessageType_MessageType_Ping, ping, sizeof(ping)); });
  // If the Ping was dispatched, this Cancel unwinds its confirm.
  poll_script.push_back(
      [] { send_main(MessageType_MessageType_Cancel, nullptr, 0); });
  poll_script.push_back([] { send_register(1); });
  kkconfirm_capture_start();
  run(1);
  const auto screens = kkconfirm_capture_finish();
  EXPECT_TRUE(screens.empty()) << "a nested confirm was drawn: " << screens[0];
  EXPECT_EQ(1, failures);
  EXPECT_EQ("Unknown message", failure_text);
  // Still armed: the retry is answered "not satisfied", not aborted.
  EXPECT_EQ((std::vector<uint16_t>{U2F_SW_CONDITIONS_NOT_SATISFIED,
                                   U2F_SW_CONDITIONS_NOT_SATISFIED}),
            statuses());
}

// Presence is a press and release that starts after the prompt is drawn.
TEST_F(U2FWait, PresenceNeedsFreshPressAndRelease) {
  hold(false, 5);  // held since before the prompt
  poll_script.push_back([] { send_register(2); });
  hold(true, 5);
  hold(false, 5);  // pressed, not yet released
  poll_script.push_back([] { send_register(2); });
  poll_script.push_back([] { send_register(3); });  // new prompt
  hold(true, 5);  // releasing a press that began before this prompt
  poll_script.push_back([] { send_register(3); });
  hold(false, 5);
  hold(true, 5);
  poll_script.push_back([] { send_register(3); });
  run(2);
  EXPECT_EQ((std::vector<uint16_t>{
                U2F_SW_CONDITIONS_NOT_SATISFIED,  // first request
                U2F_SW_CONDITIONS_NOT_SATISFIED,  // held through the prompt
                U2F_SW_CONDITIONS_NOT_SATISFIED,  // pressed, not released
                U2F_SW_CONDITIONS_NOT_SATISFIED,  // new request, new prompt
                U2F_SW_CONDITIONS_NOT_SATISFIED,  // stale press released
                U2F_SW_NO_ERROR}),                // fresh press and release
            statuses());
  EXPECT_TRUE(poll_script.empty());
}

// Every exit of a U2F session forgets the request. A session ended by the
// data timeout used to keep it armed, with its presence progress, so the next
// identical request was not prompted and a single release completed presence.
TEST_F(U2FWait, DataTimeoutForgetsPromptAndPresence) {
  std::vector<uint8_t> prompt, home, resent;
  U2FHID_FRAME init, cont;
  register_frames(7, &init, &cont);
  poll_script.push_back([&] { prompt = screen(); });
  hold(true, 3);
  hold(false, 3);  // pressed: presence needs only the release now
  // A new message that never completes ends the session by the data timeout.
  poll_script.push_back([=] { u2fhid_read(1, &init); });
  run(7);
  EXPECT_EQ(1u, count(U2FHID_ERROR, ERR_MSG_TIMEOUT));
  home = screen();
  EXPECT_NE(prompt, home);

  u2f_replies.clear();
  u2f_reply_cmds.clear();
  poll_script.push_back([&] { resent = screen(); });
  hold(true, 3);  // the release of the earlier press
  poll_script.push_back([] { send_register(7); });
  run(7);
  EXPECT_EQ(prompt, resent) << "the resent request was not prompted";
  EXPECT_EQ((std::vector<uint16_t>{U2F_SW_CONDITIONS_NOT_SATISFIED,
                                   U2F_SW_CONDITIONS_NOT_SATISFIED}),
            statuses());
}

// A U2F request arriving while a confirm waits gets the busy reply. It used to
// start a nested U2F session that, for a request armed by an earlier session,
// left the confirm on screen and took the press made for it as U2F presence.
TEST_F(U2FWait, ConfirmAnswersU2FBusy) {
  // Register to obtain a valid key handle for kAppId.
  hold(true, 3);
  hold(false, 3);
  hold(true, 3);
  poll_script.push_back([] { send_register(5); });
  run(5);
  ASSERT_EQ(
      (std::vector<uint16_t>{U2F_SW_CONDITIONS_NOT_SATISFIED, U2F_SW_NO_ERROR}),
      statuses());
  const auto& reg = u2f_replies[1];
  ASSERT_EQ(kKeyHandleLen, reg[1 + kPubKeyLen]);
  const std::vector<uint8_t> handle(
      reg.begin() + 2 + kPubKeyLen,
      reg.begin() + 2 + kPubKeyLen + kKeyHandleLen);
  const auto auth = frames_for(auth_apdu(handle));

  // Arm AUTH, then end the session by the data timeout.
  u2f_replies.clear();
  u2f_reply_cmds.clear();
  push_u2f(std::vector<U2FHID_FRAME>(auth.begin() + 1, auth.end()));
  push_u2f({auth[0]});  // never completed
  u2fhid_read(0, &auth[0]);
  ASSERT_EQ((std::vector<uint16_t>{U2F_SW_CONDITIONS_NOT_SATISFIED}),
            std::vector<uint16_t>{status(u2f_replies[0])});
  ASSERT_EQ(1u, count(U2FHID_ERROR, ERR_MSG_TIMEOUT));

  // Resend the identical AUTH while a Ping confirm waits, press and release
  // for the confirm, resend again, then cancel the confirm.
  u2f_replies.clear();
  u2f_reply_cmds.clear();
  push_u2f(auth);
  hold(true, 3);
  hold(false, 3);
  hold(true, 3);
  push_u2f(auth);
  poll_script.push_back(
      [] { send_main(MessageType_MessageType_Cancel, nullptr, 0); });
  const uint8_t ping[] = {0x10, 0x01};  // Ping.button_protection = true
  kkconfirm_capture_start();
  send_main(MessageType_MessageType_Ping, ping, sizeof(ping));
  EXPECT_EQ(1u, kkconfirm_capture_finish().size());
  EXPECT_TRUE(poll_script.empty());
  EXPECT_EQ(2 * auth.size(), count(U2FHID_ERROR, ERR_CHANNEL_BUSY));
  EXPECT_EQ(2 * auth.size(), u2f_replies.size()) << "U2F ran in the confirm";
  for (uint16_t sw : statuses())
    EXPECT_NE(U2F_SW_NO_ERROR, sw) << "the confirm's press was U2F presence";

  // After the confirm the same request is prompted afresh.
  u2f_replies.clear();
  u2f_reply_cmds.clear();
  push_u2f(std::vector<U2FHID_FRAME>(auth.begin() + 1, auth.end()));
  u2fhid_read(0, &auth[0]);
  EXPECT_EQ(std::vector<uint16_t>{U2F_SW_CONDITIONS_NOT_SATISFIED},
            std::vector<uint16_t>{status(u2f_replies.at(0))});
}

// A rejected normal message is answered through the real failure handler,
// which draws home over the prompt. Presence must not count until the prompt
// is drawn again.
TEST_F(U2FWait, RejectedMessageForgetsPrompt) {
  fsm_init();  // the real failure handler, which redraws the screen
  std::vector<uint8_t> prompt, after, redrawn;
  const uint8_t ping[] = {0x10, 0x01};
  poll_script.push_back([&] { prompt = screen(); });
  poll_script.push_back(
      [&] { send_main(MessageType_MessageType_Ping, ping, sizeof(ping)); });
  poll_script.push_back([&] { after = screen(); });
  hold(true, 3);
  hold(false, 3);
  hold(true, 3);  // a whole press and release while the prompt is gone
  poll_script.push_back([] { send_register(9); });
  poll_script.push_back([&] { redrawn = screen(); });
  hold(false, 3);
  hold(true, 3);
  poll_script.push_back([] { send_register(9); });
  run(9);
  EXPECT_NE(prompt, after) << "the failure did not draw over the prompt";
  EXPECT_EQ(prompt, redrawn);
  EXPECT_EQ(
      (std::vector<uint16_t>{U2F_SW_CONDITIONS_NOT_SATISFIED,
                             U2F_SW_CONDITIONS_NOT_SATISFIED, U2F_SW_NO_ERROR}),
      statuses());
  EXPECT_TRUE(poll_script.empty());
}

namespace {

void settle() {
  for (int frame = 0; frame < 20; ++frame) {
    force_animation_start();
    animate();
  }
}

// Arms a recovery and returns the cipher it drew.
std::vector<uint8_t> arm_recovery() {
  EXPECT_TRUE(kkconfirm_preload(1, 0));
  recovery_cipher_init(12, false, false, "english", "recovery", true, 0, 0,
                       false);
  EXPECT_EQ(0, kkconfirm_drain());
  EXPECT_TRUE(setup_isArmedAs(SETUP_RECOVERY));
  settle();
  return screen();
}

U2FHID_FRAME ping_frame() {
  U2FHID_FRAME f = {};
  f.cid = kCid;
  f.init.cmd = U2FHID_PING;
  f.init.bcntl = 4;
  memcpy(f.init.data, "ping", 4);
  return f;
}

}  // namespace

// While a ceremony waits in the main loop, U2F frames get the busy reply and
// draw nothing. A session used to end on the home screen with the recovery
// still armed, taking CharacterAcks with no cipher shown.
TEST_F(U2FWait, ArmedRecoveryAnswersU2FBusy) {
  const auto cipher = arm_recovery();
  const U2FHID_FRAME ping = ping_frame();
  U2FHID_FRAME init, cont;
  register_frames(1, &init, &cont);
  usb_test_receive_u2f(&ping);
  usb_test_receive_u2f(&init);
  usb_test_receive_u2f(&cont);
  settle();
  EXPECT_EQ(3u, count(U2FHID_ERROR, ERR_CHANNEL_BUSY));
  EXPECT_EQ(3u, u2f_replies.size()) << "a U2F session ran";
  EXPECT_TRUE(setup_isArmedAs(SETUP_RECOVERY));
  EXPECT_EQ(cipher, screen()) << "the cipher was drawn over";
  setup_abort();
}

TEST_F(U2FWait, ArmedResetAnswersU2FBusy) {
  ASSERT_TRUE(setup_stage(false, "english", "reset", 0, 0, false));
  setup_arm(SETUP_RESET);
  const auto before = screen();
  const U2FHID_FRAME ping = ping_frame();
  U2FHID_FRAME init, cont;
  register_frames(1, &init, &cont);
  usb_test_receive_u2f(&ping);
  usb_test_receive_u2f(&init);
  usb_test_receive_u2f(&cont);
  EXPECT_EQ(3u, count(U2FHID_ERROR, ERR_CHANNEL_BUSY));
  EXPECT_EQ(3u, u2f_replies.size()) << "a U2F session ran";
  EXPECT_TRUE(setup_isArmedAs(SETUP_RESET));
  EXPECT_EQ(before, screen());
  setup_abort();

  // Outside a ceremony U2F is served as before.
  u2f_replies.clear();
  u2f_reply_cmds.clear();
  usb_test_receive_u2f(&ping);
  ASSERT_EQ(1u, u2f_replies.size());
  EXPECT_EQ(U2FHID_PING, u2f_reply_cmds[0]);
  EXPECT_EQ(std::vector<uint8_t>({'p', 'i', 'n', 'g'}), u2f_replies[0]);
}

// Defence in depth: a session that ends with a recovery armed restores the
// cipher instead of going home.
TEST_F(U2FWait, SessionEndRestoresArmedCipher) {
  std::vector<uint8_t> cipher;
  poll_script.push_back([&] { cipher = arm_recovery(); });
  run(4);
  settle();
  ASSERT_FALSE(cipher.empty());
  EXPECT_TRUE(setup_isArmedAs(SETUP_RECOVERY));
  EXPECT_EQ(cipher, screen()) << "the session went home over the cipher";
  setup_abort();
}
