extern "C" {
#include <stdint.h>

#include "trezor/crypto/sha2.h"
#include "keepkey/firmware/authenticator.h"
#include "keepkey/firmware/fsm.h"
#include "keepkey/firmware/storage.h"

void setup(void);
void tim4_sighandler(int sig);  // lib/board/timer.c, emulator build
}

#include "gtest/gtest.h"

#include <csignal>
#include <unistd.h>
#include <cstring>
#include <string>
#include <vector>

bool kkconfirm_preload(int nYes, int nNo);
int kkconfirm_drain(void);
void kkconfirm_capture_start(void);
std::vector<std::string> kkconfirm_capture_finish(void);

/* A released code is shown with a countdown built on delay_ms(), which needs
 * the 1 ms tick the emulator gets from SIGALRM. The unit-test board does not
 * start it, so run it for the scope of a releasing request. */
struct ScopedTick {
  struct sigaction previous = {};
  ScopedTick() {
    struct sigaction action = {};
    action.sa_handler = tim4_sighandler;
    action.sa_flags = SA_RESTART;
    sigaction(SIGALRM, &action, &previous);
    ualarm(1000, 1000);
  }
  ~ScopedTick() {
    ualarm(0, 0);
    sigaction(SIGALRM, &previous, nullptr);
  }
};

static void ensure_auth_storage_initialized(void) {
  static bool initialized = false;
  if (!initialized) {
    setup();
    storage_init();
    initialized = true;
  }
}

TEST(Authenticator, AuthorizationLossClearsAndReloadsPersistentCache) {
  ensure_auth_storage_initialized();
  ASSERT_TRUE(kkconfirm_preload(1, 0));
  ASSERT_EQ(NOERR, wipeAuthData());
  ASSERT_EQ(0, kkconfirm_drain());

  char account_seed[] = "example:alice:JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP";
  ASSERT_TRUE(kkconfirm_preload(2, 0));
  ASSERT_EQ(NOERR, addAuthAccount(account_seed));
  ASSERT_EQ(0, kkconfirm_drain());
  ASSERT_FALSE(authenticator_cache_is_empty());

  char account[DOMAIN_SIZE + ACCOUNT_SIZE + 2] = {0};
  authenticator_clear_cache();
  ASSERT_TRUE(authenticator_cache_is_empty());
  EXPECT_EQ(NOERR, getAuthAccount("0", account));
  EXPECT_STREQ("example:alice", account);
  EXPECT_FALSE(authenticator_cache_is_empty());

  const struct {
    const char* name;
    void (*revoke)(void);
  } authorization_losses[] = {
      {"ClearSession/lock", [] { session_clear(/*clear_pin=*/true); }},
      {"Initialize", [] { fsm_msgInitialize(nullptr); }},
      {"Cancel", [] { fsm_msgCancel(nullptr); }},
  };

  for (const auto& loss : authorization_losses) {
    SCOPED_TRACE(loss.name);
    authenticator_test_seed_cache();
    ASSERT_FALSE(authenticator_cache_is_empty());
    loss.revoke();
    ASSERT_TRUE(authenticator_cache_is_empty());
  }

  ASSERT_TRUE(kkconfirm_preload(1, 0));
  ASSERT_EQ(NOERR, wipeAuthData());
  ASSERT_EQ(0, kkconfirm_drain());
}

TEST(Authenticator, RejectedOtpReviewReturnsNoOtp) {
  ensure_auth_storage_initialized();
  ASSERT_TRUE(kkconfirm_preload(1, 0));
  ASSERT_EQ(NOERR, wipeAuthData());
  ASSERT_EQ(0, kkconfirm_drain());

  char account_seed[] = "example:alice:JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP";
  ASSERT_TRUE(kkconfirm_preload(2, 0));
  ASSERT_EQ(NOERR, addAuthAccount(account_seed));
  ASSERT_EQ(0, kkconfirm_drain());

  char request[] = "example:alice:1:30";
  char otp[9];
  memset(otp, 0xA5, sizeof(otp));
  ASSERT_TRUE(kkconfirm_preload(0, 1));
  EXPECT_EQ(CANCELED, generateOTP(request, otp));
  EXPECT_EQ(0, kkconfirm_drain());
  const char zeros[9] = {0};
  EXPECT_EQ(0, memcmp(otp, zeros, sizeof(otp)));

  ASSERT_TRUE(kkconfirm_preload(1, 0));
  EXPECT_EQ(NOERR, wipeAuthData());
  EXPECT_EQ(0, kkconfirm_drain());
}

#include <string>

static void reset_auth_accounts() {
  ensure_auth_storage_initialized();
  ASSERT_TRUE(kkconfirm_preload(1, 0));
  ASSERT_EQ(NOERR, wipeAuthData());
  ASSERT_EQ(0, kkconfirm_drain());
}

static unsigned add_credential(const std::string& text, int yes, int no) {
  char source[256] = {};
  if (text.size() >= sizeof(source)) return UNKERR;
  memcpy(source, text.c_str(), text.size());
  EXPECT_TRUE(kkconfirm_preload(yes, no));
  unsigned result = addAuthAccount(source);
  EXPECT_EQ(0, kkconfirm_drain());
  for (char byte : source) EXPECT_EQ(0, byte);
  return result;
}

static const char* strong_secret = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP";

TEST(Authenticator, ExactIdentityAndSecretBoundsRejectBeforeReview) {
  reset_auth_accounts();
  const char* invalid[] = {"",
                           ":alice:",
                           "example::",
                           "::example:alice:",
                           "example:alice::",
                           "abcdefghijkl:alice:",
                           "example:abcdefghijkl:",
                           "exam\nple:alice:",
                           "example:ali\tce:",
                           "example:\x7f:"};
  for (const char* prefix : invalid) {
    SCOPED_TRACE(prefix);
    EXPECT_NE(NOERR, add_credential(std::string(prefix) + strong_secret, 0, 0));
  }
  for (size_t length : {0u, 1u, 16u, 25u, 27u, 30u, 33u, 34u, 40u}) {
    SCOPED_TRACE(length);
    EXPECT_NE(NOERR, add_credential("example:alice:" + std::string(length, 'A'),
                                    0, 0));
  }
  EXPECT_EQ(BADSECRET,
            add_credential("example:alice:" + std::string(32, '!'), 0, 0));
  EXPECT_EQ(TOKERR, addAuthAccount(nullptr));
  EXPECT_EQ(TOKERR, removeAuthAccount(nullptr));
  char account[DOMAIN_SIZE + ACCOUNT_SIZE + 2] = {};
  EXPECT_EQ(NOACC, getAuthAccount("0", account));
}

TEST(Authenticator, ExactBoundsPersistAndDuplicateCannotReplaceSecret) {
  reset_auth_accounts();
  EXPECT_EQ(
      NOERR,
      add_credential("abcdefghijk:ABCDEFGHIJK:" + std::string(26, 'A'), 2, 0));
  authType before[AUTHDATA_SIZE] = {};
  ASSERT_TRUE(storage_getAuthData(before));
  EXPECT_EQ(16, before[0].secretSize);
  EXPECT_STREQ("abcdefghijk", before[0].domain);
  EXPECT_STREQ("ABCDEFGHIJK", before[0].account);
  EXPECT_EQ(DUPLICATE,
            add_credential(
                std::string("abcdefghijk:ABCDEFGHIJK:") + strong_secret, 0, 0));
  authType after[AUTHDATA_SIZE] = {};
  ASSERT_TRUE(storage_getAuthData(after));
  EXPECT_EQ(0, memcmp(before, after, sizeof(before)));
  EXPECT_EQ(NOERR, add_credential(std::string("example:alice:") + strong_secret,
                                  2, 0));
  authenticator_clear_cache();
  char account[DOMAIN_SIZE + ACCOUNT_SIZE + 2] = {};
  EXPECT_EQ(NOERR, getAuthAccount("1", account));
  EXPECT_STREQ("example:alice", account);
}

TEST(Authenticator, EitherAddRejectionWipesInputAndLeavesStorageUnchanged) {
  reset_auth_accounts();
  for (int accepted : {0, 1}) {
    SCOPED_TRACE(accepted);
    EXPECT_EQ(CANCELED,
              add_credential(std::string("example:alice:") + strong_secret,
                             accepted, 1));
    EXPECT_TRUE(authenticator_cache_is_empty());
    char account[DOMAIN_SIZE + ACCOUNT_SIZE + 2] = {};
    EXPECT_EQ(NOACC, getAuthAccount("0", account));
  }
  EXPECT_EQ(NOERR, add_credential(std::string("example:alice:") + strong_secret,
                                  2, 0));
}

TEST(Authenticator, LegacyDuplicatesAreDeletedTogetherOnlyAfterConsent) {
  reset_auth_accounts();
  authType legacy[AUTHDATA_SIZE] = {};
  for (unsigned slot : {0u, 3u, 9u}) {
    strcpy(legacy[slot].domain, "example");
    strcpy(legacy[slot].account, "alice");
    legacy[slot].secretSize = 10;
    memset(legacy[slot].authSecret, slot + 1, 10);
  }
  legacy[1] = legacy[0];
  strcpy(legacy[1].account, "bob");
  storage_setAuthData(legacy);
  authenticator_clear_cache();
  // Pre-minimum credentials still generate the independently computed HOTP.
  char legacy_request[] = "example:alice:1:5";
  char legacy_otp[9] = {};
  ASSERT_TRUE(kkconfirm_preload(1, 0));
  {
    ScopedTick tick;
    EXPECT_EQ(NOERR, generateOTP(legacy_request, legacy_otp));
  }
  EXPECT_EQ(0, kkconfirm_drain());
  EXPECT_STREQ("356917", legacy_otp);  // HMAC-SHA1: ten 0x01 bytes, counter 1
  char refused[] = "example:alice";
  ASSERT_TRUE(kkconfirm_preload(0, 1));
  EXPECT_EQ(CANCELED, removeAuthAccount(refused));
  EXPECT_EQ(0, kkconfirm_drain());
  EXPECT_TRUE(authenticator_cache_is_empty());
  authType after[AUTHDATA_SIZE] = {};
  ASSERT_TRUE(storage_getAuthData(after));
  EXPECT_EQ(0, memcmp(legacy, after, sizeof(legacy)));
  char accepted[] = "example:alice";
  ASSERT_TRUE(kkconfirm_preload(1, 0));
  EXPECT_EQ(NOERR, removeAuthAccount(accepted));
  EXPECT_EQ(0, kkconfirm_drain());
  ASSERT_TRUE(storage_getAuthData(after));
  const authType empty = {};
  for (unsigned slot : {0u, 3u, 9u})
    EXPECT_EQ(0, memcmp(&empty, &after[slot], sizeof(empty)));
  EXPECT_EQ(0, memcmp(&legacy[1], &after[1], sizeof(empty)));
}

TEST(Authenticator, OtpIdentityCannotAliasStoredPrefixOrEmptyFields) {
  reset_auth_accounts();
  EXPECT_EQ(NOERR,
            add_credential(
                std::string("abcdefghijk:ABCDEFGHIJK:") + strong_secret, 2, 0));
  const char* invalid[] = {
      "abcdefghijkX:ABCDEFGHIJK:1:30", "abcdefghijk:ABCDEFGHIJKX:1:30",
      ":abcdefghijk:ABCDEFGHIJK:1:30", "abcdefghijk::ABCDEFGHIJK:1:30",
      "abcdefghijk:\n:1:30"};
  for (const char* value : invalid) {
    SCOPED_TRACE(value);
    char request[128] = {};
    strcpy(request, value);
    char otp[9];
    memset(otp, 0xa5, sizeof(otp));
    ASSERT_TRUE(kkconfirm_preload(0, 0));
    EXPECT_EQ(TOKERR, generateOTP(request, otp));
    EXPECT_EQ(0, kkconfirm_drain());
    const char empty[9] = {};
    EXPECT_EQ(0, memcmp(empty, otp, sizeof(otp)));
  }
}

TEST(Authenticator, ExactOtpIdentityRetainsIndependentCounterVector) {
  reset_auth_accounts();
  EXPECT_EQ(NOERR, add_credential(
                       "example:alice:GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", 2, 0));
  char request[] = "example:alice:1:5";
  char otp[9] = {};
  ASSERT_TRUE(kkconfirm_preload(1, 0));
  {
    ScopedTick tick;
    EXPECT_EQ(NOERR, generateOTP(request, otp));
  }
  EXPECT_EQ(0, kkconfirm_drain());
  // HOTP SHA1, ASCII key 12345678901234567890, counter 1, six digits.
  EXPECT_STREQ("287082", otp);
}

TEST(Authenticator, OtpTimeFieldsRejectJunkOverflowAndExcessiveCountdown) {
  reset_auth_accounts();
  EXPECT_EQ(NOERR, add_credential(std::string("example:alice:") + strong_secret,
                                  2, 0));
  for (const char* timing : {":30", "1:", "+1:30", "-1:30", "1x:30",
                             "4294967296:30", "18446744073709551616:30", "1:31",
                             "1:-1", "1:4294967295", "1:30x", "1:30:0"}) {
    SCOPED_TRACE(timing);
    std::string text = std::string("example:alice:") + timing;
    char request[128] = {};
    memcpy(request, text.c_str(), text.size());
    char otp[9];
    memset(otp, 0xa5, sizeof(otp));
    ASSERT_TRUE(kkconfirm_preload(0, 0));
    EXPECT_EQ(TOKERR, generateOTP(request, otp));
    EXPECT_EQ(0, kkconfirm_drain());
    const char empty[9] = {};
    EXPECT_EQ(0, memcmp(empty, otp, sizeof(otp)));
  }
  // Largest supported counter still reaches consent; refusal releases no OTP.
  char boundary[] = "example:alice:4294967295:30";
  char otp[9] = {};
  ASSERT_TRUE(kkconfirm_preload(0, 1));
  EXPECT_EQ(CANCELED, generateOTP(boundary, otp));
  EXPECT_EQ(0, kkconfirm_drain());
}

TEST(Authenticator, AccountSlotRejectsNumericAliasesBeforeLookup) {
  reset_auth_accounts();
  ASSERT_EQ(NOERR, add_credential(std::string("example:alice:") + strong_secret, 2, 0));
  char account[DOMAIN_SIZE + ACCOUNT_SIZE + 2] = {};
  ASSERT_EQ(NOERR, getAuthAccount("0", account));
  EXPECT_STREQ("example:alice", account);
  const char* invalid[] = {nullptr, "", "256", "0junk", "+0", "-256", " 0",
                           "0 ", "1:0", "10", "4294967296", "18446744073709551616"};
  for (const char* slot : invalid) {
    memset(account, 0, sizeof(account));
    EXPECT_EQ(NOSLOT, getAuthAccount(slot, account));
    EXPECT_STREQ("", account);
  }
  EXPECT_EQ(NOACC, getAuthAccount("9", account));
  EXPECT_EQ(NOERR, getAuthAccount("0", account));
  EXPECT_STREQ("example:alice", account);
}

// The one screen that releases a code names the stored account and the UTC
// start of the host-chosen 30 s window, so a future window is visible.
TEST(Authenticator, OtpReleaseScreenNamesAccountAndWindow) {
  reset_auth_accounts();
  ASSERT_EQ(NOERR, add_credential(std::string("example:alice:") + strong_secret,
                                  2, 0));
  const struct {
    const char* timing;
    const char* window;
  } cases[] = {{"56666666:30", "2023-11-14 22:13:00"},
               {"0:30", "1970-01-01 00:00:00"},
               {"4294967295:30", "6053-01-23 02:07:30"}};
  for (const auto& c : cases) {
    SCOPED_TRACE(c.timing);
    std::string text = std::string("example:alice:") + c.timing;
    char request[64] = {};
    memcpy(request, text.c_str(), text.size());
    char otp[9] = {};
    kkconfirm_capture_start();
    ASSERT_TRUE(kkconfirm_preload(0, 1));
    EXPECT_EQ(CANCELED, generateOTP(request, otp));
    EXPECT_EQ(0, kkconfirm_drain());
    const std::vector<std::string> screens = kkconfirm_capture_finish();
    ASSERT_EQ(1u, screens.size());
    EXPECT_EQ(std::string("Account: example:alice\nTime: ") + c.window + " UTC",
              screens[0]);
  }
}

// Too little of the window left after consent: no code. A second accepted
// screen is queued, as older firmware asked for one and then released the code;
// it must stay unused.
TEST(Authenticator, OtpTimeoutReleasesNoCode) {
  reset_auth_accounts();
  ASSERT_EQ(NOERR, add_credential(std::string("example:alice:") + strong_secret,
                                  2, 0));
  for (const char* timing : {"1:0", "1:3"}) {
    SCOPED_TRACE(timing);
    std::string text = std::string("example:alice:") + timing;
    char request[64] = {};
    memcpy(request, text.c_str(), text.size());
    char otp[9];
    memset(otp, 0xa5, sizeof(otp));
    ASSERT_TRUE(kkconfirm_preload(2, 0));
    EXPECT_EQ(OTPTIMEOUT, generateOTP(request, otp));
    EXPECT_EQ(2, kkconfirm_drain());  // one screen's ButtonAck + decision
    const char empty[9] = {};
    EXPECT_EQ(0, memcmp(empty, otp, sizeof(otp)));
  }
  char account[DOMAIN_SIZE + ACCOUNT_SIZE + 2] = {};
  EXPECT_EQ(NOERR, getAuthAccount("0", account));
  EXPECT_STREQ("example:alice", account);
}
