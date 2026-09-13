extern "C" {
#include "keepkey/board/layout.h"
#include "keepkey/emulator/setup.h"
#include "keepkey/firmware/fsm.h"
#include "keepkey/firmware/home_sm.h"
#include "keepkey/firmware/recovery_cipher.h"
#include "keepkey/firmware/reset.h"
#include "keepkey/firmware/storage.h"
#include "trezor/crypto/bip39_english.h"
}

#include "gtest/gtest.h"

#include <cstring>
#include <string>

bool kkconfirm_preload(int nYes, int nNo);
int kkconfirm_drain(void);

TEST(Recovery, ExactStrMatch) {
  char LHS[] = "allow\0";
  char RHS[] = "all\0";

  ASSERT_TRUE(exact_str_match(LHS, RHS, 1));
  ASSERT_TRUE(exact_str_match(LHS, RHS, 2));
  ASSERT_TRUE(exact_str_match(LHS, RHS, 3));
  ASSERT_FALSE(exact_str_match(LHS, RHS, 4));
}

bool attempt_auto_complete(char *partial_word);

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

TEST(Recovery, WordlistLengths) {
  for (int i = 0; wordlist[i]; i++) {
    const char *word = wordlist[i];
    size_t len = strlen(word);
    for (int c = len; c <= BIP39_MAX_WORD_LEN; c++) {
      ASSERT_EQ(word[c], '\0') << "bip39 word list must be padded";
    }
  }
}

// Regression coverage for #584: the substitution cipher rotates after every
// character, so recovery_delete_character() must reconstruct coded_word (the
// literal raw bytes the host sent) from history actually preserved at typing
// time, not by re-deriving it through whatever cipher happens to be active
// at delete time. These tests drive recovery_character()/
// recovery_delete_character() directly, via the DEBUG_LINK-only
// recovery_debugLinkStart() hook that arms a ceremony without going through
// recovery_cipher_init()'s confirm()/PIN gate (which blocks on a real button
// press and cannot run headless here).
// unittests/firmware/test_board.cpp -- single guarded board bootstrap for
// the whole binary; see that file for why this must never be called
// directly outside it.
void kk_test_board_init(void);

namespace {

class RecoveryCipher : public ::testing::Test {
 protected:
  void SetUp() override {
    kk_test_board_init();  // canvas for next_character()'s layout_cipher() draw
    static bool fsm_ready = false;
    if (!fsm_ready) {
      fsm_init();
      fsm_ready = true;
    }
    setup_abort();
  }

  void TearDown() override { setup_abort(); }
};

// Looks up the raw cipher byte that currently decodes to `plain`.
char CipherCharFor(char plain) { return recovery_get_cipher()[plain - 'a']; }

// Types `word` (at most 4 chars -- recovery_character() rejects a longer
// in-progress word) through the ACTIVE cipher, one character at a time, so
// each byte sent is the raw cipher-encoded form of a real plaintext letter.
void TypeViaCipher(const char *word) {
  for (const char *p = word; *p; ++p) {
    char buf[2] = {CipherCharFor(*p), '\0'};
    recovery_character(buf);
  }
}

// Types `word` verbatim, unencoded -- simulating a host bypassing the
// substitution cipher and sending real letters directly.
void TypeRaw(const char *word) {
  for (const char *p = word; *p; ++p) {
    char buf[2] = {*p, '\0'};
    recovery_character(buf);
  }
}

void TypeSpace() { recovery_character(" "); }

void Backspace(int n) {
  for (int i = 0; i < n; ++i) recovery_delete_character();
}

}  // namespace

TEST_F(RecoveryCipher, BackspaceWithinWord) {
  recovery_debugLinkStart(/*word_count=*/0);
  ASSERT_TRUE(setup_isArmedAs(SETUP_RECOVERY));

  TypeViaCipher("aban");
  EXPECT_STREQ(recovery_get_decoded_mnemonic(), "aban");

  Backspace(1);
  EXPECT_STREQ(recovery_get_decoded_mnemonic(), "aba");
  EXPECT_EQ(strlen(recovery_get_coded_mnemonic()), 3u);

  TypeViaCipher("n");
  EXPECT_STREQ(recovery_get_decoded_mnemonic(), "aban");
  EXPECT_TRUE(setup_isArmedAs(SETUP_RECOVERY));
}

TEST_F(RecoveryCipher, BackspaceAcrossOneWordBoundaryRestoresRawBytes) {
  recovery_debugLinkStart(/*word_count=*/0);
  ASSERT_TRUE(setup_isArmedAs(SETUP_RECOVERY));

  std::string word1_raw;
  for (const char *p = "aban"; *p; ++p) {
    char c = CipherCharFor(*p);
    word1_raw += c;
    char buf[2] = {c, '\0'};
    recovery_character(buf);
  }
  TypeSpace();
  ASSERT_TRUE(setup_isArmedAs(SETUP_RECOVERY));
  ASSERT_STREQ(recovery_get_decoded_mnemonic(), "aban ");

  Backspace(1);  // delete the trailing space

  EXPECT_STREQ(recovery_get_decoded_mnemonic(), "aban");
  EXPECT_STREQ(recovery_get_coded_mnemonic(), word1_raw.c_str());
}

// The exact repro from #584: complete two words, then back up across BOTH
// of them (deleting word2 entirely and the space in front of it), landing
// back in the middle of editing word1. coded_mnemonic must hold word1's own
// raw bytes, not word2's -- which is precisely what the single-slot
// last_completed_coded_word fix in PR #582 got wrong.
TEST_F(RecoveryCipher, BackspaceAcrossTwoWordBoundariesRestoresRawBytes) {
  recovery_debugLinkStart(/*word_count=*/0);
  ASSERT_TRUE(setup_isArmedAs(SETUP_RECOVERY));

  std::string word1_raw;
  for (const char *p = "aban"; *p; ++p) {
    char c = CipherCharFor(*p);
    word1_raw += c;
    char buf[2] = {c, '\0'};
    recovery_character(buf);
  }
  TypeSpace();
  ASSERT_TRUE(setup_isArmedAs(SETUP_RECOVERY));

  TypeViaCipher("abil");  // "ability"
  TypeSpace();
  ASSERT_TRUE(setup_isArmedAs(SETUP_RECOVERY));
  ASSERT_STREQ(recovery_get_decoded_mnemonic(), "aban abil ");

  // trailing space, all 4 letters of word2, and the space before it: 6 deletes.
  Backspace(6);

  EXPECT_STREQ(recovery_get_decoded_mnemonic(), "aban")
      << "plaintext should be back to word1 alone";
  EXPECT_STREQ(recovery_get_coded_mnemonic(), word1_raw.c_str())
      << "raw coded history must be word1's OWN bytes, not carried over "
         "from word2 (#584)";
  EXPECT_TRUE(setup_isArmedAs(SETUP_RECOVERY));
}

// Generalizes the above to 24 words and 23 boundaries. BIP39's wordlist
// guarantees every word's first four letters are a globally unique prefix,
// so wordlist[i]'s first four characters are always a valid, unambiguous
// word to type here.
TEST_F(RecoveryCipher, BackspaceAcross23WordBoundariesRestoresRawBytes) {
  recovery_debugLinkStart(/*word_count=*/0);
  ASSERT_TRUE(setup_isArmedAs(SETUP_RECOVERY));

  std::string word1_raw;
  for (const char *p = wordlist[0]; p < wordlist[0] + 4; ++p) {
    char c = CipherCharFor(*p);
    word1_raw += c;
    char buf[2] = {c, '\0'};
    recovery_character(buf);
  }
  TypeSpace();
  ASSERT_TRUE(setup_isArmedAs(SETUP_RECOVERY));

  // Complete words at indices 1..22 (22 more words: 23 completed words and
  // 23 boundaries total, counting word0). recovery_cipher.c enforces a
  // 24-word ceremony maximum (words_entered > 24 aborts), so the 24th word
  // (index 23) is typed but deliberately left un-space-completed below --
  // completing it would step words_entered to 25, one past the legitimate
  // maximum, for a reason unrelated to what this test is checking.
  int deletes = 1;  // the space just typed after word1
  for (int w = 1; w < 23; w++) {
    char prefix[5] = {0};
    memcpy(prefix, wordlist[w], 4);
    TypeViaCipher(prefix);
    TypeSpace();
    ASSERT_TRUE(setup_isArmedAs(SETUP_RECOVERY)) << "word index " << w;
    // Not every BIP39 word has 4+ letters (e.g. "act"), so count what was
    // actually typed rather than assuming 4 letters + a space every time.
    deletes += static_cast<int>(strlen(prefix)) + 1;
  }

  char last_prefix[5] = {0};
  memcpy(last_prefix, wordlist[23], 4);
  TypeViaCipher(last_prefix);
  ASSERT_TRUE(setup_isArmedAs(SETUP_RECOVERY));
  deletes += static_cast<int>(strlen(last_prefix));

  Backspace(deletes);

  EXPECT_STREQ(recovery_get_decoded_mnemonic(),
               std::string(wordlist[0], 4).c_str());
  EXPECT_STREQ(recovery_get_coded_mnemonic(), word1_raw.c_str())
      << "raw coded history must survive backing up over 23 completed words";
  EXPECT_TRUE(setup_isArmedAs(SETUP_RECOVERY));
}

// Interleave typing, deleting, and retyping a correction, checking after
// every step that the plaintext mnemonic, the raw coded history, and the
// word count implied by them stay mutually consistent.
TEST_F(RecoveryCipher, RepeatedDeleteRetypeStaysAligned) {
  recovery_debugLinkStart(/*word_count=*/0);
  ASSERT_TRUE(setup_isArmedAs(SETUP_RECOVERY));

  TypeViaCipher("aban");
  TypeSpace();
  ASSERT_TRUE(setup_isArmedAs(SETUP_RECOVERY));
  ASSERT_STREQ(recovery_get_decoded_mnemonic(), "aban ");

  TypeViaCipher("abou");  // start typing a wrong word ("about")
  ASSERT_STREQ(recovery_get_decoded_mnemonic(), "aban abou");

  Backspace(4);  // realize the mistake, delete all four letters
  ASSERT_STREQ(recovery_get_decoded_mnemonic(), "aban ");
  ASSERT_EQ(strlen(recovery_get_coded_mnemonic()),
            strlen(recovery_get_decoded_mnemonic()));

  TypeViaCipher("abov");  // correct to "above" instead
  ASSERT_TRUE(setup_isArmedAs(SETUP_RECOVERY));
  EXPECT_STREQ(recovery_get_decoded_mnemonic(), "aban abov");
  EXPECT_EQ(strlen(recovery_get_coded_mnemonic()),
            strlen(recovery_get_decoded_mnemonic()));

  TypeSpace();
  EXPECT_TRUE(setup_isArmedAs(SETUP_RECOVERY));
  EXPECT_STREQ(recovery_get_decoded_mnemonic(), "aban abov ");
}

// After a multi-boundary backspace, a host sending a real BIP39 prefix
// directly (bypassing the cipher entirely) must still be caught -- proving
// coded_word/coded_mnemonic aren't left holding stale bytes from an earlier,
// already-backed-out-of word that would mask the raw prefix.
TEST_F(RecoveryCipher, RawPrefixAfterMultiBoundaryBackspaceStillCaught) {
  recovery_debugLinkStart(/*word_count=*/0);
  ASSERT_TRUE(setup_isArmedAs(SETUP_RECOVERY));

  TypeViaCipher("aban");
  TypeSpace();
  TypeViaCipher("abil");
  TypeSpace();
  ASSERT_TRUE(setup_isArmedAs(SETUP_RECOVERY));

  Backspace(
      6);  // back into the middle of word1, same as the boundary test above
  ASSERT_TRUE(setup_isArmedAs(SETUP_RECOVERY));
  ASSERT_STREQ(recovery_get_decoded_mnemonic(), "aban");

  Backspace(4);  // and all the way out, so the next word starts clean
  ASSERT_TRUE(setup_isArmedAs(SETUP_RECOVERY));
  ASSERT_STREQ(recovery_get_decoded_mnemonic(), "");
  ASSERT_STREQ(recovery_get_coded_mnemonic(), "");

  // Try a few fixed real-word prefixes raw and take whichever one's
  // cipher-decoded form ISN'T itself coincidentally a valid prefix too (the
  // production code's own comment documents a ~0.4% coincidence rate for
  // any single one -- trying several fixed candidates makes the test
  // deterministic regardless of this ceremony's randomly generated cipher).
  static const char *kCandidates[] = {"aban", "abil", "able", "abou", "abov"};
  bool caught = false;
  for (const char *candidate : kCandidates) {
    char decoded_probe[8] = {0};
    for (size_t i = 0; i < strlen(candidate); i++) {
      const char *pos = strchr(recovery_get_cipher(), candidate[i]);
      ASSERT_NE(pos, nullptr);
      decoded_probe[i] =
          "abcdefghijklmnopqrstuvwxyz"[pos - recovery_get_cipher()];
    }
    if (attempt_auto_complete(decoded_probe)) {
      continue;  // this candidate's raw form also happens to decode validly
    }

    TypeRaw(candidate);
    if (!setup_isArmedAs(SETUP_RECOVERY)) {
      caught = true;  // mid-word uncyphered-count check aborted it
      break;
    }
    TypeSpace();
    if (!setup_isArmedAs(SETUP_RECOVERY)) {
      caught = true;  // space-completion wordlist validation aborted it
      break;
    }
    // Accepted outright: re-arm and try the next candidate. setup_abort()
    // first -- setup_stage() (inside recovery_debugLinkStart()) refuses to
    // restage over an already-armed ceremony.
    setup_abort();
    recovery_debugLinkStart(/*word_count=*/0);
  }

  EXPECT_TRUE(caught) << "a raw, unenciphered real-word prefix must be "
                         "rejected, not silently accepted as if the cipher "
                         "had been used";
}

/* A cipher-recovery ceremony driven entirely with separators: words_entered
 * counts separators, but strtok() collapses runs of them, so the count gate
 * passes while the phrase that reaches the commit has no words in it at all.
 * Committing that stores the empty mnemonic, whose seed is public. */
TEST(Recovery, SpacesOnlyCeremonyIsRefusedAndCommitsNothing) {
  // preload also performs the one-per-binary board bootstrap, fsm_init() and
  // usbInit(); one decision answers recovery_cipher_init()'s confirm screen.
  ASSERT_TRUE(kkconfirm_preload(1, 0));
  static bool storage_ready = false;
  if (!storage_ready) {
    setup();  // urandom + the emulator's mmap'd flash, as storage needs
    storage_init();
    storage_ready = true;
  }
  storage_wipe();
  ASSERT_FALSE(storage_isInitialized());

  // enforce_wordlist is omitted by default on the wire, which is what makes
  // the commit condition skip mnemonic_check() entirely.
  recovery_cipher_init(/*word_count=*/12, /*passphrase_protection=*/false,
                       /*pin_protection=*/false, "english", "spaces",
                       /*enforce_wordlist=*/false, /*auto_lock_delay_ms=*/0,
                       /*u2f_counter=*/0, /*dry_run=*/false);
  ASSERT_TRUE(setup_isArmedAs(SETUP_RECOVERY));

  for (int i = 0; i < 12; i++) {
    recovery_character(" ");
  }

  EXPECT_FALSE(storage_isInitialized())
      << "a ceremony that produced no words must not commit a seed";
  EXPECT_FALSE(setup_isArmed());
  (void)kkconfirm_drain();
  storage_wipe();
  layoutHomeForced();
}
