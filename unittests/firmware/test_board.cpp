/*
 * One board bootstrap per test binary.
 *
 * kk_board_init() calls kk_timer_init(), and timer_init() does the same work:
 * both push the three static runnables[] nodes onto free_queue
 * unconditionally. A SECOND bootstrap therefore relinks nodes that are already
 * linked -- free_queue and active_queue become circular, and the
 * runnable_queue_get() walk inside post_periodic() never returns.
 *
 * That is a hang, not a failure. Keep the guard in this single translation unit
 * so every confirmation test shares one bootstrap. Nothing else in
 * unittests/firmware may call kk_board_init() or timer_init() directly.
 *
 * No includes on purpose: keepkey_board.h declares shutdown(void), which
 * clashes with sys/socket.h, and this file has already cost one build on
 * include order.
 */

// keepkey_board.c is compiled as C.  This declaration must therefore carry C
// linkage even though the test seam itself is C++.
extern "C" void kk_board_init(void);  // lib/board/keepkey_board.c

void kk_test_board_init(void) {
  static bool initialized = false;
  if (initialized) return;
  kk_board_init();
  initialized = true;
}
