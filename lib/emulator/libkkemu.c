/*
 * libkkemu — KeepKey firmware emulator as a shared library.
 *
 * Replaces main() with kkemu_init/poll/shutdown. Uses ring buffers
 * instead of UDP sockets for message I/O.
 */
#include "keepkey/emulator/libkkemu.h"
#include "keepkey/emulator/emulator.h"
#include "keepkey/emulator/setup.h"
#include "keepkey/board/canvas.h"
#include "keepkey/board/keepkey_board.h"
#include "keepkey/board/keepkey_display.h"
#include "keepkey/board/keepkey_flash.h"
#include "keepkey/board/layout.h"
#include "keepkey/board/usb.h"
#include "keepkey/board/memory.h"
#include "keepkey/board/timer.h"
#include "keepkey/firmware/fsm.h"
#include "keepkey/firmware/home_sm.h"
#include "keepkey/firmware/storage.h"
#include "keepkey/rand/rng.h"
#include "ringbuf.h"
#include "trezor/crypto/memzero.h"

#include <stdio.h>
#include <string.h>
#include <errno.h>
#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN /* exclude winsock.h — it declares \
                               shutdown(SOCKET,int) */
#include <windows.h>
#else
#include <sys/mman.h>
#include <pthread.h>
#include <time.h>
#endif

/* Defined in firmware — we just need the declaration */
extern void fsm_init(void);

/* ── Poll thread (optional, kkemu_start) ───────────────────────────────
 * Runs the firmware loop so a blocking confirm can wait without freezing the
 * host. Only this thread drives firmware; the host uses the SPSC rings, and
 * g_fw_lock keeps storage_commit from tearing a saveFlash read. Not started:
 * single-threaded via kkemu_poll(), and the lock helpers no-op. */
#ifdef _WIN32
static CRITICAL_SECTION g_fw_lock;
static int g_fw_lock_ready = 0; /* initialized once, never deleted */
static HANDLE g_poll_thread = NULL;
#define FW_LOCK() EnterCriticalSection(&g_fw_lock)
#define FW_UNLOCK() LeaveCriticalSection(&g_fw_lock)
#define FW_TRYLOCK() TryEnterCriticalSection(&g_fw_lock)
#else
static pthread_mutex_t g_fw_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_t g_poll_thread;
#define FW_LOCK() pthread_mutex_lock(&g_fw_lock)
#define FW_UNLOCK() pthread_mutex_unlock(&g_fw_lock)
#define FW_TRYLOCK() (pthread_mutex_trylock(&g_fw_lock) == 0)
#endif

/* acquire/release also publishes the surrounding firmware/ring state. */
#include <stdatomic.h>
static _Atomic int g_poll_running = 0;
#define POLL_RUNNING() atomic_load_explicit(&g_poll_running, memory_order_acquire)
#define POLL_SET(v) atomic_store_explicit(&g_poll_running, (v), memory_order_release)

/* This host thread owns g_fw_lock; unlock keys on this, not on
 * g_poll_running. Per thread, so a thread that got the no-poll-thread success
 * from kkemu_trylock() cannot release a lock another thread still holds. */
static _Thread_local int g_host_holds_lock = 0;

/* ── Ring buffers (replace UDP sockets) ─────────────────────────────── */

static RingBuf rb_main_in;   /* host → firmware (main interface) */
static RingBuf rb_main_out;  /* firmware → host (main interface) */
static RingBuf rb_debug_in;  /* host → firmware (debug link) */
static RingBuf rb_debug_out; /* firmware → host (debug link) */

static int libkkemu_initialized = 0;

/* ── Display capture ring ───────────────────────────────────────────── */

/*
 * Captures every display_refresh() into a ring of 1-bit packed snapshots.
 * The host drains via kkemu_pop_frame(). Adjacent identical frames are
 * skipped so an idle firmware doesn't spam the ring.
 *
 * Lock-free SPSC (poll thread produces). When full the producer drops the
 * NEW frame: it must not touch a slot or index the consumer owns.
 */
#define FRAME_PACKED_SIZE 2048
#define FRAME_RING_SIZE 64

/* ms-timer ticks per poll (host polls ~16ms). */
#define KKEMU_POLL_INTERVAL_MS 16

static uint8_t frame_ring[FRAME_RING_SIZE][FRAME_PACKED_SIZE];
static uint8_t last_packed[FRAME_PACKED_SIZE];
/* Pack target for libkkemu_capture_frame(), so a frame that turns out to be a
   duplicate never touches the ring. See the comment there. */
static uint8_t capture_scratch[FRAME_PACKED_SIZE];
static int last_packed_valid = 0;
static _Atomic uint32_t frame_write_idx =
    0; /* monotonic, mod FRAME_RING_SIZE for slot */
static _Atomic uint32_t frame_read_idx = 0; /* monotonic */

/*
 * Scratch returned by kkemu_get_display(). File-scope (not function-static)
 * so kkemu_shutdown() can zero it alongside the other display buffers.
 */
static uint8_t display_packed_scratch[FRAME_PACKED_SIZE];

/* ── Replacement I/O functions ──────────────────────────────────────── */

/*
 * These replace the UDP socket functions in emulator/udp.c.
 * When building as a shared library, we link against these instead.
 */

void libkkemu_socketInit(void) {
  ringbuf_init(&rb_main_in);
  ringbuf_init(&rb_main_out);
  ringbuf_init(&rb_debug_in);
  ringbuf_init(&rb_debug_out);
}

size_t libkkemu_socketRead(int* iface, void* buffer, size_t size) {
  if (ringbuf_pop(&rb_main_in, (uint8_t*)buffer, size)) {
    *iface = 0;
    return size < RINGBUF_SLOT_SIZE ? size : RINGBUF_SLOT_SIZE;
  }
  if (ringbuf_pop(&rb_debug_in, (uint8_t*)buffer, size)) {
    *iface = 1;
    return size < RINGBUF_SLOT_SIZE ? size : RINGBUF_SLOT_SIZE;
  }
  return 0;
}

size_t libkkemu_socketWrite(int iface, const void* buffer, size_t size) {
  RingBuf* rb = (iface == 0) ? &rb_main_out : &rb_debug_out;
  if (!ringbuf_push(rb, (const uint8_t*)buffer, size)) return 0;
  return size;
}

/* ── Display capture callback ───────────────────────────────────────── */

/*
 * Pack the 8-bpp grayscale canvas (256x64 = 16384 bytes) into the
 * 1-bit SSD1306 page format the host wants. Skip if identical to the
 * last frame we captured. Called from display_refresh() on every poll
 * and on every iteration of confirm_helper's busy loop.
 */
static void libkkemu_capture_frame(const uint8_t* canvas_buf) {
  if (!canvas_buf) return;

  /* Pack into scratch, NOT straight into the ring slot.
   *
   * Packing in place and only then testing for a duplicate destroyed data:
   * once the ring is full, frame_ring[frame_write_idx % FRAME_RING_SIZE] is
   * the OLDEST UNREAD frame, and the early return on a duplicate left it
   * overwritten while frame_read_idx still pointed at it. The host's next
   * kkemu_pop_frame() then returned a frame it had never been shown, and the
   * one it was owed was gone. Deduplicate first; touch the ring only for a
   * frame that is actually going to be published. */
  memset(capture_scratch, 0, FRAME_PACKED_SIZE);
  for (int x = 0; x < 256; x++) {
    for (int y = 0; y < 64; y++) {
      if (display_mono_pixel_is_lit(canvas_buf[y * 256 + x], x, y)) {
        capture_scratch[x + (y / 8) * 256] |= (uint8_t)(1u << (y % 8));
      }
    }
  }

  /* Dedup: skip if identical to last captured */
  if (last_packed_valid &&
      memcmp(capture_scratch, last_packed, FRAME_PACKED_SIZE) == 0) {
    return;
  }
  uint32_t w = atomic_load_explicit(&frame_write_idx, memory_order_relaxed);
  uint32_t r = atomic_load_explicit(&frame_read_idx, memory_order_acquire);
  if (w - r >= FRAME_RING_SIZE) return;

  memcpy(frame_ring[w % FRAME_RING_SIZE], capture_scratch, FRAME_PACKED_SIZE);
  atomic_store_explicit(&frame_write_idx, w + 1, memory_order_release);
  /* A dropped frame must remain eligible for capture after the host drains. */
  memcpy(last_packed, capture_scratch, FRAME_PACKED_SIZE);
  last_packed_valid = 1;
}

/* ── Public API ─────────────────────────────────────────────────────── */

int kkemu_init(uint8_t* flash_buf, size_t flash_len) {
  if (flash_len != KKEMU_FLASH_SIZE) return -1;
  if (!flash_buf) return -1;
  if (libkkemu_initialized) return -1;

  /* Point firmware's flash pointer at the host-provided buffer */
  emulator_flash_base = flash_buf;

  /*
   * Lock memory to prevent secrets in the flash buffer (seed, FVK, PIN
   * derivation state) from being swapped out. Failure is non-fatal — many
   * platforms cap unprivileged mlock at a few MB (RLIMIT_MEMLOCK), and a
   * dev/CI environment that hits the cap shouldn't break emulator usage.
   * We DO log to stderr so the host can decide to escalate (raise the
   * rlimit, run with CAP_IPC_LOCK, etc.) before signing real material.
   * Production hosts of libkkemu should treat a logged failure as a
   * security warning and refuse to load secrets.
   */
#ifdef _WIN32
  if (!VirtualLock(flash_buf, flash_len)) {
    fprintf(stderr,
            "[libkkemu] VirtualLock(%zu bytes) failed (err %lu) — flash buffer "
            "may be paged to disk; do not load production secrets\n",
            flash_len, (unsigned long)GetLastError());
  }
#else
  if (mlock(flash_buf, flash_len) != 0) {
    fprintf(stderr,
            "[libkkemu] mlock(%zu bytes) failed: %s — flash buffer may be "
            "swapped to disk; do not load production secrets\n",
            flash_len, strerror(errno));
  }
#endif

  /* Initialize ring buffers (replaces UDP socket init) */
  libkkemu_socketInit();

  /* Reset frame capture state */
  frame_write_idx = 0;
  frame_read_idx = 0;
  last_packed_valid = 0;

  /* Initialize /dev/urandom for RNG */
  setup_urandom_only();

  /* Board init (timers, etc.) */
  kk_board_init();

  /* Hook display_refresh() so every canvas update is captured into
   * our ring buffer. Must be set before storage_init/fsm_init/
   * layoutHomeForced so the boot screens get captured too. */
  display_set_dump_callback(libkkemu_capture_frame);

  /* Load storage from flash buffer */
  storage_init();

  /* Initialize message handler FSM */
  fsm_init();

  /* Draw initial home screen */
  layoutHomeForced();

  libkkemu_initialized = 1;
  return 0;
}

void kkemu_shutdown(void) {
  if (!libkkemu_initialized) return;

  /* Join the producer before touching firmware, rings, or host flash. */
  kkemu_stop();

  /*
   * End any workflow still in flight BEFORE anything else.
   *
   * The buffer scrubbing below covers the transport rings and the frame ring,
   * but signing state and fsm_derived_node -- the shared derived private-key
   * scratch -- live behind fsm_abort_workflows(), which nothing here was
   * calling. In the dylib case this file is written for, the library sits in a
   * long-running host process, so a shutdown/init cycle would carry an old
   * workflow and its key material across into the next session. That is the
   * same exposure the comment below describes, and it needs the same answer.
   *
   * Before storage_commit() so the committed image reflects the aborted state
   * rather than a half-finished ceremony.
   */
  fsm_abort_workflows();

  /* Flush any pending storage to the flash buffer */
  storage_commit();

  /*
   * Zero every static buffer that could hold sensitive material before
   * we tear down. In dylib mode this library lives inside a long-running
   * host process — the static rings, frame ring, and packed-display
   * scratch can outlive the emulator session and be visible to the rest
   * of the host's memory image (core dumps, ptrace, GC roots in a Bun
   * runtime, etc.). Specifically:
   *
   *   - rb_main_in / rb_main_out:  PIN, passphrase, signing inputs/outputs
   *   - rb_debug_in / rb_debug_out: mnemonic + recovery state when
   *                                 KK_DEBUG_LINK builds are loaded
   *   - frame_ring / last_packed:  rendered OLED bytes for every screen,
   *                                including PIN matrix, recovery words,
   *                                address confirms, signing summaries
   *
   * memzero() is the trezor-crypto helper that the compiler can't optimize
   * out. Same primitive used throughout the firmware to clear key material.
   */
  memzero(&rb_main_in, sizeof(rb_main_in));
  memzero(&rb_main_out, sizeof(rb_main_out));
  memzero(&rb_debug_in, sizeof(rb_debug_in));
  memzero(&rb_debug_out, sizeof(rb_debug_out));
  memzero(frame_ring, sizeof(frame_ring));
  memzero(last_packed, sizeof(last_packed));
  memzero(capture_scratch, sizeof(capture_scratch));
  memzero(display_packed_scratch, sizeof(display_packed_scratch));
  last_packed_valid = 0;
  frame_write_idx = 0;
  frame_read_idx = 0;

  /*
   * Unlock + caller is responsible for zeroing the host-owned flash buffer
   * after this returns. We explicitly DO NOT zero it here — the host may
   * want to inspect / persist post-mortem state. Documented contract.
   */
  if (emulator_flash_base) {
#ifdef _WIN32
    VirtualUnlock(emulator_flash_base, KKEMU_FLASH_SIZE);
#else
    munlock(emulator_flash_base, KKEMU_FLASH_SIZE);
#endif
    emulator_flash_base = NULL;
  }

  libkkemu_initialized = 0;
}

int kkemu_write(const uint8_t* data, size_t len, int iface) {
  if (!libkkemu_initialized) return -1;
  if (len != KKEMU_PACKET_SIZE) return -1;

  RingBuf* rb = (iface == KKEMU_IFACE_MAIN) ? &rb_main_in : &rb_debug_in;
  return ringbuf_push(rb, data, len) ? 0 : -1;
}

int kkemu_read(uint8_t* buf, size_t len, int iface) {
  if (!libkkemu_initialized) return 0;
  if (len < KKEMU_PACKET_SIZE) return 0;

  RingBuf* rb = (iface == KKEMU_IFACE_MAIN) ? &rb_main_out : &rb_debug_out;
  return ringbuf_pop(rb, buf, KKEMU_PACKET_SIZE) ? KKEMU_PACKET_SIZE : 0;
}

/* One exec() iteration. The ms-timer is ticked here because the host
 * runtime does not deliver SIGALRM (animations would freeze). */
static void kkemu_poll_body(void) {
  for (int t = 0; t < KKEMU_POLL_INTERVAL_MS; t++) timerisr_usr();

  usbPoll();
  animate();
  display_refresh();
}

int kkemu_poll(void) {
  if (!libkkemu_initialized) return -1;
  /* Never let two threads drive the firmware core. */
  if (POLL_RUNNING()) return 0;
  kkemu_poll_body();
  return 0;
}

static void kkemu_sleep_ms(int ms) {
#ifdef _WIN32
  Sleep((DWORD)ms);
#else
  struct timespec ts = {ms / 1000, (long)(ms % 1000) * 1000000L};
  nanosleep(&ts, NULL);
#endif
}

/* g_fw_lock is held for a whole pending confirm. The host must never take it
 * blocking then (deadlock); use kkemu_trylock(). */
static void kkemu_poll_loop(void) {
  while (POLL_RUNNING()) {
    FW_LOCK();
    if (POLL_RUNNING()) kkemu_poll_body();
    FW_UNLOCK();
    kkemu_sleep_ms(KKEMU_POLL_INTERVAL_MS);
  }
}

#ifdef _WIN32
static DWORD WINAPI kkemu_poll_thread_fn(LPVOID arg) {
  (void)arg;
  kkemu_poll_loop();
  return 0;
}
#else
static void* kkemu_poll_thread_fn(void* arg) {
  (void)arg;
  kkemu_poll_loop();
  return NULL;
}
#endif

/* Cancel is the ONLY wakeup for a parked confirm before an unbounded join;
 * a silently dropped one would hang the host forever. Retry, then shout. */
/* '?##', MessageType_Cancel (20), payload length 0. */
static const uint8_t kkemu_cancel_frame[KKEMU_PACKET_SIZE] = {0x3F, 0x23, 0x23,
                                                              0x00, 0x14};

static int kkemu_inject_cancel(void) {
  for (int i = 0; i < 200; i++) {
    if (ringbuf_push(&rb_main_in, kkemu_cancel_frame, KKEMU_PACKET_SIZE))
      return 1;
    kkemu_sleep_ms(1);
  }
  fprintf(stderr,
          "[libkkemu] FATAL: could not inject Cancel to wake a parked confirm "
          "before join — rb_main_in stayed full for ~200ms; the poll thread may "
          "not exit\n");
  return 0;
}

/* After POLL_SET(0): 1 if the thread is between bodies and needs no Cancel
 * (a stray Cancel would draw an unsolicited Failure). */
static int kkemu_poll_body_quiesced(void) {
  for (int i = 0; i < 2 * KKEMU_POLL_INTERVAL_MS; i++) {
    if (FW_TRYLOCK()) {
      FW_UNLOCK();
      return 1;
    }
    kkemu_sleep_ms(1);
  }
  return 0;
}

/* Drop an unread wake Cancel (newest slot) so the next session does not
 * answer it with an unsolicited Failure. */
static void kkemu_discard_unread_cancel(void) {
  uint32_t head = atomic_load_explicit(&rb_main_in.head, memory_order_relaxed);
  uint32_t last = (head + RINGBUF_CAPACITY - 1) % RINGBUF_CAPACITY;
  if (!ringbuf_empty(&rb_main_in) &&
      memcmp(rb_main_in.data[last], kkemu_cancel_frame, KKEMU_PACKET_SIZE) == 0)
    atomic_store_explicit(&rb_main_in.head, last, memory_order_release);
}

int kkemu_start(void) {
  if (!libkkemu_initialized) return -1;
  if (POLL_RUNNING()) return 0; /* idempotent */

#ifdef _WIN32
  if (!g_fw_lock_ready) {
    InitializeCriticalSection(&g_fw_lock);
    g_fw_lock_ready = 1;
  }
  POLL_SET(1);
  g_poll_thread = CreateThread(NULL, 0, kkemu_poll_thread_fn, NULL, 0, NULL);
  if (!g_poll_thread) {
    POLL_SET(0);
    return -1;
  }
#else
  POLL_SET(1);
  if (pthread_create(&g_poll_thread, NULL, kkemu_poll_thread_fn, NULL) != 0) {
    POLL_SET(0);
    return -1;
  }
#endif
  return 0;
}

void kkemu_stop(void) {
  if (!POLL_RUNNING()) return;

  POLL_SET(0);
  int injected = !kkemu_poll_body_quiesced() && kkemu_inject_cancel();
#ifdef _WIN32
  if (g_poll_thread) {
    WaitForSingleObject(g_poll_thread, INFINITE);
    CloseHandle(g_poll_thread);
    g_poll_thread = NULL;
  }
  /* Not deleted: the host may still hold it and must be able to release it. */
#else
  pthread_join(g_poll_thread, NULL);
#endif
  if (injected) kkemu_discard_unread_cancel();
}

/* Guards saveFlash reads. WARNING: BLOCKS; never call while a confirm may be
 * pending (deadlock). Use kkemu_trylock() there. */
void kkemu_lock(void) {
  if (!POLL_RUNNING()) return;
  FW_LOCK();
  g_host_holds_lock = 1;
}

void kkemu_unlock(void) {
  if (!g_host_holds_lock) return;
  g_host_holds_lock = 0;
  FW_UNLOCK();
}

/* 1 = held (balance with kkemu_unlock), 0 = busy: yield and retry. */
int kkemu_trylock(void) {
  if (!POLL_RUNNING()) return 1;
#ifdef _WIN32
  if (!TryEnterCriticalSection(&g_fw_lock)) return 0;
#else
  if (pthread_mutex_trylock(&g_fw_lock) != 0) return 0;
#endif
  g_host_holds_lock = 1;
  return 1;
}

/* Packed SSD1306 snapshot (byte = x + (y/8)*256, bit = y%8). WARNING: NOT
 * thread-safe; host-driven mode only. Threaded hosts use kkemu_pop_frame(). */
const uint8_t* kkemu_get_display(int* width, int* height) {
  if (!libkkemu_initialized) {
    if (width) *width = 0;
    if (height) *height = 0;
    return NULL;
  }

  const Canvas* c = display_canvas();
  if (!c || !c->buffer) {
    if (width) *width = 0;
    if (height) *height = 0;
    return NULL;
  }

  memset(display_packed_scratch, 0, sizeof(display_packed_scratch));
  for (int x = 0; x < 256; x++) {
    for (int y = 0; y < 64; y++) {
      if (display_mono_pixel_is_lit(c->buffer[y * 256 + x], x, y)) {
        display_packed_scratch[x + (y / 8) * 256] |= (uint8_t)(1u << (y % 8));
      }
    }
  }

  if (width) *width = 256;
  if (height) *height = 64;
  return display_packed_scratch;
}

int kkemu_pop_frame(uint8_t* out_packed) {
  if (!libkkemu_initialized || !out_packed) return 0;
  uint32_t r = atomic_load_explicit(&frame_read_idx, memory_order_relaxed);
  uint32_t w = atomic_load_explicit(&frame_write_idx, memory_order_acquire);
  if (r == w) return 0;
  memcpy(out_packed, frame_ring[r % FRAME_RING_SIZE], FRAME_PACKED_SIZE);
  atomic_store_explicit(&frame_read_idx, r + 1, memory_order_release);
  return 1;
}

int kkemu_is_running(void) { return libkkemu_initialized; }
