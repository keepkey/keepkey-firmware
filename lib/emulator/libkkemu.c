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

/* ── Poll thread (Approach B: reactive confirm) ──────────────────────────
 *
 * Optional: the host calls kkemu_start() to run the firmware event loop on a
 * dedicated thread inside the dylib. This lets confirm_helper's blocking C
 * busy-loop wait for a button decision IN C without freezing the host's event
 * loop — so the vault can render the real OLED confirm frame, HOLD it, and
 * deliver the DebugLinkDecision only when the user clicks (screen-first gating,
 * like a physical device).
 *
 * Only the poll thread ever drives firmware execution (kkemu_poll_body). The
 * host interacts solely through the lock-free SPSC rings (kkemu_write/read,
 * kkemu_pop_frame). g_fw_lock serializes the poll body against host-side flash
 * snapshots (kkemu_lock/unlock) so storage_commit can't tear a saveFlash read.
 *
 * When the thread is NOT started (g_poll_running == 0) the dylib stays purely
 * single-threaded and host-driven via kkemu_poll() — exactly as the FFI test
 * suite and python-keepkey tests use it. The lock helpers no-op in that mode.
 */
#ifdef _WIN32
static CRITICAL_SECTION g_fw_lock;
static HANDLE g_poll_thread = NULL;
#define FW_LOCK() EnterCriticalSection(&g_fw_lock)
#define FW_UNLOCK() LeaveCriticalSection(&g_fw_lock)
#else
static pthread_mutex_t g_fw_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_t g_poll_thread;
#define FW_LOCK() pthread_mutex_lock(&g_fw_lock)
#define FW_UNLOCK() pthread_mutex_unlock(&g_fw_lock)
#endif

/* Cross-thread poll-running flag. _Atomic (not volatile — volatile is not a
 * synchronization primitive in C): the poll thread reads it each loop while
 * start/stop write it from the host thread. acquire/release publishes the
 * surrounding firmware/ring state alongside the flag. */
#include <stdatomic.h>
static _Atomic int g_poll_running = 0;
#define POLL_RUNNING() atomic_load_explicit(&g_poll_running, memory_order_acquire)
#define POLL_SET(v) atomic_store_explicit(&g_poll_running, (v), memory_order_release)

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
 * Sized for ~4 seconds at 16ms refresh. Cross-thread in thread-driven mode:
 * the poll thread is the sole producer, the host (kkemu_pop_frame) the sole
 * consumer — a lock-free SPSC ring with the same atomic discipline as the HID
 * rings (ringbuf.c). When the ring is full the producer drops the NEW frame
 * (it must NOT overwrite a slot the consumer may be mid-copy on, and it must
 * NOT write the consumer-owned read index).
 */
#define FRAME_PACKED_SIZE 2048
#define FRAME_RING_SIZE 64

/* Host poll cadence (the vault's setInterval is ~16ms). kkemu_poll() ticks the
 * firmware ms-timer this many times per call so animations advance at ~real
 * speed without relying on the (host-runtime-unreliable) SIGALRM timer. */
#define KKEMU_POLL_INTERVAL_MS 16

static uint8_t frame_ring[FRAME_RING_SIZE][FRAME_PACKED_SIZE];
static uint8_t last_packed[FRAME_PACKED_SIZE];   /* producer-only (poll thread) */
static int last_packed_valid = 0;                /* producer-only */
static uint8_t capture_scratch[FRAME_PACKED_SIZE]; /* producer-only pack buffer */
static _Atomic uint32_t frame_write_idx = 0; /* written by producer ONLY */
static _Atomic uint32_t frame_read_idx = 0;  /* written by consumer ONLY */

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

  /* Pack into a producer-private scratch — NOT a ring slot. When the ring is
   * full the next write slot still holds an unread frame the consumer may be
   * copying, so we must decide to publish/drop before touching it. */
  memset(capture_scratch, 0, FRAME_PACKED_SIZE);
  for (int x = 0; x < 256; x++) {
    for (int y = 0; y < 64; y++) {
      if (canvas_buf[y * 256 + x] > 0) {
        capture_scratch[x + (y / 8) * 256] |= (uint8_t)(1u << (y % 8));
      }
    }
  }

  /* Dedup against the last captured frame (producer-only state). */
  if (last_packed_valid &&
      memcmp(capture_scratch, last_packed, FRAME_PACKED_SIZE) == 0) {
    return;
  }

  /* SPSC publish, drop-on-full (same discipline as ringbuf.c). The producer
   * writes only frame_write_idx; the consumer writes only frame_read_idx. When
   * not full, write%SIZE != read%SIZE (their distance is in [1, SIZE-1]), so
   * producer and consumer never touch the same slot. last_packed is updated
   * ONLY on a real publish, so a frame dropped while full can still be captured
   * on a later tick. */
  uint32_t w = atomic_load_explicit(&frame_write_idx, memory_order_relaxed);
  uint32_t r = atomic_load_explicit(&frame_read_idx, memory_order_acquire);
  if (w - r >= FRAME_RING_SIZE) return; /* full → drop the new frame */

  memcpy(frame_ring[w % FRAME_RING_SIZE], capture_scratch, FRAME_PACKED_SIZE);
  memcpy(last_packed, capture_scratch, FRAME_PACKED_SIZE);
  last_packed_valid = 1;
  atomic_store_explicit(&frame_write_idx, w + 1, memory_order_release);
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

  /* Stop + join the poll thread FIRST so nothing drives firmware execution
   * while we commit storage and zero the rings below (idempotent if the host
   * never started the thread). */
  kkemu_stop();

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

/*
 * One iteration of the firmware event loop. Same as exec() in main.cpp:
 *   usbPoll()        — reads input, dispatches through FSM
 *   animate()        — updates screen animations
 *   display_refresh() — renders framebuffer
 *
 * usbPoll() internally calls emulatorSocketRead() which we've replaced with
 * libkkemu_socketRead() via the ring buffers.
 *
 * Drive the firmware millisecond timer from the poll on EVERY platform. The
 * dylib is caller-driven; relying on the SIGALRM/ualarm timer (which the
 * standalone kkemu binary uses) is unreliable inside the host runtime — Bun
 * does not deliver the firmware's SIGALRM, so animate_flag never flips and
 * every animation (boot logo, screensaver) stays frozen → a blank OLED at
 * rest. Tick ~one poll-interval of milliseconds so the periodic animation
 * runnable fires and animations + delay_ms() advance at roughly real speed.
 */
static void kkemu_poll_body(void) {
  for (int t = 0; t < KKEMU_POLL_INTERVAL_MS; t++) timerisr_usr();

  usbPoll();
  animate();
  display_refresh();
}

int kkemu_poll(void) {
  if (!libkkemu_initialized) return -1;
  /* When the poll thread owns execution, the host must not also poll —
   * that would be two threads driving the single-threaded firmware core.
   * Treat a stray host poll as a no-op rather than a data race. */
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

/* The poll thread holds g_fw_lock across each body call, releasing it during
 * the inter-poll sleep. While confirm_helper busy-waits for a decision the body
 * does not return, so the lock stays held for the whole confirm — but that must
 * NOT block the host: the decision is delivered through the lock-free rings, and
 * the host acquires the lock for flash snapshots via kkemu_trylock() (which
 * never blocks the host event loop). The host must never take g_fw_lock with a
 * blocking call while a confirm may be pending, or it would deadlock against the
 * very loop that needs the host alive to deliver the decision. */
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

/* Push a Cancel (MessageType 20) into the main input ring so a confirm_helper
 * blocked on the poll thread reads it, returns false, and lets the thread exit
 * its loop — otherwise kkemu_stop() would join a thread parked forever waiting
 * for a button decision that will never arrive.
 *
 * This injected Cancel is the ONLY firmware-side wakeup for a parked confirm
 * (confirm_helper has no idle timeout in EMULATOR builds), and kkemu_stop()
 * then joins the thread with no deadline — so a SILENTLY dropped Cancel would
 * freeze the (single-threaded) host forever, beyond any watchdog's reach. The
 * push can only fail if rb_main_in is full; the parked confirm drains one input
 * frame per spin, so a slot frees within ~a poll tick. Retry briefly, and shout
 * loudly if it somehow never takes rather than dropping it. */
static void kkemu_inject_cancel(void) {
  uint8_t frame[KKEMU_PACKET_SIZE];
  memset(frame, 0, sizeof(frame));
  frame[0] = 0x3F; /* '?' HID report marker */
  frame[1] = 0x23; /* '#' */
  frame[2] = 0x23; /* '#' */
  frame[3] = 0x00; /* MessageType_Cancel high */
  frame[4] = 0x14; /* MessageType_Cancel low (20) */
  /* payload length 0 (bytes 5-8 already zero) */
  for (int i = 0; i < 200; i++) {
    if (ringbuf_push(&rb_main_in, frame, sizeof(frame))) return;
    kkemu_sleep_ms(1);
  }
  fprintf(stderr,
          "[libkkemu] FATAL: could not inject Cancel to wake a parked confirm "
          "before join — rb_main_in stayed full for ~200ms; the poll thread may "
          "not exit\n");
}

int kkemu_start(void) {
  if (!libkkemu_initialized) return -1;
  if (POLL_RUNNING()) return 0; /* idempotent */

#ifdef _WIN32
  InitializeCriticalSection(&g_fw_lock);
  POLL_SET(1);
  g_poll_thread = CreateThread(NULL, 0, kkemu_poll_thread_fn, NULL, 0, NULL);
  if (!g_poll_thread) {
    POLL_SET(0);
    DeleteCriticalSection(&g_fw_lock);
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
  /* Unblock any confirm_helper currently parked on the thread, then join. */
  kkemu_inject_cancel();
#ifdef _WIN32
  if (g_poll_thread) {
    WaitForSingleObject(g_poll_thread, INFINITE);
    CloseHandle(g_poll_thread);
    g_poll_thread = NULL;
  }
  DeleteCriticalSection(&g_fw_lock);
#else
  pthread_join(g_poll_thread, NULL);
#endif
}

/* Host-side guard for reading the shared flash buffer (saveFlash) without
 * tearing a concurrent storage_commit on the poll thread. No-op when the
 * thread isn't running (single-threaded test path needs no lock, and on
 * Windows the CRITICAL_SECTION only exists between start and stop).
 *
 * WARNING: kkemu_lock() BLOCKS, and the poll thread can hold g_fw_lock for the
 * whole duration of a pending confirm. The host must therefore NOT call
 * kkemu_lock() from a thread/loop that also has to stay alive to deliver the
 * confirm decision (it would deadlock). Use kkemu_trylock() + an event-loop
 * yield there instead. kkemu_lock() is retained for paths with no pending
 * confirm. */
void kkemu_lock(void) {
  if (POLL_RUNNING()) FW_LOCK();
}

void kkemu_unlock(void) {
  if (POLL_RUNNING()) FW_UNLOCK();
}

/* Non-blocking acquire. Returns 1 if the firmware lock is now held by the
 * caller (balance with kkemu_unlock()), 0 if it is currently held by the poll
 * thread (e.g. mid-confirm) — the caller should yield its event loop and retry,
 * which keeps the loop alive to deliver the decision that releases the lock.
 * No-op success (returns 1, nothing to unlock) when the thread isn't running. */
int kkemu_trylock(void) {
  if (!POLL_RUNNING()) return 1;
#ifdef _WIN32
  return TryEnterCriticalSection(&g_fw_lock) ? 1 : 0;
#else
  return pthread_mutex_trylock(&g_fw_lock) == 0 ? 1 : 0;
#endif
}

/*
 * Snapshot the current OLED canvas into packed SSD1306 format (byte index =
 * x + (y/8)*256, bit = y%8). Host-driven convenience used by the python
 * screenshot harness, which drives the firmware single-threaded via kkemu_poll.
 *
 * WARNING: NOT thread-safe. It reads the live firmware canvas directly with no
 * synchronization against the poll thread, so it is only safe in HOST-DRIVEN
 * mode (no kkemu_start). In thread-driven mode the canonical, race-free way to
 * observe the display is the SPSC capture ring via kkemu_pop_frame(); do not
 * wire kkemu_get_display into a threaded host.
 */
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
      if (c->buffer[y * 256 + x] > 0) {
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
  /* SPSC consume: read frame_read_idx (we own it) and frame_write_idx (acquire,
   * to see the producer's slot write). Empty when the indices are equal. */
  uint32_t r = atomic_load_explicit(&frame_read_idx, memory_order_relaxed);
  uint32_t w = atomic_load_explicit(&frame_write_idx, memory_order_acquire);
  if (r == w) return 0;
  memcpy(out_packed, frame_ring[r % FRAME_RING_SIZE], FRAME_PACKED_SIZE);
  atomic_store_explicit(&frame_read_idx, r + 1, memory_order_release);
  return 1;
}

int kkemu_is_running(void) { return libkkemu_initialized; }
