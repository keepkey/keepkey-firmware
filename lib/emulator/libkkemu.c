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

#include <string.h>
#include <sys/mman.h>

/* Defined in firmware — we just need the declaration */
extern void fsm_init(void);

/* ── Ring buffers (replace UDP sockets) ─────────────────────────────── */

static RingBuf rb_main_in;    /* host → firmware (main interface) */
static RingBuf rb_main_out;   /* firmware → host (main interface) */
static RingBuf rb_debug_in;   /* host → firmware (debug link) */
static RingBuf rb_debug_out;  /* firmware → host (debug link) */

static int libkkemu_initialized = 0;

/* ── Display capture ring ───────────────────────────────────────────── */

/*
 * Captures every display_refresh() into a ring of 1-bit packed snapshots.
 * The host drains via kkemu_pop_frame(). Adjacent identical frames are
 * skipped so an idle firmware doesn't spam the ring.
 *
 * Sized for ~4 seconds at 16ms refresh; if the host falls behind the
 * oldest frames are dropped (write advances past read).
 */
#define FRAME_PACKED_SIZE 2048
#define FRAME_RING_SIZE 64

static uint8_t frame_ring[FRAME_RING_SIZE][FRAME_PACKED_SIZE];
static uint8_t last_packed[FRAME_PACKED_SIZE];
static int last_packed_valid = 0;
static uint32_t frame_write_idx = 0; /* monotonic, mod FRAME_RING_SIZE for slot */
static uint32_t frame_read_idx = 0;  /* monotonic */

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

size_t libkkemu_socketRead(int *iface, void *buffer, size_t size) {
    if (ringbuf_pop(&rb_main_in, (uint8_t *)buffer, size)) {
        *iface = 0;
        return size < RINGBUF_SLOT_SIZE ? size : RINGBUF_SLOT_SIZE;
    }
    if (ringbuf_pop(&rb_debug_in, (uint8_t *)buffer, size)) {
        *iface = 1;
        return size < RINGBUF_SLOT_SIZE ? size : RINGBUF_SLOT_SIZE;
    }
    return 0;
}

size_t libkkemu_socketWrite(int iface, const void *buffer, size_t size) {
    RingBuf *rb = (iface == 0) ? &rb_main_out : &rb_debug_out;
    if (!ringbuf_push(rb, (const uint8_t *)buffer, size))
        return 0;
    return size;
}

/* ── Display capture callback ───────────────────────────────────────── */

/*
 * Pack the 8-bpp grayscale canvas (256x64 = 16384 bytes) into the
 * 1-bit SSD1306 page format the host wants. Skip if identical to the
 * last frame we captured. Called from display_refresh() on every poll
 * and on every iteration of confirm_helper's busy loop.
 */
static void libkkemu_capture_frame(const uint8_t *canvas_buf) {
    if (!canvas_buf) return;

    uint8_t *slot = frame_ring[frame_write_idx % FRAME_RING_SIZE];
    memset(slot, 0, FRAME_PACKED_SIZE);
    for (int x = 0; x < 256; x++) {
        for (int y = 0; y < 64; y++) {
            if (canvas_buf[y * 256 + x] > 0) {
                slot[x + (y / 8) * 256] |= (uint8_t)(1u << (y % 8));
            }
        }
    }

    /* Dedup: skip if identical to last captured */
    if (last_packed_valid && memcmp(slot, last_packed, FRAME_PACKED_SIZE) == 0) {
        return;
    }
    memcpy(last_packed, slot, FRAME_PACKED_SIZE);
    last_packed_valid = 1;

    frame_write_idx++;
    /* Drop oldest if host fell behind */
    if (frame_write_idx - frame_read_idx > FRAME_RING_SIZE) {
        frame_read_idx = frame_write_idx - FRAME_RING_SIZE;
    }
}

/* ── Public API ─────────────────────────────────────────────────────── */

int kkemu_init(uint8_t *flash_buf, size_t flash_len) {
    if (flash_len != KKEMU_FLASH_SIZE) return -1;
    if (!flash_buf) return -1;
    if (libkkemu_initialized) return -1;

    /* Point firmware's flash pointer at the host-provided buffer */
    emulator_flash_base = flash_buf;

    /* Lock memory to prevent swapping secrets to disk */
    mlock(flash_buf, flash_len);

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

    /* Flush any pending storage to the flash buffer */
    storage_commit();

    /* Unlock memory (host should zero + free after this) */
    if (emulator_flash_base) {
        munlock(emulator_flash_base, KKEMU_FLASH_SIZE);
        emulator_flash_base = NULL;
    }

    libkkemu_initialized = 0;
}

int kkemu_write(const uint8_t *data, size_t len, int iface) {
    if (!libkkemu_initialized) return -1;
    if (len != KKEMU_PACKET_SIZE) return -1;

    RingBuf *rb = (iface == KKEMU_IFACE_MAIN) ? &rb_main_in : &rb_debug_in;
    return ringbuf_push(rb, data, len) ? 0 : -1;
}

int kkemu_read(uint8_t *buf, size_t len, int iface) {
    if (!libkkemu_initialized) return 0;
    if (len < KKEMU_PACKET_SIZE) return 0;

    RingBuf *rb = (iface == KKEMU_IFACE_MAIN) ? &rb_main_out : &rb_debug_out;
    return ringbuf_pop(rb, buf, KKEMU_PACKET_SIZE) ? KKEMU_PACKET_SIZE : 0;
}

int kkemu_poll(void) {
    if (!libkkemu_initialized) return -1;

    /*
     * This is the same as exec() in main.cpp:
     *   usbPoll()       — reads input, dispatches through FSM
     *   animate()        — updates screen animations
     *   display_refresh() — renders framebuffer
     *
     * usbPoll() internally calls emulatorSocketRead() which we've
     * replaced with libkkemu_socketRead() via the ring buffers.
     */
    usbPoll();
    animate();
    display_refresh();

    return 0;
}

const uint8_t *kkemu_get_display(int *width, int *height) {
    /*
     * Pack the firmware's 8-bpp grayscale canvas (256×64 = 16384 bytes) into
     * the 1-bit packed layout vault expects (2048 bytes). Same format
     * DebugLinkGetState.layout uses: byte index = x + (y/8)*256,
     * bit within byte = y%8 (LSB = top row of the 8-pixel column).
     */
    static uint8_t packed[2048];

    if (!libkkemu_initialized) { if (width) *width = 0; if (height) *height = 0; return NULL; }

    const Canvas *c = display_canvas();
    if (!c || !c->buffer) { if (width) *width = 0; if (height) *height = 0; return NULL; }

    memset(packed, 0, sizeof(packed));
    for (int x = 0; x < 256; x++) {
        for (int y = 0; y < 64; y++) {
            if (c->buffer[y * 256 + x] > 0) {
                packed[x + (y / 8) * 256] |= (uint8_t)(1u << (y % 8));
            }
        }
    }

    if (width)  *width = 256;
    if (height) *height = 64;
    return packed;
}

int kkemu_pop_frame(uint8_t *out_packed) {
    if (!libkkemu_initialized || !out_packed) return 0;
    if (frame_read_idx == frame_write_idx) return 0;
    const uint8_t *slot = frame_ring[frame_read_idx % FRAME_RING_SIZE];
    memcpy(out_packed, slot, FRAME_PACKED_SIZE);
    frame_read_idx++;
    return 1;
}

int kkemu_is_running(void) {
    return libkkemu_initialized;
}
