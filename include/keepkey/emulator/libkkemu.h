/*
 * libkkemu — KeepKey firmware emulator as a shared library.
 *
 * The host process provides a pre-allocated 1MB flash buffer.
 * All I/O goes through ring buffers (no UDP sockets).
 *
 * Two drive modes:
 *   - Host-driven (default): call kkemu_poll() from your event loop. Purely
 *     single-threaded — used by the FFI/python test harnesses.
 *   - Thread-driven: call kkemu_start() once after kkemu_init() and let a
 *     dedicated dylib thread own the event loop. Required for screen-first
 *     confirm gating (confirm_helper can block in C without freezing the host
 *     event loop). The host then never calls kkemu_poll(); it interacts only
 *     through the lock-free rings (kkemu_write/read/pop_frame) and brackets
 *     flash snapshots with kkemu_lock()/kkemu_unlock().
 */
#ifndef LIBKKEMU_H
#define LIBKKEMU_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#define KKEMU_FLASH_SIZE (1024 * 1024) /* 1 MB */
#define KKEMU_PACKET_SIZE 64           /* HID report size */
#define KKEMU_IFACE_MAIN 0
#define KKEMU_IFACE_DEBUG 1

/**
 * Initialize the emulator with a host-provided flash buffer.
 *
 * @param flash_buf  Pointer to 1MB buffer (host-owned, must remain valid).
 *                   If contents are all 0xFF, treated as fresh/erased device.
 *                   If contents are from a previous session, device state is
 * restored.
 * @param flash_len  Must be KKEMU_FLASH_SIZE (1048576).
 * @return 0 on success, -1 on error.
 *
 * After this call, the emulator is ready to process messages via
 * kkemu_write() + kkemu_poll() + kkemu_read().
 */
int kkemu_init(uint8_t* flash_buf, size_t flash_len);

/**
 * Shut down the emulator. Flushes pending storage writes to the
 * flash buffer. After this call, the host should encrypt and persist
 * the flash buffer, then zero it.
 */
void kkemu_shutdown(void);

/**
 * Write a 64-byte HID report into the emulator's input queue.
 *
 * @param data   Exactly 64 bytes.
 * @param len    Must be 64.
 * @param iface  KKEMU_IFACE_MAIN (0) or KKEMU_IFACE_DEBUG (1).
 * @return 0 on success, -1 if queue is full.
 */
int kkemu_write(const uint8_t* data, size_t len, int iface);

/**
 * Read a 64-byte HID report from the emulator's output queue.
 *
 * Non-blocking. Returns 0 immediately if no output is available.
 *
 * @param buf    Buffer of at least 64 bytes.
 * @param len    Must be 64.
 * @param iface  KKEMU_IFACE_MAIN (0) or KKEMU_IFACE_DEBUG (1).
 * @return Number of bytes read (64), or 0 if queue is empty.
 */
int kkemu_read(uint8_t* buf, size_t len, int iface);

/**
 * Run one iteration of the firmware event loop.
 *
 * Drains the input queue, dispatches messages through the FSM,
 * queues output messages, and updates display/animations.
 *
 * Call this at 10-60 Hz from your event loop.
 *
 * @return 0 on success, or -1 if the emulator is not initialized.
 */
int kkemu_poll(void);

/**
 * Snapshot the current OLED framebuffer (256x64, 1-bit, 2048 bytes) into
 * internal scratch and return a pointer to it (valid until the next call).
 *
 * WARNING: host-driven mode ONLY. Reads the live canvas with no synchronization
 * against the poll thread — do NOT call it once kkemu_start() is running. In
 * thread-driven mode use kkemu_pop_frame() (the lock-free SPSC ring) instead.
 * Returns NULL if the emulator is not initialized.
 *
 * @param width   Receives 256.
 * @param height  Receives 64.
 */
const uint8_t* kkemu_get_display(int* width, int* height);

/**
 * Pop the next captured framebuffer from the display capture ring.
 *
 * Every display_refresh() inside the firmware (including those that fire
 * inside confirm_helper's busy loop) snapshots the canvas into a lock-free
 * SPSC ring. Adjacent identical frames are deduplicated. This is the canonical
 * way to observe intermediate screen states (confirm dialogs, cipher prompts,
 * recovery screens) — and the only display path that is safe to call while the
 * poll thread runs.
 *
 * @param out_packed  Buffer of at least 2048 bytes (256x64, 1-bit packed
 *                    SSD1306 page format: byte index = x + (y/8)*256,
 *                    bit within byte = y%8).
 * @return 1 if a frame was popped, 0 if the ring is empty.
 */
int kkemu_pop_frame(uint8_t* out_packed);

/**
 * Check if the emulator has been initialized.
 */
int kkemu_is_running(void);

/**
 * Start the dedicated poll thread (thread-driven mode).
 *
 * After this returns 0, a dylib-internal thread owns the firmware event loop
 * and the host MUST NOT call kkemu_poll() anymore. Idempotent. Requires
 * kkemu_init() to have succeeded.
 *
 * @return 0 on success (or already started), -1 on error.
 */
int kkemu_start(void);

/**
 * Stop + join the poll thread. Injects a Cancel first so a confirm_helper
 * parked waiting for a button decision unblocks and the thread can exit.
 * Idempotent; a no-op if the thread was never started. kkemu_shutdown()
 * calls this automatically.
 */
void kkemu_stop(void);

/**
 * Bracket a host-side read of the flash buffer (e.g. before encrypting and
 * persisting it) so it can't tear a concurrent storage_commit() on the poll
 * thread. No-op in host-driven mode. Must be balanced with kkemu_unlock().
 *
 * kkemu_lock() BLOCKS and must not be used from a host loop that also has to
 * stay alive to deliver a confirm decision — use kkemu_trylock() there.
 */
void kkemu_lock(void);
void kkemu_unlock(void);

/**
 * Non-blocking acquire of the firmware lock. Returns 1 if acquired (balance
 * with kkemu_unlock()), 0 if currently held by the poll thread (e.g. during a
 * pending confirm) — yield the host event loop and retry. Returns 1 as a no-op
 * when the poll thread isn't running.
 */
int kkemu_trylock(void);

#ifdef __cplusplus
}
#endif

#endif /* LIBKKEMU_H */
