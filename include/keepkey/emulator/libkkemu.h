/*
 * libkkemu — KeepKey firmware emulator as a shared library.
 *
 * The host process provides a pre-allocated 1MB flash buffer.
 * All I/O goes through ring buffers (no UDP sockets).
 * Single-threaded: call kkemu_poll() from your event loop.
 * Or kkemu_start() a dylib poll thread (needed when confirm_helper blocks);
 * the host then uses only the rings and kkemu_lock() for flash reads.
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
 * Get the OLED framebuffer (256x64, 1-bit per pixel = 2048 bytes).
 *
 * Unsynchronized: do NOT call once kkemu_start() runs; use kkemu_pop_frame().
 * Valid until the next call; NULL if the emulator is not initialized.
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
 * SPSC ring, deduplicating adjacent frames. Safe while the poll thread runs.
 *
 * @param out_packed  Buffer of at least 2048 bytes (256x64, 1-bit packed
 *                    SSD1306 page format: byte x + (y/8)*256, bit y%8).
 * @return 1 if a frame was popped, 0 if the ring is empty.
 */
int kkemu_pop_frame(uint8_t* out_packed);

/**
 * Check if the emulator has been initialized.
 */
int kkemu_is_running(void);

/* Start the poll thread; after 0 the host MUST NOT call kkemu_poll().
 * Idempotent; requires kkemu_init(). Returns -1 on error. */
int kkemu_start(void);

/* Stop + join the poll thread, injecting a Cancel to unblock a pending
 * confirm. Idempotent; called by kkemu_shutdown(). */
void kkemu_stop(void);

/* Bracket host flash reads so they cannot tear a storage_commit(). Blocks:
 * never call from a loop that must deliver a confirm; use kkemu_trylock(). */
void kkemu_lock(void);
void kkemu_unlock(void);

/* 1 if acquired (or no poll thread), 0 if held: yield and retry. */
int kkemu_trylock(void);

#ifdef __cplusplus
}
#endif

#endif /* LIBKKEMU_H */
