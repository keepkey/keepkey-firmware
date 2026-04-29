/*
 * Lock-free single-producer single-consumer ring buffer for HID reports.
 * Used by libkkemu to pass 64-byte messages between host and firmware.
 */
#ifndef RINGBUF_H
#define RINGBUF_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#define RINGBUF_SLOT_SIZE 64 /* HID report size */

/*
 * Capacity must hold the largest synchronous response the firmware emits in
 * a single dispatch. The driver: DebugLinkGetState now serializes a 2048-byte
 * `layout` field plus the rest of DebugLinkState (~2.7 KB total payload), and
 * we want headroom for DebugLinkFlashDumpResponse (1024-byte chunks) and for
 * any future field growth. With ~62 bytes of payload per HID report after the
 * sync prefix + continuation byte, 2.7 KB is ~44 reports. The previous value
 * of 32 left effective room for 31 reports, so DebugLinkGetState was being
 * truncated mid-screenshot — emulatorSocketWrite() returned 0 but the
 * upstream `msg_debug_write()` ignored the failure, so the host saw a
 * silently-clipped response.
 *
 * 128 gives ~3x headroom on the worst current response, costs 4 * 8 KB =
 * 32 KB of RAM across the four rings, and keeps the slot index a power of
 * two so the modulo in ringbuf_push/pop remains a cheap mask.
 */
#define RINGBUF_CAPACITY 128 /* max queued messages */

typedef struct {
  uint8_t data[RINGBUF_CAPACITY][RINGBUF_SLOT_SIZE];
  volatile uint32_t head; /* written by producer */
  volatile uint32_t tail; /* written by consumer */
} RingBuf;

void ringbuf_init(RingBuf* rb);
bool ringbuf_push(RingBuf* rb, const uint8_t* msg, size_t len);
bool ringbuf_pop(RingBuf* rb, uint8_t* msg, size_t len);
bool ringbuf_empty(const RingBuf* rb);

#endif
