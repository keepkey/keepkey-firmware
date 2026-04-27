/*
 * Lock-free single-producer single-consumer ring buffer for HID reports.
 * Used by libkkemu to pass 64-byte messages between host and firmware.
 */
#ifndef RINGBUF_H
#define RINGBUF_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#define RINGBUF_SLOT_SIZE 64   /* HID report size */
#define RINGBUF_CAPACITY  32   /* max queued messages */

typedef struct {
    uint8_t data[RINGBUF_CAPACITY][RINGBUF_SLOT_SIZE];
    volatile uint32_t head;  /* written by producer */
    volatile uint32_t tail;  /* written by consumer */
} RingBuf;

void ringbuf_init(RingBuf *rb);
bool ringbuf_push(RingBuf *rb, const uint8_t *msg, size_t len);
bool ringbuf_pop(RingBuf *rb, uint8_t *msg, size_t len);
bool ringbuf_empty(const RingBuf *rb);

#endif
