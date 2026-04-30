/*
 * Lock-free SPSC ring buffer for 64-byte HID reports.
 */
#include "ringbuf.h"
#include <string.h>

void ringbuf_init(RingBuf *rb) {
    memset(rb, 0, sizeof(*rb));
}

bool ringbuf_push(RingBuf *rb, const uint8_t *msg, size_t len) {
    if (len > RINGBUF_SLOT_SIZE) return false;

    uint32_t head = rb->head;
    uint32_t next = (head + 1) % RINGBUF_CAPACITY;

    if (next == rb->tail) return false;  /* full */

    memcpy(rb->data[head], msg, len);
    if (len < RINGBUF_SLOT_SIZE)
        memset(rb->data[head] + len, 0, RINGBUF_SLOT_SIZE - len);

    __sync_synchronize();  /* memory barrier before publishing head */
    rb->head = next;
    return true;
}

bool ringbuf_pop(RingBuf *rb, uint8_t *msg, size_t len) {
    uint32_t tail = rb->tail;

    if (tail == rb->head) return false;  /* empty */

    size_t copy = len < RINGBUF_SLOT_SIZE ? len : RINGBUF_SLOT_SIZE;
    memcpy(msg, rb->data[tail], copy);

    __sync_synchronize();  /* memory barrier before advancing tail */
    rb->tail = (tail + 1) % RINGBUF_CAPACITY;
    return true;
}

bool ringbuf_empty(const RingBuf *rb) {
    return rb->head == rb->tail;
}
