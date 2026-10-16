/*
 * Lock-free SPSC ring buffer for 64-byte HID reports.
 * Uses C11 atomics with explicit acquire/release memory orders so that
 * concurrent producer/consumer threads are well-defined (no UB).
 */
#include "ringbuf.h"
#include <string.h>

void ringbuf_init(RingBuf* rb) {
  memset(rb->data, 0, sizeof(rb->data));
  atomic_init(&rb->head, 0);
  atomic_init(&rb->tail, 0);
}

bool ringbuf_push(RingBuf* rb, const uint8_t* msg, size_t len) {
  if (len > RINGBUF_SLOT_SIZE) return false;

  uint32_t head = atomic_load_explicit(&rb->head, memory_order_relaxed);
  uint32_t next = (head + 1) % RINGBUF_CAPACITY;

  if (next == atomic_load_explicit(&rb->tail, memory_order_acquire))
    return false; /* full */

  memcpy(rb->data[head], msg, len);
  if (len < RINGBUF_SLOT_SIZE)
    memset(rb->data[head] + len, 0, RINGBUF_SLOT_SIZE - len);

  atomic_store_explicit(&rb->head, next, memory_order_release);
  return true;
}

bool ringbuf_pop(RingBuf* rb, uint8_t* msg, size_t len) {
  uint32_t tail = atomic_load_explicit(&rb->tail, memory_order_relaxed);

  if (tail == atomic_load_explicit(&rb->head, memory_order_acquire))
    return false; /* empty */

  size_t copy = len < RINGBUF_SLOT_SIZE ? len : RINGBUF_SLOT_SIZE;
  memcpy(msg, rb->data[tail], copy);

  atomic_store_explicit(&rb->tail, (tail + 1) % RINGBUF_CAPACITY,
                        memory_order_release);
  return true;
}

bool ringbuf_empty(RingBuf* rb) {
  uint32_t head = atomic_load_explicit(&rb->head, memory_order_relaxed);
  uint32_t tail = atomic_load_explicit(&rb->tail, memory_order_relaxed);
  return head == tail;
}
