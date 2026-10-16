/* Link the real dispatcher in the native test executable and inspect its
 * private credential buffer after public receive entry points return. */
#include "../../lib/board/messages.c"

bool test_tiny_buffer_is_clear(void) {
  const uint8_t* bytes = (const uint8_t*)msg_tiny;
  for (size_t i = 0; i < sizeof(msg_tiny); i++) {
    if (bytes[i] != 0) return false;
  }
  return true;
}
