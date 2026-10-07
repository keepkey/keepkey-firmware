/* Exercise the address flow without enabling any Zcash wire handlers. */
#undef ZCASH_PRIVACY
#define ZCASH_PRIVACY 1
#include "keepkey/board/layout.h"
#include "keepkey/firmware/app_layout.h"
#include <string.h>
static unsigned qr_calls;
static char qr_address[256];
static void observed_zcash_qr(const char* title, const char* address,
                              NotificationType type) {
  ++qr_calls;
  strncpy(qr_address, address, sizeof(qr_address) - 1);
  layout_zcash_address_notification(title, address, type);
}
#define layout_zcash_address_notification observed_zcash_qr
#include "../../lib/firmware/app_confirm.c"
#undef layout_zcash_address_notification
void zcash_review_reset(void) {
  qr_calls = 0;
  memset(qr_address, 0, sizeof(qr_address));
}
unsigned zcash_review_qr_calls(void) { return qr_calls; }
const char* zcash_review_qr_address(void) { return qr_address; }
