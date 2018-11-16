#ifndef KEEPKEY_FIRMWARE_U2F_H
#define KEEPKEY_FIRMWARE_U2F_H

#include "keepkey/board/u2f_types.h"

#include <inttypes.h>

void u2f_do_register(const U2F_REGISTER_REQ *req);
void u2f_do_auth(const U2F_AUTHENTICATE_REQ *req);
void u2f_do_version(const uint8_t channel[4]);
#endif
