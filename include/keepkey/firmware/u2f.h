#ifndef KEEPKEY_FIRMWARE_U2F_H
#define KEEPKEY_FIRMWARE_U2F_H

#include "keepkey/board/u2f_types.h"

void u2f_do_register(const U2F_REGISTER_REQ *req);
void u2f_do_auth(const U2F_AUTHENTICATE_REQ *req);

#endif
