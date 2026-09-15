/*
 * This file is part of the TREZOR project, https://trezor.io/
 *
 * Copyright (C) 2017 Saleem Rashid <trezor@saleemrashid.com>
 *
 * This library is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 */

#include "keepkey/emulator/emulator.h"
#include "keepkey/emulator/setup.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <bcrypt.h>
#else
#include <fcntl.h>
#include <unistd.h>

static int urandom = -1;

static void setup_urandom(void) {
  if (urandom >= 0) return;

  urandom = open("/dev/urandom", O_RDONLY);
  if (urandom < 0) {
    perror("Failed to open /dev/urandom");
    exit(1);
  }
}
#endif

void setup_urandom_only(void) {
#ifndef _WIN32
  setup_urandom();
#endif
}

void emulatorRandom(void* buffer, size_t size) {
#ifdef _WIN32
  /* Windows has no /dev/urandom — use the system CSPRNG. */
  if (BCryptGenRandom(NULL, (PUCHAR)buffer, (ULONG)size,
                      BCRYPT_USE_SYSTEM_PREFERRED_RNG) != 0) {
    fprintf(stderr, "BCryptGenRandom failed\n");
    exit(1);
  }
#else
  setup_urandom();
  unsigned char* out = (unsigned char*)buffer;
  size_t remaining = size;
  while (remaining > 0) {
    ssize_t n = read(urandom, out, remaining);
    if (n < 0 && errno == EINTR) continue;
    if (n <= 0) {
      perror("Failed to read /dev/urandom");
      exit(1);
    }
    out += (size_t)n;
    remaining -= (size_t)n;
  }
#endif
}
