/*
 * This file is part of the TREZOR project, https://trezor.io/
 *
 * Copyright (C) 2017 Saleem Rashid <trezor@saleemrashid.com>
 *
 * This library is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this library.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "keepkey/board/memory.h"
#include "keepkey/board/timer.h"
#include "keepkey/rand/rng.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN /* exclude winsock.h — it declares \
                               shutdown(SOCKET,int) */
#include <windows.h>
#include <bcrypt.h>
#else
#include <fcntl.h>
#include <sys/mman.h>
#include <unistd.h>
#endif

#define EMULATOR_FLASH_FILE "emulator.img"

/* __stack_chk_guard is defined once in lib/board/keepkey_board.c (as
 * uintptr_t). It used to be redefined here as uint32_t, which is (a) the wrong
 * size on 64-bit hosts and (b) a duplicate strong symbol. Apple's ld silently
 * merged the two; GNU/MinGW ld rejects it ("multiple definition"), which
 * blocked the Linux .so and Windows .dll builds. Removed — the board copy is
 * canonical. */

static int urandom = -1;

static void setup_urandom(void);

#ifndef _WIN32
static void setup_flash(void);

void setup(void) {
  setup_urandom();
  setup_flash();
}
#endif

/* For libkkemu: init RNG only (flash buffer provided by host) */
void setup_urandom_only(void) { setup_urandom(); }

void emulatorRandom(void* buffer, size_t size) {
#ifdef _WIN32
  /* Windows has no /dev/urandom — use the system CSPRNG. */
  if (BCryptGenRandom(NULL, (PUCHAR)buffer, (ULONG)size,
                      BCRYPT_USE_SYSTEM_PREFERRED_RNG) != 0) {
    fprintf(stderr, "BCryptGenRandom failed\n");
    exit(1);
  }
#else
  ssize_t n = read(urandom, buffer, size);
  if (n < 0 || ((size_t)n) != size) {
    perror("Failed to read /dev/urandom");
    exit(1);
  }
#endif
}

static void setup_urandom(void) {
#ifndef _WIN32
  urandom = open("/dev/urandom", O_RDONLY);
  if (urandom < 0) {
    perror("Failed to open /dev/urandom");
    exit(1);
  }
#endif
}

#ifndef _WIN32
static void setup_flash(void) {
  int fd = open(EMULATOR_FLASH_FILE, O_RDWR | O_SYNC | O_CREAT, 0644);
  if (fd < 0) {
    perror("Failed to open flash emulation file");
    exit(1);
  }

  off_t length = lseek(fd, 0, SEEK_END);
  if (length < 0) {
    perror("Failed to read length of flash emulation file");
    exit(1);
  }

  emulator_flash_base =
      mmap(NULL, FLASH_TOTAL_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
  if (emulator_flash_base == MAP_FAILED) {
    perror("Failed to map flash emulation file");
    exit(1);
  }

  if (length < FLASH_TOTAL_SIZE) {
    if (ftruncate(fd, FLASH_TOTAL_SIZE) != 0) {
      perror("Failed to initialize flash emulation file");
      exit(1);
    }

    /* Initialize the flash */
    memset(emulator_flash_base, 0xff, FLASH_TOTAL_SIZE);
  }
}
#endif /* !_WIN32 — setup_flash is standalone-UDP only; the dylib/DLL host \
          owns flash */
