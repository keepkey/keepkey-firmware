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

#include <arpa/inet.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>

#ifndef KEEPKEY_UDP_PORT
#define KEEPKEY_UDP_PORT 11044
#endif

struct usb_socket {
  int fd;
  struct sockaddr_in from;
  socklen_t fromlen;
};

static struct usb_socket usb_main;
static struct usb_socket usb_debug;

static int socket_setup(int port) {
  int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
  if (fd < 0) {
    perror("Failed to create socket");
    exit(1);
  }

  struct sockaddr_in addr;
  addr.sin_family = AF_INET;
  addr.sin_port = htons(port);
  addr.sin_addr.s_addr = htonl(INADDR_ANY);
  // addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

  if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
    perror("Failed to bind socket");
    exit(1);
  }

  return fd;
}

static size_t socket_write(struct usb_socket *sock, const void *buffer,
                           size_t size) {
  if (sock->fromlen > 0) {
    ssize_t n = sendto(sock->fd, buffer, size, MSG_DONTWAIT,
                       (const struct sockaddr *)&sock->from, sock->fromlen);
    if (n < 0 || ((size_t)n) != size) {
      perror("Failed to write socket");
      return 0;
    }
  }

  return size;
}

static size_t socket_read(struct usb_socket *sock, void *buffer, size_t size) {
  sock->fromlen = sizeof(sock->from);
  ssize_t n = recvfrom(sock->fd, buffer, size, MSG_DONTWAIT,
                       (struct sockaddr *)&sock->from, &sock->fromlen);

  if (n < 0) {
    if (errno != EAGAIN && errno != EWOULDBLOCK) {
      perror("Failed to read socket");
    }
    return 0;
  }

  static const char msg_ping[] = {'P', 'I', 'N', 'G', 'P', 'I', 'N', 'G'};
  static const char msg_pong[] = {'P', 'O', 'N', 'G', 'P', 'O', 'N', 'G'};

  if (n == sizeof(msg_ping) &&
      memcmp(buffer, msg_ping, sizeof(msg_ping)) == 0) {
    socket_write(sock, msg_pong, sizeof(msg_pong));
    return 0;
  }

  return n;
}

#ifdef KKEMU_DYLIB
/*
 * Dylib mode: I/O goes through ring buffers managed by libkkemu.c.
 * These are thin trampolines to the libkkemu_socket* functions.
 */
extern void   libkkemu_socketInit(void);
extern size_t libkkemu_socketRead(int *iface, void *buffer, size_t size);
extern size_t libkkemu_socketWrite(int iface, const void *buffer, size_t size);

void emulatorSocketInit(void) { libkkemu_socketInit(); }

size_t emulatorSocketRead(int *iface, void *buffer, size_t size) {
	return libkkemu_socketRead(iface, buffer, size);
}

size_t emulatorSocketWrite(int iface, const void *buffer, size_t size) {
	return libkkemu_socketWrite(iface, buffer, size);
}

#else
/* Standard mode: UDP sockets (standalone kkemu binary) */

void emulatorSocketInit(void) {
  int port = KEEPKEY_UDP_PORT;
  const char *env_port = getenv("KEEPKEY_UDP_PORT");
  if (env_port) {
    int p = atoi(env_port);
    if (p > 0 && p < 65535) port = p;
  }
  fprintf(stderr, "Emulator listening on UDP ports %d (main) and %d (debug)\n",
          port, port + 1);
  usb_main.fd = socket_setup(port);
  usb_main.fromlen = 0;
  usb_debug.fd = socket_setup(port + 1);
  usb_debug.fromlen = 0;
}

size_t emulatorSocketRead(int *iface, void *buffer, size_t size) {
  size_t n = socket_read(&usb_main, buffer, size);
  if (n > 0) {
    *iface = 0;
    return n;
  }

  n = socket_read(&usb_debug, buffer, size);
  if (n > 0) {
    *iface = 1;
    return n;
  }

  return 0;
}

size_t emulatorSocketWrite(int iface, const void *buffer, size_t size) {
  if (iface == 0) {
    return socket_write(&usb_main, buffer, size);
  }
  if (iface == 1) {
    return socket_write(&usb_debug, buffer, size);
  }
  return 0;
}
#endif
