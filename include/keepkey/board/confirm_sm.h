/*
 * This file is part of the KeepKey project.
 *
 * Copyright (C) 2018 KeepKey LLC
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

#ifndef CONFIRM_SM_H
#define CONFIRM_SM_H

#include "keepkey/transport/interface.h"
#include "keepkey/board/layout.h"

#include <stdbool.h>

/* implement a means to display debug information */
#ifdef DEBUG_ON
  #define DEBUG_DISPLAY(TITLE) \
  {\
    (void)review(ButtonRequestType_ButtonRequest_Other, TITLE, " ");\
  }
  // Example
  // DEBUG_DISPLAY_VAL("sig", "sig %s", 65, resp->signature.bytes[ctr]);
  #define DEBUG_DISPLAY_VAL(TITLE,VALNAME,SIZE,BYTES) \
  {\
    char str[SIZE+1];\
    int ctr;\
    for (ctr=0; ctr<SIZE/2; ctr++) {\
      snprintf(&str[2*ctr], 3, "%02x", BYTES);\
    }\
    (void)review(ButtonRequestType_ButtonRequest_Other, TITLE,\
                 VALNAME, str);\
  }
#endif

/* The number of milliseconds to wait for a confirmation */
#define CONFIRM_TIMEOUT_MS 1200

typedef enum { HOME, CONFIRM_WAIT, CONFIRMED, FINISHED } DisplayState;

typedef enum {
  LAYOUT_REQUEST,
  LAYOUT_REQUEST_NO_ANIMATION,
  LAYOUT_CONFIRM_ANIMATION,
  LAYOUT_CONFIRMED,
  LAYOUT_FINISHED,
  LAYOUT_NUM_LAYOUTS,
  LAYOUT_INVALID
} ActiveLayout;

/* Define the given layout dialog texts for each screen */
typedef struct {
  const char *request_title;
  const char *request_body;
} ScreenLine;

typedef ScreenLine ScreenLines;
typedef ScreenLines DialogLines[LAYOUT_NUM_LAYOUTS];

typedef struct {
  DialogLines lines;
  DisplayState display_state;
  ActiveLayout active_layout;
} StateInfo;

typedef void (*layout_notification_t)(const char *str1, const char *str2,
                                      NotificationType type);

/// User confirmation.
/// \param type            The kind of button request to send to the host.
/// \param request_title   Title of confirm message.
/// \param request_body    Body of confirm message.
/// \returns true iff the device confirmed.
bool confirm(ButtonRequestType type, const char *request_title,
             const char *request_body, ...)
    __attribute__((format(printf, 3, 4)));

bool confirm_constant_power(ButtonRequestType type, const char *request_title, const char *request_body,
             ...) __attribute__((format(printf, 3, 4)));

/// User confirmation.
/// \param type            The kind of button request to send to the host.
/// \param request_title   Title of confirm message.
/// \param request_body    Body of confirm message.
/// \returns true iff the device confirmed.
bool confirm_with_custom_button_request(ButtonRequest *button_request,
                                        const char *request_title,
                                        const char *request_body, ...)
    __attribute__((format(printf, 3, 4)));

/// User confirmation, custom layout.
/// \param layout_notification_func      Layout callback.
/// \param type            The kind of button request to send to the host.
/// \param request_title   Title of confirm message.
/// \param request_body    Body of confirm message.
/// \returns true iff the device confirmed.
bool confirm_with_custom_layout(layout_notification_t layout_notification_func,
                                ButtonRequestType type,
                                const char *request_title,
                                const char *request_body, ...)
    __attribute__((format(printf, 4, 5)));

/// User confirmation.
///
/// Does not message the host for ButtonAcks.
/// \param request_title   Title of confirm message.
/// \param request_body    Body of confirm message.
/// \returns true iff the device confirmed.
bool confirm_without_button_request(const char *request_title,
                                    const char *request_body, ...)
    __attribute__((format(printf, 2, 3)));

/// Like confirm, but always \returns true.
/// \param request_title   Title of confirm message.
/// \param request_body    Body of confirm message.
bool review(ButtonRequestType type, const char *request_title,
            const char *request_body, ...)
    __attribute__((format(printf, 3, 4)));

/// Like confirm, but always \returns true. Does not message the host for
/// ButtonAcks. \param request_title   Title of confirm message. \param
/// request_body    Body of confirm message.
bool review_without_button_request(const char *request_title,
                                   const char *request_body, ...)
    __attribute__((format(printf, 2, 3)));

#endif
