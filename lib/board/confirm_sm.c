/*
 * This file is part of the KeepKey project.
 *
 * Copyright (C) 2015 KeepKey LLC
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

#include "keepkey/board/keepkey_display.h"
#include "keepkey/board/keepkey_button.h"
#include "keepkey/board/timer.h"
#include "keepkey/board/layout.h"
#include "keepkey/board/messages.h"
#include "keepkey/board/confirm_sm.h"
#include "keepkey/board/usb.h"
#include "keepkey/board/supervise.h"
#include "trezor/crypto/memzero.h"

#ifndef EMULATOR
#include <libopencm3/cm3/cortex.h>
#endif

#include <assert.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

/* Button request ack */
static bool button_request_acked = false;

#if DEBUG_LINK
/* DebugLink supplies one decision per ButtonRequest. A multi-screen physical
 * confirmation under one request must carry that decision across subpages. */
static bool last_exit_was_debug_decision = false;
#endif

extern bool reset_msg_stack;

static CONFIDENTIAL char strbuf[BODY_CHAR_MAX];

/* vsnprintf() returns the length it WOULD have written. Treat anything that
 * did not fit as a refusal: once characters are lost, no renderer or pager can
 * recover them and there is no complete body the user can approve. */
static bool format_body_into(char* out, size_t out_len,
                             const char* request_body, va_list vl) {
  if (!out || out_len == 0 || !request_body) return false;
  const int needed = vsnprintf(out, out_len, request_body, vl);
  return needed >= 0 && (size_t)needed < out_len;
}

static bool format_body(const char* request_body, va_list vl) {
  return format_body_into(strbuf, sizeof(strbuf), request_body, vl);
}

/// Handler for push button being pressed.
/// \param context current state context.
static void handle_screen_press(void* context) {
  assert(context != NULL);

  StateInfo* si = (StateInfo*)context;

  if (button_request_acked) {
    switch (si->display_state) {
      case HOME:
        si->active_layout = LAYOUT_CONFIRM_ANIMATION;
        si->display_state = CONFIRM_WAIT;
        break;

      default:
        break;
    }
  }
}

/// Handler for push button being pressed.
/// \param context current state context.
static void handle_screen_release(void* context) {
  assert(context != NULL);

  StateInfo* si = (StateInfo*)context;

  switch (si->display_state) {
    case CONFIRM_WAIT:
      si->active_layout = LAYOUT_REQUEST_NO_ANIMATION;
      si->display_state = HOME;
      break;

    case CONFIRMED:
      si->active_layout = LAYOUT_FINISHED;
      si->display_state = FINISHED;
      break;

    default:
      break;
  }
}

/// User has held down the push button for duration as requested.
/// \param context current state context.
static void handle_confirm_timeout(void* context) {
  assert(context != NULL);

  StateInfo* si = (StateInfo*)context;
  si->display_state = CONFIRMED;
  si->active_layout = LAYOUT_CONFIRMED;
}

/// Changes the active layout of the confirmation screen.
/// \param active_layout The layout to swtich to.
/// \param si current state information.
/// \param layout_notification_func layout callback for displaying confirm
/// message.
static void swap_layout(ActiveLayout active_layout, volatile StateInfo* si,
                        layout_notification_t layout_notification_func) {
  switch (active_layout) {
    case LAYOUT_REQUEST:
      (*layout_notification_func)(si->lines[active_layout].request_title,
                                  si->lines[active_layout].request_body,
                                  NOTIFICATION_REQUEST);
      remove_runnable(&handle_confirm_timeout);
      break;

    case LAYOUT_REQUEST_NO_ANIMATION:
      (*layout_notification_func)(si->lines[active_layout].request_title,
                                  si->lines[active_layout].request_body,
                                  NOTIFICATION_REQUEST_NO_ANIMATION);
      remove_runnable(&handle_confirm_timeout);
      break;

    case LAYOUT_CONFIRM_ANIMATION:
      (*layout_notification_func)(si->lines[active_layout].request_title,
                                  si->lines[active_layout].request_body,
                                  NOTIFICATION_CONFIRM_ANIMATION);
      if (si->immediate) {
        post_delayed(&handle_confirm_timeout, (void*)si, 1);
      } else {
        post_delayed(&handle_confirm_timeout, (void*)si, CONFIRM_TIMEOUT_MS);
      }
      break;

    case LAYOUT_CONFIRMED:

      /* Finish confirming animation */
      while (is_animating()) {
        animate();
        display_refresh();
      }

      (*layout_notification_func)(si->lines[active_layout].request_title,
                                  si->lines[active_layout].request_body,
                                  NOTIFICATION_CONFIRMED);
      remove_runnable(&handle_confirm_timeout);
      break;

    default:
      assert(0);
  };
}

/// Run one confirmation screen: draw it, then wait for either the user's hold
/// or the host's Cancel. Callers go through confirm_helper() below, which is
/// what the public confirm()/review() wrappers use.
/// \param request_title  The confirmation's title.
/// \param requesta_body  The body of the confirmation message.
/// \param layout_notification_func  layout callback for displaying confirm
/// message. \returns true iff the device confirmed.
static bool confirm_screen(const char* request_title_param,
                           const char* request_body,
                           layout_notification_t layout_notification_func,
                           bool constant_power, IconType iconNum,
                           bool immediate) {
  bool ret_stat = false;
#if DEBUG_LINK
  last_exit_was_debug_decision = false;
#endif
  volatile StateInfo state_info;
  ActiveLayout new_layout, cur_layout;
  DisplayState new_ds;
  uint16_t tiny_msg;
  static CONFIDENTIAL uint8_t msg_tiny_buf[MSG_TINY_BFR_SZ];
  const char* request_title;
  request_title = request_title_param;

#if DEBUG_LINK
  const DebugLinkDecision* dld;
  bool debug_decided = false;
#endif

  layout_has_icon(iconNum == NO_ICON ? false : true);

  reset_msg_stack = false;

  memset((void*)&state_info, 0, sizeof(state_info));
  state_info.immediate = immediate;
  state_info.display_state = HOME;
  state_info.active_layout = LAYOUT_REQUEST;

  /* Request */
  state_info.lines[LAYOUT_REQUEST].request_title = request_title;
  state_info.lines[LAYOUT_REQUEST].request_body = request_body;
  state_info.lines[LAYOUT_REQUEST_NO_ANIMATION].request_title = request_title;
  state_info.lines[LAYOUT_REQUEST_NO_ANIMATION].request_body = request_body;

  /* Confirming */
  state_info.lines[LAYOUT_CONFIRM_ANIMATION].request_title = request_title;
  state_info.lines[LAYOUT_CONFIRM_ANIMATION].request_body = request_body;

  /* Confirmed */
  state_info.lines[LAYOUT_CONFIRMED].request_title = request_title;
  state_info.lines[LAYOUT_CONFIRMED].request_body = request_body;

  keepkey_button_set_on_press_handler(&handle_screen_press, (void*)&state_info);
  keepkey_button_set_on_release_handler(&handle_screen_release,
                                        (void*)&state_info);

  cur_layout = LAYOUT_INVALID;

  while (1) {
#ifndef EMULATOR
    svc_disable_interrupts();
#endif
    new_layout = state_info.active_layout;
    new_ds = state_info.display_state;
#ifndef EMULATOR
    svc_enable_interrupts();
#endif

    /* Don't process usb tiny message unless usb has been initialized */
#ifndef EMULATOR
    if (usbInitialized())
#else
    if (1)
#endif
    {
      /* Listen for tiny messages */
      tiny_msg = check_for_tiny_msg(msg_tiny_buf);

      switch (tiny_msg) {
        case MessageType_MessageType_ButtonAck:
          button_request_acked = true;
          break;

        case MessageType_MessageType_Cancel:
        case MessageType_MessageType_Initialize:
          if (tiny_msg == MessageType_MessageType_Initialize) {
            reset_msg_stack = true;
          }

          ret_stat = false;
          goto confirm_screen_exit;
#if DEBUG_LINK

        case MessageType_MessageType_DebugLinkDecision:
          dld = (DebugLinkDecision*)msg_tiny_buf;
          ret_stat = dld->yes_no;
          debug_decided = true;
          break;

        case MessageType_MessageType_DebugLinkGetState:
          call_msg_debug_link_get_state_handler(
              (DebugLinkGetState*)msg_tiny_buf);
          break;
#endif

        default:
          break; /* break from switch statement and stay in the while loop*/
      }
    }

    if (new_ds == FINISHED) {
      ret_stat = true;
      break; /* confirmation done.  Exiting function */
    }

    if (cur_layout != new_layout) {
      swap_layout(new_layout, &state_info, layout_notification_func);
      cur_layout = new_layout;
    }

#if DEBUG_LINK

    if (debug_decided && button_request_acked) {
      last_exit_was_debug_decision = true;
      break; /* confirmation done via debug link.  Exiting function */
    }

#endif

    if (iconNum != NO_ICON) {
      layout_add_icon(iconNum);
    }

    display_constant_power(constant_power);

    display_refresh();
    animate();
  }

confirm_screen_exit:

  keepkey_button_set_on_press_handler(NULL, NULL);
  keepkey_button_set_on_release_handler(NULL, NULL);

  return (ret_stat);
}

bool confirm_body_fits(const char* body, uint16_t body_width) {
  /* This used to count rows with calc_str_line() and compare against
   * BODY_ROWS. That was a second model of the screen, and the attacker picks
   * the input on which the two models disagree: the guard has now been broken
   * three separate ways -- by plain overflow, by a uint8_t line counter
   * wrapping at 255 newlines, and by space padding that one walk collapses and
   * the other does not. Each fix taught the model one more rule that
   * draw_string() already knew.
   *
   * So there is no model any more. draw_string_fits() runs draw_string()'s own
   * loop and its own per-glyph fit test with the pixel writes switched off,
   * and reports whether the last character was placed. Measuring and drawing
   * cannot disagree because they are the same code.
   *
   * calc_str_line() survives here for one thing only, and it is not a security
   * decision: layout_standard_notification() uses it to pick the vertical
   * alignment, so the probe must start at the same sp.y the real draw will
   * start at. Both call it with the same arguments, so both get the same
   * answer -- and if that answer were ever wrong, the probe would be wrong in
   * exactly the way the real draw is, which is the property we want. */
  Canvas* canvas = layout_get_canvas();
  const Font* body_font = get_body_font();
  const char* str2 = body ? body : "";

  DrawableParams sp;
  const uint32_t body_line_count = calc_str_line(body_font, str2, body_width);
  sp.y = TOP_MARGIN;
  if (body_line_count == ONE_LINE) {
    sp.y = TOP_MARGIN_FOR_ONE_LINE;
  } else if (body_line_count == TWO_LINES) {
    sp.y = TOP_MARGIN_FOR_TWO_LINES;
  }

  /* Mirrors layout_standard_notification(): the title is drawn from sp.y, then
   * the body starts one title-height plus BODY_TOP_MARGIN below it. */
  sp.y += font_height(body_font) + BODY_TOP_MARGIN;
  sp.x = (body_width == BODY_WIDTH_WITH_ICON) ? LEFT_MARGIN_WITH_ICON
                                              : LEFT_MARGIN;
  sp.color = BODY_COLOR;

  return draw_string_fits(canvas, body_font, str2, &sp, body_width,
                          font_height(body_font) + BODY_FONT_LINE_PADDING);
}

bool confirm_body_fits_constant_power(const char* body, uint16_t body_width) {
  Canvas* canvas = layout_get_canvas();
  const Font* body_font = get_body_font();
  const char* str2 = body ? body : "";

  DrawableParams sp;
  const uint32_t body_line_count = calc_str_line(body_font, str2, body_width);
  sp.y = TOP_MARGIN;
  if (body_line_count == ONE_LINE) {
    sp.y = TOP_MARGIN_FOR_ONE_LINE;
  } else if (body_line_count == TWO_LINES) {
    sp.y = TOP_MARGIN_FOR_TWO_LINES;
  }
  sp.y += font_height(body_font) + BODY_TOP_MARGIN;
  sp.x = 128 + LEFT_MARGIN;
  sp.color = BODY_COLOR;

  return draw_string_fits(canvas, body_font, str2, &sp, body_width,
                          font_height(body_font) + BODY_FONT_LINE_PADDING);
}

/// How many characters of `body` fit one screen, starting from `body[0]`?
///
/// Binary search over confirm_body_fits(), which replays the real placement.
/// Returns at least 1 so a body of unrenderable glyphs still advances rather
/// than looping forever.
static size_t page_take(const char* body, uint16_t body_width, char* buf,
                        size_t buf_size) {
  const size_t len = strlen(body);
  if (len == 0) return 0;

  size_t lo = 1;
  size_t hi = len < (buf_size - 1) ? len : (buf_size - 1);
  size_t best = 1;

  while (lo <= hi) {
    const size_t mid = lo + (hi - lo) / 2;
    memcpy(buf, body, mid);
    buf[mid] = '\0';
    if (confirm_body_fits(buf, body_width)) {
      best = mid;
      lo = mid + 1;
    } else {
      if (mid == 1) break;
      hi = mid - 1;
    }
  }
  return best;
}

/// Show `body` across as many screens as it needs.
///
/// Intermediate pages are `immediate`: a short click advances them. Only the
/// LAST page takes the caller's real hold, because only the last page is the
/// approval. Paging through what you are being shown should not cost the same
/// effort as consenting to it.
///
/// INVARIANT (see #482): one required press, one ButtonRequest. Every page
/// after the first writes its own request and clears button_request_acked, so
/// a host that answers every request it is told about never waits on a press
/// it never heard of.
///
/// `notify_host` is false for the *_without_button_request() entry points,
/// which deliberately never message the host; emitting per-page requests for
/// those would tell a host about presses it never asked to arbitrate.
static bool page_body_confirm(const char* request_title, const char* body,
                              layout_notification_t layout_notification_func,
                              bool constant_power, IconType iconNum,
                              bool immediate, uint16_t body_width,
                              bool notify_host) {
  static CONFIDENTIAL char page_buf[BODY_CHAR_MAX];
  static char page_title[TITLE_CHAR_MAX];

  /* Pass 1: count.
   *
   * The cap REFUSES; it must never truncate. Breaking out with input still
   * unread left `pages` at 100 while the body ran on, and the render loop then
   * treats page 100 as the last one -- so the hold that means "I approve this"
   * lands on a prefix, with the tail neither shown nor accounted for. A body of
   * 351 newlines reaches that: confirm_body_fits() accepts three newlines and
   * rejects four, so page_take() returns 3 and the body needs 117 pages.
   *
   * Returning false instead is not a lost capability. BODY_CHAR_MAX is 352, and
   * a body needing more than 99 pages is one averaging under four characters a
   * screen -- unreachable for real text, and not something a user could review
   * in any meaningful sense if it were. The caller reports it exactly as it
   * reports a refused screen. */
  size_t pages = 0;
  {
    const char* p = body;
    while (*p) {
      const size_t take = page_take(p, body_width, page_buf, sizeof(page_buf));
      if (take == 0) break;
      p += take;
      while (*p == ' ') p++; /* a leading space is dropped at a line start */
      pages++;
      if (pages > 99) {
        /* title formats n/m, and a prefix must never become the approval */
        memzero(page_buf, sizeof(page_buf));
        return false;
      }
    }
  }
  if (pages <= 1) {
    /* Nothing gained by paging -- draw it as it was. */
    return confirm_screen(request_title, body, layout_notification_func,
                          constant_power, iconNum, immediate);
  }

  bool ok = false;
  const char* p = body;
  for (size_t page = 0; page < pages && *p; page++) {
    const size_t take = page_take(p, body_width, page_buf, sizeof(page_buf));
    if (take == 0) break;
    memcpy(page_buf, p, take);
    page_buf[take] = '\0';

    const int title_len =
        snprintf(page_title, sizeof(page_title), "%s %u/%u", request_title,
                 (unsigned)(page + 1), (unsigned)pages);
    if (title_len < 0 || (size_t)title_len >= sizeof(page_title)) break;

    const bool last = (page + 1 == pages);
    if (page > 0 && notify_host) {
      ButtonRequest page_ack;
      memset(&page_ack, 0, sizeof(page_ack));
      page_ack.has_code = true;
      page_ack.code = ButtonRequestType_ButtonRequest_Other;
      button_request_acked = false;
      msg_write(MessageType_MessageType_ButtonRequest, &page_ack);
    }

    if (!confirm_screen(page_title, page_buf, layout_notification_func,
                        constant_power, iconNum, last ? immediate : true)) {
      goto done;
    }

    p += take;
    while (*p == ' ') p++;
    if (last) ok = true;
  }

done:
  memzero(page_buf, sizeof(page_buf));
  memzero(page_title, sizeof(page_title));
  return ok;
}

/// Show a confirmation, paging when its complete body will not fit the screen.
///
/// draw_string() draws until a glyph no longer fits the canvas and then simply
/// stops: a body taller than BODY_ROWS is drawn in part, with no ellipsis and
/// nothing to tell the user that the tail of an address, an amount or a
/// warning was dropped. Complete formatted bodies are therefore paged here.
/// Source formatting overflow is refused by every public entry point before a
/// ButtonRequest is emitted, because lost source cannot be paged.
///
/// Bodies that fit take exactly the path they took before: one screen, one
/// ButtonRequest, one hold.
static bool confirm_helper(const char* request_title, const char* request_body,
                           layout_notification_t layout_notification_func,
                           bool constant_power, IconType iconNum,
                           bool immediate, bool notify_host) {
  const uint16_t body_width =
      (uint16_t)((iconNum == NO_ICON) ? BODY_WIDTH : BODY_WIDTH_WITH_ICON);

  /* Only layout_standard_notification is known to wrap the body at BODY_WIDTH
   * over BODY_ROWS rows. Custom layouts place and size their own body, and
   * layout_constant_power_notification draws from x = 128 + LEFT_MARGIN where
   * the canvas edge, not BODY_WIDTH, is the limit. Measuring either of those
   * against BODY_WIDTH would be wrong, so leave them exactly as they were. */
  const bool render_incomplete =
      (layout_notification_func == &layout_standard_notification) &&
      !confirm_body_fits(request_body, body_width);

  if (render_incomplete) {
    /* RENDER overflow: the body reached the renderer intact, so every
     * character is still in hand and can be shown -- on more than one screen.
     * Page it. */
    return page_body_confirm(request_title, request_body,
                             layout_notification_func, constant_power, iconNum,
                             immediate, body_width, notify_host);
  }

  return confirm_screen(request_title, request_body, layout_notification_func,
                        constant_power, iconNum, immediate);
}

bool confirm(ButtonRequestType type, const char* request_title,
             const char* request_body, ...) {
  button_request_acked = false;

  va_list vl;
  va_start(vl, request_body);
  const bool formatted = format_body(request_body, vl);
  va_end(vl);
  if (!formatted) {
    memzero(strbuf, sizeof(strbuf));
    return false;
  }

  /* Send button request */
  ButtonRequest resp;
  memset(&resp, 0, sizeof(ButtonRequest));
  resp.has_code = true;
  resp.code = type;
  msg_write(MessageType_MessageType_ButtonRequest, &resp);

  bool ret =
      confirm_helper(request_title, strbuf, &layout_standard_notification,
                     false, NO_ICON, false, true);
  memzero(strbuf, sizeof(strbuf));
  return ret;
}

size_t confirm_constant_power_subpage_take(const char* body) {
  const size_t len = strlen(body);
  if (len == 0) return 0;

  size_t best = 0;
  for (size_t i = 0; i < len; i++) {
    if (body[i] != '\n' && i + 1 != len) continue;
    const size_t take = i + 1;
    char probe[BODY_CHAR_MAX];
    if (take >= sizeof(probe)) break;
    memcpy(probe, body, take);
    probe[take] = '\0';
    if (confirm_body_fits_constant_power(probe, CONSTANT_POWER_BODY_WIDTH)) {
      best = take;
    } else {
      break;
    }
  }
  return best;
}

bool confirm_constant_power_paged(ButtonRequestType type,
                                  const char* request_title,
                                  const char* request_body) {
  button_request_acked = false;

  ButtonRequest resp;
  memset(&resp, 0, sizeof(resp));
  resp.has_code = true;
  resp.code = type;
  msg_write(MessageType_MessageType_ButtonRequest, &resp);

  static CONFIDENTIAL char sub[BODY_CHAR_MAX];
  const char* p = request_body ? request_body : "";
  bool ok = true;
#if DEBUG_LINK
  bool decided_via_debug = false;
#endif

  while (*p && ok) {
    const size_t take = confirm_constant_power_subpage_take(p);
    if (take == 0 || take >= sizeof(sub)) {
      ok = false;
      break;
    }
    memcpy(sub, p, take);
    sub[take] = '\0';
    p += take;
    const bool last = (*p == '\0');

#if DEBUG_LINK
    if (decided_via_debug) {
      /* Production keeps the legacy one-ButtonRequest-per-word-group
       * protocol. The debug build emits a request for each renderer subpage
       * so the evidence harness can capture every physical OLED page instead
       * of silently retaining only the first one. */
      memset(&resp, 0, sizeof(resp));
      resp.has_code = true;
      resp.code = type;
      msg_write(MessageType_MessageType_ButtonRequest, &resp);
      decided_via_debug = false;
    }
#endif

    ok = confirm_screen(request_title, sub, &layout_constant_power_notification,
                        true, NO_ICON,
                        /*immediate=*/!last);
#if DEBUG_LINK
    if (ok && last_exit_was_debug_decision) decided_via_debug = true;
#endif
  }

  memzero(sub, sizeof(sub));
  return ok;
}

bool confirm_constant_power(ButtonRequestType type, const char* request_title,
                            const char* request_body, ...) {
  button_request_acked = false;

  va_list vl;
  va_start(vl, request_body);
  const bool formatted = format_body(request_body, vl);
  va_end(vl);
  if (!formatted) {
    memzero(strbuf, sizeof(strbuf));
    return false;
  }

  /* Send button request */
  ButtonRequest resp;
  memset(&resp, 0, sizeof(ButtonRequest));
  resp.has_code = true;
  resp.code = type;
  msg_write(MessageType_MessageType_ButtonRequest, &resp);

  bool ret =
      confirm_helper(request_title, strbuf, &layout_constant_power_notification,
                     true, NO_ICON, false, true);
  memzero(strbuf, sizeof(strbuf));
  return ret;
}

bool confirm_with_custom_button_request(const ButtonRequest* button_request,
                                        const char* request_title,
                                        const char* request_body, ...) {
  button_request_acked = false;

  va_list vl;
  va_start(vl, request_body);
  const bool formatted = format_body(request_body, vl);
  va_end(vl);
  if (!formatted) {
    memzero(strbuf, sizeof(strbuf));
    return false;
  }

  /* Send button request */
  msg_write(MessageType_MessageType_ButtonRequest, button_request);

  bool ret =
      confirm_helper(request_title, strbuf, &layout_standard_notification,
                     false, NO_ICON, false, true);
  memzero(strbuf, sizeof(strbuf));
  return ret;
}

bool confirm_with_custom_layout(layout_notification_t layout_notification_func,
                                ButtonRequestType type,
                                const char* request_title,
                                const char* request_body, ...) {
  /* Custom renderers do not expose their placement geometry, so the confirm
   * state machine cannot prove that they drew the complete body. Route every
   * TRANSACTION-CONSENT screen through the measured standard renderer instead:
   * bespoke amount styling is not worth silently clipping signed fields.
   *
   * Address and xpub display screens do NOT come through here -- see
   * confirm_address_with_custom_layout() below for why they must not. */
  (void)layout_notification_func;
  button_request_acked = false;

  va_list vl;
  va_start(vl, request_body);
  const bool formatted = format_body(request_body, vl);
  va_end(vl);
  if (!formatted) {
    memzero(strbuf, sizeof(strbuf));
    return false;
  }

  /* Send button request */
  ButtonRequest resp;
  memset(&resp, 0, sizeof(ButtonRequest));
  resp.has_code = true;
  resp.code = type;
  msg_write(MessageType_MessageType_ButtonRequest, &resp);

  bool ret =
      confirm_helper(request_title, strbuf, &layout_standard_notification,
                     false, NO_ICON, false, true);
  memzero(strbuf, sizeof(strbuf));
  return ret;
}

bool confirm_address_with_custom_layout(
    layout_notification_t layout_notification_func, ButtonRequestType type,
    const char* request_title, const char* request_body, ...) {
  /* Address and xpub verification screens keep their own renderer.
   *
   * The measured fallback in confirm_with_custom_layout() exists to stop a
   * bespoke layout from silently clipping a field the owner is CONSENTING to
   * sign. An address screen is not that: it displays a public value the device
   * itself derived, for the owner to check against what the host claims, and
   * nothing is signed by looking at it. Routing these through the standard
   * renderer had a cost that the safety argument does not pay for -- the five
   * address layouts draw the address as a QR code through layout_address(),
   * and the standard renderer draws no QR at all. Scanning that code is how
   * the address is actually used, so the fallback removed the feature rather
   * than hardening it.
   *
   * Clipping is still handled, just by the layout rather than the pager: these
   * renderers wrap the address with draw_string() and drop to the body font
   * when it will not fit bold.
   *
   * confirm_helper() already applies its measured/paged path only to
   * layout_standard_notification, so handing it a custom layout renders
   * exactly as it did before this release line. */
  button_request_acked = false;

  va_list vl;
  va_start(vl, request_body);
  const bool formatted = format_body(request_body, vl);
  va_end(vl);
  if (!formatted) {
    memzero(strbuf, sizeof(strbuf));
    return false;
  }

  /* Send button request */
  ButtonRequest resp;
  memset(&resp, 0, sizeof(ButtonRequest));
  resp.has_code = true;
  resp.code = type;
  msg_write(MessageType_MessageType_ButtonRequest, &resp);

  bool ret = confirm_helper(request_title, strbuf, layout_notification_func,
                            false, NO_ICON, false, true);
  memzero(strbuf, sizeof(strbuf));
  return ret;
}

bool confirm_without_button_request(const char* request_title,
                                    const char* request_body, ...) {
  button_request_acked = true;

  va_list vl;
  va_start(vl, request_body);
  const bool formatted = format_body(request_body, vl);
  va_end(vl);
  if (!formatted) {
    memzero(strbuf, sizeof(strbuf));
    return false;
  }

  bool ret =
      confirm_helper(request_title, strbuf, &layout_standard_notification,
                     false, NO_ICON, false, false);
  memzero(strbuf, sizeof(strbuf));
  return ret;
}

bool confirm_with_icon(ButtonRequestType type, IconType iconNum,
                       const char* request_title, const char* request_body,
                       ...) {
  button_request_acked = false;

  va_list vl;
  va_start(vl, request_body);
  const bool formatted = format_body(request_body, vl);
  va_end(vl);
  if (!formatted) {
    memzero(strbuf, sizeof(strbuf));
    return false;
  }

  /* Send button request */
  ButtonRequest resp;
  memset(&resp, 0, sizeof(ButtonRequest));
  resp.has_code = true;
  resp.code = type;
  msg_write(MessageType_MessageType_ButtonRequest, &resp);

  bool ret =
      confirm_helper(request_title, strbuf, &layout_standard_notification,
                     false, iconNum, false, true);
  memzero(strbuf, sizeof(strbuf));
  return ret;
}

bool review(ButtonRequestType type, const char* request_title,
            const char* request_body, ...) {
  button_request_acked = false;

  va_list vl;
  va_start(vl, request_body);
  const bool formatted = format_body(request_body, vl);
  va_end(vl);
  if (!formatted) {
    memzero(strbuf, sizeof(strbuf));
    return false;
  }

  /* Send button request */
  ButtonRequest resp;
  memset(&resp, 0, sizeof(ButtonRequest));
  resp.has_code = true;
  resp.code = type;
  msg_write(MessageType_MessageType_ButtonRequest, &resp);

  const bool shown =
      confirm_helper(request_title, strbuf, &layout_standard_notification,
                     false, NO_ICON, false, true);
  memzero(strbuf, sizeof(strbuf));
  return shown;
}

bool review_without_button_request(const char* request_title,
                                   const char* request_body, ...) {
  button_request_acked = true;

  va_list vl;
  va_start(vl, request_body);
  const bool formatted = format_body(request_body, vl);
  va_end(vl);
  if (!formatted) {
    memzero(strbuf, sizeof(strbuf));
    return false;
  }

  const bool shown =
      confirm_helper(request_title, strbuf, &layout_standard_notification,
                     false, NO_ICON, false, false);
  memzero(strbuf, sizeof(strbuf));
  return shown;
}

bool review_with_icon(ButtonRequestType type, IconType iconNum,
                      const char* request_title, const char* request_body,
                      ...) {
  button_request_acked = false;

  va_list vl;
  va_start(vl, request_body);
  const bool formatted = format_body(request_body, vl);
  va_end(vl);
  if (!formatted) {
    memzero(strbuf, sizeof(strbuf));
    return false;
  }

  /* Send button request */
  ButtonRequest resp;
  memset(&resp, 0, sizeof(ButtonRequest));
  resp.has_code = true;
  resp.code = type;
  msg_write(MessageType_MessageType_ButtonRequest, &resp);

  const bool shown =
      confirm_helper(request_title, strbuf, &layout_standard_notification,
                     false, iconNum, false, true);
  memzero(strbuf, sizeof(strbuf));
  return shown;
}

bool review_immediate(ButtonRequestType type, const char* request_title,
                      const char* request_body, ...) {
  button_request_acked = false;

  va_list vl;
  va_start(vl, request_body);
  const bool formatted = format_body(request_body, vl);
  va_end(vl);
  if (!formatted) {
    memzero(strbuf, sizeof(strbuf));
    return false;
  }

  /* Send button request */
  ButtonRequest resp;
  memset(&resp, 0, sizeof(ButtonRequest));
  resp.has_code = true;
  resp.code = type;
  msg_write(MessageType_MessageType_ButtonRequest, &resp);

  const bool shown =
      confirm_helper(request_title, strbuf, &layout_standard_notification,
                     false, NO_ICON, true, true);
  memzero(strbuf, sizeof(strbuf));
  return shown;
}
