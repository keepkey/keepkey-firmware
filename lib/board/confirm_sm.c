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

extern bool reset_msg_stack;

static CONFIDENTIAL char strbuf[BODY_CHAR_MAX];

/* Set by format_body() when the formatted body did not fit strbuf, i.e. when
 * characters were lost before any screen existed to show them. Read and
 * cleared by confirm_helper(). Truncation here is invisible to every later
 * check: what reaches the renderer is a complete, well-formed, shorter string,
 * so the screen looks correct and is not. */
static bool body_truncated = false;

/* The single place a host-supplied body is formatted. vsnprintf() returns the
 * length it WOULD have written, which is the only chance to notice that
 * strbuf was too small -- after this, the evidence is gone. */
static void format_body(const char* request_body, va_list vl) {
  const int needed = vsnprintf(strbuf, sizeof(strbuf), request_body, vl);
  body_truncated = (needed < 0) || ((size_t)needed >= sizeof(strbuf));
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

/* The same probe, for constant-power screens.
 *
 * layout_constant_power_notification() draws from x = 128 + LEFT_MARGIN,
 * because the display driver mirrors the right half of the canvas onto the
 * panel. Only KEEPKEY_DISPLAY_WIDTH - (128 + LEFT_MARGIN) = 124 px exists past
 * that origin, while BODY_WIDTH (225) is what gets passed as the wrap width.
 * The wrap therefore never fires before the canvas edge does, draw_char_impl
 * rejects the first glyph that crosses 256, and draw_string_walk stops --
 * dropping the rest of the body, including whole later lines, with no ellipsis
 * and no indicator.
 *
 * Measuring with BODY_WIDTH from the LEFT margin (confirm_body_fits) would say
 * such a body fits, because from x = 4 it does. The origin is the whole point,
 * so this probe starts where the real draw starts. Same loop, same per-glyph
 * fit test, so measuring and drawing cannot disagree.
 *
 * body_width is accepted and forwarded unchanged so this can stand in for
 * confirm_body_fits() wherever a fit probe is selected by layout. */
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

  /* Mirrors layout_constant_power_notification() exactly. */
  sp.y += font_height(body_font) + BODY_TOP_MARGIN;
  sp.x = 128 + LEFT_MARGIN;
  sp.color = BODY_COLOR;

  return draw_string_fits(canvas, body_font, str2, &sp, body_width,
                          font_height(body_font) + BODY_FONT_LINE_PADDING);
}

/// Fit probe selected by layout: measuring must start where drawing starts.
typedef bool (*body_fits_fn)(const char*, uint16_t);

static body_fits_fn fits_probe_for(layout_notification_t fn) {
  if (fn == &layout_constant_power_notification) {
    return &confirm_body_fits_constant_power;
  }
  return &confirm_body_fits;
}

/// How many characters of `body` fit one screen, starting from `body[0]`?
///
/// Binary search over confirm_body_fits(), which replays the real placement.
/// Returns at least 1 so a body of unrenderable glyphs still advances rather
/// than looping forever.
static size_t page_take(const char* body, uint16_t body_width, char* buf,
                        size_t buf_size, body_fits_fn fits) {
  const size_t len = strlen(body);
  if (len == 0) return 0;

  size_t lo = 1;
  size_t hi = len < (buf_size - 1) ? len : (buf_size - 1);
  size_t best = 1;

  while (lo <= hi) {
    const size_t mid = lo + (hi - lo) / 2;
    memcpy(buf, body, mid);
    buf[mid] = '\0';
    if (fits(buf, body_width)) {
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
static bool page_body_confirm(const char* request_title, const char* body,
                              layout_notification_t layout_notification_func,
                              bool constant_power, IconType iconNum,
                              bool immediate, uint16_t body_width) {
  const body_fits_fn fits = fits_probe_for(layout_notification_func);
  static CONFIDENTIAL char page_buf[BODY_CHAR_MAX];
  static char page_title[TITLE_CHAR_MAX];

  /* Pass 1: count. */
  size_t pages = 0;
  {
    const char* p = body;
    while (*p) {
      const size_t take =
          page_take(p, body_width, page_buf, sizeof(page_buf), fits);
      if (take == 0) break;
      p += take;
      while (*p == ' ') p++; /* a leading space is dropped at a line start */
      pages++;
      if (pages > 99) break; /* title formats n/m; refuse to run away */
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
    const size_t take =
        page_take(p, body_width, page_buf, sizeof(page_buf), fits);
    if (take == 0) break;
    memcpy(page_buf, p, take);
    page_buf[take] = '\0';

    const int title_len =
        snprintf(page_title, sizeof(page_title), "%s %u/%u", request_title,
                 (unsigned)(page + 1), (unsigned)pages);
    if (title_len < 0 || (size_t)title_len >= sizeof(page_title)) break;

    const bool last = (page + 1 == pages);
    if (page > 0) {
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

/// Show a confirmation, warning first when its body will not fit the screen.
///
/// draw_string() draws until a glyph no longer fits the canvas and then simply
/// stops: a body taller than BODY_ROWS is drawn in part, with no ellipsis and
/// nothing to tell the user that the tail of an address, an amount or a
/// warning was dropped. The vsnprintf() into strbuf[BODY_CHAR_MAX] below cuts
/// long host strings a second time, just as quietly.
///
/// So when the body will not fit, put an explicit screen in front of it. That
/// screen costs its own hold, and the hold is a real consent signal: a host
/// Cancel breaks it and the caller reports ActionCancelled, exactly as it
/// would for the body screen. A body that is only partly shown is now never
/// shown without saying so.
///
/// Bodies that fit take exactly the path they took before: one screen, one
/// ButtonRequest, one hold.
static bool confirm_helper(const char* request_title, const char* request_body,
                           layout_notification_t layout_notification_func,
                           bool constant_power, IconType iconNum,
                           bool immediate) {
  const uint16_t body_width =
      (uint16_t)((iconNum == NO_ICON) ? BODY_WIDTH : BODY_WIDTH_WITH_ICON);

  /* Consume the source-completeness latch exactly once, whatever happens
   * below: leaving it set would make the NEXT confirmation warn for this
   * one's reason. */
  const bool truncated = body_truncated;
  body_truncated = false;

  /* Two independent ways the user can be shown less than what is being
   * approved, and they need separate measurements because they happen at
   * different times:
   *
   *   SOURCE       the formatted body did not fit strbuf. Characters were lost
   *                before the renderer ever saw them, so no amount of looking
   *                at the screen can detect it -- only vsnprintf()'s return
   *                value could, and format_body() kept it.
   *   RENDER       the body reached the renderer intact but did not fit the
   *                canvas. draw_string_fits() replays the real placement and
   *                reports whether the last character landed.
   *
   * The probe must start where the real draw starts, so it is selected by
   * layout. layout_standard_notification wraps at BODY_WIDTH from LEFT_MARGIN;
   * layout_constant_power_notification draws from x = 128 + LEFT_MARGIN, where
   * the canvas edge and not BODY_WIDTH is the limit.
   *
   * Constant-power screens used to be excluded here on the grounds that
   * measuring them against BODY_WIDTH would be wrong. It would have been -- but
   * excluding them meant the seed-backup pages, which are drawn by exactly that
   * layout, had NO completeness check at all. Measured over 200k random 24-word
   * mnemonics with the real font tables: 1.7% produce a backup page the
   * renderer silently clips, and 0.65% never show one of the words at all,
   * because the walk stops at the first rejected glyph and drops every
   * character after it. A user writes down 23 words and cannot restore.
   *
   * The answer is to measure at the right origin, not to skip the measurement.
   * Custom layouts that place their own body still opt out.
   *
   * A SOURCE truncation is layout-independent and must warn regardless. */
  const body_fits_fn render_probe =
      (layout_notification_func == &layout_standard_notification ||
       layout_notification_func == &layout_constant_power_notification)
          ? fits_probe_for(layout_notification_func)
          : NULL;
  const bool render_incomplete =
      render_probe && !render_probe(request_body, body_width);

  if (truncated) {
    /* SOURCE truncation: characters were lost in vsnprintf() before the
     * renderer ever saw them. They cannot be paged, because they do not
     * exist any more. Say exactly that -- the old copy promised to show the
     * rest on the next hold and then redrew the same clipped body, which is
     * worse than not warning at all: a user who read it carefully was
     * misled about what they had seen. */
    if (!confirm_screen("Cut Off",
                        "This text is too long to show in full. The rest "
                        "cannot be displayed. Hold to continue anyway.",
                        &layout_standard_notification, constant_power, NO_ICON,
                        immediate)) {
      return false;
    }
    return page_body_confirm(request_title, request_body,
                             layout_notification_func, constant_power, iconNum,
                             immediate, body_width);
  }

  if (render_incomplete) {
    /* RENDER overflow: the body reached the renderer intact, so every
     * character is still in hand and can be shown -- on more than one screen.
     * Page it. */
    return page_body_confirm(request_title, request_body,
                             layout_notification_func, constant_power, iconNum,
                             immediate, body_width);
  }

  return confirm_screen(request_title, request_body, layout_notification_func,
                        constant_power, iconNum, immediate);
}

bool confirm(ButtonRequestType type, const char* request_title,
             const char* request_body, ...) {
  button_request_acked = false;

  va_list vl;
  va_start(vl, request_body);
  format_body(request_body, vl);
  va_end(vl);

  /* Send button request */
  ButtonRequest resp;
  memset(&resp, 0, sizeof(ButtonRequest));
  resp.has_code = true;
  resp.code = type;
  msg_write(MessageType_MessageType_ButtonRequest, &resp);

  bool ret =
      confirm_helper(request_title, strbuf, &layout_standard_notification,
                     false, NO_ICON, false);
  memzero(strbuf, sizeof(strbuf));
  return ret;
}

bool confirm_constant_power(ButtonRequestType type, const char* request_title,
                            const char* request_body, ...) {
  button_request_acked = false;

  va_list vl;
  va_start(vl, request_body);
  format_body(request_body, vl);
  va_end(vl);

  /* Send button request */
  ButtonRequest resp;
  memset(&resp, 0, sizeof(ButtonRequest));
  resp.has_code = true;
  resp.code = type;
  msg_write(MessageType_MessageType_ButtonRequest, &resp);

  bool ret =
      confirm_helper(request_title, strbuf, &layout_constant_power_notification,
                     true, NO_ICON, false);
  memzero(strbuf, sizeof(strbuf));
  return ret;
}

bool confirm_with_custom_button_request(const ButtonRequest* button_request,
                                        const char* request_title,
                                        const char* request_body, ...) {
  button_request_acked = false;

  va_list vl;
  va_start(vl, request_body);
  format_body(request_body, vl);
  va_end(vl);

  /* Send button request */
  msg_write(MessageType_MessageType_ButtonRequest, button_request);

  bool ret =
      confirm_helper(request_title, strbuf, &layout_standard_notification,
                     false, NO_ICON, false);
  memzero(strbuf, sizeof(strbuf));
  return ret;
}

bool confirm_with_custom_layout(layout_notification_t layout_notification_func,
                                ButtonRequestType type,
                                const char* request_title,
                                const char* request_body, ...) {
  button_request_acked = false;

  va_list vl;
  va_start(vl, request_body);
  format_body(request_body, vl);
  va_end(vl);

  /* Send button request */
  ButtonRequest resp;
  memset(&resp, 0, sizeof(ButtonRequest));
  resp.has_code = true;
  resp.code = type;
  msg_write(MessageType_MessageType_ButtonRequest, &resp);

  bool ret = confirm_helper(request_title, strbuf, layout_notification_func,
                            false, NO_ICON, false);
  memzero(strbuf, sizeof(strbuf));
  return ret;
}

bool confirm_without_button_request(const char* request_title,
                                    const char* request_body, ...) {
  button_request_acked = true;

  va_list vl;
  va_start(vl, request_body);
  format_body(request_body, vl);
  va_end(vl);

  bool ret =
      confirm_helper(request_title, strbuf, &layout_standard_notification,
                     false, NO_ICON, false);
  memzero(strbuf, sizeof(strbuf));
  return ret;
}

bool confirm_with_icon(ButtonRequestType type, IconType iconNum,
                       const char* request_title, const char* request_body,
                       ...) {
  button_request_acked = false;

  va_list vl;
  va_start(vl, request_body);
  format_body(request_body, vl);
  va_end(vl);

  /* Send button request */
  ButtonRequest resp;
  memset(&resp, 0, sizeof(ButtonRequest));
  resp.has_code = true;
  resp.code = type;
  msg_write(MessageType_MessageType_ButtonRequest, &resp);

  bool ret =
      confirm_helper(request_title, strbuf, &layout_standard_notification,
                     false, iconNum, false);
  memzero(strbuf, sizeof(strbuf));
  return ret;
}

bool review(ButtonRequestType type, const char* request_title,
            const char* request_body, ...) {
  button_request_acked = false;

  va_list vl;
  va_start(vl, request_body);
  format_body(request_body, vl);
  va_end(vl);

  /* Send button request */
  ButtonRequest resp;
  memset(&resp, 0, sizeof(ButtonRequest));
  resp.has_code = true;
  resp.code = type;
  msg_write(MessageType_MessageType_ButtonRequest, &resp);

  const bool shown =
      confirm_helper(request_title, strbuf, &layout_standard_notification,
                     false, NO_ICON, false);
  memzero(strbuf, sizeof(strbuf));
  return shown;
}

bool review_without_button_request(const char* request_title,
                                   const char* request_body, ...) {
  button_request_acked = true;

  va_list vl;
  va_start(vl, request_body);
  format_body(request_body, vl);
  va_end(vl);

  const bool shown =
      confirm_helper(request_title, strbuf, &layout_standard_notification,
                     false, NO_ICON, false);
  memzero(strbuf, sizeof(strbuf));
  return shown;
}

bool review_with_icon(ButtonRequestType type, IconType iconNum,
                      const char* request_title, const char* request_body,
                      ...) {
  button_request_acked = false;

  va_list vl;
  va_start(vl, request_body);
  format_body(request_body, vl);
  va_end(vl);

  /* Send button request */
  ButtonRequest resp;
  memset(&resp, 0, sizeof(ButtonRequest));
  resp.has_code = true;
  resp.code = type;
  msg_write(MessageType_MessageType_ButtonRequest, &resp);

  const bool shown =
      confirm_helper(request_title, strbuf, &layout_standard_notification,
                     false, iconNum, false);
  memzero(strbuf, sizeof(strbuf));
  return shown;
}

bool review_immediate(ButtonRequestType type, const char* request_title,
                      const char* request_body, ...) {
  button_request_acked = false;

  va_list vl;
  va_start(vl, request_body);
  format_body(request_body, vl);
  va_end(vl);

  /* Send button request */
  ButtonRequest resp;
  memset(&resp, 0, sizeof(ButtonRequest));
  resp.has_code = true;
  resp.code = type;
  msg_write(MessageType_MessageType_ButtonRequest, &resp);

  const bool shown =
      confirm_helper(request_title, strbuf, &layout_standard_notification,
                     false, NO_ICON, true);
  memzero(strbuf, sizeof(strbuf));
  return shown;
}
