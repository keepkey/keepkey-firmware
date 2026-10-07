/*
 * This file is part of the KeepKey project.
 *
 * Copyright (C) 2026 KeepKey
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

#include "keepkey/firmware/dice_input.h"

#include "keepkey/board/draw.h"
#include "keepkey/board/font.h"
#include "keepkey/board/keepkey_button.h"
#include "keepkey/board/keepkey_display.h"
#include "keepkey/board/layout.h"
#include "keepkey/board/messages.h"
#include "keepkey/board/supervise.h"
#include "keepkey/board/timer.h"
#include "keepkey/transport/interface.h"
#include "trezor/crypto/memzero.h"
#include "trezor/crypto/sha2.h"

#include <stdio.h>
#include <string.h>

#define _(X) (X)

/* Selector positions 0-5 are digits '1'-'6'; 6 is UNDO. */
#define DICE_POSITIONS 7
#define DICE_UNDO_POS 6

/* Holding this long commits the selection; edges closer together than the
 * debounce window are contact bounce. Distinct from CONFIRM_TIMEOUT_MS on
 * purpose: a 1200ms hold per roll makes 99 rolls a slog. */
#define DICE_HOLD_MS 800
#define DICE_DEBOUNCE_MS 30

/* The screen runs with display_constant_power(true): the display driver
 * fills x<128 with the INVERSE of x>=128 at refresh time so total lit
 * pixels stay constant (OLED power side-channel defense — same reason the
 * PIN matrix lives on the right half). All drawing must stay in x>=128. */
#define DICE_LEFT 130
#define DICE_CELL_SIZE 15
#define DICE_CELL_GAP 2
#define DICE_GRID_Y 14
#define DICE_STATUS_Y 33
#define DICE_BAR_X DICE_LEFT
#define DICE_BAR_Y 48
#define DICE_BAR_W (7 * DICE_CELL_SIZE + 6 * DICE_CELL_GAP)
#define DICE_BAR_H 6

extern bool reset_msg_stack;

/* Button state shared with the ISR. Every classification decision (short vs
 * hold) is made exactly once per press cycle and guarded by dice_committed,
 * so a press can never produce both an advance and a commit. The UI loop
 * reads and drains these under masked interrupts. */
static volatile bool dice_accept; /* host has ButtonAck'd the screen */
static volatile bool dice_pressed;
static volatile bool dice_committed; /* this press cycle already classified */
static volatile uint32_t dice_press_start;
static volatile uint32_t dice_release_time;
static volatile bool dice_have_release;
static volatile uint8_t dice_short_events;
static volatile uint8_t dice_hold_events;

#ifndef EMULATOR
static void dice_on_press(void *context) {
  (void)context;
  uint32_t now = getSysTime();
  /* Mirror confirm_sm: input is dead until the host acks the request, so a
   * press begun before the ack cannot accrue hold time toward a commit. */
  if (!dice_accept || dice_pressed) {
    return;
  }
  dice_pressed = true;
  if (dice_have_release && now - dice_release_time < DICE_DEBOUNCE_MS) {
    /* Release-edge bounce: the release that just queued an event was not a
     * real one. Retract it and continue the original press cycle — the UI
     * loop is barred from consuming events until the line has settled for
     * DICE_DEBOUNCE_MS, so it cannot have acted on it yet. */
    if (!dice_committed && dice_short_events > 0) {
      dice_short_events--;
    }
    return;
  }
  dice_press_start = now;
  dice_committed = false;
}

static void dice_on_release(void *context) {
  (void)context;
  uint32_t now = getSysTime();
  if (!dice_accept || !dice_pressed) {
    return;
  }
  dice_pressed = false;
  dice_release_time = now;
  dice_have_release = true;
  if (dice_committed) {
    return; /* the UI loop already committed this hold while it was held */
  }
  uint32_t held = now - dice_press_start;
  if (held >= DICE_HOLD_MS) {
    /* A hold completed inside the UI-loop poll gap still counts. */
    dice_committed = true;
    if (dice_hold_events < 8) {
      dice_hold_events++;
    }
  } else if (held >= DICE_DEBOUNCE_MS && dice_short_events < 8) {
    dice_short_events++;
  }
}
#endif

uint32_t dice_rolls_for_strength(uint32_t strength_bits) {
  switch (strength_bits) {
    case 128:
      return 50;
    case 192:
      return 75;
    default:
      return 99; /* 256 */
  }
}

void dice_mix(uint8_t entropy[32], const char *rolls, uint32_t count) {
  SHA256_CTX ctx;
  sha256_Init(&ctx);
  sha256_Update(&ctx, entropy, 32);
  sha256_Update(&ctx, (const uint8_t *)rolls, count);
  sha256_Final(&ctx, entropy);
  memzero(&ctx, sizeof(ctx));
}

static void dice_draw_screen(uint32_t count, uint32_t target, uint8_t position,
                             const char *status, uint16_t hold_permil) {
  Canvas *canvas = layout_get_canvas();
  char line[32];

  layout_clear();
  display_constant_power(true);

  DrawableParams p = {.color = 0xFF, .x = DICE_LEFT, .y = 0};
  /* Clamped: the final commit redraws before the loop re-tests its
   * condition, which would otherwise render an impossible "ROLL 100/99". */
  snprintf(line, sizeof(line), "ROLL %lu/%lu",
           (unsigned long)(count < target ? count + 1 : target),
           (unsigned long)target);
  draw_string(canvas, get_title_font(), line, &p, 0, 10);

  for (uint8_t i = 0; i < DICE_POSITIONS; i++) {
    uint16_t cx = DICE_LEFT + i * (DICE_CELL_SIZE + DICE_CELL_GAP);
    bool active = (i == position);
    /* Inverse video marks the active cell: white box, ink-black glyph.
     * Gray levels collapse to white in the 1bpp DebugLink capture, so the
     * machine-checkable signal must be geometry, not shade. */
    draw_box_simple(canvas, active ? 0xFF : 0x22, cx, DICE_GRID_Y,
                    DICE_CELL_SIZE, DICE_CELL_SIZE);
    uint8_t ink = active ? 0x00 : 0xFF;
    if (i < DICE_UNDO_POS) {
      /* pin_font '1' is 4px wide where '2'-'6' are 8px (font.c) — center
       * each on its own metric rather than on the common case. */
      uint16_t glyph_w = (i == 0) ? 4 : 8;
      draw_char_simple(canvas, get_pin_font(), (char)('1' + i), ink,
                       cx + (DICE_CELL_SIZE - glyph_w) / 2, DICE_GRID_Y + 2);
    } else {
      draw_char_simple(canvas, get_title_font(), '<', ink, cx + 5,
                       DICE_GRID_Y + 3);
    }
  }

  p.color = 0xFF;
  p.x = DICE_LEFT;
  p.y = DICE_STATUS_Y;
  draw_string(canvas, get_body_font(), status, &p, DICE_BAR_W, 10);

  if (hold_permil > 0) {
    draw_box_simple(canvas, 0xCC, DICE_BAR_X, DICE_BAR_Y, DICE_BAR_W,
                    DICE_BAR_H);
    draw_box_simple(canvas, 0x00, DICE_BAR_X + 1, DICE_BAR_Y + 1,
                    DICE_BAR_W - 2, DICE_BAR_H - 2);
    uint16_t fill =
        (uint16_t)(((uint32_t)(DICE_BAR_W - 2) * hold_permil) / 1000);
    if (fill > 0) {
      draw_box_simple(canvas, 0xFF, DICE_BAR_X + 1, DICE_BAR_Y + 1, fill,
                      DICE_BAR_H - 2);
    }
  }

  display_refresh();
}

bool dice_input_collect(char *rolls, uint32_t target) {
  uint32_t count = 0;
  uint8_t position = 0;
  bool ret = false;
  bool redraw = true;
  uint16_t last_bar_permil = 0;
  char status[48];
  static CONFIDENTIAL uint8_t msg_tiny_buf[MSG_TINY_BFR_SZ];

#if DEBUG_LINK
  _Static_assert(sizeof(DebugLinkDecision) <= MSG_TINY_BFR_SZ,
                 "DebugLinkDecision must fit the tiny message buffer");
#endif

  if (target > DICE_MAX_ROLLS) {
    return false;
  }

  reset_msg_stack = false;

  dice_accept = false;
  dice_pressed = false;
  dice_committed = false;
  dice_press_start = 0;
  dice_release_time = 0;
  dice_have_release = false;
  dice_short_events = 0;
  dice_hold_events = 0;

  call_leaving_handler();

  snprintf(status, sizeof(status), _("PRESS next HOLD ok"));

#ifndef EMULATOR
  keepkey_button_set_on_press_handler(&dice_on_press, NULL);
  keepkey_button_set_on_release_handler(&dice_on_release, NULL);
#endif

  ButtonRequest br;
  memset(&br, 0, sizeof(br));
  br.has_code = true;
  br.code = ButtonRequestType_ButtonRequest_DiceRoll;
  msg_write(MessageType_MessageType_ButtonRequest, &br);

  while (count < target) {
    bool pressed;
    uint32_t held = 0;
    uint8_t shorts = 0;
    uint8_t holds;

    /* One critical section performs the whole read-classify-drain step, so
     * the in-flight hold below cannot also be classified by the release ISR
     * (and vice versa): whoever gets there first sets dice_committed. */
#ifndef EMULATOR
    svc_disable_interrupts();
#endif
    {
      uint32_t now = getSysTime();
      pressed = dice_pressed;
      if (pressed) {
        held = now - dice_press_start;
        if (!dice_committed && held >= DICE_HOLD_MS) {
          dice_committed = true;
          if (dice_hold_events < 8) {
            dice_hold_events++;
          }
        }
      }
      /* Queued short presses stay queued until a debounce window has passed
       * since the release that produced them, giving dice_on_press the
       * chance to retract a bounce-generated one before it is acted on.
       * Deliberately NOT conditioned on the button being up: a retraction
       * can only happen inside that window, so once it closes the count is
       * final. Waiting for the button to be released instead would let a
       * tap-then-hold commit the digit the tap was meant to move off of. */
      if (dice_have_release && now - dice_release_time >= DICE_DEBOUNCE_MS) {
        shorts = dice_short_events;
        dice_short_events = 0;
      }
      holds = dice_hold_events;
      dice_hold_events = 0;
    }
#ifndef EMULATOR
    svc_enable_interrupts();
#endif

    uint16_t tiny_msg = check_for_tiny_msg(msg_tiny_buf);
    switch (tiny_msg) {
      case MessageType_MessageType_ButtonAck:
        dice_accept = true; /* arms the button ISRs and debug injection */
        break;

      case MessageType_MessageType_Cancel:
      case MessageType_MessageType_Initialize:
        if (tiny_msg == MessageType_MessageType_Initialize) {
          reset_msg_stack = true;
        }
        goto dice_exit;

#if DEBUG_LINK
      case MessageType_MessageType_DebugLinkDecision: {
        const DebugLinkDecision *dld = (const DebugLinkDecision *)msg_tiny_buf;
        if (dice_accept && dld->has_input) {
          for (const char *c = dld->input; *c != '\0' && count < target; c++) {
            if (*c >= '1' && *c <= '6') {
              rolls[count++] = *c;
              snprintf(status, sizeof(status), _("Entered %c (%lu)"), *c,
                       (unsigned long)count);
            } else if (*c == 'u' && count > 0) {
              count--;
              snprintf(status, sizeof(status), _("Removed #%lu"),
                       (unsigned long)(count + 1));
            }
          }
          redraw = true;
        }
        break;
      }

      case MessageType_MessageType_DebugLinkGetState:
        call_msg_debug_link_get_state_handler(
            (DebugLinkGetState *)msg_tiny_buf);
        break;
#endif

      default:
        break;
    }

    if (shorts > 0) {
      position = (uint8_t)((position + shorts) % DICE_POSITIONS);
      redraw = true;
    }

    /* Commits arrive either from the in-flight check above or from a release
     * that completed inside the poll gap; both funnel through here, and
     * dice_committed guarantees at most one per press. */
    while (holds-- > 0 && count < target) {
      if (position < DICE_UNDO_POS) {
        rolls[count++] = (char)('1' + position);
        snprintf(status, sizeof(status), _("Entered %c (%lu)"),
                 (char)('1' + position), (unsigned long)count);
      } else if (count > 0) {
        count--;
        snprintf(status, sizeof(status), _("Removed #%lu"),
                 (unsigned long)(count + 1));
      } else {
        snprintf(status, sizeof(status), _("Nothing to undo"));
      }
      redraw = true;
    }

    uint16_t bar_permil = 0;
    if (pressed && held < DICE_HOLD_MS) {
      bar_permil = (uint16_t)((held * 1000) / DICE_HOLD_MS);
    } else if (pressed) {
      bar_permil = 1000; /* held past the threshold: keep the bar full */
    }

    /* Quantize the bar so idle passes stay refresh-free. */
    bar_permil = (uint16_t)(bar_permil - (bar_permil % 50));
    if (redraw || bar_permil != last_bar_permil) {
      dice_draw_screen(count, target, position, status, bar_permil);
      last_bar_permil = bar_permil;
      redraw = false;
    }

    animate();
    display_refresh();
  }

  ret = true;

dice_exit:
  dice_accept = false;
#ifndef EMULATOR
  keepkey_button_set_on_press_handler(NULL, NULL);
  keepkey_button_set_on_release_handler(NULL, NULL);
#endif
  memzero(status, sizeof(status));
  memzero(msg_tiny_buf, sizeof(msg_tiny_buf));
  return ret;
}
