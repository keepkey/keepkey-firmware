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

#include "variant.h"

#include "keepkey/board/keepkey_display.h"
#include "keepkey/board/layout.h"
#include "keepkey/firmware/app_layout.h"
#include "keepkey/firmware/fsm.h"
#include "keepkey/firmware/home_sm.h"
#include "keepkey/firmware/storage.h"

/* Track state of home screen */
static HomeState home_state = AT_HOME;

static uint32_t idle_time = 0;

static void layoutLockedState(void) {
  const Font* font = get_body_font();
  const char* state =
      (!storage_hasPin() || session_isPinCached()) ? "\x02" : "\x03";
  DrawableParams sp;
  sp.x = 2;
  sp.y = KEEPKEY_DISPLAY_HEIGHT - 1 * font_height(font) - 6;
  sp.color = 0x22;
  draw_string(layout_get_canvas(), font, state, &sp, KEEPKEY_DISPLAY_WIDTH,
              font_height(font));
}

/*
 * layoutHome() - Returns to home screen
 *
 * INPUT
 *     none
 * OUTPUT
 *     none
 */
void layoutHome(void) {
  switch (home_state) {
    case AWAY_FROM_HOME:
      layoutHomeForced();
      break;

    case SCREENSAVER:
    case AT_HOME:
    default:
      /* no action required */
      break;
  }

  layoutLockedState();
}

/*
 * layoutHomeForced() - Returns to home screen regardless of home state
 *
 * INPUT
 *     none
 * OUTPUT
 *     none
 */
void layoutHomeForced(void) {
  layout_home();
  layoutLockedState();
  reset_idle_time();
  home_state = AT_HOME;
}

/*
 * leave_home() - Leaves home screen
 *
 * INPUT
 *     none
 * OUTPUT
 *     none
 */
void leave_home(void) {
  switch (home_state) {
    case AT_HOME:
      layout_home_reversed();
      reset_idle_time();
      home_state = AWAY_FROM_HOME;
      break;

    case SCREENSAVER:
      home_state = AWAY_FROM_HOME;
      break;

    case AWAY_FROM_HOME:
    default:
      /* no action requires */
      break;
  }
}

/*
 * toggle_screensaver() - Toggles the screensaver based on idle time
 *
 * INPUT
 *     none
 * OUTPUT
 *     none
 */
void toggle_screensaver(void) {
  /* Auto-lock is a session boundary even while the device is waiting for the
   * host between streamed signing messages.  Confirmation handlers block the
   * main loop, so this check cannot interrupt a button hold; AWAY_FROM_HOME
   * here means firmware has returned to the main loop and is idle, and
   * note_host_activity() has cleared the timer for every frame the host sent,
   * so reaching the delay means the host really did stall. */
  if (home_state != SCREENSAVER && idle_time >= storage_getAutoLockDelayMs()) {
    /* signing_abort() and ethereum_signing_abort() draw the home screen, and
     * layoutHomeForced() resets the idle timer. Restore it, or the screensaver
     * drawn below is replaced by the home screen on the very next tick. */
    const uint32_t locked_at = idle_time;
    fsm_abort_workflows();
    session_clear(/*clear_pin=*/true);
    idle_time = locked_at;
    layout_screensaver();
    home_state = SCREENSAVER;
    return;
  }

  switch (home_state) {
    case AT_HOME:
      break;

    case SCREENSAVER:
      if (idle_time < storage_getAutoLockDelayMs()) {
        layout_home();
        layoutLockedState();
        home_state = AT_HOME;
      }

      break;

    case AWAY_FROM_HOME:
    default:
      /* no action requires */
      break;
  }
}

/*
 * increment_idle_time() - Increments idle time
 *
 * INPUT
 *     increment_ms - time to increment in ms
 * OUTPUT
 *     none
 */
void increment_idle_time(uint32_t increment_ms) { idle_time += increment_ms; }

/*
 * reset_idle_time() - Resets idle time
 *
 * INPUT
 *     none
 * OUTPUT
 *     none
 */
void reset_idle_time(void) { idle_time = 0; }

/*
 * note_host_activity() - Counts a received host frame as activity
 *
 * A streamed ceremony (recovery characters, TxAck, EntropyAck) can outlast the
 * auto-lock delay while the user is working, and nothing else resets the timer
 * once the device has left the home screen. Only AWAY_FROM_HOME is reset:
 * polling a device sitting at the home screen must never hold it unlocked.
 *
 * INPUT
 *     none
 * OUTPUT
 *     none
 */
void note_host_activity(void) {
  if (home_state == AWAY_FROM_HOME) {
    reset_idle_time();
  }
}

/*
 * home_get_state() - Current home-screen state, for tests
 *
 * INPUT
 *     none
 * OUTPUT
 *     the state toggle_screensaver() last settled on
 */
HomeState home_get_state(void) { return home_state; }
