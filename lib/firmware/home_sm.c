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
#include "keepkey/firmware/home_sm.h"
#include "keepkey/firmware/storage.h"

/* Track state of home screen */
static HomeState home_state = AT_HOME;

static uint32_t idle_time = 0;

static void layoutLockedState(void) {
  const Font *font = get_body_font();
  const char *state =
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
  switch (home_state) {
    case AT_HOME:
      if (idle_time >= storage_getAutoLockDelayMs()) {
        session_clear(/*clear_pin=*/true);
        layout_screensaver();
        home_state = SCREENSAVER;
      }

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
