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
#include "keepkey/board/messages.h"
#include "keepkey/firmware/app_layout.h"
#include "keepkey/firmware/fsm.h"
#include "keepkey/firmware/home_sm.h"
#include "keepkey/firmware/storage.h"

/* Track state of home screen */
static HomeState home_state = AT_HOME;

/* Time since the user last pressed the button or entered a correct PIN. */
static uint32_t idle_time = 0;
/* Time since a workflow last accepted validated progress. */
static uint32_t progress_age = UINT32_MAX;
/* home_clock_ms() when both ages were last brought up to date. */
static uint32_t idle_clock = 0;

/* Weak only so unit tests can drive the clock without the 1 ms tick. */
__attribute__((weak)) uint32_t home_clock_ms(void) { return getSysTime(); }

static uint32_t saturating_add(uint32_t a, uint32_t b) {
  return (b > UINT32_MAX - a) ? UINT32_MAX : a + b;
}

/* Count real elapsed time, including time spent nested in a long wait (a U2F
 * frame, a PIN or confirm prompt) that never returns to the main loop. The
 * unsigned difference survives the ms counter's ~49.7-day wrap as long as
 * samples are taken less than that far apart. */
static void update_idle_time(void) {
  /* The button ISR runs this too. Read the last sample before the clock: an
   * ISR that lands between the two reads then only makes `now` later, so the
   * difference cannot wrap and saturate both ages. */
  const uint32_t last = idle_clock;
  const uint32_t now = home_clock_ms();
  increment_idle_time(now - last);
  idle_clock = now;
  drop_workflow_progress_if_idle();
}

/* Progress defers the lock only for the workflow that made it. Once none
 * runs (it completed or was aborted), forget it, so a workflow started
 * afterwards that never notes progress itself inherits no deferral. An armed
 * ceremony keeps its own progress when only the signers are aborted. */
void drop_workflow_progress_if_idle(void) {
  if (!fsm_workflowInProgress()) progress_age = UINT32_MAX;
}

/* Called from every nested USB wait so that no stretch between samples
 * approaches the counter's wrap. Throttled to keep the read-modify-write that
 * the button ISR can race no more frequent than the main loop's tick. */
void keepkey_idle_clock_sample(void) {
  if (home_clock_ms() - idle_clock >= 1000) update_idle_time();
}

void keepkey_user_activity(void) { reset_idle_time(); }

/* A workflow that is still accepting validated progress may finish after the
 * deadline: a large transaction can stream previous transactions long after
 * the user's last press. Deferring never renews idle_time, so the moment the
 * workflow ends, stalls for a full delay, or is aborted by any other request,
 * the lock is due. */
static bool lock_deferred(void) {
  return progress_age < storage_getAutoLockDelayMs() &&
         fsm_workflowInProgress();
}

bool auto_lock_if_due(void) {
  update_idle_time();
  if (home_state == SCREENSAVER || idle_time < storage_getAutoLockDelayMs() ||
      lock_deferred()) {
    return false;
  }
  /* Aborts may draw the home screen, so finish them before drawing the
   * screensaver, and keep the lock time so nothing they do counts as
   * activity that would replace the screensaver on the next tick. */
  const uint32_t locked_at = idle_time;
  fsm_abort_workflows();
  session_clear(/*clear_pin=*/true);
  idle_time = locked_at;
  layout_screensaver();
  home_state = SCREENSAVER;
  return true;
}

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
   * host between streamed signing messages. Confirmation handlers block the
   * main loop, so this check cannot interrupt a button hold. Only the user
   * (a button press or a correct PIN) renews the deadline; host traffic,
   * including validated workflow progress, can at most defer it while that
   * workflow runs. */
  if (auto_lock_if_due()) return;

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
 * increment_idle_time() - Charges elapsed time to the idle deadline and to
 * the age of the last workflow progress alike
 *
 * Only update_idle_time() and unit tests call this; no production path
 * charges idle time except from the clock.
 *
 * INPUT
 *     increment_ms - time to increment in ms
 * OUTPUT
 *     none
 */
void increment_idle_time(uint32_t increment_ms) {
  /* Saturate: a wrap after ~49.7 days idle would read as fresh activity and
   * wake the locked screen. Only reset_idle_time() may lower it. */
  idle_time = saturating_add(idle_time, increment_ms);
  progress_age = saturating_add(progress_age, increment_ms);
}

/*
 * reset_idle_time() - Resets idle time
 *
 * INPUT
 *     none
 * OUTPUT
 *     none
 */
void reset_idle_time(void) {
  update_idle_time(); /* age progress_age up to now first */
  idle_time = 0;
}

/*
 * Record that a workflow accepted a signing stage or a real recovery edit, or
 * accepted entropy for an armed reset. Callers must validate both the session
 * and its payload first; receiving/decoding a host packet alone is never
 * progress. This is host-driven, so it never renews the deadline: it only
 * keeps the running workflow from being locked mid-flow. A completed lock
 * cannot be undone by this hook.
 */
void note_workflow_progress(void) {
  if (home_state != SCREENSAVER) {
    update_idle_time();
    progress_age = 0;
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
