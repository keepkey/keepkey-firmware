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

#include <stdbool.h>
#include <stdint.h>

#include "keepkey/board/keepkey_board.h"
#include "keepkey/board/draw.h"
#include "keepkey/board/layout.h"
#include "trezor/crypto/rand.h"

#include <string.h>
#include <stdlib.h>

#define MIN(A, B) ((A) > (B) ? (B) : (A))

static uint32_t *fire[64];
static uint32_t buffer[64 * 256];

static void firedemo(const uint8_t *eater, Canvas *canvas) {
    for (int i = 0; i < 256 * 64; ++i) {
        if (eater[i] && (random32() & 15) == 15)
            buffer[i] = abs(32768 + random32()) % 256;
    }

    for (int y = 0; y < 62; ++y) {
        for (int x = 1; x < 255; ++x) {
            fire[y][x] = ((fire[y+1][x-1] + fire[y+1][x] + fire[y+1][x+1] +
                                            fire[y+2][x]) * 32) / 129;
        }
    }

    for (int y = 0; y < 63; ++y) {
        for (int x = 0; x < 256; ++x) {
            canvas->buffer[y * 256 + x] = MIN(fire[y][x] * 3, 255);
        }
    }

    for (int i = 0; i < 256 * 64; ++i) {
        canvas->buffer[i] = eater[i] ? 255 : canvas->buffer[i];
    }

    canvas->dirty = true;
}

int main(void) {
    board_init();

    memset(buffer, 0, sizeof(buffer));
    for (int y = 0; y < 64; ++y)
        fire[y] = &buffer[y * 256];

    static uint8_t eater[64 * 256];
    memset(eater, 0, sizeof(eater));

    Canvas eater_canvas = {
        .buffer = &eater[0],
        .width = 256,
        .height = 64
    };

    DrawableParams sp;
    sp.x = 0;
    sp.y = 64 - font_height(get_body_font()) * 3;
    sp.color = 255;
    draw_string(&eater_canvas, get_title_font(),
                "Burn 3.00 BTC", &sp, 256,
                font_height(get_title_font()));

    sp.y = 64 - font_height(get_body_font());
    draw_string(&eater_canvas, get_title_font(),
                "1bitcoineateraddressdontsendf59kue", &sp, 256,
                font_height(get_title_font()));

    sp.x = 233;
    sp.y = 4;

    Canvas *canvas = display_canvas();
    for(;;) {
        firedemo(eater, canvas);
        draw_bitmap_mono_rle(canvas, get_confirm_icon_frame(), false);
        display_refresh();
    }

    return(0);
}
