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


#ifndef EMULATOR
#  include <libopencm3/stm32/rcc.h>
#  include <libopencm3/stm32/gpio.h>
#  include <libopencm3/stm32/usart.h>
#endif

#include "keepkey/board/timer.h"
#include "keepkey/board/keepkey_usart.h"

#include <stdio.h>
#include <string.h>


/*
 * put_console_char() - Display a character on serial debug port
 *
 * INPUT
 *     - c: ASCII character to debug port
 * OUTPUT
 *     true/false status
 */
#ifdef USART_DEBUG_ON
static bool put_console_char(int8_t c)
{
#ifndef EMULATOR
    int timeout_cnt = 100; /* allow 100msec for USART busy timeout*/
    bool ret_stat = false;

    do
    {
        /* check Tx register ready transmissiion */
        if(USART_SR(USART3_BASE) & USART_SR_TXE)
        {
            USART_DR(USART3_BASE) = c;
            ret_stat = true;
            break;
        }

        delay_ms(1);   /* 1 ms sampling */
    }
    while(--timeout_cnt);

    return(ret_stat);
#else
    return false;
#endif
}

/*
 * get_console_input() - Gets a character from serial port
 *
 * INPUT
 *     - read_char: load pointer with received char data
 * OUTPUT
 *     true/false update status
 */
static bool get_console_input(char *read_char)
{
#ifndef EMULATOR
    int timeout_cnt = 100; /* allow 100msec for USART busy timeout*/
    bool ret_stat = false;

    do
    {
        /* check Rx register ready for read*/
        if(USART_SR(USART3_BASE) & USART_SR_RXNE)
        {
            /* data received */
            *read_char = USART_DR(USART3_BASE);
            ret_stat = true;
            break;
        }

        delay_ms(1);   /* 1 ms sampling */
    }
    while(--timeout_cnt);

    return (ret_stat);
#else
    return false;
#endif
}


/*
 * display_debug_string() - Dump string to debug console
 *
 * INPUT
 *     - str: string to write to debug console
 * OUTPUT
 *     none
 */
static void display_debug_string(char *str)
{
    do
    {
        put_console_char(*str);
    }
    while(*(str++));
}

/*
 * usart_init() - Initialize USART Debug Port
 *
 * INPUT
 *     none
 * OUTPUT
 *     none
 */
void usart_init(void)
{
#ifndef EMULATOR
    /* Setup PB10 for USART-TX */
    gpio_mode_setup(GPIOB, GPIO_MODE_AF, GPIO_PUPD_NONE, GPIO10);
    gpio_set_output_options(GPIOB, GPIO_OTYPE_PP, GPIO_OSPEED_50MHZ, GPIO10);

    /* Setup PB11 for USART-RX */
    gpio_mode_setup(GPIOB, GPIO_MODE_AF, GPIO_PUPD_NONE, GPIO11);
    gpio_set_output_options(GPIOB, GPIO_OTYPE_PP, GPIO_OSPEED_50MHZ, GPIO11);

    /* Set PB10 and PB11 to USART3 alternate aunction */
    gpio_set_af(GPIOB, 7, GPIO10);
    gpio_set_af(GPIOB, 7, GPIO11);

    /*enable USART3 clock source */
    rcc_periph_clock_enable(RCC_USART3);

    /* disable USART3 before you are allow to write to USART3 registers */
    usart_disable(USART3_BASE)  ;

    /* set Word Length */
    usart_set_databits(USART3_BASE, 8);

    /* Set Transmit/Receive mode */
    usart_set_mode(USART3_BASE, USART_CR1_RE | USART_CR1_TE);

    usart_set_stopbits(USART3_BASE, USART_CR2_STOPBITS_1);

    /* disable parity */
    usart_set_parity(USART3_BASE, 0); /* USART_CR1_PCE */

    usart_set_flow_control(USART3_BASE, 0);

    usart_set_baudrate(USART3_BASE, 115200);

    /* enable USART */
    usart_enable(USART3_BASE);

    /* Note : RDR= Read data, TDR=Transmit data */
#endif
}

/*
 * dbg_print() - Print to debug console
 *
 * INPUT
 *     - str: string to write to debug console
 * OUTPUT
 *     none
 */
#ifndef EMULATOR
void dbg_print(const char *out_str, ...)
{
    char str[LARGE_DEBUG_BUF];
    va_list arg;

    va_start(arg, out_str);
    vsnprintf(str, LARGE_DEBUG_BUF, out_str, arg);

    if(strlen(str) + 1 <= LARGE_DEBUG_BUF)
    {
        display_debug_string(str);
    }
    else
    {
        snprintf(str, LARGE_DEBUG_BUF, "error: Debug string(%d) exceeds buffer size(%d)\n\r",
                 strlen(str) + 1, LARGE_DEBUG_BUF);
        display_debug_string(str);
    }
}
#endif

/*
 * dbg_trigger() - Scope trigger pulse for debugging
 *
 * INPUT
 *     - color: color of led to trigger
 * OUTPUT
 *     none
 */
void dbg_trigger(uint32_t color)
{
#ifndef EMULATOR
    switch(color)
    {
        case 1:
            led_func(CLR_RED_LED);
            led_func(SET_RED_LED);
            break;

        case 2:
            led_func(CLR_GREEN_LED);
            led_func(SET_GREEN_LED);
    }
#else
    switch (color)
    {
        case 1:
            printf("dbg trigger 1\n");
            break;
        case 2:
            printf("dbg trigger 2\n");
            break;
    }
#endif
}

/*
 * read_console() - Read debug console port for user input
 * 
 * INPUT
 *     none
 * OUTPUT
 *     character read from console
 */
char read_console(void)
{
#ifndef EMULATOR
    char char_read = 0, str_dbg[SMALL_DEBUG_BUF];

    while(1)
    {
        if(get_console_input(&char_read))
        {
            /* print for debug only */
            snprintf(str_dbg, SMALL_DEBUG_BUF, "%c\n\r", char_read);
            display_debug_string(str_dbg);
        }
    }

    return(char_read);
#else
    return '\0';
#endif
}
#else // USART_DEBUG_ON
#ifndef EMULATOR
void dbg_print(const char *pStr, ...) {(void)pStr;}
#endif
void usart_init(void) {}
#endif
