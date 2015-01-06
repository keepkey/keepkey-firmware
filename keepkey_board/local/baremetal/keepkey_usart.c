/* START KEEPKEY LICENSE */
/*
 * This file is part of the KeepKey project.
 *
 * Copyright (C) 2014 KeepKey LLC
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
 *
 */
/* END KEEPKEY LICENSE */

#include <libopencm3/stm32/rcc.h>
#include <libopencm3/stm32/gpio.h>
#include <libopencm3/stm32/usart.h>
#include <timer.h>
#include <keepkey_usart.h>
#include <string.h>

#ifdef DEBUG_ON  /* Enable serial port only for debug version */
/*
 * usart_init () - Initialize USART Debug Port 
 *
 * INPUT - 
 *      none
 * OUTPUT - 
 *      none 
 */
void usart_init(void)  
{
    /* Setup PB10 for USART-TX */
    gpio_mode_setup( GPIOB, GPIO_MODE_AF, GPIO_PUPD_NONE, GPIO10 );
    gpio_set_output_options(GPIOB, GPIO_OTYPE_PP, GPIO_OSPEED_50MHZ, GPIO10);

    /* Setup PB11 for USART-RX */
    gpio_mode_setup(GPIOB, GPIO_MODE_AF, GPIO_PUPD_NONE, GPIO11 );
    gpio_set_output_options(GPIOB, GPIO_OTYPE_PP, GPIO_OSPEED_50MHZ, GPIO11 );

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
}

/********************************************************************
 * put_console_char - Display a character on serial debug port
 *
 * input - ASCII character to debug port
 * output - send to debug port  
 ********************************************************************/

static bool put_console_char(int8_t nCharVal)
{
    int timeout_cnt = 100; /* allow 100msec for USART busy timeout*/
    bool ret_stat = false;

    do
    {
        /* check Tx register ready transmissiion */
        if(USART_SR(USART3_BASE) & USART_SR_TXE)
        {
            USART_DR(USART3_BASE) = nCharVal;
            ret_stat = true;
            break;
        }
        delay(1);   /* 1msec sampling */
    }while(--timeout_cnt);
    return(ret_stat);
}

/********************************************************************
 * get_console_input - Display a character on serial port
 *
 * Input - char pointer
 * Output - 
 *      - load pointer with received char data
 *      - update status 
 ********************************************************************/
static bool get_console_input(char *read_char)
{
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
        delay(1);   /* 1msec sampling */
    }while(--timeout_cnt);
    return (ret_stat);
}

/********************************************************************
 * display_debug_string - Dump string to debug console
 *
 * Input - pointer to string
 * Output- send string to debug port  
 ********************************************************************/
static void display_debug_string(char *pStr)
{
    do
    {
        put_console_char(*(pStr));
    }while (*(pStr++));
}

/********************************************************************
 * dbg_print - print to debug console 
 *
 * Input - content to print
 * Output- send to debug port  
 ********************************************************************/
bool dbg_print(char *pStr, ...)
{
    bool ret_stat = true;
    char str[DBG_BFR_SIZE];
    va_list arg;

    va_start(arg, pStr);
    vsprintf(str, pStr, arg);
    if(strlen(str)+1 <= DBG_BFR_SIZE)
    {
        display_debug_string(str);
    }
    else
    {
        sprintf(str,"error: Debug string(%d) exceeds buffer size(%d)\n\r", strlen(str)+1, DBG_BFR_SIZE );
        display_debug_string(str);
        ret_stat = false;
    }
    return(ret_stat);
}

/*
 * read_console - Read debug console port for user input 
 *                (Example for how to implement USART read )
 *
 *
 * Input - none 
 * Output- send to debug port  
 */
char read_console(void)
{
    int timeout_cnt = 100; /* allow 100msec for USART busy timeout*/
    char char_read = 0, str_dbg[30];

    while(1)
    {
        if(get_console_input(&char_read))
        {
            /* print for debug only */
            sprintf(str_dbg, "%c\n\r", char_read);
            display_debug_string(str_dbg); 
        }
    }
    return(char_read);
}
#else
bool dbg_print(char *pStr, ...){}
void usart_init(void){}
#endif




