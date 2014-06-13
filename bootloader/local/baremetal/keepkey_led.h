#ifndef KEEPKEY_LED_H
#define KEEPKEY_LED_H

#include <stdlib.h>
#include <libopencm3/stm32/rcc.h>
#include <libopencm3/stm32/gpio.h>


static const uint32_t LED_GPIO_PORT = GPIOC;
static const uint32_t LED_GPIO_RCC = RCC_GPIOC;
static const uint16_t LED_GPIO_GREEN  = GPIO14;
static const uint16_t LED_GPIO_RED  = GPIO15;

/**
 * Initialze the KeepKey board LEDs.
 */
void led_init(void);

/**
 * Set the green LED on/off.
 *
 * @param state - true = on, false = off.
 */
void led_green(bool state);

/**
 * Set the red LED on/off.
 *
 * @param state - true = on, false = off.
 */
void led_red(bool state);

#endif
