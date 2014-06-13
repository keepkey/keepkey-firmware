#include <stdlib.h>

#include <libopencm3/stm32/rcc.h>
#include <libopencm3/stm32/gpio.h>

#include "keepkey_led.h"

void led_init(void)
{
    rcc_periph_clock_enable(LED_GPIO_RCC);
    gpio_mode_setup(LED_GPIO_PORT, 
                    GPIO_MODE_OUTPUT, 
                    GPIO_PUPD_NONE, 
                    LED_GPIO_RED | LED_GPIO_GREEN);


    gpio_clear(LED_GPIO_PORT, LED_GPIO_RED);
    gpio_clear(LED_GPIO_PORT, LED_GPIO_GREEN);
}

void led_green(bool state)
{
    if(state)
    {
        gpio_clear(LED_GPIO_PORT, LED_GPIO_GREEN);
    } else {
        gpio_set(LED_GPIO_PORT, LED_GPIO_GREEN);
    }
}

void led_red(bool state)
{
    if(state)
    {
        gpio_clear(LED_GPIO_PORT, LED_GPIO_RED);
    } else {
        gpio_set(LED_GPIO_PORT, LED_GPIO_RED);
    }
}


