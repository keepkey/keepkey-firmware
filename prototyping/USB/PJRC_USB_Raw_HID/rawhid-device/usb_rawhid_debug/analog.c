// Simple analog to digitial conversion, similar to Wiring/Arduino

#include <avr/io.h>
#include <avr/pgmspace.h>

#include "analog.h"


#if defined(__AVR_ATmega32U4__)

uint8_t analog_reference_config_val = 0x40;

static const uint8_t PROGMEM adc_mapping[] = {
        0, 1, 4, 5, 6, 7, 13, 12, 11, 10, 9, 8
};

int analogRead(uint8_t pin)
{
        uint8_t low, adc;

        if (pin >= 12) return 0;
        adc = pgm_read_byte(adc_mapping + pin);
        if (adc < 8) {
                DIDR0 |= (1 << adc);
                ADCSRB = 0;
                ADMUX = analog_reference_config_val | adc;
        } else {
                adc -= 8;
                DIDR2 |= (1 << adc);
                ADCSRB = (1<<MUX5);
                ADMUX = analog_reference_config_val | adc;
        }
	ADCSRA = (1<<ADSC)|(1<<ADEN)|(1<<ADPS2)|(1<<ADPS1)|(1<<ADPS0);
        while (ADCSRA & (1<<ADSC)) ;
        low = ADCL;
        return (ADCH << 8) | low;
}

#elif defined(__AVR_AT90USB646__) || defined(__AVR_AT90USB1286__)

uint8_t analog_reference_config_val = 0x40;

int analogRead(uint8_t pin)
{
        uint8_t low;

	if (pin >= 8) return 0;
        DIDR0 |= (1 << pin);
        ADMUX = analog_reference_config_val | pin;
	ADCSRA = (1<<ADSC)|(1<<ADEN)|(1<<ADPS2)|(1<<ADPS1)|(1<<ADPS0);
        while (ADCSRA & (1<<ADSC)) ;
        low = ADCL;
        return (ADCH << 8) | low;
}

#endif

