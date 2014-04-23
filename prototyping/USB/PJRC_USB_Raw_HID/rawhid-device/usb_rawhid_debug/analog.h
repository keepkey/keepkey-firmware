#ifndef _analog_h_included__
#define _analog_h_included__

#include <stdint.h>

#if defined(__AVR_AT90USB162__)
#define analogRead(pin) (0)
#define analogReference(ref)
#else
int16_t analogRead(uint8_t pin);
extern uint8_t analog_reference_config_val;
#define analogReference(ref) (analog_reference_config_val = (ref) << 6)
#endif

#endif
