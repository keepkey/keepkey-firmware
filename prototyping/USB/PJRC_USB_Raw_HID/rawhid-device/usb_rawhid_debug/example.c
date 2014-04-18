/* Teensy RawHID example
 * http://www.pjrc.com/teensy/rawhid.html
 * Copyright (c) 2009 PJRC.COM, LLC
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 * 
 * The above description, website URL and copyright notice and this permission
 * notice shall be included in all copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

#include <avr/io.h>
#include <avr/pgmspace.h>
#include <avr/interrupt.h>
#include <util/delay.h>
#include "usb_rawhid_debug.h"
#include "print.h"
#include "analog.h"

#define CPU_PRESCALE(n)	(CLKPR = 0x80, CLKPR = (n))

volatile uint8_t do_output=0;
uint8_t buffer[64];

int main(void)
{
	int8_t r;
	uint8_t i;
	uint16_t val, count=0;

	// set for 16 MHz clock
	CPU_PRESCALE(0);

	// Initialize the USB, and then wait for the host to set configuration.
	// If the Teensy is powered without a PC connected to the USB port,
	// this will wait forever.
	usb_init();
	while (!usb_configured()) /* wait */ ;

	// Wait an extra second for the PC's operating system to load drivers
	// and do whatever it does to actually be ready for input
	_delay_ms(1000);

        // Configure timer 0 to generate a timer overflow interrupt every
        // 256*1024 clock cycles, or approx 61 Hz when using 16 MHz clock
        TCCR0A = 0x00;
        TCCR0B = 0x05;
        TIMSK0 = (1<<TOIE0);

	print("Begin rawhid example program\n");
	while (1) {
		// if received data, do something with it
		r = usb_rawhid_recv(buffer, 0);
		if (r > 0) {
			// output 4 bits to D0, D1, D2, D3 pins
			DDRD = 0x0F;
			PORTD = (PORTD & 0xF0) | (buffer[0] & 0x0F);
			// ignore the other 63.5 bytes....
			print("receive packet, buffer[0]=");
			phex(buffer[0]);
			print("\n");
		}
		// if time to send output, transmit something interesting
		if (do_output) {
			do_output = 0;
			// send a packet, first 2 bytes 0xABCD
			buffer[0] = 0xAB;
			buffer[1] = 0xCD;
 			// put A/D measurements into next 24 bytes
			for (i=0; i<12; i++) {
				val = analogRead(i);
				buffer[i * 2 + 2] = val >> 8;
				buffer[i * 2 + 3] = val & 255;
			}
			// most of the packet filled with zero
			for (i=26; i<62; i++) {
				buffer[i] = 0;
			}
			// put a count in the last 2 bytes
			buffer[62] = count >> 8;
			buffer[63] = count & 255;
			// send the packet
			usb_rawhid_send(buffer, 50);
			print("transmit packet ");
			phex16(count);
			print(", r=");
			phex(r);
			print("\n");
			count++;
		}
	}
}

// This interrupt routine is run approx 61 times per second.
ISR(TIMER0_OVF_vect)
{
	static uint8_t count=0;

	// set the do_output variable every 2 seconds
	if (++count > 122) {
		count = 0;
		do_output = 1;
	}
}



