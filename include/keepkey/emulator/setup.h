#ifndef KEEPKEY_EMULATOR_SETUP_H
#define KEEPKEY_EMULATOR_SETUP_H

void setup(void);
void setup_urandom_only(void);  /* For libkkemu: init RNG without flash mmap */

#endif
