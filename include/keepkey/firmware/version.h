#ifndef INC_FIRMWARE_VERSION_H
#define INC_FIRMWARE_VERSION_H

#include <stdint.h>

uint8_t get_major_version(void);
uint8_t get_minor_version(void);
uint8_t get_patch_version(void);

const char* get_scm_revision(void);

#endif
