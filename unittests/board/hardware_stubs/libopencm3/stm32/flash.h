/* Only hw_entropy_probe.c sees these register substitutes. */
#ifndef HW_ENTROPY_TEST_FLASH_H
#define HW_ENTROPY_TEST_FLASH_H
#define FLASH_SR 0u
#define FLASH_SR_PGAERR 1u
#define FLASH_SR_PGPERR 2u
#define FLASH_SR_PGSERR 4u
#define FLASH_SR_WRPERR 8u
#endif
