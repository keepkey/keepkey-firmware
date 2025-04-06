#! /bin/bash -e

KEEPKEY_FIRMWARE="$(dirname "$( cd "$(dirname "$0")" ; pwd -P )")"

openocd -s /usr/share/openocd/scripts \
    -f "$KEEPKEY_FIRMWARE/scripts/openocd/openocd.cfg" \
    "$KEEPKEY_FIRMWARE/scripts/openocd/stm32f2x.cfg" \
    -c "init" -c "halt" -c "reset halt"

