#! /bin/bash

KEEPKEY_FIRMWARE="$(dirname "$(dirname "$( cd "$(dirname "$0")" ; pwd -P )")")"
CONFIG_SCRIPTS="/usr/local/share/openocd/scripts/"

BIN_FILE=$KEEPKEY_FIRMWARE/bin/firmware.keepkey.elf
openocd -s "$CONFIG_SCRIPTS" -f "$KEEPKEY_FIRMWARE/scripts/dev2/openocd/stm32f4x.cfg" -c "init" -c "reset init" -c "program $BIN_FILE verify reset 0x08080000"
if [[ $? -ne 0 ]]; then
        echo $?
        echo "error in loading application image"
        exit
fi
