#! /bin/bash

KEEPKEY_FIRMWARE="$(dirname "$(dirname "$( cd "$(dirname "$0")" ; pwd -P )")")"
CONFIG_SCRIPTS="/usr/local/share/openocd/scripts/"

BIN_FILE=$KEEPKEY_FIRMWARE/bin/bootstrap.bin
openocd -s "$CONFIG_SCRIPTS" -f "$KEEPKEY_FIRMWARE/scripts/dev2/openocd/stm32f4x.cfg" -c "program $BIN_FILE 0x08000000 verify exit"
if [[ $? -ne 0 ]]; then
        echo $?
        echo "error in loading bootstrap"
        exit
fi
