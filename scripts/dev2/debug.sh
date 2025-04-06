#! /bin/bash -e

KEEPKEY_FIRMWARE="$(dirname "$( cd "$(dirname "$0")" ; pwd -P )")"
CONFIG_SCRIPTS="/usr/local/share/openocd/scripts/"

openocd -s "$CONFIG_SCRIPTS" -f "$KEEPKEY_FIRMWARE/dev2/openocd/stm32f4x.cfg" -c "init" -c "halt" -c "reset halt"

