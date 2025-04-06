#! /bin/bash

BIN_FILE=./bin/firmware.keepkey.bin
openocd -s /usr/share/openocd/scripts -f interface/jlink.cfg -f ./scripts/openocd/stm32f2x.cfg -c "program $BIN_FILE 0x08080000 verify reset"
if [[ $? -ne 0 ]]; then
        echo $?
        echo "error in loading application image"
        exit
fi
