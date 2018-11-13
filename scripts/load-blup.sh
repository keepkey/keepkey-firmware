#! /bin/bash

BIN_FILE=./bin/blupdater.bin
openocd -s /usr/share/openocd/scripts -f ./scripts/openocd/jlink.cfg -f ./scripts/openocd/stm32f2x.cfg -c "program $BIN_FILE 0x08060000 verify reset"
if [[ $? -ne 0 ]]; then
        echo $?
        echo "error in loading application image"
        exit
fi
