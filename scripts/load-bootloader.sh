#! /bin/bash

BIN_FILE=./bin/bootloader.bin

openocd -s /usr/share/openocd/scripts -f interface/jlink.cfg -f ./scripts/openocd/stm32f2x.cfg  -c "program $BIN_FILE 0x08020000 verify exit"
if [[ $? -ne 0 ]]; then
        echo $?
        echo "error in loading bootloader"
        exit
fi
