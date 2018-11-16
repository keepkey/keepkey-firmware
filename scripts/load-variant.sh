#! /bin/bash

BIN_FILE=./bin/variant.fox.bin
openocd -s /usr/share/openocd/scripts -f interface/jlink.cfg -f ./scripts/openocd/stm32f2x.cfg  -c "program $BIN_FILE 0x08010000 verify exit"
if [[ $? -ne 0 ]]; then
        echo $?
        echo "error in loading variant"
        exit
fi
