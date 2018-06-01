#! /bin/bash

BIN_FILE=./bin/bootstrap.bin
openocd -s /usr/share/openocd/scripts -f interface/jlink.cfg -f ./scripts/openocd/openocd.cfg -c "program $BIN_FILE 0x08000000 verify exit"
if [[ $? -ne 0 ]]; then
        echo $?
        echo "error in loading bootstrap"
        exit
fi

BIN_FILE=./bin/bootloader.bin
openocd -s /usr/share/openocd/scripts -f interface/jlink.cfg -f ./scripts/openocd/stm32f2x.cfg  -c "program $BIN_FILE 0x08020000 verify exit"
if [[ $? -ne 0 ]]; then
        echo $?
        echo "error in loading bootloader"
        exit
fi

BIN_FILE=./bin/firmware.keepkey.bin
openocd -s /usr/share/openocd/scripts -f interface/jlink.cfg -f ./scripts/openocd/stm32f2x.cfg -c "program $BIN_FILE 0x08080000 verify reset"
if [[ $? -ne 0 ]]; then
        echo $?
        echo "error in loading application image"
        exit
fi
