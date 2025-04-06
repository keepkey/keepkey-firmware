#! /bin/bash

BIN_FILE=./bin/bootstrap.bin
openocd -s /usr/share/openocd/scripts -f interface/jlink.cfg -f ./scripts/openocd/openocd.cfg -c "program $BIN_FILE 0x08000000 verify exit"
if [[ $? -ne 0 ]]; then
        echo $?
        echo "error in loading bootstrap"
        exit
fi
