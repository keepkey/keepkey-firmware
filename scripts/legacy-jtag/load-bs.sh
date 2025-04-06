#! /bin/bash

openocd -s /usr/share/openocd/scripts \
    -f ./scripts/openocd/jlink.cfg  \
    -f ./scripts/openocd/openocd.cfg \
    -f ./scripts/openocd/stm32f2x.cfg \
    -c "reset halt" \
    -c "program ./bin/bootstrap.bin 0x08000000 verify exit"
if [[ $? -ne 0 ]]; then
        echo $?
        echo "error in loading bootstrap"
        exit
fi
