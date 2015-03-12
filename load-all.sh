#! /bin/bash

BINDIR=./build/arm-none-gnu-eabi/debug/bin/
BSTRAPNAME=bootstrap_main
ELF_FILE=$BINDIR/$BSTRAPNAME.elf

openocd -s /usr/share/openocd/scripts -f interface/jlink.cfg -f board/keepkey_board.cfg -c "program $ELF_FILE verify"
if [[ $? -ne 0 ]]; then
        echo $?
        echo "error in loading bootstrap"
        exit
fi

BINDIR=./build/arm-none-gnu-eabi/debug/bin/
BINNAME=bootloader_main
ELF_FILE=$BINDIR/$BINNAME.elf

openocd -s /usr/share/openocd/scripts -f interface/jlink.cfg -f board/keepkey_board.cfg -c "program $ELF_FILE verify"
if [[ $? -ne 0 ]]; then
        echo $?
        echo "error in loading bootloader"
        exit
fi

INDIR=./build/arm-none-gnu-eabi/debug/bin/
BINAPPNAME=keepkey_main
ELF_FILE=$BINDIR/$BINAPPNAME.elf

openocd -s /usr/share/openocd/scripts -f interface/jlink.cfg -f board/keepkey_board.cfg -c "program $ELF_FILE verify reset"
if [[ $? -ne 0 ]]; then
        echo $?
        echo "error in loading application image"
        exit
fi
