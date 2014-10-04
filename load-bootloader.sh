#! /bin/bash

BINDIR=./build/arm-none-gnu-eabi/debug/bin/
BINNAME=bootloader_main
ELF_FILE=$BINDIR/$BINNAME.elf

openocd -s /usr/share/openocd/scripts -f interface/jlink.cfg -f board/keepkey_board.cfg -c "program $ELF_FILE verify"
if [[ $? -ne 0 ]]; then
	echo $?
	exit
fi

