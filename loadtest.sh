#! /bin/bash

BINDIR=./build/arm-none-gnu-eabi/debug/bin/
BINNAME=$1
ELF_FILE=$BINDIR/$BINNAME.elf

openocd -s /usr/share/openocd/scripts -f interface/jlink.cfg -f board/keepkey_board.cfg -c "program $ELF_FILE verify reset"
if [[ $? -ne 0 ]]; then
	echo $?
	exit
fi

