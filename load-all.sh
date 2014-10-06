#! /bin/bash

# 
#  this is a combination of both load.sh and load-bootloader.sh and using the open OCD sw
#                                                          ...Keepkey
BINDIR=./build/arm-none-gnu-eabi/debug/bin/
BINNAME=bootloader_main
ELF_FILE=$BINDIR/$BINNAME.elf

openocd -s /usr/share/openocd/scripts -f interface/jlink.cfg -f board/keepkey_board.cfg -c "program $ELF_FILE verify"
if [[ $? -ne 0 ]]; then
	echo $?
        echo "error in bootloading"
	exit
fi

INDIR=./build/arm-none-gnu-eabi/debug/bin/
BINAPPNAME=keepkey_main
ELF_FILE=$BINDIR/$BINAPPNAME.elf

openocd -s /usr/share/openocd/scripts -f interface/jlink.cfg -f board/keepkey_board.cfg -c "program $ELF_FILE verify"
if [[ $? -ne 0 ]]; then
	echo $?
        echo "error in loading application image"
	exit
fi
