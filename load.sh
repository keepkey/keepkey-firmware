#! /bin/bash

OBJCOPY=/opt/carbon/gcc-arm-none-eabi-4_8-2014q1/bin/arm-none-eabi-objcopy
OBJDUMP=/opt/carbon/gcc-arm-none-eabi-4_8-2014q1/bin/arm-none-eabi-objdump
BINDIR=~/src/keepkey/build/arm-none-gnu-eabi/debug/bin
BINNAME=keepkey_main
ELF_FILE=$BINDIR/keepkey_main.elf
HEX_FILE=$BINDIR/keepkey_main.hex
MAP_FILE=$bindir/keepkey_main.map


$OBJCOPY -O ihex $ELF_FILE $HEX_FILE
openocd -s /usr/share/openocd/scripts -f interface/jlink.cfg -f board/stm3210e_eval.cfg -c "program $HEX_FILE verify reset"
if [[ $? -ne 0 ]]; then
	echo $?
	exit
fi

