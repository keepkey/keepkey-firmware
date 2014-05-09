#! /bin/bash

./b -s -v -d

if [[ $? -ne 0 ]]; then
	echo $?
	exit
fi
OBJCOPY=/opt/carbon/gcc-arm-none-eabi-4_8-2014q1/bin/arm-none-eabi-objcopy
OBJDUMP=/opt/carbon/gcc-arm-none-eabi-4_8-2014q1/bin/arm-none-eabi-objdump
BINDIR=~/Projects/keepkey/build/arm-none-gnu-eabi/debug/bin
BINNAME=keepkey_main
ELF_FILE=$BINDIR/keepkey_main.elf
HEX_FILE=$BINDIR/keepkey_main.hex
MAP_FILE=$bindir/keepkey_main.map


$OBJCOPY -O ihex $ELF_FILE $HEX_FILE
if [[ $? -ne 0 ]]; then
	echo $?
	exit
fi

#$OBJDUMP -dgSltG $ELF_FILE > $MAP_FILE
#if [[ $? -ne 0 ]]; then
#	echo $?
#	exit
#fi

openocd -s /usr/share/openocd/scripts -f interface/jlink.cfg -f board/stm3210e_eval.cfg -c "program $HEX_FILE verify reset"
if [[ $? -ne 0 ]]; then
	echo $?
	exit
fi

#openocd -s /usr/share/openocd/scripts -f interface/jlink.cfg -f target/stm32f1x.cfg -c "init" -c "halt" -c "reset halt"

