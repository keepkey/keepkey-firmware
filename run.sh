#! /bin/bash

scons target=arm-none-gnu-eabi debug=1 --clean
scons target=arm-none-gnu-eabi debug=1

if [[ $? -ne 0 ]]; then
	echo $?
	exit
fi

ELF_FILE=/home/paulb/Projects/keepkey/build/arm-none-gnu-eabi/debug/keepkey_app/test_main.elf
HEX_FILE=/home/paulb/Projects/keepkey/build/arm-none-gnu-eabi/debug/keepkey_app/test_main.hex
MAP_FILE=/home/paulb/Projects/keepkey/build/arm-none-gnu-eabi/debug/keepkey_app/test_main.map

arm-none-eabi-objcopy -O ihex $ELF_FILE $HEX_FILE
if [[ $? -ne 0 ]]; then
	echo $?
	exit
fi

arm-none-eabi-objdump -dgSltG $ELF_FILE > $MAP_FILE
if [[ $? -ne 0 ]]; then
	echo $?
	exit
fi

openocd -s /usr/share/openocd/scripts -f interface/jlink.cfg -f board/stm3210e_eval.cfg -c "program $HEX_FILE verify reset"
if [[ $? -ne 0 ]]; then
	echo $?
	exit
fi

#openocd -s /usr/share/openocd/scripts -f interface/jlink.cfg -f target/stm32f1x.cfg -c "init" -c "halt" -c "reset halt"
