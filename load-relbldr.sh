#! /bin/bash

RELDIR=/var/lib/jenkins/workspace/Release_dir/Bootloader/
BINNAME=$1
ELF_FILE=$RELDIR/$BINNAME.elf

openocd -s /usr/share/openocd/scripts -f interface/jlink.cfg -f board/keepkey_board.cfg -c "program $ELF_FILE verify reset"
if [[ $? -ne 0 ]]; then
        echo $?
        exit
fi

