#! /bin/bash
openocd -s /usr/share/openocd/scripts -f interface/jlink.cfg  -f board/keepkey_board.cfg -c "init" -c "halt" -c "reset halt"

