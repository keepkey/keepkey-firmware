#! /bin/bash
openocd -s /usr/share/openocd/scripts -f interface/jlink.cfg -f target/stm32f2x.cfg -c "init" -c "halt" -c "reset halt"

