file bin/firmware.keepkey.elf
set substitute-path /root/keepkey-firmware .
set substitute-path /root/libopencm3 ../libopencm3
target extended-remote localhost:3333
monitor reset halt
load
