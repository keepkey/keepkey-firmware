#!/bin/bash

IMAGETAG=kktech/firmware:v3

docker pull $IMAGETAG

docker run -t \
  -v $(pwd):/root/keepkey-firmware \
  -v $(pwd)/../device-protocol:/root/device-protocol $IMAGETAG /bin/sh -c "\
	cd /root/keepkey-firmware/libopencm3 && \
	make clean && \
    make && \
	cd /root/keepkey-firmware && \
	./b -d -dl && \
	mkdir -p bin/debug/keepkey && \
    mv build/arm-none-gnu-eabi/debug/bin/*.bin bin/debug/keepkey/"
