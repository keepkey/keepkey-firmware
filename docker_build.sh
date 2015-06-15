#!/bin/bash

IMAGETAG=keepkey/firmware

docker build -t $IMAGETAG .

docker run -t -v $(pwd):/root/keepkey-firmware --rm $IMAGETAG /bin/sh -c "\
	cd /root/keepkey-firmware/libopencm3 && \
	make clean && \
  make && \
	cd /root/keepkey-firmware && \
	./b -d"
