#!/bin/bash

echo "*********************************************************************"
echo "* You are about to build a release version of KeepKey firmware. The *"
echo "* resulting bootloader image will memory protect the flash on your  *"
echo "* device, so please use it with extreme care.                       *"
echo "*********************************************************************"
read -p "Are you sure you want to continue? " -n 1 -r
echo    # (optional) move to a new line
if [[ $REPLY =~ ^[Yy]$ ]]
then

IMAGETAG=keepkey/firmware

docker build -t $IMAGETAG .

docker run -t -v $(pwd):/root/kf --rm $IMAGETAG /bin/sh -c "\
  cd /root/ && \
  git clone https://github.com/keepkey/keepkey-firmware.git && \
	cd /root/keepkey-firmware/libopencm3 && \
	make clean && \
  make && \
	cd /root/keepkey-firmware && \
	./b -mp && \
  sha256sum build/arm-none-gnu-eabi/release/bin/keepkey_main.bin"

fi