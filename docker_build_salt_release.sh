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

docker run -t -v $(pwd):/root/keepkey-firmware --rm $IMAGETAG /bin/sh -c "\
	cd /root/keepkey-firmware/libopencm3 && \
	make clean && \
	make && \
	cd /root/keepkey-firmware && \
	./b -mp -salt && \
	mkdir -p bin/release/salt && \
    mv build/arm-none-gnu-eabi/release/bin/*.bin bin/release/salt/ && \
    echo '*********************************************************************' && \
    echo '* KeepKey Application Fingerprint (SALT)                            *' && \
    echo '*********************************************************************' && \
    cat bin/release/salt/keepkey_main.bin | sha256sum"
fi