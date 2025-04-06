#!/bin/bash -e

KEEPKEY_FIRMWARE="$(dirname "$(dirname "$(dirname "$(dirname "$( cd "$(dirname "$0")" ; pwd -P )")")")")"
cd $KEEPKEY_FIRMWARE

IMAGETAG=kkfirmware:v16

docker run -t \
  -v $(pwd):/root/keepkey-firmware:z \
  $IMAGETAG /bin/sh -c "\
      mkdir /root/build && cd /root/build && \
      cmake -C /root/keepkey-firmware/cmake/caches/devdevice.cmake /root/keepkey-firmware \
        -DCMAKE_BUILD_TYPE=Debug \
        -DKK_DEBUG_LINK=ON \
        -DVARIANTS=NoObsoleteVariants \
        -DDEVDEBUG=true \
        -DTWODISP=true \
        -DCMAKE_COLOR_MAKEFILE=ON &&\
      make && \
      mkdir -p /root/keepkey-firmware/bin && \
      cp -r /root/build /root/keepkey-firmware/bin/ && \
      cp bin/*.bin /root/keepkey-firmware/bin/ && \
      cp bin/*.elf /root/keepkey-firmware/bin/ && \
      chown -R \`stat -c \"%u:%g\" /root/keepkey-firmware\` /root/keepkey-firmware/bin"
