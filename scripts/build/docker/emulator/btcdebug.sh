#!/bin/bash -e

KEEPKEY_FIRMWARE="$(dirname "$(dirname "$(dirname "$(dirname "$( cd "$(dirname "$0")" ; pwd -P )")")")")"
cd $KEEPKEY_FIRMWARE

IMAGETAG=kktech/firmware:v15

docker pull $IMAGETAG

docker run -t \
  -v $(pwd):/root/keepkey-firmware:z \
  $IMAGETAG /bin/sh -c "\
      rm -rf /root/keepkey-firmware/build && \
      mkdir /root/build && cd /root/build && \
      cmake -C /root/keepkey-firmware/cmake/caches/emulator.cmake /root/keepkey-firmware \
        -DCMAKE_C_COMPILER=clang \
        -DCMAKE_CXX_COMPILER=clang++ \
        -DCOIN_SUPPORT=BTC \
        -DCMAKE_BUILD_TYPE=Debug \
        -DCMAKE_COLOR_MAKEFILE=ON &&\
      make all && \
      (make xunit || true) && \
      cp -r /root/build /root/keepkey-firmware/build && \
      chown -R \`stat -c \"%u:%g\" /root/keepkey-firmware\` /root/keepkey-firmware/build"
