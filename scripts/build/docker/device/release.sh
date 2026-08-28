#!/bin/bash -e

KEEPKEY_FIRMWARE="$(dirname "$(dirname "$(dirname "$(dirname "$( cd "$(dirname "$0")" ; pwd -P )")")")")"
cd $KEEPKEY_FIRMWARE

IMAGETAG=kktech/firmware@sha256:7438e53933d47d53157ed6d96d864cb208597e62dce26235ace09d1063427fa2

docker image inspect $IMAGETAG > /dev/null || docker pull $IMAGETAG

# Extra cmake flags pass straight through. The only alternate release product
# is bitcoin-only: ./release.sh -DKK_BITCOIN_ONLY=ON
EXTRA_CMAKE_FLAGS="$*"

docker run -t \
  -v $(pwd):/root/keepkey-firmware:z \
  $IMAGETAG /bin/sh -c "\
      mkdir /root/build && cd /root/build && \
      cmake -C /root/keepkey-firmware/cmake/caches/device.cmake /root/keepkey-firmware \
        -DCMAKE_BUILD_TYPE=MinSizeRel \
        -DCMAKE_COLOR_MAKEFILE=ON \
        ${EXTRA_CMAKE_FLAGS} &&\
      make && \
      mkdir -p /root/keepkey-firmware/bin && \
      cp -r /root/build /root/keepkey-firmware/bin/ && \
      cp bin/*.bin /root/keepkey-firmware/bin/ && \
      cp bin/*.elf /root/keepkey-firmware/bin/ && \
      chown -R \`stat -c \"%u:%g\" /root/keepkey-firmware\` /root/keepkey-firmware/bin"
