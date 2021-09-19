#!/bin/bash -e

KEEPKEY_FIRMWARE="$(dirname "$(dirname "$(dirname "$(dirname "$( cd "$(dirname "$0")" ; pwd -P )")")")")"
cd $KEEPKEY_FIRMWARE

docker build . -f Dockerfile.rust --build-arg CARGO_TARGET=thumbv7m-none-eabi
RUST_IMAGE_HASH="$(docker build . -f Dockerfile.rust --build-arg CARGO_TARGET=thumbv7m-none-eabi -q)"
docker run -t \
  -v $(pwd):/root/keepkey-firmware:z \
  "$RUST_IMAGE_HASH" /bin/sh -c "\
      cd /root/keepkey-firmware/keepkey-rs && \
      cargo build --target thumbv7m-none-eabi --release && \
      chown -R \`stat -c \"%u:%g\" /root/keepkey-firmware\` /root/keepkey-firmware/keepkey-rs"

IMAGETAG=kktech/firmware:v15
docker image inspect $IMAGETAG > /dev/null || docker pull $IMAGETAG

docker run -t \
  -v $(pwd):/root/keepkey-firmware:z \
  $IMAGETAG /bin/sh -c "\
      mkdir /root/build && cd /root/build && \
      cmake -C /root/keepkey-firmware/cmake/caches/device.cmake /root/keepkey-firmware \
        -DCMAKE_BUILD_TYPE=MinSizeRel \
        -DCMAKE_COLOR_MAKEFILE=ON && \
      make && \
      mkdir -p /root/keepkey-firmware/bin && \
      cp -r /root/build /root/keepkey-firmware/bin/ && \
      cp bin/*.bin /root/keepkey-firmware/bin/ && \
      cp bin/*.elf /root/keepkey-firmware/bin/ && \
      chown -R \`stat -c \"%u:%g\" /root/keepkey-firmware\` /root/keepkey-firmware/bin"
