FROM ubuntu:14.04

MAINTAINER darin@keepkey.com

# Install toolchain
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -yq make git scons gcc-arm-none-eabi python-protobuf protobuf-compiler fabric exuberant-ctags wget

# Install nanopb
WORKDIR /root
RUN git clone --branch nanopb-0.2.9 https://code.google.com/p/nanopb/
WORKDIR /root/nanopb/generator/proto
RUN make

# Setup environment
ENV PATH /root/nanopb/generator:$PATH

# Copy context
ADD . /root/keepkey_firmware

# Build libopencm3
WORKDIR /root/keepkey_firmware/libopencm3
RUN make

# Set WORKDIR
WORKDIR /root/keepkey_firmware
