FROM ubuntu:14.04

MAINTAINER darin@keepkey.com

# Install toolchain
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -yq build-essential git scons gcc-arm-none-eabi python-protobuf protobuf-compiler fabric exuberant-ctags wget

# Install nanopb
WORKDIR /root
RUN git clone --branch nanopb-0.2.9.2 https://github.com/nanopb/nanopb/
WORKDIR /root/nanopb/generator/proto
RUN make

# Setup environment
ENV PATH /root/nanopb/generator:$PATH
