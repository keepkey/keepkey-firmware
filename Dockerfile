FROM ubuntu:zesty

MAINTAINER tech@keepkey.com

# Install toolchain
RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -yq \
    build-essential git scons gcc-arm-none-eabi \
    python3-pip python-protobuf python3-protobuf protobuf-compiler \
    fabric exuberant-ctags wget && \
    rm -rf /var/lib/apt/lists/*

# Install protobuf/python3 support
RUN pip3 install protobuf3

# Install nanopb
WORKDIR /root
RUN git clone --branch nanopb-0.2.9.2 https://github.com/nanopb/nanopb/
WORKDIR /root/nanopb/generator/proto
RUN make

# Setup environment
ENV PATH /root/nanopb/generator:$PATH
