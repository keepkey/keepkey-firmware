FROM ubuntu:zesty

MAINTAINER tech@keepkey.com

# Zesty has EOL'd
RUN sed -i.bak -r 's/(archive|security).ubuntu.com/old-releases.ubuntu.com/g' /etc/apt/sources.list

# Install toolchain
RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -yq \
    build-essential git scons gcc-arm-none-eabi \
    python3-pip python-protobuf python3-protobuf \
    fabric exuberant-ctags wget unzip && \
    rm -rf /var/lib/apt/lists/*

# Install protobuf-compiler v3.5.1
WORKDIR /root
RUN wget https://github.com/google/protobuf/releases/download/v3.5.1/protoc-3.5.1-linux-x86_64.zip
RUN unzip protoc-3.5.1-linux-x86_64.zip -d protoc3
RUN mv protoc3/bin/* /usr/local/bin
RUN mv protoc3/include/* /usr/local/include

# Install protobuf/python3 support
RUN pip3 install protobuf3

# Install nanopb
WORKDIR /root
RUN git clone --branch nanopb-0.2.9.2 https://github.com/nanopb/nanopb/
WORKDIR /root/nanopb/generator/proto
RUN make

# Setup environment
ENV PATH /root/nanopb/generator:$PATH
