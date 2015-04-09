FROM ubuntu:14.04

MAINTAINER darin@keepkey.com

# Install toolchain
RUN apt-key adv --keyserver keyserver.ubuntu.com --recv-keys FE324A81C208C89497EFC6246D1D8367A3421AFB
RUN echo "deb http://ppa.launchpad.net/terry.guo/gcc-arm-embedded/ubuntu trusty main" >> /etc/apt/sources.list
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -yq build-essential git scons gcc-arm-none-eabi=4.9.3.2015q1-0trusty13 python-protobuf protobuf-compiler fabric exuberant-ctags wget

# Install nanopb
WORKDIR /root
RUN git clone --branch nanopb-0.2.9.2 https://code.google.com/p/nanopb/
WORKDIR /root/nanopb/generator/proto
RUN make

# Setup environment
ENV PATH /root/nanopb/generator:$PATH
