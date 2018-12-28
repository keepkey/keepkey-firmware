FROM frolvlad/alpine-glibc:glibc-2.27

MAINTAINER tech@keepkey.com

RUN apk add --update --no-cache \
    bzip2-dev \
    ca-certificates \
    git \
    openssl \
    python \
    scons \
    tar \
    w3m \
    unzip \
    py-setuptools \
    make \
    cmake

# Install gcc-arm-none-eabi
WORKDIR /root
RUN wget https://developer.arm.com/-/media/Files/downloads/gnu-rm/7-2017q4/gcc-arm-none-eabi-7-2017-q4-major-linux.tar.bz2
RUN tar xvf gcc-arm-none-eabi-7-2017-q4-major-linux.tar.bz2
RUN cp -r gcc-arm-none-eabi-7-2017-q4-major/* /usr/local
RUN rm gcc-arm-none-eabi-7-2017-q4-major-linux.tar.bz2
RUN rm -rf gcc-arm-none-eabi-7-2017-q4-major

# Install protobuf-compiler v3.5.1
WORKDIR /root
RUN mkdir protoc3
RUN wget https://github.com/google/protobuf/releases/download/v3.5.1/protoc-3.5.1-linux-x86_64.zip
RUN unzip protoc-3.5.1-linux-x86_64.zip -d protoc3
RUN mv protoc3/bin/* /usr/local/bin
RUN mv protoc3/include/* /usr/local/include
RUN rm -rf protoc3

# Install protobuf/python3 support
WORKDIR /root
RUN wget https://github.com/google/protobuf/releases/download/v3.5.1/protobuf-python-3.5.1.zip
RUN mkdir protobuf-python
RUN unzip protobuf-python-3.5.1.zip -d protobuf-python

WORKDIR /root/protobuf-python/protobuf-3.5.1/python
RUN python setup.py install

# Install nanopb
WORKDIR /root
RUN git clone --branch nanopb-0.2.9.2 https://github.com/nanopb/nanopb/
WORKDIR /root/nanopb/generator/proto
RUN make

RUN rm -rf /root/protobuf-python

# Setup environment
ENV PATH /root/nanopb/generator:$PATH

# Build libopencm3
WORKDIR /root
RUN git clone -b docker-v8 https://github.com/keepkey/libopencm3.git libopencm3
WORKDIR /root/libopencm3
RUN make

RUN apk add --update --no-cache \
    clang \
    gcc \
    g++ \
    binutils
