ARG TARGETPLATFORM=amd64/alpine
FROM $TARGETPLATFORM

ARG ARCH="amd64"

RUN apk add gcompat

RUN apk add --update --no-cache \
    bzip2-dev \
    xz-dev \
    ca-certificates \
    git \
    openssl \
    scons \
    tar \
    w3m \
    unzip \
    make \
    cmake

RUN apk add --no-cache py3-setuptools

# RUN apk add py3-MarkupSafe py3-ecdsa py3-protobuf py3-mnemonic py3-requests py3-flask py3-pytest py3-semver
RUN apk add py3-ecdsa py3-requests py3-flask py3-pytest py3-semver
RUN apk add --update py3-protobuf
RUN apk add --update py3-build

# Apparently py3-mnemonic is not in the latest version of Alpine packages so get it another way
RUN apk add py3-pip
RUN pip install --break-system-packages --root-user-action ignore mnemonic

WORKDIR /root

# FOR ARM BUILD
# the lines similar to "arm-none-eabi-objcopy -w -R .gnu.warning.* libnosys.a"
# are a kludge that patches the system library so that useless system call warnings 
# aren't generated, e.g., 
#              warning: _close is not implemented and will always fail 
# during link. The warnings are harmless but there is no way to turn them off with a flag. 
# Note that the library is particular to the hardware and no floating point instructions. 
# 
# see https://stackoverflow.com/questions/73742774/gcc-arm-none-eabi-11-3-is-not-implemented-and-will-always-fail 
RUN if [[ "$ARCH" == "arm64v8" ]]; \
  then \
    apk add gcc-arm-none-eabi g++-arm-none-eabi newlib-arm-none-eabi && \
    cd /usr/arm-none-eabi/lib/thumb/v7e-m/nofp && \
    arm-none-eabi-objcopy -w -R .gnu.warning.* libnosys.a && \
    cd /usr/arm-none-eabi/lib/thumb/v7-m/nofp && \
    arm-none-eabi-objcopy -w -R .gnu.warning.* libnosys.a && \
    cd /root && \
    mkdir protoc3 && \
    wget https://github.com/protocolbuffers/protobuf/releases/download/v3.19.4/protoc-3.19.4-linux-aarch_64.zip && \
    unzip protoc-3.19.4-linux-aarch_64 -d protoc3 && \
    mv protoc3/bin/* /usr/local/bin && \
    mv protoc3/include/* /usr/local/include && \
    rm -rf protoc3 && \
    rm protoc-3.19.4-linux-aarch_64.zip; \
  fi

# FOR AMD64 BUILD
# Install gcc-arm-none-eabi and protobuf-compiler
RUN if [[ "$ARCH" == "amd64" ]]; \
  then \
    wget https://developer.arm.com/-/media/Files/downloads/gnu-rm/10-2020q4/gcc-arm-none-eabi-10-2020-q4-major-x86_64-linux.tar.bz2 && \
    tar xvf gcc-arm-none-eabi-10-2020-q4-major-x86_64-linux.tar.bz2 && \
    cp -r gcc-arm-none-eabi-10-2020-q4-major/* /usr/local && \
    rm gcc-arm-none-eabi-10-2020-q4-major-x86_64-linux.tar.bz2 && \
    rm -rf gcc-arm-none-eabi-10-2020-q4-major && \
    mkdir protoc3 && \
    wget https://github.com/google/protobuf/releases/download/v3.19.4/protoc-3.19.4-linux-x86_64.zip && \
    unzip protoc-3.19.4-linux-x86_64.zip -d protoc3 && \
    mv protoc3/bin/* /usr/local/bin && \
    mv protoc3/include/* /usr/local/include && \
    rm -rf protoc3; \
  fi

# Install protobuf/python3 support
WORKDIR /root
RUN wget https://github.com/protocolbuffers/protobuf/releases/download/v3.19.4/protobuf-python-3.19.4.zip
RUN mkdir protobuf-python
RUN unzip protobuf-python-3.19.4.zip -d protobuf-python

WORKDIR /root/protobuf-python/protobuf-3.19.4/python
RUN python setup.py install
WORKDIR /root
RUN rm protobuf-python-3.19.4.zip

# Install nanopb
WORKDIR /root
RUN git clone --branch v1.0.0 https://github.com/markrypt0/nanopb.git
WORKDIR /root/nanopb/generator/proto
RUN make

RUN rm -rf /root/protobuf-python

# Setup environment
ENV PATH=/root/nanopb/generator:$PATH

# Build libopencm3
WORKDIR /root
RUN git clone --branch devdebug-1 https://github.com/markrypt0/libopencm3.git
WORKDIR /root/libopencm3
ENV FP_FLAGS="-mfloat-abi=soft"
RUN make TARGETS='stm32/f2 stm32/f4'

RUN apk add --update --no-cache \
    clang \
    gcc \
    g++ \
    binutils
