FROM frolvlad/alpine-glibc:glibc-2.27

RUN apk add --no-cache python3 py3-pip
RUN apk add --update --no-cache \
    bzip2-dev \
    ca-certificates \
    git \
    openssl \
    scons \
    tar \
    w3m \
    unzip \
    make \
    cmake

RUN pip3 install \
    requests \
    flask

# Install gcc-arm-none-eabi
WORKDIR /root
RUN wget https://developer.arm.com/-/media/Files/downloads/gnu-rm/10-2020q4/gcc-arm-none-eabi-10-2020-q4-major-x86_64-linux.tar.bz2
RUN tar xvf gcc-arm-none-eabi-10-2020-q4-major-x86_64-linux.tar.bz2
RUN cp -r gcc-arm-none-eabi-10-2020-q4-major/* /usr/local
RUN rm gcc-arm-none-eabi-10-2020-q4-major-x86_64-linux.tar.bz2
RUN rm -rf gcc-arm-none-eabi-10-2020-q4-major

# Build libopencm3
WORKDIR /root
RUN git clone -b docker-v9 https://github.com/keepkey/libopencm3.git libopencm3
WORKDIR /root/libopencm3
RUN make

RUN apk add --update --no-cache \
    clang \
    gcc \
    g++ \
    binutils
