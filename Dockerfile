FROM frolvlad/alpine-glibc:glibc-2.27

RUN apk add --update --no-cache \
    gcompat \
    python3 \
    py3-pip \
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
COPY armtools.sha256sum ./
RUN sha256sum -c armtools.sha256sum
RUN tar xvf gcc-arm-none-eabi-10-2020-q4-major-x86_64-linux.tar.bz2
RUN cp -r gcc-arm-none-eabi-10-2020-q4-major/* /usr/local
RUN rm gcc-arm-none-eabi-10-2020-q4-major-x86_64-linux.tar.bz2
RUN rm -rf gcc-arm-none-eabi-10-2020-q4-major

RUN ln -s /usr/bin/python3 /usr/bin/python

# Build libopencm3
WORKDIR /root
RUN git clone -b docker-v9 https://github.com/keepkey/libopencm3.git libopencm3
WORKDIR /root/libopencm3
RUN apk add --update --no-cache patch
COPY libopencm.Makefile.patch ./
RUN patch Makefile libopencm.Makefile.patch && rm libopencm.Makefile.patch
RUN make

RUN apk add --update --no-cache \
    clang \
    gcc \
    g++ \
    binutils
