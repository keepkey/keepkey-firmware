# Development Environment

## To Setup Repo & Toolchain

Install Git and clone firmware repository (this assumes you have properly setup ssh keys on KeepKey's GitLab)

* sudo apt-get install git
* git clone git@gitlab.keepkey.com:embedded-software/keepkey-firmware.git

Install toolchain, scons, exuberant-ctags, and fabric

* sudo add-apt-repository ppa:terry.guo/gcc-arm-embedded
* sudo apt-get update
* sudo apt-get install scons gcc-arm-none-eabi exuberant-ctags fabric

Install google protocol buffer compiler, python protocol buffer bindings and libprotobuf-dev
* sudo apt-get install protobuf-compiler python-protobuf libprotobuf-dev

Download and decompress nanopb to home directory
* wget http://koti.kapsi.fi/~jpa/nanopb/download/nanopb-0.2.8-linux-x86.tar.gz ~/.
* tar zxf ~/nanopb-0.2.8-linux-x86.tar.gz -C ~
* mv ~/nanopb-0.2.8-linux-x86 ~/nanopb

## To Build From Source

Add nanopb to path
* export NANOPB_PATH=~/nanopb/generator
* export PATH=$PATH:$NANOPB_PATH

Clean build for the opencm3 library
* cd libopencm3
* make clean
* make
* cd ..

Build nanopb
* cd interface
* ./build_protos.sh
* cd ..

Build KeepKey
* scons -c
* ./b -s

The resulting binaries are located in: build/arm-none-gnu-eabi/release/bin

## Eclipse Setup

These instructions have not been verified, so proceed at your own risk.

1. Install sconsolidator if you want to do builds in eclipse ( http://www.sconsolidator.com/ )
2. Install jlink gdb plugin, http://gnuarmeclipse.livius.net/blog/jlink-debugging/
1. Follow instructions to install the embsys plugin: 
 1. https://www.nordicsemi.com/eng/nordic/download_resource/22748/3/4972989 
 2. Eclipse update site: http://embsysregview.sourceforge.net/update
