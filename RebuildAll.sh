#! /bin/bash


export NANOPB_PATH=~/nanopb-0.2.8-linux-x86/generator
export PATH=$PATH:$NANOPB_PATH

# clean build for the opencm3 library
cd libopencm3 
make clean
make
cd -

# build the nanopb
cd interface
./build_protos.sh
cd -

# clean build the keepkey sources
scons -c
./b -s




