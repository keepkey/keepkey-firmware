#! /bin/bash

sudo chmod +X setup.sh
./setup.sh

# clean build for the opencm3 library
cd libopencm3 
make clean
make

# build the nanopb
cd interface
./build_protos.sh
cd -

# clean build the keepkey sources
scons -c
./b -s




