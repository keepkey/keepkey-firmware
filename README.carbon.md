Development Environment
=======================
### Linux 
###### Note: terry.guo maintains the 64-bit build

1. Toolchain setup
  1. sudo add-apt-repository ppa:terry.guo/gcc-arm-embedded 
  1. sudo apt-get update
  1. sudo apt-get install scons gcc-arm-none-eabi
  1. sudo apt-get install exuberant-ctags

1. Eclipse Setup
  1. Install sconsolidator if you want to do builds in eclipse ( http://www.sconsolidator.com/ )
  1. Install jlink gdb plugin, http://gnuarmeclipse.livius.net/blog/jlink-debugging/
1. Follow instructions to install the embsys plugin: 
  1. https://www.nordicsemi.com/eng/nordic/download_resource/22748/3/4972989 
    1. Eclipse update site: http://embsysregview.sourceforge.net/update


### Prerequisites to running any product build:

1. Build opencm3
  1. cd libopencm3 && make
1. Generate protobufs
  1. cd interface && ./build_protos.sh
1. Run setup.sh to setup some environment variables.
1. To build:
  1. Build debug version: ./b -s -d 
  1. Build release version: ./b -s
  
