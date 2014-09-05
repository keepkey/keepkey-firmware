
Development Environment
=======================

Windows (incomplete)
-------

1. Install gcc-arm-embedded toolchain: https://launchpad.net/gcc-arm-embedded/4.8/4.8-2014-q1-update
2. Install cygwin (including make): https://cygwin.com/install.html

Linux 
-----
*Note: terry.guo maintains the 64-bit build
1. sudo add-apt-repository ppa:terry.guo/gcc-arm-embedded 
2. sudo apt-get update
3. sudo apt-get install scons gcc-arm-none-eabi

Eclipse Setup:
1. Install sconsolidator if you want to do builds in eclipse:
   http://www.sconsolidator.com/
2. Install jlink gdb plugin:
   http://gnuarmeclipse.livius.net/blog/jlink-debugging/
3. Follow instructions to install the embsys plugin: 
   https://www.nordicsemi.com/eng/nordic/download_resource/22748/3/4972989 
4. Eclipse update site: 
   http://embsysregview.sourceforge.net/update

Create Scons project in Eclipse:
+ In Eclipse, "File / New / New Scons project from existing source"
+ In new project dialog: give the project a name, browse to source code
+ In project properties, Scons tab, enter Scons options (refer to SuperAction 'b' script):
    target=arm-none-gnu-eabi
    verbose=1
    debug=1
+ In project properties, Scons tab, specify additional environment variables:
    GCC_ROOT=/opt/carbon/gcc-arm-none-eabi-4_8-2014q1/

Debugging under Eclipse:
+ In Debug Configurations, create new GDB SEGGER J-Link Debugging configuration for KeepKey Debug
+ Debug configuration, Main tab:
    C/C++ Application: specify path to controller_main.elf
    Project: SuperAction
+ Debug configuration, Debugger tab:
    J-Link GDB Server Setup: Start the J-Link GDB server locally
    Executable: /usr/bin/JLinkGDBServer
    Device name: STM32F2RG
    Endianness, etc: use the defaults
    GDB Client Setup, Executable: /usr/bin/arm-none-eabi-gdb
+ Debug configuration, Startup tab: use the defaults
+ Use SEGGER J-Link debugger (hardware)
+ Connect 10-pin CortexM cable from J-Link to SuperAction controller board
+ Debug!

### Prerequisites to running any product build:

1. Build opencm3
  1. cd libopencm3 && make
1. Generate protobufs
  1. cd interface && ./build_protos.sh
1. Run setup.sh to setup some environment variables.
1. To build:
  1. Build debug version: ./b -s -d 
  1. Build release version: ./b -s

