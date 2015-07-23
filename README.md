# KeepKey Build Procedure for Ubuntu 14.04

### Toolchain Installation

These instructions were used to setup toolchain in Ubuntu 14.04

First, update "apt-get"
```
$ sudo apt-get update
```
Remove gdb package. It causes error during gdb-arm-none-eabi toolchain installation
```
$ sudo apt-get remove gdb
```
Install supporting packages for build
```
$ sudo apt-get install git scons gcc-arm-none-eabi python-protobuf protobuf-compiler fabric exuberant-ctags gdb-arm-none-eabi default-jre
```

Download firmware source code from KeepKey respository (https://github.com/keepkey/keepkey-firmware.git)
```
$ git clone git@gitlab.keepkey.com:embedded-software/keepkey-firmware.git
```

### command line build

To build libopencm3, go to the root of the firmware repository and run:
```
$ cd libopencm3 && make
```
To build a Application for debug version, run the following command in the root of the repository:
```
$ ./b -d -b app 
```
To build a Application for release version, run the following command in the root of the repository:
```
$ ./b -b app 
```
The resultant binaries will be located in ./build/arm-none-gnu-eabi/release/bin directory.
