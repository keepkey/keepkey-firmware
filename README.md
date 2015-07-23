# Install Toolchain and Eclipse IDE

### Install Toolchain (Build machine - Ubuntu 14.04)

These instructions were used to setup toolchain in Ubuntu 14.04

First, update "apt-get"
```
$ sudo apt-get update
```
Remove gdb package. It causes error when we install gdb-arm-none-eabi toolchain
```
$ sudo apt-get remove gdb
```
Install misc required packages 
```
$ sudo apt-get install git scons gcc-arm-none-eabi python-protobuf protobuf-compiler fabric exuberant-ctags gdb-arm-none-eabi default-jre
```

Download firmware source code from KeepKey respository (https://github.com/keepkey/keepkey-firmware.git)
```
$ git clone git@gitlab.keepkey.com:embedded-software/keepkey-firmware.git
```

### Build command line in Ubuntu

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
