

Overview
--------

It is possible to build the firmware on an ARM-based system with the pi-dev branch. It was developed specifically for a raspbery pi 5 running Bookworm but in general should work for any ARM-based build system.
The standard build uses a docker container to isolate the raspi os, but theoretically this is not required. The dockerized environment has some patches to surpress moot warnings from the linker and does some other tricks to make the build clean.
The pi-dev branch has been refactored to simplify the build, namely the crypto library. No longer is the entire trezor monorepo pulled into the firmware build just to use some of the trezor crypto library. The crypto library submodule is now called hw-crypto, which was copied directly from the keepkey branch of the trezor crypto directory.

Requirements for pi environment
-------------------------------
docker
docker-compose (if you want to run the emulator for testing)

Install
-------
```sh
$ git clone https://github.com/markrypt0/keepkey-firmware.git
$ git checkout pi-dev
$ git submodule update --init --recursive
```

Build the docker container from keepkey-firmware root directory
```sh
$ ./armDockerStart
```

Build firmware
```sh
$ ./scripts/build/docker/device/debug.sh
```

## Using Keepkey on Raspberry Pi

You'll need to install UDEV rules in order to allow non-root users to communicate with the device. The rules for a Raspberry Pi are slightly different than what is described for linux in Host.md

Add the following udev rules to `/etc/udev/rules.d/51-usb-keepkey.rules`:

```
# KeepKey: Your Private Bitcoin Vault
# http://www.keepkey.com/
# Put this file into /etc/udev/rules.d/ on a Raspberry Pi

# KeepKey HID Firmware/Bootloader
SUBSYSTEM=="usb", ATTR{idVendor}=="2b24", ATTR{idProduct}=="0001", MODE="0666", GROUP="plugdev", TAG+="uaccess", TAG+="udev-acl", SYMLINK+="keepkey%n"
KERNEL=="hiddev*", ATTRS{idVendor}=="2b24", ATTRS{idProduct}=="0001",  MODE="0666", GROUP="plugdev", TAG+="uaccess", TAG+="udev-acl"

# KeepKey WebUSB Firmware/Bootloader
SUBSYSTEM=="usb", ATTR{idVendor}=="2b24", ATTR{idProduct}=="0002", MODE="0666", GROUP="plugdev", TAG+="uaccess", TAG+="udev-acl", SYMLINK+="keepkey%n"
KERNEL=="hiddev*", ATTRS{idVendor}=="2b24", ATTRS{idProduct}=="0002",  MODE="0666", GROUP="plugdev", TAG+="uaccess", TAG+="udev-acl"
```