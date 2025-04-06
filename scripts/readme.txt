Description of the shell files in the /scripts directory tree for building keepkey firmware

scripts/emulator
These files run the emulator for python testing without a keepkey device on an amd64 platform.

scripts/armEmulator
These files are the equivalent to the /scripts/emulator files but they run on an arm64 platform

scripts/build/docker/device
initiate these scripts from top level directory keepkey-firmware/
btcdebug.sh:    build debug version of bitcoin-only firmware
btcrelease.sh:  build release version of bitcoin-only firmware (must be signed)
debug.sh:       build debug version of full-featured firmware
release.sh:     build release version of full-featured firmware (must be signed)
devdebug.sh:    build debug version of firmware for development board (described elsewhere)

script/build/docker/emulator
These files kick off building and running the emulator on debug firmware. They can be used 
stand-alone to test code coverage directly without going through the comm interface as well
as interface testing though the scripts/emulator interface test suite.

scripts/dev2
These files are used with the development board for jtag debugging (described in the dev2 readme)

scripts/legacy-jtag
These are the legacy script files for keepkey boards. They use openocd to load firmware builds
onto a keepkey board and debug via jtag. These files are only useful on special board 
builds that do not have the jtag port locked. All out-of-the-box Keepkey devices have permanently
locked jtag ports as a security feature.

