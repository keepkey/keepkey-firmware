Prerequisites
-------------

Install nanopb-0.2.9.2 from:

`https://github.com/nanopb/nanopb/releases/tag/nanopb-0.2.9.2`


Building the Emulator
---------------------

```
$ git clone https://github.com/keepkey/keepkey-firmware.git
$ cd keepkey-firmware/deps
$ git clone https://github.com/keepkey/device-protocol.git
$ cd ../../
$ mkdir build
$ cd build
$ cmake -C ../../keepkey-firmware/cmake/caches/emulator.cmake ../keepkey-firmware \
    -DNANOPB_DIR=/path/to/your/nanopb \
    -DPROTOC_BINARY=/path/to/your/bin/protoc \
$ make -j8
```


Running the tests
-----------------

```
$ cd build
$ make test
```
