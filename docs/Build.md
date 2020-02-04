Prerequisites
-------------

Install nanopb-0.3.9.4 from:

`https://github.com/nanopb/nanopb/releases/tag/nanopb-0.3.9.4`


Building the Emulator
---------------------

```
$ git clone https://github.com/keepkey/keepkey-firmware.git
$ git submodule update --init --recursive
$ mkdir build
$ cd build
$ cmake -C ../../keepkey-firmware/cmake/caches/emulator.cmake ../keepkey-firmware \
    -DNANOPB_DIR=/path/to/your/nanopb \
    -DPROTOC_BINARY=/path/to/your/bin/protoc \
$ make -j
```


Running the tests
-----------------

```
$ cd build
$ make all test
```
