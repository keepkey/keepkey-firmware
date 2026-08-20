Prerequisites
-------------

Install nanopb-0.3.9.8 from:

`https://github.com/nanopb/nanopb/releases/tag/nanopb-0.3.9.8`

This must match the version baked into the pinned builder image
(`Dockerfile`, `git clone --branch nanopb-0.3.9.8`). Generated headers
differ between nanopb majors, so a mismatch means a local build and a CI
build are not the same product even from the same source. See GH #425.

Install the python-protobuf dependency:

`pip install protobuf`

Building the Emulator
---------------------

```sh
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

```sh
$ cd build
$ make all test
```
