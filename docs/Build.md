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

Release products
-----------------

Two release products, no separate `zcash-privacy` artifact:

| Product | Contents |
| --- | --- |
| Regular (`full`) | Every supported chain, including Zcash shielded/Orchard |
| Bitcoin-only | Bitcoin only; all non-Bitcoin coins and Zcash privacy code removed |

An unflagged CMake build is the regular product (`BITCOIN_ONLY=0`,
`ZCASH_PRIVACY=1`). `-DKK_BITCOIN_ONLY=ON` sets `BITCOIN_ONLY=1` and
`ZCASH_PRIVACY=0`. Zcash privacy is part of the regular firmware and cannot be
disabled as a release choice; the internal `ZCASH_PRIVACY` value exists only so
bitcoin-only can compile the privacy sources out. Device, emulator, unit-test,
SRAM, and tagged-release CI matrices cover only these two products.
