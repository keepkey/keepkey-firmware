[![CircleCI](https://circleci.com/gh/keepkey/keepkey-firmware.svg?style=svg)](https://circleci.com/gh/keepkey/keepkey-firmware)

## KeepKey Build Procedure

### Toolchain Installation

Install Docker Community Edition from: `https://www.docker.com/get-docker`

```
$ docker pull kktech/firmware:v5-beta
```

### Clone the Source

The sources can be obtained from github:

```
$ git clone git@github.com:keepkey/keepkey-firmware.git
$ git submodule update --init --recursive
```

### Build

To build the firmware using the docker container, use the provided script:

```
$ ./scripts/build/docker/device/release.sh
```

## Verifying Published Binaries

Compare the hash of a given tagged build:
```
$ git checkout v5.8.1
$ git submodule update --init --recursive
$ ./scripts/build/docker/device/release.sh
$ shasum -a 256 ./bin/firmware.keepkey.bin
```

With that of the [signed v5.8.1 binary on github](https://github.com/keepkey/keepkey-firmware/releases/download/v5.8.1/firmware.keepkey.bin), ignoring signatures and firmware metadata:
```
$ tail -c +257 firmware.keepkey.bin | shasum -a 256
```

Then inspect the metadata itself by comparing against the structure described [here](https://github.com/keepkey/keepkey-firmware/blob/f20484804285decfacceb71519ae83bc18f2266f/include/keepkey/board/memory.h#L55):

```
$ head -c +256 signed_firmware.bin | xxd -

```

### Docs

Documentation can be found [here](docs/README.md).

## License

If license is not specified in the header of a file, it can be assumed that it is licensed under LGPLv3.
