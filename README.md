
## markrypt0-keepkey-firmware development repo

This is a branch of the keepkey/keepkey-firmware repo that has been refactored to support a simplified crypto library, an ARM build environment, specifically raspberry pi, and also supports new hardware used for a debug environment since all original keepkeys are permanently jtag locked.

## KeepKey Build Procedure

### Clone the Source

The sources can be obtained from github:

```
$ git clone git@github.com:markrypt0/markrypt0-keepkey-firmware.git
$ git submodule update --init --recursive
```

### Toolchain Installation

The build is done via a docker environment, thus Docker is a reqirement.

You must build a local docker image since currently there is no keepkey build image in the docker repo.

Build the image in your dev environment from a shell command line.

For amd64 architecture build environment:

```
$ ./DockerStart.sh
```

For arm64v8 architecture build environment:

```
$ ./armDockerStart.sh
```

### Build

To build the firmware using the docker container, use the provided script, for example, to build a debug version of the firmware:

```
$ ./scripts/build/docker/device/debug.sh
```

See ./scripts/readme.txt for various build descriptions

## Verifying Published Binaries

There are no official keepkey firmware releases build from this repo.

### Docs

Documentation can be found [here](docs/README.md).

## License

If license is not specified in the header of a file, it can be assumed that it is licensed under LGPLv3.
