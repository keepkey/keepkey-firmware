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
$ git clone git@github.com:keepkey/device-protocol.git
$ ln -s $PWD/device-protocol $PWD/keepkey-firmware/deps/device-protocol
```

### Build

To build the firmware using the docker container, use the provided script:

```
$ ./scripts/build/docker/release.sh
```

## License

If license is not specified in the header of a file, it can be assumed that it is licensed under GPLv3.
