## KeepKey Build Procedure for Ubuntu 14.04

### Toolchain Installation

Install Docker Community Edition from: https://www.docker.com/get-docker

Download firmware source code from KeepKey respository (https://github.com/keepkey/keepkey-firmware.git)
```
$ git clone git@github.com:keepkey/keepkey-firmware.git
```

Build the docker image for the toolchain:

```
$ cd keepkey-firmware && docker build -t keepkey/firmware:latest .
```

Build the debug version of the standard firmware:
```
$ docker_build_keepkey_debug.sh
```

Build the release version of the standard firmware:
```
$ docker_build_keepkey_release.sh
```

Build the debug version of the SALT-branded firmware:
```
$ docker_build_salt_debug.sh
```

Build the release version of the SALT-branded firmware:
```
$ docker_build_salt_release.sh
```

The resultant binaries will be located in the ./bin/{debug,release}/{keepkey,salt} directories as appropriate.

## License

If license is not specified in the header of a file, it can be assumed that it is licensed under GPLv3.
