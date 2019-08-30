Prerequisites
-------------

### linux (fedora 30)

### OSX

```
brew install protobuf
```

## install protoc
```
sudo dnf install protobuf-compiler
sudo dnf install python-protobuf
```

verify
```
protoc --version
```
version libprotoc 3.6.1

## download nanopb-0.2.9.2 from:

```wget https://github.com/nanopb/nanopb/archive/nanopb-0.2.9.2.tar.gz```

```tar -xvf nanopb-0.2.9.2.tar.gz```

Build protobuf libs

```cd nanopb-0.2.9.2/generator/proto ```

make
```make```

note: warning is normal
```
[libprotobuf WARNING google/protobuf/compiler/parser.cc:647] No syntax specified for the proto file: google/protobuf/descriptor.proto. Please use 'syntax = "proto2";' or 'syntax = "proto3";' to specify a syntax version. (Defaulted to proto2 syntax.)
```


move to home dir
```
cp -R nanopb-nanopb-0.2.9.2 ../
```

set generator in $PATH for

View PATH
```
echo $PATH
```

```PATH=$PATH:/home/*username*/nanopb-nanopb-0.2.9.2/generator```

#windows
TODO

#OSX
TODO


Building the Emulator
---------------------

Build repo
```
git clone https://github.com/keepkey/keepkey-firmware.git

```

init submodules
```
git submodule update --init --recursive
```


## Compile Emulator

create build dir
```
 mkdir build
 cd build
```

make
```
 cmake -C ../cmake/caches/emulator.cmake .. -DNANOPB_DIR=/home/*username*/nanopb-nanopb-0.2.9.2/generator -DPROTOC_BINARY=/usr/bin/protoc
 make -j8
```

param1: Path to cmake (tracked)
param2: Path to source (up one level)
param3: Path to nanopb source code (Sample assumes HOME)
param4: Path to protoc bin (linux)


skip tests
```
make kkemu
```


Running the tests
-----------------

```
$ cd build
$ make test
```

Run Emulator
-----------------

```
./kkemu
```


# troubleshoot

Error:

```
CMake Error at CMakeLists.txt:44 (message):
  Must install nanopb 0.2.9.2, and put nanopb-nanopb-0.2.9.2/generator on
  your PATH
```

Failed to point PATH to the downloaded nanopb


```
/bin/sh: /usr/local/bin/protoc: No such file or directory
make[2]: *** [lib/transport/CMakeFiles/kktransport.pb.dir/build.make:75: lib/transport/kktransport.pb.stamp] Error 127
make[1]: *** [CMakeFiles/Makefile2:530: lib/transport/CMakeFiles/kktransport.pb.dir/all] Error 2
make[1]: *** Waiting for unfinished jobs....
```

DPROTOC_BINARY setting passed on make was incorrect

possibles

Fedora
```
/usr/bin/protoc
```
Other distro
```
/usr/local/bin/protoc
```

Failed on make
```
protoc-gen-nanopb: program not found or is not executable
--nanopb_out: protoc-gen-nanopb: Plugin failed with status code 1.
```

