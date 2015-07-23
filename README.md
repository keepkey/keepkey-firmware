# Install Toolchain and Eclipse IDE

## Linux (Ubuntu 14.04)

### Install Toolchain

These instructions were used to setup toolchain and IDE on a brand new installtion of Ubuntu 14.04

First, make sure that apt-get is up to date update

```
$ sudo apt-get update
```

You must remove gdb package because it will cause conflicts when we install gdb-arm-none-eabi

```
$ sudo apt-get remove gdb
```

Then install neccassary packages

```
$ sudo apt-get install git scons gcc-arm-none-eabi python-protobuf protobuf-compiler fabric exuberant-ctags gdb-arm-none-eabi default-jre
```

We can generate a SSH key to add to our GitLab profile so we don't have to enter credentials each and everytime we use git.  Replace $your_email with your KeepKey email address.  Your email here is used to seed your RSA key.  During this process you are asked for a passphrase.  You can either choose a passphrase or leave blank. If you decide to use a passphrase, you will have to enter it everytime you interact with git.

```
$ ssh-keygen -t rsa -C "$your_email"
```

Copy your public SSH key from the command below and enter it into your GitLab profile. Make sure you copied everything returned by this command.

```
$ cat ~/.ssh/id_rsa.pub
```

Now, you can clone down the firmware respository

```
$ git clone git@gitlab.keepkey.com:embedded-software/keepkey-firmware.git
```

Download nanopb and decompress it. Keep it in a location you'll remember, as it's location will need to be set in PATH to compile protocol buffer via the command line as well as used in Eclipse to debug

```
$ wget -P ~/ http://koti.kapsi.fi/~jpa/nanopb/download/nanopb-0.2.9-linux-x86.tar.gz
$ tar zxf ~/nanopb-0.2.9-linux-x86.tar.gz -C ~
$ mv ~/nanopb-0.2.9-linux-x86 ~/nanopb
```

### Build from command line

To build opencm3, go to the root of the firmware repository and run:

```
$ cd libopencm3 && make
```

To compile protocol buffer files, first you must add nanopb generator to path:

```
$ export PATH=$PATH:~/nanopb/generator
```

When you compile protocol buffers you may see some warnings.  Run to following commands in the root of the firmware repository:

```
$ cd interface && ./build_protos.sh
```

To build a Application for debug version, run the following command in the root of the repository:

```
$ ./b -d -b app 
```

To build a Application for release version, run the following command in the root of the repository:

```
$ ./b -b app 
