# Install Toolchain and Eclipse IDE

## Windows (Incomplete)

1. Install gcc-arm-embedded toolchain: https://launchpad.net/gcc-arm-embedded/4.8/4.8-2014-q1-update
2. Install cygwin (including make): https://cygwin.com/install.html

## Linux (Ubuntu 14.04)

###Install Toolchain

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

###Build from command line

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

To build a debug version, run the following command in the root of the repository:

```
$ ./b -s -d
```

To build a release version, run the following command in the root of the repository:

```
$ ./b -s
```

###Install IDE (Eclipse Luna)

First, download Eclipse and decompress, then move it to /opt:

```
$ wget -P ~/ http://www.gtlib.gatech.edu/pub/eclipse/technology/epp/downloads/release/luna/R/eclipse-cpp-luna-R-linux-gtk-x86_64.tar.gz
$ tar zxf ~/eclipse-cpp-luna-R-linux-gtk-x86_64.tar.gz -C ~
$ sudo mv ~/eclipse /opt
```

Now we make sure it is accessable by all users:

```
$ sudo ln -s /opt/eclipse/eclipse /usr/bin/eclipse
```

You can also create an entry in Unity Dash.  Run the following command:

```
$ sudo gedit /usr/share/applications/eclipse.desktop
```

And then enter everything below into file and save it

```
[Desktop Entry]
Version=4.4.0
Name=Eclipse
Comment=IDE for all seasons
Exec=env UBUNTU_MENUPROXY=0 /opt/eclipse/eclipse
Icon=/opt/eclipse/icon.xpm
Terminal=false
Type=Application
Categories=Utility;Application;Development;IDE
```

Now install the GDB Server plugin for the JLINK Plus.  We can get that on Segger's website.  Look for the DEB Installer.  The one I used was "Software and documentation pack for Linux V4.90b, DEB Installer 64-bit version."  Download the plugin and then run the following command:

```
$ sudo dpkg -i jlink_4.90.2_x86_64.deb
```

Now we install the Sconsolidator plugin for Eclipse. In Eclipse click "Help" -> "Install New Software" in the menu. Then click Add and for "Name" enter "Sconsolidator" and for "Location" enter "http://www.sconsolidator.com/update" and then click "Ok".  It will take a few seconds but the package will appear.  Put a check in the ckeckbox next to it and proceed to install it.

Then proceed to install the GNU ARM plugin following the previous method for Sconsolidator.  Use the "Location" of "http://gnuarmeclipse.sourceforge.net/updates"

Next, install embsysregview by going to "Help" -> "Eclipse Marketplace" and searching for "embsysregview"

Setup Project in Eclipse

Create Scons project in Eclipse by going to "File" -> "New" -> "Other", then finding "New SCons project from existing source" under the "C/C++" category.  Then enter the project name and locate the repository for "Existing Code Location"

Now, open the project properties and navigate to the "SCons" category. Select "Use project settings" and then under "SCons Options" enter:

```
target=arm-none-gnu-eabi
verbose=1
debug=1
```

Click OK, then attempt to build all.  Everything should compile properly.

Setup Debugging in Eclipse

In the menu goto "Run" -> "Debug Configurations".  Navigate to the "GDB SEGGER J-Link Debugging" category in the left column, then right-click and click "New". For "C/C++ Application", choose "keepkey_main.elf" in the "/build/arm-none-gnu-eabi/debug/bin" directory of the firmware repository. Click "Apply".

Then navigate to "Debugger" tab. Fill in the following

* Executable: /usr/bin/JLinkGDBServer
..* Device name: STM32F2RG
..* Initial speed: auto

And under "GDB Client Setup"

* Executable: /usr/bin/arm-none-eabi-gdb
