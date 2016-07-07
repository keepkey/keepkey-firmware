#!/bin/bash
####################################################
#  BASH Script for building KeepKey Firmware
####################################################
#default to exit on any error
set -e  

DEVICE_PROTO="device-protocol"
KEEPKEY_FIRMWARE="keepkey-firmware"
IMAGETAG=keepkey/firmware
GITUSER_ID="git"


#******************************
#check build permision
#******************************
if [ "$USER" != "root" ]
then
    echo -e "\n\tError: Root permission requires for the build!!!\n"
    exit
fi

#******************************
#check number of valid inputs
#******************************
if [ "$#" -eq 0 ] || [ "$#" -gt 1 ]
then
    echo -e "\n\tError: Illegal number of inputs (should be 1 only) !!!\n"
    exit
fi

#******************************
#check build image type
#******************************
if [ "$1" != "bstrap" ] && [ "$1" != "bldr" ] && [ "$1" != "app" ] && [ "$1" != "all" ]
then
    echo -e "\n\tError: Incorrect build type arguement($1)!!!\n"
    exit
else
    echo "******************************************************"
    case "$1" in 
        "bstrap")
            echo "*       Building Boot Strap Firmware                 " 
            bldcmd="./b -b bstrap"
            ;;
        "bldr")
            echo "*       Building Boot Loader Firmware                " 
            bldcmd="./b -b bldr"
            ;;
        "app")
            echo "*       Building Application Firmware                " 
            bldcmd="./b -b app"
            ;;
        "all")
            echo "*       Building Boot Strap/BLdr/App Firmware        " 
            bldcmd="./b"
            echo 
            ;;
    esac
    echo "*            ($bldcmd)                                "
    echo "******************************************************"
fi

#**************************************
# clean directory for prestine build
#**************************************
if [ -d keepkey-firmware ]
then
    echo -e "\n\tError : Remove \"keepkey_firmware\" directory before building!!!\n"
    exit
fi

# clone keepkey firmware from repository to local drive
git clone https://$GITUSER_ID@github.com/keepkey/keepkey-firmware.git 

cd  $KEEPKEY_FIRMWARE

# clone protocol buffer from repository to local drive
git clone https://$GITUSER_ID@github.com/keepkey/$DEVICE_PROTO.git $DEVICE_PROTO

docker build -t $IMAGETAG .

docker run -t -v $(pwd):/root/keepkey-firmware -v $(pwd)/$DEVICE_PROTO:/root/$DEVICE_PROTO --rm $IMAGETAG /bin/sh -c "\
        cd /root/$DEVICE_PROTO && \
	cp /root/keepkey-firmware/interface/public/*.options . && \
	protoc -I. -I/usr/include --plugin=nanopb=protoc-gen-nanopb --nanopb_out=. *.proto && \
	mv *.pb.c /root/keepkey-firmware/interface/local && \
	mv *.pb.h /root/keepkey-firmware/interface/public && \
	cd /root/keepkey-firmware/libopencm3 && \
	make clean &&  make && \
	cd .. && \
	$bldcmd"

echo "*******************************************************"
echo "*                                                     *"
echo "*                 Build Success !!!                   *"
echo "*                                                     *"
echo "*******************************************************"
ls -l build/arm-none-gnu-eabi/release/bin
echo -e "\n\r"
