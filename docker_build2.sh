#!/bin/bash
####################################################
#  BASH Script for building KeepKey Firmware
####################################################
set -e  #default to exit on any error

DEVICE_PROTO="device-protocol"
KEEPKEY_FIRMWARE="keepkey-firmware"
IMAGETAG=keepkey/firmware
GITUSER_ID="git"
BUILD_DIR="build"
LIBOPENCM3_DIR="libopencm3" 
BLDCMD="./b $1 $2 $3 $4"

#*************************************************************
#  Clean project directory
#*************************************************************
if [ "$1" == "clean" ]
then
    echo "Clean directory..."
    if [ -d $BUILD_DIR ]
    then
        rm -rf $BUILD_DIR
    fi
    make clean -C $LIBOPENCM3_DIR --no-print-directory
    find . -name "*.o" -type f -delete
    exit
fi

#*************************************************************
# clone protocol buffer from repository to local drive
#*************************************************************
if [ ! -d $DEVICE_PROTO ]
then
    echo -e "\n\t**************************************************************"
    echo -e "\t*** "$DEVICE_PROTO" directory missing.  Enlisting directory   "
    echo -e "\t**************************************************************\n"
    git clone https://$GITUSER_ID@github.com/keepkey/$DEVICE_PROTO.git $DEVICE_PROTO
fi

#************************************************************
#  Begin Dock build 
#************************************************************

docker build -t $IMAGETAG .
docker run -t -v $(pwd):/root/$KEEPKEY_FIRMWARE -v $(pwd)/$DEVICE_PROTO:/root/$DEVICE_PROTO --rm $IMAGETAG /bin/sh -c "\
        cd /root/$DEVICE_PROTO && \
	cp /root/$KEEPKEY_FIRMWARE/interface/public/*.options . && \
	protoc -I. -I/usr/include --plugin=nanopb=protoc-gen-nanopb --nanopb_out=. *.proto && \
	mv *.pb.c /root/$KEEPKEY_FIRMWARE/interface/local && \
	mv *.pb.h /root/$KEEPKEY_FIRMWARE/interface/public && \
        cd /root/$KEEPKEY_FIRMWARE && \
        make -C $LIBOPENCM3_DIR && \
        $BLDCMD"

echo "*******************************************************"
echo "*                                                      "
echo "*              Build Success !!!                       "
echo "*           (build cmd : $BLDCMD)                       "
echo "*                                                      "
echo "*******************************************************"
