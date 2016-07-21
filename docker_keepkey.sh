#!/bin/bash
####################################################
#  BASH Script for building KeepKey image
####################################################
#default to exit on any error
set -e  

DEVICE_PROTO="device-protocol-private"
KEEPKEY_FIRMWARE="keepkey-firmware-private"
IMAGETAG=keepkey/firmware
GITUSER_ID="git"
BINTYPE="release"
BUILDTYPE="app"

# Help Function
Help()
{
    echo -e \
    "usage: \n   docker_build_rlc.sh [-h] [-i] [-dl] [-mp] [-p PROJECT] [-b BUILD_TYPE] [-bf] [-bb] [-bt] [-d] [-v]
                                 [clean]
       arguments:
        -h, --help              show this help message and exit
        -i, --invert            Build with inverted display.
        -dl, --debug-link       Build with Debug Link.
        -mp, --memory-protect   Build with memory protection
        -p PROJECT, --project   PROJECT
                                Build specific project (bootloader, bootstrap, crypto,
                                interface, keepkey, keepkey_board, nanopb).
        -b BUILD_TYPE, --build-type BUILD_TYPE
                                Build specifc build type (bstrap, bldr, app).
        -bf, --bump-feature     Bump feature release version.
        -bb, --bump-bug-fix     Bump bug fix version.
        -bt, --bump-test        Bump test version.
        -d, --debug             Build debug variant.
        -v, --verbose           Build with verbose output.
        clean                   delete $KEEPKEY_FIRMWARE."

}


#******************************
#assemble build commands 
#******************************
if [ "$#" -lt 1 ]
then
    BUILDTYPE="all"
    bldcmd="./b -mp"
else
    #******************************
    #assemble build arguments 
    #******************************
    for i in "$@"
    do 
        if [ "$i" == "-bf" ] || [ "$i" == "-bb" ] || [ "$i" == "-bt" ]
        then
            bldcmd="./b $i"
        elif [ "$i" == "-h" ]
        then
            Help
            exit
        elif [ "$i" == "clean" ]
        then
            echo "************************************************************"
            echo "  Removing $KEEPKEY_FIRMWARE directory         "
            echo "************************************************************"
            if [ -d $KEEPKEY_FIRMWARE ]
            then
                sudo rm -rf $KEEPKEY_FIRMWARE
            else
                echo -e "\n Error: $KEEPKEY_FIRMWARE directory does not exist!!!\n"
            fi
            exit
        else
            bldarg="$bldarg $i"
            if [ "$i" == "-d" ]
            then
                BINTYPE="debug"
            fi

            if [ "$i" == "bldr" ] || [ "$i" == "bstrap" ]
            then
                BUILDTYPE=$i
            fi
        fi
    done

    #In case user set "bf", "bb" and "bd" for none application build
    if [ $BUILDTYPE != "app" ]
    then
        
        #reset bldcmd.  The build is not for application.  No need to bump version
        bldcmd=""
    fi

    #******************************
    #combine build commands 
    #******************************
    if [ "$bldcmd" != "" ]
    then
        bldcmd="$bldcmd && ./b $bldarg"
    else
        bldcmd="./b $bldarg"
    fi
fi

#**************************************
# Clone and Build using docker
#**************************************
if ! [ -d $KEEPKEY_FIRMWARE ]
then
    # clone keepkey firmware from repository to local drive
    git clone $GITUSER_ID@github.com:keepkey/$KEEPKEY_FIRMWARE.git $KEEPKEY_FIRMWARE

    cd $KEEPKEY_FIRMWARE

    # clone protocol buffer from repository to local drive
    git clone $GITUSER_ID@github.com:keepkey/$DEVICE_PROTO.git $DEVICE_PROTO
else
    cd $KEEPKEY_FIRMWARE
fi

docker build -t $IMAGETAG .

docker run -t -v $(pwd):/root/$KEEPKEY_FIRMWARE -v $(pwd)/$DEVICE_PROTO:/root/$DEVICE_PROTO --rm $IMAGETAG /bin/sh -c "\
            cd /root/$DEVICE_PROTO && \
	    cp /root/$KEEPKEY_FIRMWARE/interface/public/*.options . && \
	    protoc -I. -I/usr/include --plugin=nanopb=protoc-gen-nanopb --nanopb_out=. *.proto && \
	    mv *.pb.c /root/$KEEPKEY_FIRMWARE/interface/local && \
	    mv *.pb.h /root/$KEEPKEY_FIRMWARE/interface/public && \
	    cd /root/$KEEPKEY_FIRMWARE && \
	    make -C libopencm3 && \
        $bldcmd"

# Display Build status
echo -e  \
"********************************
BUILD SUCCESS!!!                    
Build Command : $bldcmd                             
(BuildType = $BINTYPE) "
if [ "$BUILDTYPE" == "app" ] || [ "$BUILDTYPE" == "all" ]
then
    #display application version 
    strings build/arm-none-gnu-eabi/$BINTYPE/bin/keepkey_main.bin | grep VER
fi
echo -e \
"********************************\n"

#list output files in binary directory
ls -l build/arm-none-gnu-eabi/$BINTYPE/bin

