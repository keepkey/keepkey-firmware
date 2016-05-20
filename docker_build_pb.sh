#!/bin/bash

TEMPDIR="device-protocol"
IMAGETAG=keepkey/firmware

#git clone git@github.com:keepkey/device-protocol.git $TEMPDIR

docker build -t $IMAGETAG .

docker run -t -v $(pwd):/root/keepkey-firmware -v $(pwd)/$TEMPDIR:/root/$TEMPDIR --rm $IMAGETAG /bin/sh -c "\
	cd /root/$TEMPDIR && \
	cp /root/keepkey-firmware/interface/public/*.options . && \
	protoc -I. -I/usr/include --plugin=nanopb=protoc-gen-nanopb --nanopb_out=. *.proto && \
	mv *.pb.c /root/keepkey-firmware/interface/local && \
	mv *.pb.h /root/keepkey-firmware/interface/public"

#rm -rf $TEMPDIR
