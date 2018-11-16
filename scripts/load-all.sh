#! /bin/bash -ex

HERE="$(dirname "$(which "$0")")"

source $HERE/load-bootstrap.sh

source $HERE/load-bootloader.sh

source $HERE/load-variant.sh

#source $HERE/load-firmware.sh
