DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

export NANOPB_PATH=~/src/nanopb
export OPENCM3_DIR=$DIR/src/keepkey/libopencm3
#export PATH=/opt/carbon/gcc-arm-none-eabi-4_8-2014q1/bin:$NANOPB_PATH/generator:$PATH
export PATH=$NANOPB_PATH/generator:$PATH
