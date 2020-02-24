#! /bin/bash -e

KEEPKEY_FIRMWARE="$(dirname "$( cd "$(dirname "$0")" ; pwd -P )")"
declare -a subdirs=("docs" "fuzzer" "include" "lib" "scripts" "tools" "unittests")
cd $KEEPKEY_FIRMWARE

for i in "${subdirs[@]}"
do
    find ./${i} -name '*.c' -o -name '*.h' -o -name '*.cpp' -o -name '*.hpp' | xargs clang-format -i --verbose -style=file
done