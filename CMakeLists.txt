cmake_minimum_required(VERSION 3.7)
project(keepkey)
set(CMAKE_CXX_STANDARD 11)
file(GLOB_RECURSE sources ./*.c)
set(SOURCE_FILES
        ${sources})
include_directories(
        bootloader/public
        keepkey/public
        keepkey_board/public
        bootstrap/public
        libopencm3/include
        nanopb/public
        interface/public
        crypto/public
)
add_executable(keepkey ${SOURCE_FILES})