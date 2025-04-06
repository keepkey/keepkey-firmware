cmake_minimum_required(VERSION 3.7.2)

project(
  KeepKeyFirmware
  VERSION 7.10.0
  LANGUAGES C CXX ASM)

set(BOOTLOADER_MAJOR_VERSION 2)
set(BOOTLOADER_MINOR_VERSION 1)
set(BOOTLOADER_PATCH_VERSION 5)

option(KK_EMULATOR "Build the emulator" OFF)
option(KK_DEBUG_LINK "Build with debug-link enabled" OFF)
option(KK_BUILD_FUZZERS "Build the fuzzers?" OFF)
set(LIBOPENCM3_PATH
    /root/libopencm3
    CACHE PATH "Path to an already-built libopencm3")
set(PROTOC_BINARY
    protoc
    CACHE PATH "Path to the protobuf compiler binary")
set(NANOPB_DIR
    /root/nanopb
    CACHE PATH "Path to the nanopb build")
set(DEVICE_PROTOCOL
    ${CMAKE_SOURCE_DIR}/deps/device-protocol
    CACHE PATH "Path to device-protocol")
set(CMAKE_DEBUG_POSTFIX CACHE STRING "Debug library name postfix")

list(APPEND CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/cmake/modules/")
include(GetGitRevisionDescription)
get_git_head_revision(GIT_REFSPEC GIT_SHA1)

if(NOT EXISTS ${DEVICE_PROTOCOL})
  message(FATAL_ERROR "Missing deps/device-protocol symlink?")
endif()

if(NOT EXISTS ${CMAKE_SOURCE_DIR}/deps/googletest/CMakeLists.txt)
  message(
    FATAL_ERROR
      "googletest missing. Need to 'git submodule update --init --recursive")
endif()

if(NOT EXISTS ${CMAKE_SOURCE_DIR}/deps/crypto/hw-crypto/crypto/Makefile)
  message(
    FATAL_ERROR
      " hw-crypto missing. Need to 'git submodule update --init --recursive"
  )
endif()

if(NOT EXISTS ${CMAKE_SOURCE_DIR}/deps/qrenc/QR-Code-generator/c/Makefile)
  message(
    FATAL_ERROR
      " QR-Code-generator missing. Need to 'git submodule update --init --recursive"
  )
endif()

find_program(NANOPB_GENERATOR nanopb_generator.py)
if(${KK_EMULATOR} AND NOT NANOPB_GENERATOR)
  message(
    FATAL_ERROR
      "Must install nanopb v1.0.0, and put nanopb-nanopb-v1.0.0/generator on your PATH"
  )
endif()

if(${KK_EMULATOR})
  add_definitions(-DEMULATOR)
  add_definitions(-DCONFIDENTIAL=)
else()
  add_definitions(-DCONFIDENTIAL=__attribute__\(\(section\("confidential"\)\)\))
endif()

if("${DEVDEBUG}" STREQUAL "true")
  add_definitions(-DDEV_DEBUG)
  add_definitions(-DSTM32F4=1)
  if("${TWODISP}" STREQUAL "true")
    add_definitions(-DTWO_DISP)
  endif()
else()
  add_definitions(-DSTM32F2=1)
endif()

add_definitions(-DED25519_CUSTOMHASH=1)
add_definitions(-DED25519_CUSTOMRANDOM=1)
add_definitions(-DED25519_NO_INLINE_ASM)
add_definitions(-DED25519_FORCE_32BIT=1)

add_definitions(-DUSE_PRECOMPUTED_CP=0)

add_definitions(-DUSE_ETHEREUM=1)
add_definitions(-DUSE_KECCAK=1)
add_definitions(-DUSE_GRAPHENE=0)
add_definitions(-DUSE_CARDANO=0)
add_definitions(-DUSE_MONERO=0)
add_definitions(-DUSE_NEM=0)
add_definitions(-DUSE_NANO=1)

add_definitions(-DRAND_PLATFORM_INDEPENDENT=0)

add_definitions(-DPB_FIELD_16BIT=1)
add_definitions(-DPB_NO_ERRMSG=1)
add_definitions(-DPB_BUFFER_ONLY=1)

add_definitions(-DMAJOR_VERSION=${PROJECT_VERSION_MAJOR})
add_definitions(-DMINOR_VERSION=${PROJECT_VERSION_MINOR})
add_definitions(-DPATCH_VERSION=${PROJECT_VERSION_PATCH})

add_definitions(-DBOOTLOADER_MAJOR_VERSION=${BOOTLOADER_MAJOR_VERSION})
add_definitions(-DBOOTLOADER_MINOR_VERSION=${BOOTLOADER_MINOR_VERSION})
add_definitions(-DBOOTLOADER_PATCH_VERSION=${BOOTLOADER_PATCH_VERSION})

add_definitions(-DBIP39_WORDLIST_PADDED=1)

add_definitions(-DAES_128=1)

if(${KK_DEBUG_LINK})
  add_definitions(-DDEBUG_LINK=1)
else()
  add_definitions(-DDEBUG_LINK=0)
endif()

if("${COIN_SUPPORT}" STREQUAL "BTC")
  add_definitions(-DBITCOIN_ONLY)
endif()

if("${CMAKE_BUILD_TYPE}" STREQUAL "Debug")
  add_definitions(-DDEBUG_ON)
  add_definitions(-DMEMORY_PROTECT=0)
elseif(
  "${CMAKE_BUILD_TYPE}" STREQUAL "Release"
  OR "${CMAKE_BUILD_TYPE}" STREQUAL "MinSizeRel"
  OR "${CMAKE_BUILD_TYPE}" STREQUAL "")
  add_definitions(-DNDEBUG)
  add_definitions(-DMEMORY_PROTECT=1)
  if(NOT ${KK_EMULATOR})
    message(
      WARNING
        "*********************************************************************\n"
        "* You are about to build a release version of KeepKey firmware. The *\n"
        "* resulting bootloader image will memory protect the flash on your  *\n"
        "* device, so please use it with extreme care.                       *\n"
        "*********************************************************************")
  endif()
else()
  message(ERROR "Must pick Release *or* Debug CMAKE_BUILD_TYPE")
endif()

include_directories(${CMAKE_SOURCE_DIR}/include)

set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

if(NOT ${KK_EMULATOR})
  link_directories(${LIBOPENCM3_PATH}/lib)
  include_directories(${LIBOPENCM3_PATH}/include)

  # Dummy empty libraries for stack smashing protection support, since we
  # implement __stack_chk_guard and __stack_chk_fail ourselves.
  file(WRITE ${CMAKE_BINARY_DIR}/ssp.c "")
  add_library(ssp ${CMAKE_BINARY_DIR}/ssp.c)
  add_library(ssp_nonshared ${CMAKE_BINARY_DIR}/ssp.c)
  set_property(TARGET ssp PROPERTY LINKER_LANGUAGE CXX)
  set_property(TARGET ssp_nonshared PROPERTY LINKER_LANGUAGE CXX)
  set_target_properties(ssp ssp_nonshared PROPERTIES LIBRARY_OUTPUT_DIRECTORY
                                                     ${CMAKE_BINARY_DIR}/lib)
endif()

add_subdirectory(lib)
add_subdirectory(tools)
add_subdirectory(deps/crypto)
add_subdirectory(deps/qrenc)
add_subdirectory(deps/sca-hardening)

if(${KK_EMULATOR})
  add_subdirectory(deps/googletest)
  add_subdirectory(unittests)
  if(${KK_BUILD_FUZZERS})
    add_subdirectory(fuzzer)
  endif()

  enable_testing()
  add_test(test-firmware ${CMAKE_BINARY_DIR}/bin/firmware-unit)
  add_test(test-board ${CMAKE_BINARY_DIR}/bin/board-unit)
  add_test(test-crypto ${CMAKE_BINARY_DIR}/bin/crypto-unit)

  add_custom_target(
    xunit
    COMMAND ${CMAKE_BINARY_DIR}/bin/firmware-unit
            --gtest_output=xml:${CMAKE_BINARY_DIR}/unittests/firmware.xml
    COMMAND ${CMAKE_BINARY_DIR}/bin/board-unit
            --gtest_output=xml:${CMAKE_BINARY_DIR}/unittests/board.xml
    COMMAND ${CMAKE_BINARY_DIR}/bin/crypto-unit
            --gtest_output=xml:${CMAKE_BINARY_DIR}/unittests/crypto.xml)

endif()
