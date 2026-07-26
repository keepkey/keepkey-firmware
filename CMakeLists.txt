cmake_minimum_required(VERSION 3.7.2)

# CMP0079: allow target_link_libraries() to reference targets defined in
# a different directory. Required so tools/emulator can add firmware libs
# to kkemulator_dylib (defined in lib/emulator).
if(POLICY CMP0079)
  cmake_policy(SET CMP0079 NEW)
endif()

project(
  KeepKeyFirmware
  VERSION 7.15.0
  LANGUAGES C CXX ASM)

set(BOOTLOADER_MAJOR_VERSION 2)
set(BOOTLOADER_MINOR_VERSION 1)
set(BOOTLOADER_PATCH_VERSION 5)

option(KK_EMULATOR "Build the emulator" OFF)
option(KK_BUILD_DYLIB "Build libkkemu shared library (.dylib/.so)" OFF)
option(KK_DEBUG_LINK "Build with debug-link enabled" OFF)
option(KK_BUILD_FUZZERS "Build the fuzzers?" OFF)
option(KK_BITCOIN_ONLY "Build Bitcoin-only firmware (strip all non-BTC coins)" OFF)
# Zcash shielded/Orchard support is part of the regular firmware. It is an
# internal compile selection, not a third release variant: bitcoin-only strips
# the Zcash coin and privacy engine; every regular device/emulator build ships
# both. The open constant-time Pallas audit finding remains a release gate for
# RC18, but it must not silently change the product being audited.
if(KK_BITCOIN_ONLY)
  set(KK_ZCASH_PRIVACY OFF)
else()
  set(KK_ZCASH_PRIVACY ON)
endif()

# When building the dylib, every static lib it links (kkfirmware, kkboard,
# trezorcrypto, kkrand, kktransport, qrcodegenerator, SecAESSTM32, ...) must
# itself be compiled with -fPIC. macOS happens to be lenient and will produce
# a working .dylib without it; Linux's link step against a non-PIC archive
# fails with "recompile with -fPIC". Set this BEFORE add_subdirectory(lib)
# below so all targets pick it up at definition time. CMP0079 (already set
# above) lets us reach across directories to link them.
if(KK_BUILD_DYLIB)
  set(CMAKE_POSITION_INDEPENDENT_CODE ON)
endif()
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

if(NOT EXISTS ${CMAKE_SOURCE_DIR}/deps/crypto/trezor-firmware/crypto/Makefile)
  message(
    FATAL_ERROR
      "trezor-crypto fork missing. Run 'git submodule update --init deps/crypto/trezor-firmware'"
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
      "Must install nanopb 0.3.9.4, and put nanopb-nanopb-0.3.9.4/generator on your PATH"
  )
endif()

if(${KK_EMULATOR})
  add_definitions(-DEMULATOR)
  add_definitions(-DCONFIDENTIAL=)
  # macOS/BSD declare strlcpy/strlcat in <string.h>; glibc (Linux) and MinGW
  # (Windows) do not. Force-include the prototypes so the ~20 call sites build
  # without -Werror=implicit-function-declaration (definitions come from
  # lib/board/strlcpy.c + strlcat.c). Apple already has them in <string.h>.
  if(NOT APPLE)
    add_compile_options(-include ${CMAKE_SOURCE_DIR}/include/keepkey/board/bsd_compat.h)
  endif()
else()
  add_definitions(-DCONFIDENTIAL=__attribute__\(\(section\("confidential"\)\)\))
endif()

add_definitions(-DSTM32F2=1)

add_definitions(-DED25519_CUSTOMHASH=1)
add_definitions(-DED25519_CUSTOMRANDOM=1)
add_definitions(-DED25519_NO_INLINE_ASM)
add_definitions(-DED25519_FORCE_32BIT=1)

add_definitions(-DUSE_PRECOMPUTED_CP=0)

if(${KK_BITCOIN_ONLY})
  # Bitcoin-only: strip the coin-specific trezor-crypto primitives whose only
  # callers (ethereum.c / nano.c) are compiled out below. KECCAK stays on --
  # marginal size win, and it is a generic hash we don't want to risk.
  add_definitions(-DUSE_ETHEREUM=0)
  add_definitions(-DUSE_NANO=0)
else()
  add_definitions(-DUSE_ETHEREUM=1)
  add_definitions(-DUSE_NANO=1)
endif()
add_definitions(-DUSE_KECCAK=1)
add_definitions(-DUSE_GRAPHENE=0)
add_definitions(-DUSE_CARDANO=0)
add_definitions(-DUSE_MONERO=0)
add_definitions(-DUSE_NEM=0)

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

# NOTE: AES table size is selected per release product below. The regular
# image includes Zcash and its Pallas curve arithmetic, so it uses the smaller
# AES tables to preserve flash headroom. Bitcoin-only keeps FOUR_TABLES AES.

if(${KK_DEBUG_LINK})
  add_definitions(-DDEBUG_LINK=1)
else()
  add_definitions(-DDEBUG_LINK=0)
endif()

# Value macros (always defined 0/1) -- device builds use -Wundef -Werror, so an
# undefined identifier in `#if` is a hard error. Guard code with `#if FLAG`.
if(${KK_BITCOIN_ONLY})
  add_definitions(-DBITCOIN_ONLY=1)
else()
  add_definitions(-DBITCOIN_ONLY=0)
endif()

if(${KK_ZCASH_PRIVACY})
  add_definitions(-DZCASH_PRIVACY=1)
  # The Orchard engine leaves the regular image tightest on flash; shrink the
  # Gladman AES lookup tables from 4KB to 1KB each (-15,360 bytes ROM,
  # slightly slower AES). Bitcoin-only keeps the fast FOUR_TABLES.
  add_definitions(-DAES_SMALL_TABLES)
else()
  add_definitions(-DZCASH_PRIVACY=0)
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

  # Emit per-function stack-frame sizes (.su files) on device builds. CI's
  # SRAM budget gate (tools/check_sram_budget.py) reports the largest frames
  # and fails when the linker-asserted stack reserve minus the largest frame
  # leaves less than the configured margin. See tools/firmware/keepkey.ld.
  add_compile_options(-fstack-usage)

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
  if(${KK_ZCASH_PRIVACY})
    add_test(test-pallas-ct ${CMAKE_BINARY_DIR}/bin/pallas-ct-unit)
    add_test(test-zcash-crypto ${CMAKE_BINARY_DIR}/bin/zcash-crypto-unit)
  endif()

  add_custom_target(
    xunit
    COMMAND ${CMAKE_BINARY_DIR}/bin/firmware-unit
            --gtest_output=xml:${CMAKE_BINARY_DIR}/unittests/firmware.xml
    COMMAND ${CMAKE_BINARY_DIR}/bin/board-unit
            --gtest_output=xml:${CMAKE_BINARY_DIR}/unittests/board.xml
    COMMAND ${CMAKE_BINARY_DIR}/bin/crypto-unit
            --gtest_output=xml:${CMAKE_BINARY_DIR}/unittests/crypto.xml)

  if(${KK_ZCASH_PRIVACY})
    add_custom_command(TARGET xunit POST_BUILD
      COMMAND ${CMAKE_BINARY_DIR}/bin/pallas-ct-unit
              --gtest_output=xml:${CMAKE_BINARY_DIR}/unittests/pallas-ct.xml)
  endif()

endif()
