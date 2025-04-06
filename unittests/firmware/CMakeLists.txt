set(sources
    coins.cpp
    recovery.cpp
    storage.cpp
    usb_rx.cpp
    u2f.cpp)

if("${COIN_SUPPORT}" STREQUAL "BTC")
else()    
  list(APPEND sources
  cosmos.cpp
  eos.cpp
  ethereum.cpp
  nano.cpp
  ripple.cpp)
endif()

include_directories(
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/lib/firmware
    ${CMAKE_BINARY_DIR}/include
    ${CMAKE_SOURCE_DIR}/deps/crypto/hw-crypto)

add_executable(firmware-unit ${sources})
target_link_libraries(firmware-unit
    gmock_main
    kkfirmware
    kkfirmware.keepkey
    kkboard
    kkboard.keepkey
    kkvariant.keepkey
    kkvariant.salt
    kkboard
    kkemulator
    hwcrypto
    qrcodegenerator
    SecAESSTM32
    kkrand
    kktransport)

# these nanopb files need to be removed and since this is the last binary built, they
# are set to be removed post-build. See lib/CMakeLists.txt for further explanation.
set(nanopb_rmsources
  ${CMAKE_SOURCE_DIR}/lib/transport/pb_common.c
  ${CMAKE_SOURCE_DIR}/lib/transport/pb_decode.c
  ${CMAKE_SOURCE_DIR}/lib/transport/pb_encode.c)

set(nanopb_rminc
  ${CMAKE_SOURCE_DIR}/include/pb_common.h
  ${CMAKE_SOURCE_DIR}/include/pb_decode.h
  ${CMAKE_SOURCE_DIR}/include/pb_encode.h
  ${CMAKE_SOURCE_DIR}/include/pb.h)

  add_custom_command(TARGET firmware-unit
  POST_BUILD
  COMMAND
    ${CMAKE_COMMAND} -E rm ${nanopb_rmsources}
  COMMAND
    ${CMAKE_COMMAND} -E rm ${nanopb_rminc}
  COMMAND_EXPAND_LISTS)
