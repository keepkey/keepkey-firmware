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
    ${CMAKE_SOURCE_DIR}/deps/crypto/trezor-crypto)

add_executable(firmware-unit ${sources})

set(libraries
    gmock_main
    kkfirmware
    kkfirmware.keepkey
    kkboard
    kkboard.keepkey
    kkvariant.keepkey
    kkboard
    kkemulator
    trezorcrypto
    qrcodegenerator
    SecAESSTM32
    kkrand
    kktransport)

if("${COIN_SUPPORT}" STREQUAL "BTC")
else()
    list(APPEND libraries kkvariant.salt)
endif()

target_link_libraries(firmware-unit ${libraries})
