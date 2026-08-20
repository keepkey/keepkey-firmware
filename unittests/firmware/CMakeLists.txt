set(sources
    binance.cpp
    coins.cpp
    cosmos.cpp
    eos.cpp
    ethereum.cpp
    nano.cpp
    recovery.cpp
    setup_ceremony.cpp
    ripple.cpp
    solana.cpp
    storage.cpp
    usb_rx.cpp
    u2f.cpp)

include_directories(
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/lib/firmware
    ${CMAKE_BINARY_DIR}/include
    ${CMAKE_SOURCE_DIR}/deps/crypto/trezor-crypto)

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
    trezorcrypto
    qrcodegenerator
    SecAESSTM32
    kkrand
    kkemulator
    kktransport)
