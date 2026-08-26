# Every .cpp in this directory belongs here. thorchain.cpp and mayachain.cpp
# existed on disk since 2019/2021 but were never listed, so nothing in them
# ever compiled -- including the memo-disclosure regression added by this
# release. A test that is not built is not a test.
set(sources
    binance.cpp
    coins.cpp
    cosmos.cpp
    eos.cpp
    ethereum.cpp
    fsm.cpp
    mayachain.cpp
    osmosis.cpp
    nano.cpp
    recovery.cpp
    setup_ceremony.cpp
    ripple.cpp
    solana.cpp
    storage.cpp
    thorchain.cpp
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
