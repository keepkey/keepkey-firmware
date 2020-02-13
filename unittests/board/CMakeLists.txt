set(sources
    memcmp_s.cpp
    board.cpp)

include_directories(
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_BINARY_DIR}/include
    ${CMAKE_SOURCE_DIR}/deps/crypto/trezor-crypto)

add_executable(board-unit ${sources})
target_link_libraries(board-unit
    gtest_main
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
    kkemulator
    kkrand
    kktransport)
