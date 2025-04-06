set(sources
    memcmp_s.cpp
    board.cpp)

include_directories(
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_BINARY_DIR}/include
    ${CMAKE_SOURCE_DIR}/deps/crypto/hw-crypto)

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
    hwcrypto
    qrcodegenerator
    SecAESSTM32
    kkemulator
    kkrand
    kktransport)
