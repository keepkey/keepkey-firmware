set(sources
    font.cpp
    hw_entropy.cpp
    hw_entropy_probe.c
    memcmp_s.cpp
    signatures.cpp
    board.cpp)

# Only this probe compiles the device entropy branch on the native host.
set_source_files_properties(hw_entropy_probe.c PROPERTIES
    INCLUDE_DIRECTORIES ${CMAKE_CURRENT_SOURCE_DIR}/hardware_stubs)

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
    kkrand
    kkemulator
    kktransport)
