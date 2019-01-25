include_directories(
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/lib/firmware
    ${CMAKE_BINARY_DIR}/include
    ${CMAKE_SOURCE_DIR}/deps/crypto/trezor-crypto)

set(libraries
    kkfirmware
    kkfirmware.keepkey
    kkboard
    kkboard.keepkey
    kkvariant.keepkey
    kkvariant.salt
    kkboard
    kkemulator
    trezorcrypto
    trezorqrenc
    kkrand
    kktransport)

add_executable(fuzz-eos_formatName eos_formatName.cpp)
target_link_libraries(fuzz-eos_formatName ${libraries})

add_executable(fuzz-eos_formatAsset eos_formatAsset.cpp)
target_link_libraries(fuzz-eos_formatAsset ${libraries})
