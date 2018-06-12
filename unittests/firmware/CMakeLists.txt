set(sources
    ethereum.cpp
    recovery.cpp
    storage.cpp)

include_directories(
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_BINARY_DIR}/include)

add_executable(firmware-unit ${sources})
target_link_libraries(firmware-unit
    gtest_main
    kkfirmware
    kkfirmware.mfr
    kkboard
    kkboard.mfr
    kkvariant.keepkey
    kkvariant.salt
    kkboard
    kkcrypto
    kkrand
    kktransport)
