set(sources
    ethereum.cpp)

add_executable(firmware-unit ${sources})
target_link_libraries(firmware-unit
    gtest_main
    kkfirmware
    kkfirmware.keepkey
    kkboard
    kkboard.keepkey
    kkcrypto
    kktransport)
