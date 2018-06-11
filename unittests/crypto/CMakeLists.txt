set(sources
    rand.cpp)

include_directories(
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_BINARY_DIR}/include)

add_executable(crypto-unit ${sources})
target_link_libraries(crypto-unit
    gtest_main
    kkfirmware
    kkfirmware.keepkey
    kkboard
    kkboard.keepkey
    kkvariant
    kkvariant.keepkey
    kkcrypto
    kkrand
    kktransport)
