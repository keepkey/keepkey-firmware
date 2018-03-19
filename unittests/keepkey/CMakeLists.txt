set(sources ethereum.cpp)

add_executable(keepkey_unittests ${sources})
target_link_libraries(keepkey_unittests gtest_main kkfirmware kkfirmware.keepkey kkboard kkboard.keepkey kkcrypto kktransport)
