set(sources ethereum.cpp)

add_executable(keepkey_unittests ${sources})
target_link_libraries(keepkey_unittests gtest_main keepkey keepkey_board crypto transport)
