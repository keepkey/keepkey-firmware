set(sources
    board.cpp)

include_directories(
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_BINARY_DIR}/include)

add_executable(board-unit ${sources})
target_link_libraries(board-unit
    gtest_main
    kkfirmware
    kkfirmware.keepkey
    kkboard
    kkboard.keepkey
    kkvariant.keepkey
    kkboard
    kkcrypto
    kkrand
    kktransport)
