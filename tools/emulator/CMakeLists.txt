if(${KK_EMULATOR})
  set(sources
      main.cpp)

  include_directories(${CMAKE_SOURCE_DIR}/deps/matrix/include)
  include_directories(
      ${CMAKE_SOURCE_DIR}/include
      ${CMAKE_BINARY_DIR}/include)

  add_executable(kkemu ${sources})

  target_link_libraries(kkemu
      kkfirmware
      kkboard
      kkrand
      kkemulator)
endif()
