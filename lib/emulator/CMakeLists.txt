if(${KK_EMULATOR})

  set(sources
      oled.c
      udp.c
      setup.c)



  include_directories(
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_BINARY_DIR}/include)

  add_library(kkemulator ${sources})

endif()
