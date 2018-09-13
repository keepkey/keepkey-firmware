if(${KK_EMULATOR})

  set(sources
      oled.c
      udp.c
      setup.c)

  if(NOT ${KK_HAVE_STRLCPY})
      set(sources ${sources} strlcpy.c)
  endif()

  if(NOT ${KK_HAVE_STRLCAT})
      set(sources ${sources} strlcat.c)
  endif()

  include_directories(
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_BINARY_DIR}/include)

  add_library(kkemulator ${sources})

endif()
