set(sources
    version.c
    storage.c)

configure_file("${CMAKE_CURRENT_SOURCE_DIR}/scm_revision.h.in"
               "${CMAKE_CURRENT_BINARY_DIR}/scm_revision.h" @ONLY)

include_directories(
  ${CMAKE_BINARY_DIR}/include
  ${CMAKE_SOURCE_DIR}/lib/firmware
  ${CMAKE_CURRENT_BINARY_DIR})

add_library(kkfirmware ${sources})
