set(sources
    variant.c)

include_directories(
  ${CMAKE_SOURCE_DIR}/include
  ${CMAKE_BINARY_DIR}/include
  ${CMAKE_CURRENT_SOURCE_DIR})

add_library(kkvariant ${sources})
#add_dependencies(kkvariant )

add_library(kkvariant.keepkey
    ${CMAKE_CURRENT_SOURCE_DIR}/keepkey.c)
