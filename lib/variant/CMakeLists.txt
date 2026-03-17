include_directories(
  ${CMAKE_SOURCE_DIR}/include
  ${CMAKE_BINARY_DIR}/include
  ${CMAKE_CURRENT_SOURCE_DIR})

if("${COIN_SUPPORT}" STREQUAL "BTC")
  add_library(kkvariant.keepkey
      ${CMAKE_CURRENT_SOURCE_DIR}/keepkey/keepkey.c
      ${CMAKE_CURRENT_SOURCE_DIR}/keepkey/logobtc.c)
else()
  add_library(kkvariant.keepkey
      ${CMAKE_CURRENT_SOURCE_DIR}/keepkey/keepkey.c
      ${CMAKE_CURRENT_SOURCE_DIR}/keepkey/logo.c)
endif()

add_library(kkvariant.salt
    ${CMAKE_CURRENT_SOURCE_DIR}/salt/salt.c
    ${CMAKE_CURRENT_SOURCE_DIR}/salt/logo.c)

add_library(kkvariant.poweredBy
    ${CMAKE_CURRENT_SOURCE_DIR}/poweredBy/poweredBy.c
    ${CMAKE_CURRENT_SOURCE_DIR}/poweredBy/logo.c)



