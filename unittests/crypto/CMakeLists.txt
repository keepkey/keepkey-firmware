set(sources
    rand.cpp
    vuln1845.cpp)

include_directories(
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_BINARY_DIR}/include
    ${CMAKE_SOURCE_DIR}/deps/crypto/hw-crypto)

add_executable(crypto-unit ${sources})

set(libraries
  gtest_main
  kkfirmware
  kkfirmware.keepkey
  kkboard
  kkboard.keepkey
  kkvariant.keepkey
  kkboard
  kkemulator
  qrcodegenerator
  kkrand
  hwcrypto
  kktransport)

if("${COIN_SUPPORT}" STREQUAL "BTC")
else()
  list(APPEND libraries
    kkvariant.salt
  )
endif()

target_link_libraries(crypto-unit
  ${libraries}
  )
