set(sources
    bip340.cpp
    rand.cpp
    vuln1845.cpp)

include_directories(
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_BINARY_DIR}/include
    ${CMAKE_SOURCE_DIR}/deps/crypto/trezor-firmware/crypto)

add_executable(crypto-unit ${sources})
target_link_libraries(crypto-unit
    gtest_main
    kkfirmware
    kkfirmware.keepkey
    kkboard
    kkboard.keepkey
    kkvariant.keepkey
    kkvariant.salt
    kkrand
    kkemulator
    qrcodegenerator
    trezorcrypto
    kktransport)

# Orchard/Pallas engine + its unit test only exist when privacy is built in.
if(${KK_ZCASH_PRIVACY})
  # Compile the constant-time implementation a second time with test-only
  # operation counters.  Keeping this separate from trezorcrypto ensures the
  # counters are never present in firmware or the normal emulator binary.
  add_executable(pallas-ct-unit
      pallas_ct.cpp
      ${CMAKE_SOURCE_DIR}/deps/crypto/trezor-firmware/crypto/pallas_ct.c
      ${CMAKE_SOURCE_DIR}/deps/crypto/trezor-firmware/crypto/memzero.c)
  target_compile_definitions(pallas-ct-unit PRIVATE PALLAS_CT_TESTING)
  target_include_directories(pallas-ct-unit PRIVATE
      ${CMAKE_SOURCE_DIR}/include
      ${CMAKE_BINARY_DIR}/include
      ${CMAKE_SOURCE_DIR}/deps/crypto/trezor-firmware/crypto)
  target_link_libraries(pallas-ct-unit gtest_main)

  add_executable(zcash-crypto-unit
      ../firmware/zcash.cpp
      ${CMAKE_SOURCE_DIR}/lib/firmware/zcash.c
      ${CMAKE_SOURCE_DIR}/lib/emulator/random.c)
  target_include_directories(zcash-crypto-unit PRIVATE
      ${CMAKE_SOURCE_DIR}/include
      ${CMAKE_SOURCE_DIR}/lib/firmware
      ${CMAKE_SOURCE_DIR}/deps/crypto/trezor-firmware/crypto
      ${CMAKE_SOURCE_DIR}/deps/crypto/trezor-firmware/crypto/ed25519-donna)
  target_link_libraries(zcash-crypto-unit
      gtest_main
      trezorcrypto
      kkrand)
  if(WIN32)
    target_link_libraries(zcash-crypto-unit bcrypt)
  endif()
endif()
