if(${KK_EMULATOR})
  set(sources
      main.cpp)

  include_directories(${CMAKE_SOURCE_DIR}/deps/matrix/include)
  include_directories(
      ${CMAKE_SOURCE_DIR}/include
      ${CMAKE_BINARY_DIR}/include
      ${CMAKE_SOURCE_DIR}/deps/crypto/trezor-crypto)

  set(FIRMWARE_LIBS
      kkfirmware
      kkfirmware.keepkey
      kkboard
      kkboard.keepkey
      kkvariant.keepkey
      kkvariant.salt
      kktransport
      trezorcrypto
      trezorqrenc
      kkrand)

  # Standalone emulator binary (uses UDP sockets)
  add_executable(kkemu ${sources})
  target_link_libraries(kkemu ${FIRMWARE_LIBS} kkemulator)

  # Shared library (uses ring buffers, no sockets)
  if(KK_BUILD_DYLIB)
    target_link_libraries(kkemulator_dylib ${FIRMWARE_LIBS})
  endif()
endif()
