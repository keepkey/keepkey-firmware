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
      qrcodegenerator
      SecAESSTM32
      kkrand)

  # Standalone emulator binary (uses UDP sockets)
  add_executable(kkemu ${sources})

  # Add linker flags for ARM64 Mac compatibility
  if(APPLE AND CMAKE_SYSTEM_PROCESSOR MATCHES "arm64")
    target_link_options(kkemu PRIVATE "-Wl,-no_fixup_chains")
  endif()

  target_link_libraries(kkemu ${FIRMWARE_LIBS} kkemulator)

  # Shared library (ring buffers, no sockets) for in-process FFI (vault)
  if(KK_BUILD_DYLIB)
    target_link_libraries(kkemulator_dylib ${FIRMWARE_LIBS})
    if(APPLE AND CMAKE_SYSTEM_PROCESSOR MATCHES "arm64")
      target_link_options(kkemulator_dylib PRIVATE "-Wl,-no_fixup_chains")
    endif()
  endif()
endif()
