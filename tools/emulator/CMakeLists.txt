if(${KK_EMULATOR})
  set(sources
      main.cpp)

  include_directories(${CMAKE_SOURCE_DIR}/deps/matrix/include)
  include_directories(
      ${CMAKE_SOURCE_DIR}/include
      ${CMAKE_BINARY_DIR}/include
      ${CMAKE_SOURCE_DIR}/deps/crypto/trezor-firmware/crypto)

  # Standalone emulator binary — UDP sockets on :11044/:11045 (used by firmware
  # CI: python-keepkey UDP tests + OLED screenshots). NOT built on Windows: it
  # depends on BSD sockets + signal(); the vault never uses it — the vault loads
  # the dylib/DLL below instead.
  if(NOT WIN32)
    add_executable(kkemu ${sources})

    # Add linker flags for ARM64 Mac compatibility
    if(APPLE AND CMAKE_SYSTEM_PROCESSOR MATCHES "arm64")
      set_property(TARGET kkemu APPEND_STRING PROPERTY LINK_FLAGS
                   " -Wl,-no_fixup_chains")
    endif()

    target_link_libraries(kkemu ${FIRMWARE_LIBS} kkemulator)
  endif()

endif()
