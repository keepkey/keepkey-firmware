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

  # Standalone emulator binary — UDP sockets on :11044/:11045 (used by firmware
  # CI: python-keepkey UDP tests + OLED screenshots). NOT built on Windows: it
  # depends on BSD sockets + signal(); the vault never uses it — the vault loads
  # the dylib/DLL below instead.
  if(NOT WIN32)
    add_executable(kkemu ${sources})

    # Add linker flags for ARM64 Mac compatibility
    if(APPLE AND CMAKE_SYSTEM_PROCESSOR MATCHES "arm64")
      target_link_options(kkemu PRIVATE "-Wl,-no_fixup_chains")
    endif()

    target_link_libraries(kkemu ${FIRMWARE_LIBS} kkemulator)
  endif()

  # Shared library (ring buffers, no sockets) for in-process FFI — this is what
  # the vault loads via bun:ffi (libkkemu.dylib on macOS, .so on Linux, .dll on
  # Windows).
  if(KK_BUILD_DYLIB)
    if(WIN32)
      # kkrand and trezorcrypto cross-reference each other (random32 /
      # random_uniform). GNU/MinGW ld resolves static archives left-to-right in
      # a single pass, so wrap FIRMWARE_LIBS in a linker group. Use the raw
      # --start-group/--end-group flags rather than the LINK_GROUP genex: the
      # genex needs CMake >= 3.24, but this repo's cmake_minimum_required is
      # 3.7.2. macOS ld64 is multi-pass and needs neither.
      # Also: MinGW exports nothing from a DLL by default (unlike Mach-O/ELF),
      # so export the kkemu_* FFI entry points; and link the Windows CSPRNG
      # (bcrypt, BCryptGenRandom) used by setup.c / rng.c on _WIN32.
      target_link_libraries(kkemulator_dylib
          -Wl,--start-group ${FIRMWARE_LIBS} -Wl,--end-group bcrypt)
      target_link_options(kkemulator_dylib PRIVATE "-Wl,--export-all-symbols")
    else()
      target_link_libraries(kkemulator_dylib ${FIRMWARE_LIBS})
      if(APPLE AND CMAKE_SYSTEM_PROCESSOR MATCHES "arm64")
        target_link_options(kkemulator_dylib PRIVATE "-Wl,-no_fixup_chains")
      endif()
    endif()
  endif()
endif()
