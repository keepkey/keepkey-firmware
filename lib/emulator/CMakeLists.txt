if(${KK_EMULATOR})

  set(sources
      oled.c
      udp.c
      setup.c)



  include_directories(
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_BINARY_DIR}/include)

  # The standalone UDP transport uses BSD sockets and is not built on Win32.
  # Windows consumers load only the ring-buffer DLL below.
  if(NOT WIN32)
    add_library(kkemulator ${sources})
  endif()

  # ── Shared library target (libkkemu.dylib / libkkemu.so) ──────────
  if(KK_BUILD_DYLIB)
    set(dylib_sources
        oled.c
        udp.c
        setup.c
        ringbuf.c
        libkkemu.c)

    if(NOT KK_HAVE_STRLCPY)
        list(APPEND dylib_sources ${CMAKE_CURRENT_SOURCE_DIR}/../board/strlcpy.c)
    endif()
    if(NOT KK_HAVE_STRLCAT)
        list(APPEND dylib_sources ${CMAKE_CURRENT_SOURCE_DIR}/../board/strlcat.c)
    endif()

    add_library(kkemulator_dylib SHARED ${dylib_sources})
    target_compile_definitions(kkemulator_dylib PRIVATE KKEMU_DYLIB=1)
    target_include_directories(kkemulator_dylib PRIVATE
        ${CMAKE_SOURCE_DIR}/include
        ${CMAKE_BINARY_DIR}/include
        ${CMAKE_SOURCE_DIR}/deps/crypto/trezor-crypto)
    # libkkemu.c runs the firmware event loop on a dedicated thread (POSIX
    # pthreads; Win32 CreateThread under MinGW). Threads::Threads is a no-op on
    # the Win32 path and pulls in -lpthread on POSIX. Use the PLAIN signature —
    # the FIRMWARE_LIBS link below is plain, and CMake forbids mixing keyword
    # (PRIVATE) and plain target_link_libraries calls.
    find_package(Threads REQUIRED)
    target_link_libraries(kkemulator_dylib Threads::Threads)
    set_target_properties(kkemulator_dylib PROPERTIES
        OUTPUT_NAME "kkemu"
        POSITION_INDEPENDENT_CODE ON)
  endif()

  set(FIRMWARE_LIBS kkfirmware kkfirmware.keepkey kkboard kkboard.keepkey
      kkvariant.keepkey kkvariant.salt kktransport trezorcrypto qrcodegenerator
      SecAESSTM32 kkrand)
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
      set_property(TARGET kkemulator_dylib APPEND_STRING PROPERTY LINK_FLAGS
          " -Wl,--export-all-symbols")
    else()
      target_link_libraries(kkemulator_dylib ${FIRMWARE_LIBS})
      if(APPLE AND CMAKE_SYSTEM_PROCESSOR MATCHES "arm64")
        set_property(TARGET kkemulator_dylib APPEND_STRING PROPERTY LINK_FLAGS
            " -Wl,-no_fixup_chains")
      endif()
    endif()
  endif()
endif()
