if(${KK_EMULATOR})

  set(sources
      oled.c
      udp.c
      setup.c
      random.c)



  include_directories(
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_BINARY_DIR}/include)

  # The standalone emulator and native unit targets are POSIX-only. Windows
  # builds the in-process DLL below, which uses ring buffers and does not need
  # setup(), mmap(), or BSD UDP sockets.
  if(NOT WIN32)
    add_library(kkemulator ${sources})
  endif()

  # ── Shared library target (libkkemu.dylib / libkkemu.so) ──────────
  if(KK_BUILD_DYLIB)
    set(dylib_sources
        oled.c
        udp.c
        setup.c
        random.c
        ringbuf.c
        libkkemu.c)

    if(NOT ${KK_HAVE_STRLCPY})
        set(dylib_sources ${dylib_sources} strlcpy.c)
    endif()
    if(NOT ${KK_HAVE_STRLCAT})
        set(dylib_sources ${dylib_sources} strlcat.c)
    endif()

    add_library(kkemulator_dylib SHARED ${dylib_sources})
    target_compile_definitions(kkemulator_dylib PRIVATE KKEMU_DYLIB=1)
    target_include_directories(kkemulator_dylib PRIVATE
        ${CMAKE_SOURCE_DIR}/include
        ${CMAKE_BINARY_DIR}/include
        ${CMAKE_SOURCE_DIR}/deps/crypto/trezor-firmware/crypto)
    # libkkemu.c runs the firmware event loop on a dedicated thread (POSIX
    # pthreads; Win32 CreateThread under MinGW). Threads::Threads is a no-op on
    # the Win32 path and pulls in -lpthread on POSIX. Keep the plain signature
    # for compatibility with the repository's CMake 3.7 minimum.
    find_package(Threads REQUIRED)
    target_link_libraries(kkemulator_dylib Threads::Threads)
    if(WIN32)
      # These static archives cross-reference each other. Keep this in the
      # target's defining directory so CMake 3.7 does not need CMP0079.
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
    set_target_properties(kkemulator_dylib PROPERTIES
        OUTPUT_NAME "kkemu"
        POSITION_INDEPENDENT_CODE ON)
  endif()

endif()
