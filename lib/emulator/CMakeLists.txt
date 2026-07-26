if(${KK_EMULATOR})

  set(sources
      oled.c
      udp.c
      setup.c
      random.c)



  include_directories(
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_BINARY_DIR}/include)

  add_library(kkemulator ${sources})

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
    # the Win32 path and pulls in -lpthread on POSIX. Use the PLAIN signature —
    # tools/emulator/CMakeLists.txt links this same target plainly, and CMake
    # forbids mixing keyword (PRIVATE) and plain target_link_libraries calls.
    find_package(Threads REQUIRED)
    target_link_libraries(kkemulator_dylib Threads::Threads)
    set_target_properties(kkemulator_dylib PROPERTIES
        OUTPUT_NAME "kkemu"
        POSITION_INDEPENDENT_CODE ON)
  endif()

endif()
