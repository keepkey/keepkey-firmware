if(${KK_EMULATOR})

  set(sources
      oled.c
      udp.c
      setup.c)



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
        ${CMAKE_SOURCE_DIR}/deps/crypto/trezor-crypto)
    set_target_properties(kkemulator_dylib PROPERTIES
        OUTPUT_NAME "kkemu"
        POSITION_INDEPENDENT_CODE ON)
  endif()

endif()
