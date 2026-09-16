# The Linux emulator builder uses an old Clang without C11 stdatomic.h; this
# dylib-specific regression runs in the macOS dylib job with a C11 toolchain.
if(APPLE)
# Inject the post-timeout state into the real implementation in a standalone
# translation unit, without exposing a production FFI for forcing a wedge.
add_executable(emulator-wedge-unit wedged_poll.c
    ${CMAKE_SOURCE_DIR}/lib/emulator/oled.c
    ${CMAKE_SOURCE_DIR}/lib/emulator/udp.c
    ${CMAKE_SOURCE_DIR}/lib/emulator/setup.c
    ${CMAKE_SOURCE_DIR}/lib/emulator/random.c
    ${CMAKE_SOURCE_DIR}/lib/emulator/ringbuf.c)
target_compile_definitions(emulator-wedge-unit PRIVATE KKEMU_DYLIB=1)
target_include_directories(emulator-wedge-unit PRIVATE
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_BINARY_DIR}/include
    ${CMAKE_SOURCE_DIR}/deps/crypto/trezor-firmware)
target_link_libraries(emulator-wedge-unit
    kkfirmware
    kkfirmware.keepkey
    kkboard
    kkboard.keepkey
    kkvariant.keepkey
    kkvariant.salt
    trezorcrypto
    qrcodegenerator
    SecAESSTM32
    kkrand
    kktransport)
find_package(Threads REQUIRED)
target_link_libraries(emulator-wedge-unit Threads::Threads)
if(APPLE)
  set_property(TARGET emulator-wedge-unit APPEND_STRING PROPERTY LINK_FLAGS
               " -Wl,-no_fixup_chains")
endif()
endif()
