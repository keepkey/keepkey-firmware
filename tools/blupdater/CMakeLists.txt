if(NOT ${KK_EMULATOR})
  set(sources
      main.c
      startup.s
      ../bootloader/bl_mpu.c
      ../bootloader/isr.s)

  include_directories(
      ${CMAKE_SOURCE_DIR}/include
      ${CMAKE_BINARY_DIR}/include
      ${CMAKE_SOURCE_DIR}/deps/crypto/trezor-crypto)

  set(linker_script ${CMAKE_CURRENT_SOURCE_DIR}/blupdater.ld)

  set(CMAKE_EXE_LINKER_FLAGS
      "${CMAKE_EXE_LINKER_FLAGS} -T${linker_script} -L${CMAKE_BINARY_DIR}/lib")

  set(LINK_FLAGS
      kkfirmware
      kkboard
      kktransport
      trezorcrypto
      -lopencm3_stm32f2
      -lc
      -lm)

  add_executable(blupdater.elf ${sources})
  target_link_libraries(blupdater.elf
      kkboard
      trezorcrypto
      kkrand
      -lopencm3_stm32f2
      -lc
      -lm)
  add_custom_command(TARGET blupdater.elf
      POST_BUILD
      COMMAND ${CMAKE_OBJCOPY} ARGS -O binary
          ${CMAKE_BINARY_DIR}/bin/blupdater.elf
          ${CMAKE_BINARY_DIR}/bin/blupdater.bin)

endif()
