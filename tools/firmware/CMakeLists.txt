if(NOT ${KK_EMULATOR})
  set(sources
      keepkey_main.c)

  include_directories(
      ${CMAKE_SOURCE_DIR}/include
      ${CMAKE_BINARY_DIR}/include)

  set(linker_script ${CMAKE_CURRENT_SOURCE_DIR}/keepkey.ld)

  set(CMAKE_EXE_LINKER_FLAGS
      "${CMAKE_EXE_LINKER_FLAGS} -T${linker_script} -L${CMAKE_BINARY_DIR}/lib")

  set(LINK_FLAGS
      kkfirmware
      kkboard
      kktransport
      kkcrypto
      -lopencm3_stm32f2
      -lc
      -lm)

  add_executable(firmware.keepkey.elf ${sources})
  target_link_libraries(firmware.keepkey.elf
      kkfirmware
      -Wl,--whole-archive kkfirmware.keepkey -Wl,--no-whole-archive
      kkboard
      -Wl,--whole-archive kkboard.keepkey -Wl,--no-whole-archive
      kktransport
      kkcrypto
      kkrand
      -lopencm3_stm32f2
      -lc
      -lm)
  add_custom_command(TARGET firmware.keepkey.elf
      POST_BUILD
      COMMAND ${CMAKE_OBJCOPY} ARGS -O binary
          ${CMAKE_BINARY_DIR}/bin/firmware.keepkey.elf
          ${CMAKE_BINARY_DIR}/bin/firmware.keepkey.bin)

  add_executable(firmware.salt.elf ${sources})
  target_link_libraries(firmware.salt.elf
      kkfirmware
      -Wl,--whole-archive kkfirmware.salt -Wl,--no-whole-archive
      kkboard
      -Wl,--whole-archive kkboard.salt -Wl,--no-whole-archive
      kktransport
      kkcrypto
      kkrand
      -lopencm3_stm32f2
      -lc
      -lm)
  add_custom_command(TARGET firmware.salt.elf
      POST_BUILD
      COMMAND ${CMAKE_OBJCOPY} ARGS -O binary
          ${CMAKE_BINARY_DIR}/bin/firmware.salt.elf
          ${CMAKE_BINARY_DIR}/bin/firmware.salt.bin)

  add_executable(firmware.mfr.elf ${sources})
  target_link_libraries(firmware.mfr.elf
      kkfirmware
      -Wl,--whole-archive kkfirmware.mfr -Wl,--no-whole-archive
      kkboard
      -Wl,--whole-archive kkboard.mfr -Wl,--no-whole-archive
      kktransport
      kkcrypto
      kkrand
      -lopencm3_stm32f2
      -lc
      -lm)
  add_custom_command(TARGET firmware.mfr.elf
      POST_BUILD
      COMMAND ${CMAKE_OBJCOPY} ARGS -O binary
          ${CMAKE_BINARY_DIR}/bin/firmware.mfr.elf
          ${CMAKE_BINARY_DIR}/bin/firmware.mfr.bin)

endif()
