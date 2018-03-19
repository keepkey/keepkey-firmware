if(NOT ${KK_EMULATOR})

  set(sources
      main.c
      signatures.c
      usb_flash.c)

  include_directories(
      ${CMAKE_SOURCE_DIR}/include
      ${CMAKE_BINARY_DIR}/include)

  set(linker_script ${CMAKE_CURRENT_SOURCE_DIR}/bootloader.ld)

  set(CMAKE_EXE_LINKER_FLAGS
      "${CMAKE_EXE_LINKER_FLAGS} -T${linker_script} -L${CMAKE_BINARY_DIR}/lib")

  add_executable(bootloader.salt.elf ${sources})
  target_link_libraries(bootloader.salt.elf
      kkboard
      kkboard.salt
      kktransport
      kkcrypto
      -lopencm3_stm32f2
      -lc
      -lm)
  add_custom_command(TARGET bootloader.salt.elf
      POST_BUILD
      COMMAND ${CMAKE_OBJCOPY} ARGS -O binary
          ${CMAKE_BINARY_DIR}/bin/bootloader.salt.elf
          ${CMAKE_BINARY_DIR}/bin/bootloader.salt.bin)

  add_executable(bootloader.keepkey.elf ${sources})
  target_link_libraries(bootloader.keepkey.elf
      kkboard
      kkboard.keepkey
      kktransport
      kkcrypto
      -lopencm3_stm32f2
      -lc
      -lm)
  add_custom_command(TARGET bootloader.keepkey.elf
      POST_BUILD
      COMMAND ${CMAKE_OBJCOPY} ARGS -O binary
          ${CMAKE_BINARY_DIR}/bin/bootloader.keepkey.elf
          ${CMAKE_BINARY_DIR}/bin/bootloader.keepkey.bin)

endif()
