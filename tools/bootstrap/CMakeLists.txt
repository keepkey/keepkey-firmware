if(NOT ${KK_EMULATOR})

  set(sources
      main.c)

  include_directories(
      ${CMAKE_SOURCE_DIR}/include
      ${CMAKE_BINARY_DIR}/include)

  set(linker_script ${CMAKE_CURRENT_SOURCE_DIR}/bootstrap.ld)

  set(CMAKE_EXE_LINKER_FLAGS
      "${CMAKE_EXE_LINKER_FLAGS} -T${linker_script} -L${CMAKE_BINARY_DIR}/lib")

  add_executable(bootstrap.salt.elf ${sources})
  target_link_libraries(bootstrap.salt.elf
      kkboard
      kkboard.salt
      kktransport
      kkcrypto
      -lopencm3_stm32f2
      -lc
      -lm)
  add_custom_command(TARGET bootstrap.salt.elf
      POST_BUILD
      COMMAND ${CMAKE_OBJCOPY} ARGS -O binary
          ${CMAKE_BINARY_DIR}/bin/bootstrap.salt.elf
          ${CMAKE_BINARY_DIR}/bin/bootstrap.salt.bin)

  add_executable(bootstrap.keepkey.elf ${sources})
  target_link_libraries(bootstrap.keepkey.elf
      kkboard
      kkboard.keepkey
      kktransport
      kkcrypto
      -lopencm3_stm32f2
      -lc
      -lm)
  add_custom_command(TARGET bootstrap.keepkey.elf
      POST_BUILD
      COMMAND ${CMAKE_OBJCOPY} ARGS -O binary
          ${CMAKE_BINARY_DIR}/bin/bootstrap.keepkey.elf
          ${CMAKE_BINARY_DIR}/bin/bootstrap.keepkey.bin)

endif()
