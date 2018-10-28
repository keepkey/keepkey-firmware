if(NOT ${KK_EMULATOR})

  set(sources
      main.c
      startup.s)

  include_directories(
      ${CMAKE_SOURCE_DIR}/include
      ${CMAKE_BINARY_DIR}/include
      ${CMAKE_SOURCE_DIR}/deps/crypto/trezor-crypto)

  set(linker_script ${CMAKE_CURRENT_SOURCE_DIR}/bootstrap.ld)

  set(CMAKE_EXE_LINKER_FLAGS
      "${CMAKE_EXE_LINKER_FLAGS} -T${linker_script} -L${CMAKE_BINARY_DIR}/lib")

  add_executable(bootstrap.elf ${sources})
  target_link_libraries(bootstrap.elf
      -lopencm3_stm32f2
      -lc
      -lm)
  add_custom_command(TARGET bootstrap.elf
      POST_BUILD
      COMMAND ${CMAKE_OBJCOPY} ARGS -O binary
          ${CMAKE_BINARY_DIR}/bin/bootstrap.elf
          ${CMAKE_BINARY_DIR}/bin/bootstrap.bin)

endif()
