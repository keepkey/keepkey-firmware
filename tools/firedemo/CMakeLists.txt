if(NOT ${KK_EMULATOR})
  set(sources
      main.c)

  include_directories(
      ${CMAKE_SOURCE_DIR}/include
      ${CMAKE_BINARY_DIR}/include)

  set(linker_script ${CMAKE_CURRENT_SOURCE_DIR}/firedemo.ld)

  set(CMAKE_EXE_LINKER_FLAGS
      "${CMAKE_EXE_LINKER_FLAGS} -T${linker_script} -L${CMAKE_BINARY_DIR}/lib")

  add_executable(firedemo.elf ${sources})
  target_link_libraries(firedemo.elf
      kkboard
      kkrand
      -lopencm3_stm32f2
      -lc
      -lm)
  add_custom_command(TARGET firedemo.elf
      POST_BUILD
      COMMAND ${CMAKE_OBJCOPY} ARGS -O binary
          ${CMAKE_BINARY_DIR}/bin/firedemo.elf
          ${CMAKE_BINARY_DIR}/bin/firedemo.bin)

endif()
