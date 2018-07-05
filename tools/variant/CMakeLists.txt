if(NOT ${KK_EMULATOR})
  include_directories(
      ${CMAKE_SOURCE_DIR}/include
      ${CMAKE_BINARY_DIR}/include)

  set(linker_script ${CMAKE_CURRENT_SOURCE_DIR}/variant.ld)

  set(CMAKE_EXE_LINKER_FLAGS
      "${CMAKE_EXE_LINKER_FLAGS} -T${linker_script} -L${CMAKE_BINARY_DIR}/lib")

  add_executable(variant.keepkey.elf keepkey.c)
  target_link_libraries(variant.keepkey.elf
      -Wl,--whole-archive kkvariant.keepkey -Wl,--no-whole-archive)
  add_custom_command(TARGET variant.keepkey.elf
      POST_BUILD
      COMMAND ${CMAKE_OBJCOPY} ARGS -O binary
          ${CMAKE_BINARY_DIR}/bin/variant.keepkey.elf
          ${CMAKE_BINARY_DIR}/bin/variant.keepkey.bin)

  add_executable(variant.salt.elf salt.c)
  target_link_libraries(variant.salt.elf
      -Wl,--whole-archive kkvariant.salt -Wl,--no-whole-archive)
  add_custom_command(TARGET variant.salt.elf
      POST_BUILD
      COMMAND ${CMAKE_OBJCOPY} ARGS -O binary
          ${CMAKE_BINARY_DIR}/bin/variant.salt.elf
          ${CMAKE_BINARY_DIR}/bin/variant.salt.bin)

  add_executable(variant.fox.elf fox.c)
  add_custom_command(TARGET variant.fox.elf
      POST_BUILD
      COMMAND ${CMAKE_OBJCOPY} ARGS -O binary
          ${CMAKE_BINARY_DIR}/bin/variant.fox.elf
          ${CMAKE_BINARY_DIR}/bin/variant.fox.bin)

endif()
