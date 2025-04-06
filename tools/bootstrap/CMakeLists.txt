if(NOT ${KK_EMULATOR})
  set(sources
      main.c
      startup.s)

  include_directories(
      ${CMAKE_SOURCE_DIR}/include
      ${CMAKE_BINARY_DIR}/include
      ${CMAKE_SOURCE_DIR}/deps/crypto/hw-crypto)

  set(linker_script ${CMAKE_CURRENT_SOURCE_DIR}/bootstrap.ld)

  if(CMAKE_C_COMPILER_VERSION VERSION_LESS "12.2.1")
    set(warnopt "")
  else()
    set(warnopt "-Wl,--no-warn-rwx-segments")
  endif()

  set(CMAKE_EXE_LINKER_FLAGS
      "${CMAKE_EXE_LINKER_FLAGS} ${warnopt} -T${linker_script} -L${CMAKE_BINARY_DIR}/lib")

  if("${DEVDEBUG}" STREQUAL "true")
    set(targtype -lopencm3_stm32f4)
  else()
    set(targtype -lopencm3_stm32f2)
  endif()
    
  add_executable(bootstrap.elf ${sources})
  target_link_libraries(bootstrap.elf
      ${targtype}
      -lc
      -lm)
  add_custom_command(TARGET bootstrap.elf
      POST_BUILD
      COMMAND ${CMAKE_OBJCOPY} ARGS -O binary
          ${CMAKE_BINARY_DIR}/bin/bootstrap.elf
          ${CMAKE_BINARY_DIR}/bin/bootstrap.bin)

endif()
