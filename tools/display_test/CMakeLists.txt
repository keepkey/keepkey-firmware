if("${VARIANTS}" STREQUAL "NoObsoleteVariants")
  return()
endif()

if(NOT ${KK_EMULATOR})
  set(sources
      main.c
      startup.s)

  include_directories(
      ${CMAKE_SOURCE_DIR}/include
      ${CMAKE_BINARY_DIR}/include
      ${CMAKE_SOURCE_DIR}/deps/crypto/hw-crypto)

  set(linker_script ${CMAKE_CURRENT_SOURCE_DIR}/display_test.ld)

  set(CMAKE_EXE_LINKER_FLAGS
      "${CMAKE_EXE_LINKER_FLAGS} -T${linker_script} -L${CMAKE_BINARY_DIR}/lib")

  if("${DEVDEBUG}" STREQUAL "true")
    set(targtype -lopencm3_stm32f4)
  else()
    set(targtype -lopencm3_stm32f2)
  endif()
    
  add_executable(display_test.elf ${sources})
  target_link_libraries(display_test.elf
      kkfirmware
      kkfirmware.keepkey
      kkboard
      kkboard.keepkey
      kkvariant.keepkey
      kktransport
      hwcrypto
      kkrand
      ${targtype}
      -lc
      -lm)
  add_custom_command(TARGET display_test.elf
      POST_BUILD
      COMMAND ${CMAKE_OBJCOPY} ARGS -O binary
          ${CMAKE_BINARY_DIR}/bin/display_test.elf
          ${CMAKE_BINARY_DIR}/bin/display_test.bin)

endif()
