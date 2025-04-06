if(NOT ${KK_EMULATOR})
  set(sources
      main.c
      startup.s
      ../bootloader/bl_mpu.c
      ../bootloader/isr.s
      header.s)

  include_directories(
      ${CMAKE_SOURCE_DIR}/include
      ${CMAKE_BINARY_DIR}/include
      ${CMAKE_SOURCE_DIR}/deps/crypto/hw-crypto)

  set(linker_script ${CMAKE_CURRENT_SOURCE_DIR}/blupdater.ld)

  set(CMAKE_EXE_LINKER_FLAGS
      "${CMAKE_EXE_LINKER_FLAGS} -T${linker_script} -L${CMAKE_BINARY_DIR}/lib")

  add_library(payload
      STATIC payload.o)

  add_custom_command(OUTPUT payload.o
      DEPENDS ${CMAKE_BINARY_DIR}/bin/bootloader.elf
      COMMAND ${CMAKE_OBJCOPY} ARGS -O binary
          ${CMAKE_BINARY_DIR}/bin/bootloader.elf
          ${CMAKE_BINARY_DIR}/bin/payload.bin
      COMMAND cd ${CMAKE_BINARY_DIR}/bin && ${CMAKE_LINKER} -r -b binary -o ${CMAKE_CURRENT_BINARY_DIR}/payload.o payload.bin
      COMMAND ${CMAKE_OBJCOPY} --rename-section .data=.rodata,alloc,load,readonly,data,contents ${CMAKE_CURRENT_BINARY_DIR}/payload.o ${CMAKE_CURRENT_BINARY_DIR}/payload.o)

  set_source_files_properties(payload.o
      PROPERTIES
      EXTERNAL_OBJECT true
      GENERATED true)

  set_target_properties(payload
      PROPERTIES
      LINKER_LANGUAGE C)

  add_executable(blupdater.elf ${sources})

  if("${DEVDEBUG}" STREQUAL "true")
    set(targtype -lopencm3_stm32f4)
  else()
    set(targtype -lopencm3_stm32f2)
  endif()

  target_link_libraries(blupdater.elf
      payload
      kkboard
      kkboard.keepkey
      kkvariant.keepkey
      hwcrypto
      kkrand
      ${targtype}
      -lc
      -lm)
  add_custom_command(TARGET blupdater.elf
      POST_BUILD
      COMMAND ${CMAKE_OBJCOPY} ARGS -O binary
          ${CMAKE_BINARY_DIR}/bin/blupdater.elf
          ${CMAKE_BINARY_DIR}/bin/blupdater.bin)

  add_custom_command(TARGET blupdater.elf
      POST_BUILD
      COMMAND echo "Bootloader Hash:"
      COMMAND cat ${CMAKE_BINARY_DIR}/bin/bootloader.bin | openssl dgst -sha256 -binary | openssl dgst -sha256)

endif()
