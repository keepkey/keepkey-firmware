if(NOT ${KK_EMULATOR})

  if("${DEVDEBUG}" STREQUAL "true")
    set(LIBCM3TARG opencm3_stm32f4)
    set(ASMDEF "-Xassembler --defsym -Xassembler DEV_DEBUG")
  else()
    set(LIBCM3TARG opencm3_stm32f2)
    set(ASMDEF "")
  endif()

  set(sources
      main.c
      usb_flash.c
      bl_mpu.c
      startup.s
      isr.s)

  include_directories(
      ${CMAKE_SOURCE_DIR}/include
      ${CMAKE_BINARY_DIR}/include
      ${CMAKE_SOURCE_DIR}/deps/crypto/hw-crypto)

  set(linker_script ${CMAKE_CURRENT_SOURCE_DIR}/bootloader.ld)

  set(CMAKE_EXE_LINKER_FLAGS
      "${CMAKE_EXE_LINKER_FLAGS} ${ASMDEF} -T${linker_script} -L${CMAKE_BINARY_DIR}/lib")
  
  add_executable(bootloader.elf ${sources})

  target_link_libraries(bootloader.elf
    kkboard
    kkboard.keepkey
    kkvariant.keepkey
    kkvariant.poweredBy
    kktransport
    hwcrypto
    kkrand
    -l${LIBCM3TARG}
    -lc
    -lm)
  
  add_custom_command(TARGET bootloader.elf
      POST_BUILD
      COMMAND ${CMAKE_OBJCOPY} ARGS -O binary
          ${CMAKE_BINARY_DIR}/bin/bootloader.elf
          ${CMAKE_BINARY_DIR}/bin/bootloader.bin)

endif()
