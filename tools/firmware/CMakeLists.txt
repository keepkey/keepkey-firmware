if(NOT ${KK_EMULATOR})

  set(TARGESTR "firmware.keepkey.elf")
  set(TARGBSTR "firmware.keepkey.bin")
  if("${COIN_SUPPORT}" STREQUAL "BTC")
    set(TARGESTR "firmware.keepkeybtc.elf")
    set(TARGBSTR "firmware.keepkeybtc.bin")
  endif()

  set(sources
      keepkey_main.c
      startup.s
      ../bootloader/bl_mpu.c
      ../bootloader/isr.s
      header.s)

  include_directories(
      ${CMAKE_SOURCE_DIR}/include
      ${CMAKE_BINARY_DIR}/include
      ${CMAKE_SOURCE_DIR}/deps/crypto/trezor-crypto)

  set(linker_script ${CMAKE_CURRENT_SOURCE_DIR}/keepkey.ld)

  set(CMAKE_EXE_LINKER_FLAGS
      "${CMAKE_EXE_LINKER_FLAGS} -T${linker_script} -L${CMAKE_BINARY_DIR}/lib")

  set(LINK_FLAGS
      kkfirmware
      kkboard
      kktransport
      trezorcrypto
      -lopencm3_stm32f2
      -lc
      -lm)

  add_executable(${TARGESTR} ${sources})

  set(libraries
    kkfirmware
    kkfirmware.keepkey
    kkboard
    kkboard.keepkey
    kkvariant.keepkey
    kktransport
    trezorcrypto
    qrcodegenerator
    SecAESSTM32
    kkrand)

if("${COIN_SUPPORT}" STREQUAL "BTC")
else()
  list(APPEND libraries
    kkvariant.salt
  )
endif()

  target_link_libraries(${TARGESTR}
      ${libraries}
      -lopencm3_stm32f2
      -lc
      -lm)

  add_custom_command(TARGET ${TARGESTR}
    POST_BUILD
    COMMAND ${CMAKE_OBJCOPY} ARGS -O binary
      ${CMAKE_BINARY_DIR}/bin/${TARGESTR}
      ${CMAKE_BINARY_DIR}/bin/${TARGBSTR})

endif()
