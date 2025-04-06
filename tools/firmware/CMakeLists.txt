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
      ${CMAKE_SOURCE_DIR}/deps/crypto/hw-crypto)

  set(linker_script ${CMAKE_CURRENT_SOURCE_DIR}/keepkey.ld)

  set(CMAKE_EXE_LINKER_FLAGS
      "${CMAKE_EXE_LINKER_FLAGS} -T${linker_script} -L${CMAKE_BINARY_DIR}/lib")

  if("${DEVDEBUG}" STREQUAL "true")
    set(targtype -lopencm3_stm32f4)
  else()
    set(targtype -lopencm3_stm32f2)
  endif()

  add_executable(${TARGESTR} ${sources})
  
  set(libraries
    kkfirmware
    kkfirmware.keepkey
    kkboard
    kkboard.keepkey
    kkvariant.keepkey
    kktransport
    hwcrypto
    qrcodegenerator
    SecAESSTM32
    kkrand)

  if("${COIN_SUPPORT}" STREQUAL "BTC")
  else()
    list(APPEND libraries
      kkvariant.salt
    )
  endif()

# these nanopb files need to be removed and since this is the last binary built, they
# are set to be removed post-build. See lib/CMakeLists.txt for further explanation.
  set(nanopb_rmsources
    ${CMAKE_SOURCE_DIR}/lib/transport/pb_common.c
    ${CMAKE_SOURCE_DIR}/lib/transport/pb_decode.c
    ${CMAKE_SOURCE_DIR}/lib/transport/pb_encode.c)

  set(nanopb_rminc
    ${CMAKE_SOURCE_DIR}/include/pb_common.h
    ${CMAKE_SOURCE_DIR}/include/pb_decode.h
    ${CMAKE_SOURCE_DIR}/include/pb_encode.h
    ${CMAKE_SOURCE_DIR}/include/pb.h)

  target_link_libraries(${TARGESTR}
      ${libraries}
      ${targtype}
      -lc
      -lm)

  add_custom_command(TARGET ${TARGESTR}
    POST_BUILD
    COMMAND ${CMAKE_OBJCOPY} ARGS -O binary
      ${CMAKE_BINARY_DIR}/bin/${TARGESTR}
      ${CMAKE_BINARY_DIR}/bin/${TARGBSTR}
    COMMAND
      ${CMAKE_COMMAND} -E rm ${nanopb_rmsources}
    COMMAND
      ${CMAKE_COMMAND} -E rm ${nanopb_rminc}
    COMMAND_EXPAND_LISTS)

endif() # KK_EMULATOR