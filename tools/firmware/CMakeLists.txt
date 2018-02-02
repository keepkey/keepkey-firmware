if(NOT ${KK_EMULATOR})
  set(sources
      keepkey_main.c)

  include_directories(
      ${CMAKE_SOURCE_DIR}/include
      ${CMAKE_BINARY_DIR}/include)

  set(linker_script ${CMAKE_CURRENT_SOURCE_DIR}/keepkey.ld)

  set(CMAKE_EXE_LINKER_FLAGS
      "${CMAKE_EXE_LINKER_FLAGS} -T${linker_script} -L${CMAKE_BINARY_DIR}/lib")

  set(LINK_FLAGS
      kkfirmware
      kkboard
      kktransport
      kkcrypto
      -lopencm3_stm32f2
      -lc
      -lm)

  add_executable(firmware.keepkey.bin ${sources})
  target_link_libraries(firmware.keepkey.bin ${LINK_FLAGS} kkfirmware.keepkey kkboard.keepkey)

  add_executable(firmware.salt.bin ${sources})
  target_link_libraries(firmware.salt.bin ${LINK_FLAGS} kkfirmware.salt kkboard.salt)
endif()
