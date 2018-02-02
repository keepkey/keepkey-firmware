if(NOT ${KK_EMULATOR})

  set(sources
      main.c
      signatures.c
      usb_flash.c)

  include_directories(
      ${CMAKE_SOURCE_DIR}/include
      ${CMAKE_BINARY_DIR}/include)

  set(linker_script ${CMAKE_CURRENT_SOURCE_DIR}/bootloader.ld)

  set(CMAKE_EXE_LINKER_FLAGS
      "${CMAKE_EXE_LINKER_FLAGS} -T${linker_script} -L${CMAKE_BINARY_DIR}/lib")

  add_executable(bootloader.salt.bin ${sources})
  target_link_libraries(bootloader.salt.bin
      kkboard
      kkboard.salt
      kktransport
      kkcrypto
      -lopencm3_stm32f2
      -lc
      -lm)
#  add_dependencies(bootloader.salt.bin kkboard kkboard.salt)

  add_executable(bootloader.keepkey.bin ${sources})
  target_link_libraries(bootloader.keepkey.bin
      kkboard
      kkboard.keepkey
      kktransport
      kkcrypto
      -lopencm3_stm32f2
      -lc
      -lm)
#  add_dependencies(bootloader.keepkey.bin kkboard kkboard.keepkey)

endif()
