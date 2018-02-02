if(NOT ${KK_EMULATOR})

  set(sources
      main.c)

  include_directories(
      ${CMAKE_SOURCE_DIR}/include
      ${CMAKE_BINARY_DIR}/include)

  set(linker_script ${CMAKE_CURRENT_SOURCE_DIR}/bootstrap.ld)

  set(CMAKE_EXE_LINKER_FLAGS
      "${CMAKE_EXE_LINKER_FLAGS} -T${linker_script} -L${CMAKE_BINARY_DIR}/lib")

  add_executable(bootstrap.salt.bin ${sources})
  target_link_libraries(bootstrap.salt.bin
      kkboard
      kkboard.salt
      kktransport
      kkcrypto
      -lopencm3_stm32f2
      -lc
      -lm)

  add_executable(bootstrap.keepkey.bin ${sources})
  target_link_libraries(bootstrap.keepkey.bin
      kkboard
      kkboard.keepkey
      kktransport
      kkcrypto
      -lopencm3_stm32f2
      -lc
      -lm)

endif()
