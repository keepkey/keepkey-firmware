if(${KK_EMULATOR})
  set(sources
      main.cpp)

  include_directories(
      ${CMAKE_SOURCE_DIR}/include
      ${CMAKE_BINARY_DIR}/include)

  add_executable(rle-dump ${sources})
  target_link_libraries(rle-dump
      kkfirmware
      kkfirmware.keepkey
      kkboard
      kkboard.keepkey
      kkvariant.keepkey
      kkvariant.salt
      kkboard
      kktransport
      hwcrypto
      kkrand
      -lc
      -lm)

endif()
