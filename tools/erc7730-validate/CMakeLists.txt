# Like the standalone emulator, this CLI links the POSIX socket backend.
# Windows supports the socket-free kkemulator_dylib target instead.
if(${KK_EMULATOR} AND NOT ${KK_BITCOIN_ONLY} AND NOT WIN32)
  include_directories(
      ${CMAKE_SOURCE_DIR}/include
      ${CMAKE_BINARY_DIR}/include
      ${CMAKE_SOURCE_DIR}/deps/crypto/trezor-firmware/crypto)

  add_executable(erc7730-validate main.c)
  target_link_libraries(erc7730-validate
      kkfirmware
      kkfirmware.keepkey
      kkboard
      kkboard.keepkey
      kkvariant.keepkey
      kkvariant.salt
      kktransport
      trezorcrypto
      qrcodegenerator
      SecAESSTM32
      kkrand
      kkemulator)

  add_custom_target(erc7730-validator-test
      COMMAND python3 ${CMAKE_CURRENT_SOURCE_DIR}/test_cli.py
              $<TARGET_FILE:erc7730-validate>
      DEPENDS erc7730-validate)
endif()
