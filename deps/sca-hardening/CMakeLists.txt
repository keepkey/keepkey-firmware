set(sources aes128_cbc.c)

if(NOT ${KK_EMULATOR})
    set(sources ${sources}
        SecAESSTM32/src/aes/affine_aes.S
        SecAESSTM32/src/aes/aes.c)
endif()

include_directories(
  ${CMAKE_CURRENT_SOURCE_DIR}/SecAESSTM32/src/aes)

add_library(SecAESSTM32 ${sources})
