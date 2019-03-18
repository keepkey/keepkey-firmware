set(sources
    QR-Code-generator/c/qrcodegen.c)

include_directories(
  ${CMAKE_SOURCE_DIR}/deps/qrenc/QR-Code-generator/c
  ${OPENSSL_INCLUDE_DIR})

add_library(qrcodegenerator ${sources})
