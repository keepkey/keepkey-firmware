set(sources
    trezor-qrenc/qr_encode.c)


include_directories(
  ${CMAKE_SOURCE_DIR}/deps/qrenc/trezor-qrenc
  ${OPENSSL_INCLUDE_DIR})

add_library(trezorqrenc ${sources})
