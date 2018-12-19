set(sources
    app_confirm.c
    app_layout.c
    coins.c
    crypto.c
    ethereum.c
    ethereum_tokens.c
    exchange.c
    fsm.c
    home_sm.c
    passphrase_sm.c
    pin_sm.c
    policy.c
    recovery.c
    recovery_cipher.c
    reset.c
    signing.c
    storage.c
    transaction.c
    u2f.c)

configure_file("${CMAKE_CURRENT_SOURCE_DIR}/scm_revision.h.in"
               "${CMAKE_CURRENT_BINARY_DIR}/scm_revision.h" @ONLY)

include_directories(
  ${CMAKE_BINARY_DIR}/include
  ${CMAKE_SOURCE_DIR}/deps/crypto/trezor-crypto
  ${CMAKE_CURRENT_BINARY_DIR})

add_library(kkfirmware ${sources})
add_dependencies(kkfirmware kktransport.pb trezorcrypto trezorqrenc)

add_library(kkfirmware.keepkey variant/keepkey/resources.c)
add_library(kkfirmware.mfr variant/mfr/resources.c)
