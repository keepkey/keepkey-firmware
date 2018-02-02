set(sources
    app_confirm.c
    app_layout.c
    coins.c
    crypto.c
    ethereum.c
    exchange.c
    fsm.c
    home_sm.c
    passphrase_sm.c
    pin_sm.c
    policy.c
    qr_encode.c
    recovery.c
    recovery_cipher.c
    reset.c
    signing.c
    storage.c
    transaction.c
    util.c)

include_directories(${CMAKE_BINARY_DIR}/include)

add_library(kkfirmware ${sources})
add_dependencies(kkfirmware kktransport.pb)

add_library(kkfirmware.keepkey whitelabel/keepkey/resources.c)
add_library(kkfirmware.salt whitelabel/keepkey/resources.c)
