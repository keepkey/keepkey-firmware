set(sources
    address.c
    aes_modes.c
    aescrypt.c
    aeskey.c
    aestab.c
    base58.c
    bignum.c
    bip32.c
    bip39.c
    curves.c
    ecdsa.c
    ed25519.c
    hmac.c
    nist256p1.c
    pbkdf2.c
    ripemd160.c
    secp256k1.c
    sha2.c
    sha3.c)

add_compile_options(-O3)

include_directories(
  ${CMAKE_SOURCE_DIR}/crypto/public
  ${CMAKE_SOURCE_DIR}/crypto/public/ed25519-donna
  ${OPENSSL_INCLUDE_DIR})

add_library(kkcrypto ${sources})
