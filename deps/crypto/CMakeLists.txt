set(sources
    trezor-firmware/crypto/bip39.c
    trezor-firmware/crypto/hmac.c
    trezor-firmware/crypto/hmac_drbg.c
    trezor-firmware/crypto/sha2.c
    trezor-firmware/crypto/base32.c
    trezor-firmware/crypto/hasher.c
    #trezor-firmware/crypto/tools/bip39bruteforce.c
    #trezor-firmware/crypto/tools/mktable.c
    #trezor-firmware/crypto/tools/xpubaddrgen.c
    trezor-firmware/crypto/rand.c
    trezor-firmware/crypto/rc4.c
    trezor-firmware/crypto/blake256.c
    trezor-firmware/crypto/cash_addr.c
    trezor-firmware/crypto/curves.c
    trezor-firmware/crypto/rfc6979.c
    trezor-firmware/crypto/ed25519-donna/curve25519-donna-scalarmult-base.c
    trezor-firmware/crypto/ed25519-donna/ed25519-donna-32bit-tables.c
    trezor-firmware/crypto/ed25519-donna/ed25519.c
    trezor-firmware/crypto/ed25519-donna/curve25519-donna-helpers.c
    trezor-firmware/crypto/ed25519-donna/ed25519-blake2b.c
    trezor-firmware/crypto/ed25519-donna/ed25519-keccak.c
    trezor-firmware/crypto/ed25519-donna/ed25519-sha3.c
    trezor-firmware/crypto/ed25519-donna/ed25519-donna-basepoint-table.c
    trezor-firmware/crypto/ed25519-donna/modm-donna-32bit.c
    trezor-firmware/crypto/ed25519-donna/curve25519-donna-32bit.c
    trezor-firmware/crypto/ed25519-donna/ed25519-donna-impl-base.c
    trezor-firmware/crypto/nem.c
    trezor-firmware/crypto/nano.c
    #trezor-firmware/crypto/tests/test_check.c
    #trezor-firmware/crypto/tests/test_openssl.c
    #trezor-firmware/crypto/tests/test_speed.c
    trezor-firmware/crypto/secp256k1.c
    trezor-firmware/crypto/bignum.c
    trezor-firmware/crypto/segwit_addr.c
    trezor-firmware/crypto/ripemd160.c
    trezor-firmware/crypto/groestl.c
    trezor-firmware/crypto/nist256p1.c
    #trezor-firmware/crypto/monero/serialize.c
    #trezor-firmware/crypto/monero/range_proof.c
    #trezor-firmware/crypto/monero/xmr.c
    #trezor-firmware/crypto/monero/base58.c
    trezor-firmware/crypto/memzero.c
    trezor-firmware/crypto/blake2b.c
    trezor-firmware/crypto/script.c
    trezor-firmware/crypto/bip32.c
    trezor-firmware/crypto/address.c
    trezor-firmware/crypto/blake2s.c
    trezor-firmware/crypto/sha3.c
    trezor-firmware/crypto/base58.c
    trezor-firmware/crypto/ecdsa.c
    trezor-firmware/crypto/pbkdf2.c
    trezor-firmware/crypto/aes/aeskey.c
    trezor-firmware/crypto/aes/aescrypt.c
    trezor-firmware/crypto/aes/aes_modes.c
    #trezor-firmware/crypto/aes/aestst.c
    trezor-firmware/crypto/aes/aestab.c)

    # Clang 5.0 in the docker image (kktech/firmware:v7) is missing
    # <xmmintrin.h>, which breaks these. Until they're needed, we'll just elide
    # them.
    #trezor-firmware/crypto/chacha20poly1305/chacha_merged.c
    #trezor-firmware/crypto/chacha20poly1305/rfc7539.c
    #trezor-firmware/crypto/chacha20poly1305/poly1305-donna.c
    #trezor-firmware/crypto/chacha20poly1305/chacha20poly1305.c


include_directories(
  ${CMAKE_CURRENT_SOURCE_DIR}/trezor-firmware/crypto
  ${CMAKE_CURRENT_SOURCE_DIR}/trezor-firmware/
  ${CMAKE_CURRENT_SOURCE_DIR}/trezor-firmware/crypto/ed25519-donna
  ${OPENSSL_INCLUDE_DIR})

add_library(trezorcrypto ${sources})
