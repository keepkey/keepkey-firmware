# BTC core crypto — always compiled
set(base_sources
    trezor-firmware/crypto/bip39.c
    trezor-firmware/crypto/bip39_english.c
    trezor-firmware/crypto/hmac.c
    trezor-firmware/crypto/hmac_drbg.c
    trezor-firmware/crypto/sha2.c
    trezor-firmware/crypto/base32.c
    trezor-firmware/crypto/hasher.c
    trezor-firmware/crypto/rand.c
    trezor-firmware/crypto/rc4.c
    trezor-firmware/crypto/blake256.c
    trezor-firmware/crypto/cash_addr.c
    trezor-firmware/crypto/curves.c
    trezor-firmware/crypto/rfc6979.c
    trezor-firmware/crypto/secp256k1.c
    trezor-firmware/crypto/bignum.c
    trezor-firmware/crypto/segwit_addr.c
    trezor-firmware/crypto/ripemd160.c
    trezor-firmware/crypto/memzero.c
    trezor-firmware/crypto/blake2b.c
    trezor-firmware/crypto/script.c
    trezor-firmware/crypto/bip32.c
    trezor-firmware/crypto/address.c
    trezor-firmware/crypto/blake2s.c
    trezor-firmware/crypto/base58.c
    trezor-firmware/crypto/ecdsa.c
    trezor-firmware/crypto/pbkdf2.c
    trezor-firmware/crypto/aes/aeskey.c
    trezor-firmware/crypto/aes/aescrypt.c
    trezor-firmware/crypto/aes/aes_modes.c
    trezor-firmware/crypto/aes/aestab.c
    trezor-firmware/crypto/groestl.c
    trezor-firmware/crypto/sha3.c
    trezor-firmware/crypto/nist256p1.c
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
    trezor-firmware/crypto/ed25519-donna/ed25519-donna-impl-base.c)

# Altcoin crypto — skipped in BTC-only builds
set(altcoin_sources
    trezor-firmware/crypto/nem.c
    trezor-firmware/crypto/nano.c)

include_directories(
  ${CMAKE_CURRENT_SOURCE_DIR}/trezor-firmware/crypto
  ${CMAKE_CURRENT_SOURCE_DIR}/trezor-firmware/
  ${CMAKE_CURRENT_SOURCE_DIR}/trezor-firmware/crypto/ed25519-donna
  ${OPENSSL_INCLUDE_DIR})

if(KK_BITCOIN_ONLY)
    set(sources ${base_sources})
else()
    set(sources ${base_sources} ${altcoin_sources})
endif()

add_library(trezorcrypto ${sources})
