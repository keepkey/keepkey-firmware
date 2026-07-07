set(sources
    recovery.cpp
    storage.cpp
    usb_rx.cpp
    u2f.cpp)

# Coin/token unit tests exercise handlers/helpers that are compiled out of the
# bitcoin-only firmware (ethereum_address_checksum, tokenByTicker, ...), so they
# only build against a full-feature firmware. coins.cpp asserts the multi-chain
# coin+token table.
if(NOT ${KK_BITCOIN_ONLY})
  list(APPEND sources
      coins.cpp
      cosmos.cpp
      eos.cpp
      ethereum.cpp
      mayachain.cpp
      nano.cpp
      ripple.cpp
      signed_metadata.cpp
      solana.cpp
      thorchain.cpp
      tron.cpp)
endif()

# zcash.cpp exercises the Orchard engine (lib/firmware/zcash.c), which is only
# compiled into kkfirmware when the privacy flag is on.
if(${KK_ZCASH_PRIVACY})
  list(APPEND sources zcash.cpp)
endif()

include_directories(
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/lib/firmware
    ${CMAKE_BINARY_DIR}/include
    ${CMAKE_SOURCE_DIR}/deps/crypto/trezor-crypto)

add_executable(firmware-unit ${sources})
target_link_libraries(firmware-unit
    gmock_main
    kkfirmware
    kkfirmware.keepkey
    kkboard
    kkboard.keepkey
    kkvariant.keepkey
    kkvariant.salt
    kkboard
    kkemulator
    trezorcrypto
    qrcodegenerator
    SecAESSTM32
    kkrand
    kktransport)
