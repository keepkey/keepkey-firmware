# Only tests that build against BOTH firmware variants belong here. The
# multi-chain suites are appended below under NOT KK_BITCOIN_ONLY -- the merge
# had leaked eight of them (binance, coins, cosmos, eos, ethereum, nano, ripple,
# solana) into this unconditional list as well, so the bitcoin-only build
# compiled them anyway and died on ethereum_address_checksum, which is compiled
# out of that image. recovery.cpp was also listed twice.
set(sources
    dice.cpp
    recovery.cpp
    rng_health.cpp
    signing.cpp
    setup_ceremony.cpp
    storage.cpp
    test_board.cpp
    transaction.cpp
    usb_rx.cpp
    u2f.cpp)

# Suites for the coin engines the bitcoin-only image compiles out. Building
# them against that image fails at the first reference to an absent symbol
# (ethereum_address_checksum, tokenByTicker, ...), so they follow their
# subjects out of the build. coins.cpp is here because it asserts the
# multi-chain coin AND token table, not just the Bitcoin rows.
if(NOT ${KK_BITCOIN_ONLY})
  list(APPEND sources
      authenticator.cpp
      binance.cpp
      coins.cpp
      cosmos.cpp
      eip712.cpp
      eos.cpp
      ethereum.cpp
      hive.cpp
      mayachain.cpp
      nano.cpp
      osmosis.cpp
      ripple.cpp
      signed_metadata.cpp
      solana.cpp
      thorchain.cpp
      tron.cpp)
endif()

# zcash.cpp exercises the Orchard engine (lib/firmware/zcash.c), which is only
# compiled into kkfirmware when the privacy flag is on. KK_BITCOIN_ONLY forces
# KK_ZCASH_PRIVACY off (see the top-level CMakeLists), so the bitcoin-only build
# skips it.
if(${KK_ZCASH_PRIVACY})
  list(APPEND sources zcash.cpp)
endif()

include_directories(
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/lib/firmware
    ${CMAKE_BINARY_DIR}/include
    ${CMAKE_SOURCE_DIR}/deps/crypto/trezor-firmware/crypto)

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
    trezorcrypto
    qrcodegenerator
    SecAESSTM32
    kkrand
    kkemulator
    kktransport)
