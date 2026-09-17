set(sources
    app_confirm.c
    app_layout.c
    authenticator.c
    bip85.c
    coins.c
    crypto.c
    ctap2.c
    ctap2_cbor.c
    dice_input.c
    fsm.c
    home_sm.c
    passphrase_sm.c
    pin_sm.c
    policy.c
    recovery_cipher.c
    reset.c
    signing.c
    storage.c
    tiny-json.c
    transaction.c
    txin_check.c
    u2f.c)

# Non-Bitcoin coin families -- excluded from the bitcoin-only image.
if(NOT ${KK_BITCOIN_ONLY})
  list(APPEND sources
      eip712.c
      eip712_stream.c
      eos.c
      eos-contracts/eosio.system.c
      eos-contracts/eosio.token.c
      ethereum.c
      ethereum_contracts.c
      erc7730_abi.c
      erc7730_catalog.c
      erc7730_program.c
      erc7730_tx.c
      ethereum_contracts/makerdao.c
      ethereum_contracts/saproxy.c
      ethereum_contracts/zxappliquid.c
      ethereum_contracts/thortx.c
      ethereum_contracts/zxliquidtx.c
      ethereum_contracts/zxtransERC20.c
      ethereum_contracts/zxswap.c
      ethereum_tokens.c
      clearsign_root.c
      signed_metadata.c
      mayachain.c
      nano.c
      osmosis.c
      ripple.c
      ripple_base58.c
      signtx_tendermint.c
      solana.c
      hive.c
      tron.c
      ton.c
      tendermint.c
      thorchain.c)
endif()

# Zcash shielded/Orchard engine -- transparent Zcash needs none of this.
if(${KK_ZCASH_PRIVACY})
  list(APPEND sources zcash.c)
endif()

configure_file("${CMAKE_CURRENT_SOURCE_DIR}/scm_revision.h.in"
               "${CMAKE_CURRENT_BINARY_DIR}/scm_revision.h" @ONLY)

include_directories(
  ${CMAKE_BINARY_DIR}/include
  ${CMAKE_SOURCE_DIR}/deps/crypto/trezor-firmware/crypto
  ${CMAKE_SOURCE_DIR}/lib/firmware
  ${CMAKE_CURRENT_BINARY_DIR})

add_library(kkfirmware ${sources})

# Root inclusion is an explicit product choice. OFF remains fail-closed for
# production/release builds. Alpha artifacts and emulator/unit builds opt into
# the hardware-held alpha root whose certificates Vault currently serves.
option(KK_CLEARSIGN_ALPHA_ROOT "Compile in the hardware-held alpha ClearSign root" OFF)
if(KK_CLEARSIGN_ALPHA_ROOT)
  target_compile_definitions(kkfirmware PRIVATE KK_CLEARSIGN_ALPHA_ROOT=1)
endif()
add_dependencies(kkfirmware kktransport.pb trezorcrypto qrcodegenerator ethereum_tokens.def)

set(ETHEREUM_TOKENS ${CMAKE_BINARY_DIR}/include/keepkey/firmware/ethereum_tokens)
set(UNISWAP_TOKENS ${CMAKE_BINARY_DIR}/include/keepkey/firmware/uniswap_tokens)

add_custom_target(ethereum_tokens.def
  BYPRODUCTS ${ETHEREUM_TOKENS}.def ${UNISWAP_TOKENS}.def
  COMMAND ${CMAKE_COMMAND} -E make_directory ${CMAKE_BINARY_DIR}/include/keepkey/firmware
  COMMAND python3 ${CMAKE_SOURCE_DIR}/deps/python-keepkey/keepkeylib/eth/ethereum_tokens.py ${ETHEREUM_TOKENS}.def
  COMMAND python3 ${CMAKE_SOURCE_DIR}/deps/python-keepkey/keepkeylib/eth/uniswap_tokens.py ${UNISWAP_TOKENS}.def
  COMMAND python3 ${CMAKE_SOURCE_DIR}/scripts/verify-token-def.py
          ${ETHEREUM_TOKENS}.def ${UNISWAP_TOKENS}.def
  COMMENT "Generating and verifying firmware token tables")

add_library(kkfirmware.keepkey variant/keepkey/resources.c)
