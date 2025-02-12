set(sources
    app_confirm.c
    app_layout.c
    authenticator.c
    coins.c
    crypto.c
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

if("${COIN_SUPPORT}" STREQUAL "BTC")
else()    
  list(APPEND sources
      binance.c
      eip712.c
      eos.c
      eos-contracts/eosio.system.c
      eos-contracts/eosio.token.c
      ethereum.c
      ethereum_contracts.c
      ethereum_contracts/makerdao.c
      ethereum_contracts/saproxy.c
      ethereum_contracts/zxappliquid.c
      ethereum_contracts/thortx.c
      ethereum_contracts/zxliquidtx.c
      ethereum_contracts/zxtransERC20.c
      ethereum_contracts/zxswap.c
      ethereum_tokens.c
      mayachain.c
      nano.c
      osmosis.c
      ripple.c
      ripple_base58.c
      signtx_tendermint.c
      tendermint.c
      thorchain.c)
endif()

configure_file("${CMAKE_CURRENT_SOURCE_DIR}/scm_revision.h.in"
               "${CMAKE_CURRENT_BINARY_DIR}/scm_revision.h" @ONLY)

include_directories(
  ${CMAKE_BINARY_DIR}/include
  ${CMAKE_SOURCE_DIR}/deps/crypto/trezor-crypto
  ${CMAKE_SOURCE_DIR}/lib/firmware
  ${CMAKE_CURRENT_BINARY_DIR})

add_library(kkfirmware ${sources})

if("${COIN_SUPPORT}" STREQUAL "BTC")
  # for bitcoin-only, do not build eth token table or uniswap tokens
  add_dependencies(kkfirmware kktransport.pb trezorcrypto qrcodegenerator)

else()
  add_dependencies(kkfirmware kktransport.pb trezorcrypto qrcodegenerator ethereum_tokens.def)
  set(ETHEREUM_TOKENS ${CMAKE_BINARY_DIR}/include/keepkey/firmware/ethereum_tokens)
  set(UNISWAP_TOKENS ${CMAKE_BINARY_DIR}/include/keepkey/firmware/uniswap_tokens)

  add_custom_target(ethereum_tokens.def
    COMMAND ${CMAKE_COMMAND} -E make_directory ${CMAKE_BINARY_DIR}/include/keepkey/firmware
    COMMAND python3 ${CMAKE_SOURCE_DIR}/deps/python-keepkey/keepkeylib/eth/ethereum_tokens.py ${ETHEREUM_TOKENS}.def
    COMMAND python3 ${CMAKE_SOURCE_DIR}/deps/python-keepkey/keepkeylib/eth/uniswap_tokens.py ${UNISWAP_TOKENS}.def)
endif()

add_library(kkfirmware.keepkey variant/keepkey/resources.c)
