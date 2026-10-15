set(sources
    app_confirm.cpp
    block13_confirmation.cpp
    block13_entropy.cpp
    block13_progress.cpp
    nanopb_bounds.cpp
    authenticator.cpp
    confirm_test_utils.cpp
    crypto_cleanup.cpp
    fsm.cpp
    dice.cpp
    recovery.cpp
    recovery_review_probe.c
    review_handlers.cpp
    rng_health.cpp
    setup_ux.cpp
    setup_ceremony.cpp
    reset_policy_probe.c
    signing.cpp
    storage.cpp
    storage_cipher_probe.c
    storage_passphrase.cpp
    test_board.cpp
    transaction.cpp
    usb_rx.cpp
    messages_probe.c
    usb_callbacks.cpp
    u2f.cpp)

# Suites for the coin engines the bitcoin-only image compiles out. Building
# them against that image fails at the first reference to an absent symbol
# (ethereum_address_checksum, tokenByTicker, ...), so they follow their
# subjects out of the build. coins.cpp is here because it asserts the
# multi-chain coin AND token table, not just the Bitcoin rows.
if(NOT ${KK_BITCOIN_ONLY})
  list(APPEND sources
      binance.cpp
      coins.cpp
      cosmos.cpp
      eos.cpp
      eos_authorization.cpp
      eos_authorization_probe.c
      ethereum.cpp
      hive_transfer.cpp
      eip712_stream.cpp
      mayachain.cpp
      nano.cpp
      osmosis.cpp
      ripple.cpp
      signed_metadata.cpp
      contact_book.cpp
      erc7730_abi.cpp
      erc7730_abi_stream.cpp
      erc7730_catalog.cpp
      erc7730_field.cpp
      erc7730_format.cpp
      erc7730_program.cpp
      erc7730_tx.cpp
      erc7730_workflow.cpp
      solana.cpp
      thorchain.cpp
      tron.cpp)

  # Native and Python tests share the corpus in the pinned Python dependency.
  # Generate into the build tree, with an explicit dependency for parallel builds.
  find_program(EIP712_PYTHON_EXECUTABLE NAMES python3)
  if(NOT EIP712_PYTHON_EXECUTABLE)
    message(FATAL_ERROR "Python 3 is required to generate the EIP-712 test corpus")
  endif()
  set(eip712_corpus_json
      "${CMAKE_SOURCE_DIR}/deps/python-keepkey/tests/eip712_corpus.json")
  set(eip712_corpus_inc
      "${CMAKE_CURRENT_BINARY_DIR}/generated/eip712_corpus.inc")
  add_custom_command(
      OUTPUT "${eip712_corpus_inc}"
      COMMAND "${CMAKE_COMMAND}" -E make_directory
              "${CMAKE_CURRENT_BINARY_DIR}/generated"
      COMMAND "${EIP712_PYTHON_EXECUTABLE}"
              "${CMAKE_CURRENT_SOURCE_DIR}/eip712_corpus_gen.py"
              --output "${eip712_corpus_inc}"
      DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/eip712_corpus_gen.py"
              "${eip712_corpus_json}"
      VERBATIM)
  list(APPEND sources "${eip712_corpus_inc}")
  set_property(SOURCE eip712_stream.cpp APPEND PROPERTY OBJECT_DEPENDS
               "${eip712_corpus_inc}")
endif()

if(${KK_ZCASH_PRIVACY})
  list(APPEND sources zcash.cpp)
endif()

include_directories(
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/lib/firmware
    ${CMAKE_BINARY_DIR}/include
    ${CMAKE_SOURCE_DIR}/deps/crypto/trezor-crypto)

add_executable(firmware-unit ${sources})
target_include_directories(firmware-unit PRIVATE "${CMAKE_CURRENT_BINARY_DIR}")
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

# Exercise the Zcash address display (paged address + QR) on its own,
# independent of KK_ZCASH_PRIVACY and the Zcash signing handlers.
if(NOT KK_BITCOIN_ONLY)
  add_executable(zcash-display-unit
      zcash_display.cpp zcash_display_confirm_probe.c zcash_display_layout_probe.c
      confirm_test_utils.cpp test_board.cpp)
  get_target_property(FIRMWARE_TEST_LIBS firmware-unit LINK_LIBRARIES)
  target_link_libraries(zcash-display-unit ${FIRMWARE_TEST_LIBS})
endif()
