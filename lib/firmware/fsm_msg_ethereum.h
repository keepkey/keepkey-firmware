
/*
 * This file is part of the Keepkey project
 *
 * Copyright (C) 2022
 *
 * This library is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this library.  If not, see <http://www.gnu.org/licenses/>.
 */

static int process_ethereum_xfer(const CoinType *coin, EthereumSignTx *msg) {
  if (!ethereum_isStandardERC20Transfer(msg) && msg->data_length != 0)
    return TXOUT_COMPILE_ERROR;

  char node_str[NODE_STRING_LENGTH];
  if (!bip32_node_to_string(node_str, sizeof(node_str), coin, msg->to_address_n,
                            msg->to_address_n_count, /*whole_account=*/false,
                            /*show_addridx=*/false))
    return TXOUT_COMPILE_ERROR;

  if (!coin->has_forkid) return TXOUT_COMPILE_ERROR;

  const uint32_t chain_id = coin->forkid;

  const uint8_t *value_bytes;
  size_t value_size;
  const TokenType *token;

  if (ethereum_isStandardERC20Transfer(msg)) {
    value_bytes = msg->data_initial_chunk.bytes + 4 + 32;
    value_size = 32;
    token = tokenByChainAddress(chain_id, msg->to.bytes);
  } else {
    value_bytes = msg->value.bytes;
    value_size = msg->value.size;
    token = NULL;
  }

  bignum256 value;
  bn_from_bytes(value_bytes, value_size, &value);

  char amount_str[128 + sizeof(msg->token_shortcut) + 3];
  ethereumFormatAmount(&value, token, chain_id, amount_str, sizeof(amount_str));

  if (!confirm_transfer_output(
          ButtonRequestType_ButtonRequest_ConfirmTransferToAccount, amount_str,
          node_str))
    return TXOUT_CANCEL;

  const HDNode *node = fsm_getDerivedNode(SECP256K1_NAME, msg->to_address_n,
                                          msg->to_address_n_count, NULL);
  if (!node) return TXOUT_COMPILE_ERROR;

  uint8_t to_bytes[20];
  if (!hdnode_get_ethereum_pubkeyhash(node, to_bytes))
    return TXOUT_COMPILE_ERROR;

  if (ethereum_isStandardERC20Transfer(msg)) {
    if (memcmp(msg->data_initial_chunk.bytes + 4 + (32 - 20), to_bytes, 20) !=
        0)
      return TXOUT_COMPILE_ERROR;
  } else {
    msg->has_to = true;
    msg->to.size = 20;
    memcpy(msg->to.bytes, to_bytes, sizeof(to_bytes));
  }

  memzero((void *)node, sizeof(HDNode));
  return TXOUT_OK;
}

static int process_ethereum_msg(EthereumSignTx *msg, bool *needs_confirm) {
  const CoinType *coin = fsm_getCoin(true, ETHEREUM);
  if (!coin) return TXOUT_COMPILE_ERROR;

  switch (msg->address_type) {
    case OutputAddressType_TRANSFER: {
      // prep transfer type transaction
      *needs_confirm = false;
      return process_ethereum_xfer(coin, msg);
    }
    default:
      return TXOUT_OK;
  }
}

void fsm_msgEthereumSignTx(EthereumSignTx *msg) {
  CHECK_INITIALIZED

  CHECK_PIN

  bool needs_confirm = true;
  int msg_result = process_ethereum_msg(msg, &needs_confirm);

  if (msg_result < TXOUT_OK) {
    ethereum_signing_abort();
    send_fsm_co_error_message(msg_result);
    layoutHome();
    return;
  }

  HDNode *node = fsm_getDerivedNode(SECP256K1_NAME, msg->address_n,
                                    msg->address_n_count, NULL);
  if (!node) return;

  ethereum_signing_init(msg, node, needs_confirm);
  memzero(node, sizeof(*node));
}

void fsm_msgEthereumTxAck(EthereumTxAck *msg) { ethereum_signing_txack(msg); }

void fsm_msgEthereumGetAddress(EthereumGetAddress *msg) {
  RESP_INIT(EthereumAddress);

  CHECK_INITIALIZED

  CHECK_PIN

  HDNode *node = fsm_getDerivedNode(SECP256K1_NAME, msg->address_n,
                                    msg->address_n_count, NULL);
  if (!node) return;

  resp->address.size = 20;

  if (!hdnode_get_ethereum_pubkeyhash(node, resp->address.bytes)) {
    memzero(node, sizeof(*node));
    return;
  }

  const CoinType *coin = NULL;
  bool rskip60 = false;
  uint32_t chain_id = 0;

  if (msg->address_n_count == 5) {
    coin = coinBySlip44(msg->address_n[1]);
    uint32_t slip44 = msg->address_n[1] & 0x7fffffff;
    // constants from trezor-common/defs/ethereum/networks.json
    switch (slip44) {
      case 137:
        rskip60 = true;
        chain_id = 30;
        break;
      case 37310:
        rskip60 = true;
        chain_id = 31;
        break;
    }
  }

  char address[43] = {'0', 'x'};
  ethereum_address_checksum(resp->address.bytes, address + 2, rskip60,
                            chain_id);

  resp->has_address_str = true;
  strlcpy(resp->address_str, address, sizeof(resp->address_str));

  if (msg->has_show_display && msg->show_display) {
    char node_str[NODE_STRING_LENGTH];
    if (!(coin && isEthereumLike(coin->coin_name) &&
          bip32_node_to_string(node_str, sizeof(node_str), coin, msg->address_n,
                               msg->address_n_count,
                               /*whole_account=*/false,
                               /*show_addridx=*/false)) &&
        !bip32_path_to_string(node_str, sizeof(node_str), msg->address_n,
                              msg->address_n_count)) {
      memset(node_str, 0, sizeof(node_str));
    }

    if (!confirm_ethereum_address(node_str, address)) {
      memzero(node, sizeof(*node));
      fsm_sendFailure(FailureType_Failure_ActionCancelled,
                      _("Show address cancelled"));
      layoutHome();
      return;
    }
  }

  memzero(node, sizeof(*node));
  msg_write(MessageType_MessageType_EthereumAddress, resp);
  layoutHome();
}

void fsm_msgEthereumSignMessage(EthereumSignMessage *msg) {
  RESP_INIT(EthereumMessageSignature);

  CHECK_INITIALIZED

  if (!confirm(ButtonRequestType_ButtonRequest_ProtectCall, _("Sign Message"),
               "%s", msg->message.bytes)) {
    fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL);
    layoutHome();
    return;
  }

  CHECK_PIN

  HDNode *node = fsm_getDerivedNode(SECP256K1_NAME, msg->address_n,
                                    msg->address_n_count, NULL);
  if (!node) return;

  ethereum_message_sign(msg, node, resp);
  memzero(node, sizeof(*node));
  layoutHome();
}

void fsm_msgEthereumVerifyMessage(const EthereumVerifyMessage *msg) {
  CHECK_PARAM(msg->has_address, _("No address provided"));
  CHECK_PARAM(msg->has_message, _("No message provided"));

  if (ethereum_message_verify(msg) != 0) {
    fsm_sendFailure(FailureType_Failure_SyntaxError, _("Invalid signature"));
    return;
  }

  char address[43] = {'0', 'x'};
  ethereum_address_checksum(msg->address.bytes, address + 2, false, 0);
  if (!confirm_address(_("Confirm Signer"), address)) {
    fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL);
    layoutHome();
    return;
  }
  if (!confirm(ButtonRequestType_ButtonRequest_Other, _("Message Verified"),
               "%s", msg->message.bytes)) {
    fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL);
    layoutHome();
    return;
  }
  fsm_sendSuccess(_("Message verified"));

  layoutHome();
}

void fsm_msgEthereumSignTypedHash(const EthereumSignTypedHash *msg) {
  RESP_INIT(EthereumTypedDataSignature);

  CHECK_INITIALIZED

  CHECK_PIN

  if (msg->domain_separator_hash.size != 32 ||
      (msg->has_message_hash && msg->message_hash.size != 32)) {
    fsm_sendFailure(FailureType_Failure_Other, _("Invalid EIP-712 hash length"));
    return;
  }

  const HDNode *node = fsm_getDerivedNode(SECP256K1_NAME, msg->address_n,
                                          msg->address_n_count, NULL);
  if (!node) return;

  uint8_t pubkeyhash[20] = {0};
  if (!hdnode_get_ethereum_pubkeyhash(node, pubkeyhash)) {
    layoutHome();
    return;
  }

  resp->address[0] = '0';
  resp->address[1] = 'x';
  ethereum_address_checksum(pubkeyhash, resp->address+2, false, 0);

  // No message hash when setting primaryType="EIP712Domain"
  // https://ethereum-magicians.org/t/eip-712-standards-clarification-primarytype-as-domaintype/3286
  if (msg->has_message_hash) {
    char str[64+1];
    int ctr;
    char *addrTitleStr = "Verify Address";
    confirm(ButtonRequestType_ButtonRequest_Other, addrTitleStr, "Confirm address: %s", resp->address);

    char *hashTitleStr = "EIP-712 domain hash";
    for (ctr=0; ctr<64/2; ctr++) {
      snprintf(&str[2*ctr], 3, "%02x", msg->domain_separator_hash.bytes[ctr]);
    }
    confirm(ButtonRequestType_ButtonRequest_Other, hashTitleStr, "Confirm hash digest: %s", str);
  }

  ethereum_typed_hash_sign(msg, node, resp);
  layoutHome();
}

void fsm_msgEthereum712TypesValues(Ethereum712TypesValues *msg) {
  RESP_INIT(EthereumTypedDataSignature);

  CHECK_INITIALIZED

  CHECK_PIN

  if (strlen(msg->eip712types) == 0) {
    fsm_sendFailure(FailureType_Failure_Other, _("Invalid EIP-712 types property string"));
    return;
  }
  e712_types_values(msg, resp);

  layoutHome();
}
