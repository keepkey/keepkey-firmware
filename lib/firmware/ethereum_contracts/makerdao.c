/*
 * This file is part of the KeepKey project.
 *
 * Copyright (C) 2019 ShapeShift
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

#include "keepkey/firmware/ethereum_contracts/makerdao.h"

#include "keepkey/board/confirm_sm.h"
#include "keepkey/board/util.h"
#include "keepkey/firmware/ethereum.h"
#include "keepkey/firmware/ethereum_tokens.h"
#include "keepkey/firmware/fsm.h"
#include "hwcrypto/crypto/address.h"

static bool getCupId(const uint8_t *param, uint32_t *val) {
  bignum256 value;
  bn_from_bytes(param, 32, &value);

  if (32 < bn_bitcount(&value)) return false;

  *val = bn_write_uint32(&value);
  return true;
}

static bool confirmParamIsTub(const uint8_t *param, uint32_t chain_id) {
  if (memcmp(param, "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", 12) !=
      0)
    return false;

  const uint8_t *address = param + 12;

  // Mainnet
  // saiValuesAggregator:
  // https://github.com/makerdao/scd-cdp-portal/blob/fac7b0571dc4128e89dcd5f7f8d44ded4b66073b/src/settings.json#L16
  // saiValuesAggregator.tub:
  // https://etherscan.io/readContract?m=normal&a=0x83f6ed3d377674186d8898a89d9032216e07e659#collapse4
  if (chain_id == 1 && memcmp(address,
                              "\x44\x8a\x50\x65\xae\xbb\x8e\x42\x3f\x08\x96\xe6"
                              "\xc5\xd5\x25\xc0\x40\xf5\x9a\xf3",
                              20) == 0)
    return true;

  // Kovan
  if (chain_id == 42 && memcmp(address,
                               "\xa7\x19\x37\x14\x7b\x55\xde\xb8\xa5\x30\xc7"
                               "\x22\x9c\x44\x2f\xd3\xf3\x1b\x7d\xb2",
                               20) == 0)
    return true;

  char contract[43] = "0x";
  ethereum_address_checksum(address, contract + 2, false, chain_id);

  return confirm(ButtonRequestType_ButtonRequest_ConfirmOutput, "MakerDAO",
                 "Confirm TUB:\n%s", contract);
}

bool makerdao_isOasisDEXAddress(const uint8_t *address, uint32_t chain_id) {
  // Mainnet
  // https://github.com/makerdao/scd-cdp-portal/blob/fac7b0571dc4128e89dcd5f7f8d44ded4b66073b/src/settings.json#L17
  if (chain_id == 1 && memcmp(address,
                              "\x39\x75\x53\x57\x75\x9c\xe0\xd7\xf3\x2d\xc8\xdc"
                              "\x45\x41\x4c\xca\x40\x9a\xe2\x4e",
                              20) == 0)
    return true;

  // Kovan
  if (chain_id == 42 && memcmp(address,
                               "\x4a\x6b\xc4\xe8\x03\xc6\x20\x81\xff\xeb\xcc"
                               "\x8d\x22\x7b\x5a\x87\xa5\x8f\x1f\x8f",
                               20) == 0)
    return true;

  return false;
}

static bool confirmParamIsOTCProvider(const uint8_t *param, uint32_t chain_id,
                                      const char **otcProvider) {
  if (memcmp(param, "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", 12) !=
      0)
    return false;

  const uint8_t *address = param + 12;

  if (makerdao_isOasisDEXAddress(address, chain_id)) {
    if (otcProvider) *otcProvider = " via OasisDEX";
    return true;
  }

  char contract[43] = "0x";
  ethereum_address_checksum(address, contract + 2, false, chain_id);

  return confirm(ButtonRequestType_ButtonRequest_ConfirmOutput, "MakerDAO",
                 "Confirm OTC:\n%s", contract);
}

static bool confirmParamIsRegistryAddress(const uint8_t *param,
                                          uint32_t chain_id) {
  if (memcmp(param, "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", 12) !=
      0)
    return false;

  const uint8_t *address = param + 12;

  // Mainnet
  // https://github.com/makerdao/scd-cdp-portal/blob/fac7b0571dc4128e89dcd5f7f8d44ded4b66073b/src/settings.json#L21
  if (chain_id == 1 && memcmp(address,
                              "\x46\x78\xf0\xa6\x95\x8e\x4d\x2b\xc4\xf1\xba\xf7"
                              "\xbc\x52\xe8\xf3\x56\x4f\x3f\xe4",
                              20) == 0)
    return true;

  // Kovan
  if (chain_id == 42 && memcmp(address,
                               "\x64\xa4\x36\xae\x83\x1c\x16\x72\xae\x81\xf6"
                               "\x74\xca\xb8\xb6\x77\x5d\xf3\x47\x5c",
                               20) == 0)
    return true;

  char contract[43] = "0x";
  ethereum_address_checksum(address, contract + 2, false, chain_id);

  return confirm(ButtonRequestType_ButtonRequest_ConfirmOutput, "MakerDAO",
                 "Confirm Proxy Registry:\n%s", contract);
}

static bool confirmSaiProxyCreateAndExecuteAddress(const uint8_t *address,
                                                   uint32_t chain_id) {
  // Mainnet
  // https://github.com/makerdao/scd-cdp-portal/blob/fac7b0571dc4128e89dcd5f7f8d44ded4b66073b/src/settings.json#L22
  if (chain_id == 1 && memcmp(address,
                              "\x52\x6a\xf3\x36\xd6\x14\xad\xe5\xcc\x25\x2a\x40"
                              "\x70\x62\xb8\x86\x1a\xf9\x98\xf5",
                              20) == 0)
    return true;

  if (chain_id == 1 && memcmp(address,
                              "\x19\x0c\x2C\xFC\x69\xE6\x8A\x8e\x8D\x5e\x2b\x9e"
                              "\x2B\x9C\xc3\x33\x2C\xaf\xF7\x7B",
                              20) == 0)
    return true;

  // Kovan
  // https://github.com/makerdao/scd-cdp-portal/blob/bde18348919784c14bb36c747d368b72b1c8f064/src/settings.json#L12
  if (chain_id == 42 && memcmp(address,
                               "\x96\xfc\x00\x5a\x8b\xa8\x2b\x84\xb1\x1e\x0f"
                               "\xf2\x11\xa2\xa1\x36\x2f\x10\x7e\xf0",
                               20) == 0)
    return true;

  char contract[43] = "0x";
  ethereum_address_checksum(address, contract + 2, false, chain_id);

  return confirm(ButtonRequestType_ButtonRequest_ConfirmOutput, "MakerDAO",
                 "Confirm SaiProxyCreateAndExecute:\n%s", contract);
}

static bool isProxyCall(const EthereumSignTx *msg) {
  if (memcmp(msg->data_initial_chunk.bytes, "\x1c\xff\x79\xcd", 4) != 0)
    return false;

  if (msg->data_initial_chunk.size < 4 + 32 + 32 + 32) return false;

  bignum256 offset;
  bn_from_bytes(msg->data_initial_chunk.bytes + 4 + 32, 32, &offset);

  if (32 < bn_bitcount(&offset)) return false;

  if (64 != bn_write_uint32(&offset)) return false;

  bignum256 length;
  bn_from_bytes(msg->data_initial_chunk.bytes + 4 + 32 + 32, 32, &length);

  if (32 < bn_bitcount(&length)) return false;

  if (msg->data_initial_chunk.size ==
      4 + 3 * 32 + (bn_write_uint32(&length) - 4))
    return false;

  return true;
}

static bool confirmProxyCall(const EthereumSignTx *msg) {
  if (memcmp(msg->data_initial_chunk.bytes + 4,
             "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", 12) != 0)
    return false;

  if (!confirmSaiProxyCreateAndExecuteAddress(
          msg->data_initial_chunk.bytes + 4 + 12, msg->chain_id))
    return false;

  return true;
}

static inline bool hasParams(const EthereumSignTx *msg, size_t count) {
  return msg->data_initial_chunk.size == 4 + count * 32;
}

static inline bool hasProxiedParams(const EthereumSignTx *msg, size_t count) {
  return msg->data_initial_chunk.size == 4 + 3 * 32 + 4 + count * 32 + (32 - 4);
}

static inline const uint8_t *getMethod(const EthereumSignTx *msg) {
  return msg->data_initial_chunk.bytes;
}

static inline const uint8_t *getParam(const EthereumSignTx *msg, size_t idx) {
  if (isProxyCall(msg)) {
    return msg->data_initial_chunk.bytes + 4 + 3 * 32 + 4 + idx * 32;
  }

  return msg->data_initial_chunk.bytes + 4 + idx * 32;
}

static inline const uint8_t *getProxiedMethod(const EthereumSignTx *msg) {
  return msg->data_initial_chunk.bytes + 4 + 3 * 32;
}

static bool isMethod(const EthereumSignTx *msg, const char *hash,
                     size_t arg_count) {
  if (isProxyCall(msg)) {
    if (!hasProxiedParams(msg, arg_count)) return false;

    if (memcmp(getProxiedMethod(msg), hash, 4) != 0) return false;

    return true;
  }

  if (!hasParams(msg, arg_count)) return false;

  if (memcmp(getMethod(msg), hash, 4) != 0) return false;

  return true;
}

static void getETHValue(const EthereumSignTx *msg, bignum256 *val) {
  uint8_t pad_val[32];
  memset(pad_val, 0, sizeof(pad_val));
  memcpy(pad_val + (32 - msg->value.size), msg->value.bytes, msg->value.size);
  bn_read_be(pad_val, val);
}

static bool isETHValueZero(const EthereumSignTx *msg) {
  bignum256 val;
  getETHValue(msg, &val);
  return bn_is_zero(&val);
}

bool makerdao_isOpen(const EthereumSignTx *msg) {
  // `open(address)`
  if (!isMethod(msg, "\xc7\x40\x73\xa1", 1)) return false;

  return true;
}

bool makerdao_confirmOpen(const EthereumSignTx *msg) {
  if (!confirmParamIsTub(getParam(msg, 0), msg->chain_id)) return false;

  return confirm(ButtonRequestType_ButtonRequest_ConfirmOutput, "MakerDAO",
                 "Open CDP?");
}

bool makerdao_isClose(const EthereumSignTx *msg) {
  // `shut(address,bytes32)`
  // `shut(address,bytes32,address)`
  if (!isMethod(msg, "\xbc\x24\x4c\x11", 2) &&
      !isMethod(msg, "\x79\x20\x37\xe3", 3))
    return false;

  uint32_t cupId;
  if (!getCupId(getParam(msg, 1), &cupId)) return false;

  if (!isETHValueZero(msg)) return false;

  return true;
}

bool makerdao_confirmClose(const EthereumSignTx *msg) {
  if (!confirmParamIsTub(getParam(msg, 0), msg->chain_id)) return false;

  uint32_t cupId;
  if (!getCupId(getParam(msg, 1), &cupId)) return false;

  const char *otcProvider = "";
  if (isMethod(msg, "\x79\x20\x37\xe3", 3)) {
    if (confirmParamIsOTCProvider(getParam(msg, 2), msg->chain_id,
                                  &otcProvider))
      return false;
  }

  return confirm(ButtonRequestType_ButtonRequest_ConfirmOutput, "MakerDAO",
                 "Close CDP %" PRIu32 "%s?", cupId, otcProvider);
}

bool makerdao_isGive(const EthereumSignTx *msg) {
  // `give(address,bytes32,address)`
  if (!isMethod(msg, "\xda\x93\xdf\xcf", 3)) return false;

  uint32_t cupId;
  if (!getCupId(getParam(msg, 1), &cupId)) return false;

  if (memcmp(getParam(msg, 2),
             "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", 12) != 0)
    return false;

  if (!isETHValueZero(msg)) return false;

  return true;
}

bool makerdao_confirmGive(const EthereumSignTx *msg) {
  if (!confirmParamIsTub(getParam(msg, 0), msg->chain_id)) return false;

  uint32_t cupId;
  if (!getCupId(getParam(msg, 1), &cupId)) return false;

  char new_owner[43] = "0x";
  ethereum_address_checksum(getParam(msg, 2) + 12, new_owner + 2, false,
                            msg->chain_id);

  return confirm(ButtonRequestType_ButtonRequest_ConfirmOutput, "MakerDAO",
                 "Move CDP %" PRIu32 " to %s?", cupId, new_owner);
}

bool makerdao_isLockAndDraw2(const EthereumSignTx *msg) {
  // `lockAndDraw(address,uint256)`
  if (!isMethod(msg, "\x51\x6e\x9a\xec", 2)) return false;

  return true;
}

bool makerdao_confirmLockAndDraw2(const EthereumSignTx *msg) {
  if (!confirmParamIsTub(getParam(msg, 0), msg->chain_id)) return false;

  bignum256 deposit_val;
  getETHValue(msg, &deposit_val);

  char deposit[32];
  ethereumFormatAmount(&deposit_val, NULL, msg->chain_id, deposit,
                       sizeof(deposit));

  const TokenType *DAI;
  if (!tokenByTicker(msg->chain_id, "DAI", &DAI)) return false;

  bignum256 withdraw_val;
  bn_from_bytes(getParam(msg, 1), 32, &withdraw_val);

  char withdraw[32];
  ethereumFormatAmount(&withdraw_val, DAI, msg->chain_id, withdraw,
                       sizeof(withdraw));

  return confirm(ButtonRequestType_ButtonRequest_ConfirmOutput, "MakerDAO",
                 "Create CDP, deposit %s, and generate %s from it?", deposit,
                 withdraw);
}

bool makerdao_isCreateOpenLockAndDraw(const EthereumSignTx *msg) {
  // `createOpenLockAndDraw(address,address,uint256)`
  if (!isMethod(msg, "\xd3\x14\x0a\x65", 3)) return false;

  return true;
}

bool makerdao_confirmCreateOpenLockAndDraw(const EthereumSignTx *msg) {
  if (!confirmParamIsRegistryAddress(getParam(msg, 0), msg->chain_id))
    return false;

  if (!confirmParamIsTub(getParam(msg, 1), msg->chain_id)) return false;

  bignum256 deposit_val;
  getETHValue(msg, &deposit_val);

  char deposit[32];
  ethereumFormatAmount(&deposit_val, NULL, msg->chain_id, deposit,
                       sizeof(deposit));

  const TokenType *DAI;
  if (!tokenByTicker(msg->chain_id, "DAI", &DAI)) return false;

  bignum256 withdraw_val;
  bn_from_bytes(getParam(msg, 2), 32, &withdraw_val);

  char withdraw[32];
  ethereumFormatAmount(&withdraw_val, DAI, msg->chain_id, withdraw,
                       sizeof(withdraw));

  return confirm(
      ButtonRequestType_ButtonRequest_ConfirmOutput, "MakerDAO",
      "Create proxy, create CDP, deposit %s, and generate %s from it?", deposit,
      withdraw);
}

bool makerdao_isLock(const EthereumSignTx *msg) {
  // `lock(address,bytes32)`
  if (!isMethod(msg, "\xbc\x25\xa8\x10", 2)) return false;

  uint32_t cupId;
  if (!getCupId(getParam(msg, 1), &cupId)) return false;

  return true;
}

bool makerdao_confirmLock(const EthereumSignTx *msg) {
  if (!confirmParamIsTub(getParam(msg, 0), msg->chain_id)) return false;

  bignum256 deposit_val;
  getETHValue(msg, &deposit_val);

  char deposit[32];
  ethereumFormatAmount(&deposit_val, NULL, msg->chain_id, deposit,
                       sizeof(deposit));

  uint32_t cupId;
  if (!getCupId(getParam(msg, 1), &cupId)) return false;

  return confirm(ButtonRequestType_ButtonRequest_ConfirmOutput, "MakerDAO",
                 "Deposit %s into CDP %" PRIu32 "?", deposit, cupId);
}

bool makerdao_isDraw(const EthereumSignTx *msg) {
  // `draw(address,bytes32,uint256)`
  if (!isMethod(msg, "\x03\x44\xa3\x6f", 3)) return false;

  uint32_t cupId;
  if (!getCupId(getParam(msg, 1), &cupId)) return false;

  if (!isETHValueZero(msg)) return false;

  return true;
}

bool makerdao_confirmDraw(const EthereumSignTx *msg) {
  if (!confirmParamIsTub(getParam(msg, 0), msg->chain_id)) return false;

  uint32_t cupId;
  if (!getCupId(getParam(msg, 1), &cupId)) return false;

  bignum256 withdraw_val;
  bn_from_bytes(getParam(msg, 2), 32, &withdraw_val);

  const TokenType *DAI;
  if (!tokenByTicker(msg->chain_id, "DAI", &DAI)) return false;

  char withdraw[32];
  ethereumFormatAmount(&withdraw_val, DAI, msg->chain_id, withdraw,
                       sizeof(withdraw));

  return confirm(ButtonRequestType_ButtonRequest_ConfirmOutput, "MakerDAO",
                 "Generate %s from CDP %" PRIu32 "?", withdraw, cupId);
}

bool makerdao_isLockAndDraw3(const EthereumSignTx *msg) {
  // `lockAndDraw(address,bytes32,uint256)`
  if (!isMethod(msg, "\x1e\xdf\x0c\x1e", 3)) return false;

  uint32_t cupId;
  if (!getCupId(getParam(msg, 1), &cupId)) return false;

  return true;
}

bool makerdao_confirmLockAndDraw3(const EthereumSignTx *msg) {
  if (!confirmParamIsTub(getParam(msg, 0), msg->chain_id)) return false;

  bignum256 deposit_val;
  getETHValue(msg, &deposit_val);

  char deposit[32];
  ethereumFormatAmount(&deposit_val, NULL, msg->chain_id, deposit,
                       sizeof(deposit));

  uint32_t cupId;
  if (!getCupId(getParam(msg, 1), &cupId)) return false;

  bignum256 withdraw_val;
  bn_from_bytes(getParam(msg, 2), 32, &withdraw_val);

  const TokenType *DAI;
  if (!tokenByTicker(msg->chain_id, "DAI", &DAI)) return false;

  char withdraw[32];
  ethereumFormatAmount(&withdraw_val, DAI, msg->chain_id, withdraw,
                       sizeof(withdraw));

  return confirm(ButtonRequestType_ButtonRequest_ConfirmOutput, "MakerDAO",
                 "Deposit %s into CDP %" PRIu32 " and generate %s?", deposit,
                 cupId, withdraw);
}

bool makerdao_isFree(const EthereumSignTx *msg) {
  // `free(address,bytes32,uint256)`
  if (!isMethod(msg, "\xf9\xef\x04\xbe", 3)) return false;

  uint32_t cupId;
  if (!getCupId(getParam(msg, 1), &cupId)) return false;

  if (!isETHValueZero(msg)) return false;

  return true;
}

bool makerdao_confirmFree(const EthereumSignTx *msg) {
  if (!confirmParamIsTub(getParam(msg, 0), msg->chain_id)) return false;

  uint32_t cupId;
  if (!getCupId(getParam(msg, 1), &cupId)) return false;

  bignum256 withdraw_val;
  bn_from_bytes(getParam(msg, 2), 32, &withdraw_val);

  char withdraw[32];
  ethereumFormatAmount(&withdraw_val, NULL, msg->chain_id, withdraw,
                       sizeof(withdraw));

  return confirm(ButtonRequestType_ButtonRequest_ConfirmOutput, "MakerDAO",
                 "Withdraw %s from CDP %" PRIu32 "?", withdraw, cupId);
}

bool makerdao_isWipe(const EthereumSignTx *msg) {
  // `wipe(address,bytes,uint256)`
  // `wipe(address,bytes,uint256,address)`
  if (!isMethod(msg, "\xa3\xdc\x65\xa7", 3) &&
      !isMethod(msg, "\x8a\x9f\xc4\x75", 4))
    return false;

  uint32_t cupId;
  if (!getCupId(getParam(msg, 1), &cupId)) return false;

  if (!isETHValueZero(msg)) return false;

  return true;
}

bool makerdao_confirmWipe(const EthereumSignTx *msg) {
  if (!confirmParamIsTub(getParam(msg, 0), msg->chain_id)) return false;

  uint32_t cupId;
  if (!getCupId(getParam(msg, 1), &cupId)) return false;

  bignum256 deposit_val;
  bn_from_bytes(getParam(msg, 2), 32, &deposit_val);

  const TokenType *DAI;
  if (!tokenByTicker(msg->chain_id, "DAI", &DAI)) return false;

  char deposit[32];
  ethereumFormatAmount(&deposit_val, DAI, msg->chain_id, deposit,
                       sizeof(deposit));

  const char *otcProvider = "";
  if (isMethod(msg, "\x8a\x9f\xc4\x75", 4)) {
    if (confirmParamIsOTCProvider(getParam(msg, 2), msg->chain_id,
                                  &otcProvider))
      return false;
  }

  return confirm(ButtonRequestType_ButtonRequest_ConfirmOutput, "MakerDAO",
                 "Payback %s into CDP %" PRIu32 "%s?", deposit, cupId,
                 otcProvider);
}

bool makerdao_isWipeAndFree(const EthereumSignTx *msg) {
  // `wipeAndFree(address,bytes32,uint256,uint256)`
  // `wipeAndFree(address,bytes32,uint256,uint256,address)`
  if (!isMethod(msg, "\xfa\xed\x77\xab", 4) &&
      !isMethod(msg, "\x1b\x96\x81\x60", 5))
    return false;

  uint32_t cupId;
  if (!getCupId(getParam(msg, 1), &cupId)) return false;

  if (!isETHValueZero(msg)) return false;

  return true;
}

bool makerdao_confirmWipeAndFree(const EthereumSignTx *msg) {
  if (!confirmParamIsTub(getParam(msg, 0), msg->chain_id)) return false;

  uint32_t cupId;
  if (!getCupId(getParam(msg, 1), &cupId)) return false;

  bignum256 deposit_val;
  bn_from_bytes(getParam(msg, 2), 32, &deposit_val);

  const TokenType *DAI;
  if (!tokenByTicker(msg->chain_id, "DAI", &DAI)) return false;

  char deposit[32];
  ethereumFormatAmount(&deposit_val, DAI, msg->chain_id, deposit,
                       sizeof(deposit));

  bignum256 withdraw_val;
  bn_from_bytes(getParam(msg, 2), 32, &withdraw_val);

  char withdraw[32];
  ethereumFormatAmount(&withdraw_val, NULL, msg->chain_id, withdraw,
                       sizeof(withdraw));

  const char *otcProvider = "";
  if (isMethod(msg, "\x1b\x96\x81\x60", 5)) {
    if (!confirmParamIsOTCProvider(getParam(msg, 4), msg->chain_id,
                                   &otcProvider))
      return false;
  }

  return confirm(ButtonRequestType_ButtonRequest_ConfirmOutput, "MakerDAO",
                 "Payback %s and withdraw %s from CDP %" PRIu32 "%s?", deposit,
                 withdraw, cupId, otcProvider);
}

bool makerdao_isMakerDAO(uint32_t data_total, const EthereumSignTx *msg) {
  if (!msg->has_chain_id) return false;

  if (data_total != msg->data_initial_chunk.size) return false;

  if (makerdao_isOpen(msg)) return true;

  if (makerdao_isClose(msg)) return true;

  if (makerdao_isGive(msg)) return true;

  if (makerdao_isLockAndDraw2(msg)) return true;

  if (makerdao_isCreateOpenLockAndDraw(msg)) return true;

  if (makerdao_isLock(msg)) return true;

  if (makerdao_isDraw(msg)) return true;

  if (makerdao_isLockAndDraw3(msg)) return true;

  if (makerdao_isFree(msg)) return true;

  if (makerdao_isWipe(msg)) return true;

  if (makerdao_isWipeAndFree(msg)) return true;

  return false;
}

bool makerdao_confirmMakerDAO(uint32_t data_total, const EthereumSignTx *msg) {
  (void)data_total;

  if (isProxyCall(msg)) {
    if (!confirmProxyCall(msg)) {
      return false;
    }
  } else {
    if (!confirmSaiProxyCreateAndExecuteAddress(msg->to.bytes, msg->chain_id)) {
      return false;
    }
  }

  if (makerdao_isOpen(msg)) return makerdao_confirmOpen(msg);

  if (makerdao_isClose(msg)) return makerdao_confirmClose(msg);

  if (makerdao_isGive(msg)) return makerdao_confirmGive(msg);

  if (makerdao_isLockAndDraw2(msg)) return makerdao_confirmLockAndDraw2(msg);

  if (makerdao_isCreateOpenLockAndDraw(msg))
    return makerdao_confirmCreateOpenLockAndDraw(msg);

  if (makerdao_isLock(msg)) return makerdao_confirmLock(msg);

  if (makerdao_isDraw(msg)) return makerdao_confirmDraw(msg);

  if (makerdao_isLockAndDraw3(msg)) return makerdao_confirmLockAndDraw3(msg);

  if (makerdao_isFree(msg)) return makerdao_confirmFree(msg);

  if (makerdao_isWipe(msg)) return makerdao_confirmWipe(msg);

  if (makerdao_isWipeAndFree(msg)) return makerdao_confirmWipeAndFree(msg);

  return false;
}
