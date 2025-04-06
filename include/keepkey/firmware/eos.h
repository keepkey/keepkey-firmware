/*
 * This file is part of the KeepKey project.
 *
 * Copyright (C) 2018 KeepKey
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

#ifndef KEEPKEY_FIRMWARE_EOS_H
#define KEEPKEY_FIRMWARE_EOS_H

#include "hwcrypto/crypto/bip32.h"

#include "messages-eos.pb.h"

#include <inttypes.h>
#include <stdbool.h>

#define EOS_NAME_STR_SIZE (12 + 1 + 1)
#define EOS_ASSET_STR_SIZE (1 + 21 + 1 + 12 + 1)

// C++ constexpr would be neat here...
typedef enum _EosActionName {
  EOS_Transfer = 0xcdcd3c2d57000000L,
  EOS_Owner = 0xa726ab8000000000L,
  EOS_Active = 0x3232eda800000000L,
  EOS_DelegateBW = 0x4aa2a61b2a3f0000L,
  EOS_UndelegateBW = 0xd4d2a8a986ca8fc0L,
  EOS_Refund = 0xba97a9a400000000L,
  EOS_BuyRam = 0x3ebd734800000000L,
  EOS_BuyRamBytes = 0x3ebd7348fecab000L,
  EOS_SellRam = 0xc2a31b9a40000000L,
  EOS_VoteProducer = 0xdd32aade89d21570L,
  EOS_UpdateAuth = 0xd5526ca8dacb4000L,
  EOS_DeleteAuth = 0x4aa2aca8dacb4000L,
  EOS_LinkAuth = 0x8ba7036b2d000000L,
  EOS_UnlinkAuth = 0xd4e2e9c0dacb4000L,
  EOS_NewAccount = 0x9ab864229a9e4000L,
} EosActionName;

typedef enum _EosContractName {
  EOS_eosio = 0x5530ea0000000000L,
  EOS_eosio_token = 0x5530ea033482a600L,
} EosContractName;

/// \returns true iff the asset can be correctly decoded.
bool eos_formatAsset(const EosAsset *asset, char str[EOS_ASSET_STR_SIZE]);

/// \returns true iff the name can be correctly decoded.
bool eos_formatName(uint64_t name, char str[EOS_NAME_STR_SIZE]);

/// \returns true iff successful.
bool eos_derivePublicKey(const uint32_t *addr_n, size_t addr_n_count,
                         uint8_t *public_key, size_t len);

/// \returns true iff successful.
bool eos_getPublicKey(const HDNode *node, const curve_info *curve,
                      EosPublicKeyKind kind, char *str, size_t len);

/// \returns true iff successful.
bool eos_publicKeyToWif(const uint8_t *public_key, EosPublicKeyKind kind,
                        char *pubkey, size_t len);

void eos_signingInit(const uint8_t *chain_id, uint32_t num_actions,
                     const EosTxHeader *_header, const HDNode *_root,
                     const uint32_t _address_n[8], size_t _address_n_count);

bool eos_signingIsInited(void);

void eos_signingAbort(void);

bool eos_signingIsFinished(void);

uint32_t eos_actionsRemaining(void);

bool eos_hasActionUnknownDataRemaining(void);

/// \returns true iff successful.
bool eos_compileActionUnknown(const EosActionCommon *common,
                              const EosActionUnknown *action);

/// \brief Append a u64 to the hash, with variable length encoding.
/// \param hasher   If nonnull, the hasher to append to.
/// \param val      The value to append.
/// \returns the number of bytes hashed.
size_t eos_hashUInt(Hasher *hasher, uint64_t val);

/// \returns true iff successful.
bool eos_compileAsset(const EosAsset *asset);

/// \returns true iff successful.
bool eos_compileActionCommon(const EosActionCommon *common);

/// \returns true iff successful.
bool eos_compilePermissionLevel(const EosPermissionLevel *auth);

bool eos_signTx(EosSignedTx *sig);

#endif
