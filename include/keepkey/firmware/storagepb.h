/*
 * This file is part of the KeepKey project.
 *
 * Copyright (C) 2018 KeepKey LLC
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

/* === Includes ============================================================ */

#ifndef STORAGEPB_H
#define STORAGEPB_H

/* 
    WARNING:
    These structs overlay state information needed for firmware updates. All
    storage sizes and ordering should remain in place. To remove a variable
    from use, indicate that it is deprecated rather than deleting it.
*/

typedef struct _StoragePolicy {
    bool has_policy_name;
    char policy_name[15];
    bool has_enabled;
    bool enabled;
} StoragePolicy;

typedef struct _StorageHDNode {
    uint32_t depth;
    uint32_t fingerprint;
    uint32_t child_num;
    struct {
        uint32_t size;
        uint8_t bytes[32];
    } chain_code;
    bool has_private_key;
    struct {
        uint32_t size;
        uint8_t bytes[32];
    } private_key;
    bool has_public_key;
    struct {
        uint32_t size;
        uint8_t bytes[33];
    } public_key;
} StorageHDNode;

typedef struct _Storage {
    uint32_t version;
    bool has_node;
    StorageHDNode node;
    bool has_mnemonic;
    char mnemonic[241];
    bool has_passphrase_protection;
    bool passphrase_protection;
    bool has_pin_failed_attempts;
    uint32_t pin_failed_attempts;
    bool has_pin;
    char pin[10];
    bool has_language;
    char language[17];
    bool has_label;
    char label[33];
    bool has_imported;
    bool imported;
    uint32_t policies_count;
    StoragePolicy policies[1];
} Storage;

#endif
