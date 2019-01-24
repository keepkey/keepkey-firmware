STORAGE_VERSION 1 layout
------------------------

This is the original storage layout, derived from the use of un-serialized
protobuf structs as a serialization format. This made storage extremely
sensitive to changes in the protobuf descriptors, and is considered bad
practice.

| Field                     | Type           | Size (bytes) | Offset (bytes) |
| ------------------------- | -------------- | ------------ | -------------- |
| version                   | u32            |            4 |              0 |
| has_node                  | bool           |            1 |              4 |
| node                      | StorageHDNode  |          129 |              8 |
| reserved                  | N/A            |            3 |            137 |
| has_mnemonic              | bool           |            1 |            140 |
| mnemonic                  | char[241]      |          241 |            141 |
| reserved                  | N/A            |            1 |            382 |
| passphrase_protection     | bool           |            1 |            383 |
| has_pin_failed_attempts   | bool           |            1 |            384 |
| reserved                  | N/A            |            3 |            385 |
| pin_failed_attempts       | u32            |            4 |            388 |
| has_pin                   | bool           |            1 |            392 |
| pin                       | char[10]       |           10 |            393 |
| has_language              | bool           |            1 |            403 |
| language                  | char[17]       |           17 |            404 |
| has_label                 | bool           |            1 |            421 |
| label                     | char[33]       |           33 |            422 |
| reserved                  | N/A            |            1 |            455 |
| imported                  | bool           |            1 |            456 |


STORAGE_VERSION 2-10 layout
---------------------------

This version added the root seed cache, and policy objects. Since it is closely
aligned with V1's layout, it shares many of the same reader functions, which
accounts for the "missing" `storage_readStorageV2()`.

| Field                     | Type           | Size (bytes) | Offset (bytes) |
| ------------------------- | -------------- | ------------ | -------------- |
| version                   | u32            |            4 |              0 |
| has_node                  | bool           |            1 |              4 |
| node                      | StorageHDNode  |          129 |              8 |
| reserved                  | N/A            |            3 |            137 |
| has_mnemonic              | bool           |            1 |            140 |
| mnemonic                  | char[241]      |          241 |            141 |
| reserved                  | N/A            |            1 |            382 |
| passphrase_protection     | bool           |            1 |            383 |
| has_pin_failed_attempts   | bool           |            1 |            384 |
| reserved                  | N/A            |            3 |            385 |
| pin_failed_attempts       | u32            |            4 |            388 |
| has_pin                   | bool           |            1 |            392 |
| pin                       | char[10]       |           10 |            393 |
| has_language              | bool           |            1 |            403 |
| language                  | char[17]       |           17 |            404 |
| has_label                 | bool           |            1 |            421 |
| label                     | char[33]       |           33 |            422 |
| reserved                  | N/A            |            1 |            455 |
| imported                  | bool           |            1 |            456 |
| reserved                  | N/A            |            3 |            457 |
| policies_count            | u32            |            4 |            460 |
| policies[0]               | StoragePolicy  |           18 |            464 |
| reserved                  | N/A            |            2 |            482 |
| root_seed_cache_status    | u8             |            1 |            484 |
| root_seed_cache           | char[64]       |           64 |            485 |
| root_ecdsa_curve_type     | char[10]       |           10 |            549 |


STORAGE_VERSION 11 layout
-------------------------

This is the third generation of storage layouts. It leverages a clean breaking
point to compactify fields, and arrange things in two sections: one for
secrets, and one for public(ish) information.  The secret area is then aes256
encrypted with a randomly generated 64-bit key, which is then wrapped with the
user's pin.  This further hardens the security of a powered-down device.
Additionally, it leaves reserved bytes & bits open for future additions, making
it easier to extend for new features later on.

#### Public(ish) Storage

| Field                     | Type           | Size (bytes) | Offset (bytes) |
| ------------------------- | -------------- | ------------ | -------------- |
| version                   | u32            |            4 |              0 |
| flags                     | u32            |            4 |              4 |
|   has_pin                 |   bit 0        |              |                |
|   has_language            |   bit 1        |              |                |
|   has_label               |   bit 2        |              |                |
|   has_auto_lock_delay_ms  |   bit 3        |              |                |
|   imported                |   bit 4        |              |                |
|   passphrase_protection   |   bit 5        |              |                |
|   ShapeShift policy       |   bit 6        |              |                |
|   Pin Caching policy      |   bit 7        |              |                |
|   has_node                |   bit 8        |              |                |
|   has_mnemonic            |   bit 9        |              |                |
|   has_u2froot             |   bit 10       |              |                |
|   Experinemtal policy     |   bit 11       |              |                |
|   AdvancedMode policy     |   bit 12       |              |                |
|   no backup (seedless)    |   bit 13       |              |                |
|   has_sec_fingerprint     |   bit 14       |              |                |
|   reserved                |   bits 15 - 31 |              |                |
| pin_failed_attempts       | u32            |            4 |              8 |
| auto_lock_delay_ms        | u32            |            4 |             12 |
| language                  | char[16]       |           16 |             16 |
| label                     | char[48]       |           48 |             32 |
| wrapped_storage_key       | char[64]       |           64 |             80 |
| storage_key_fingerprint   | char[64]       |            8 |            144 |
| u2froot                   | StorageHDNode  |          129 |            176 |
| u2f_counter               | u32            |            4 |            305 |
| sec_fingerprint           | char[32]       |           32 |            309 |
| reserved                  | char[123]      |          123 |            341 |
| encrypted_secrets_version | u32            |            4 |            464 |
| encrypted_secrets         | char[512]      |          512 |            468 |


#### Secret Storage

| Field                     | Type           | Size (bytes) | Offset (bytes) |
| ------------------------- | -------------- | ------------ | -------------- |
| node                      | StorageHDNode  |          129 |              0 |
| mnemonic                  | char[241]      |          241 |            129 |
| root_seed_cache_status    | u8             |            1 |            370 |
| root_seed_cache           | char[64]       |           64 |            371 |
| root_ecdsa_curve_type     | char[10]       |           10 |            435 |
| reserved                  | char[63]       |           63 |            445 |
