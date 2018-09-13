| Field                     | Type           | Size (bytes) | Storage Offset (bytes) |
| ------------------------- | -------------- | ------------ | ---------------------- |
| version                   | u32            |            4 |                      0 |
| has_node                  | bool           |            1 |                      4 |
| node                      | StorageHDNode  |              |                      8 |
| reserved                  | N/A            |            3 |                    137 |
| has_mnemonic              | bool           |            1 |                    140 |
| mnemonic                  | char[241]      |          241 |                    141 |
| reserved                  | N/A            |            1 |                    382 |
| passphrase_protection     | bool           |            1 |                    383 |
| has_pin_failed_attempts   | bool           |            1 |                    384 |
| reserved                  | N/A            |            3 |                    385 |
| pin_failed_attempts       | u32            |            4 |                    388 |
| has_pin                   | bool           |            1 |                    392 |
| pin                       | char[10]       |           10 |                    393 |
| has_language              | bool           |            1 |                    403 |
| language                  | char[17]       |           17 |                    404 |
| has_label                 | bool           |            1 |                    421 |
| label                     | char[33]       |           33 |                    422 |
| reserved                  | N/A            |            1 |                    455 |
| imported                  | bool           |            1 |                    456 |
| reserved                  | N/A            |            3 |                    457 |
| policies_count            | u32            |            4 |                    460 |
| policies[0]               | StoragePolicy  |           18 |                    464 |
| policies[1]               | StoragePolicy  |           18 |                    482 |
| policies[2] (reserved)    | StoragePolicy  |           18 |                    500 |
| policies[3] (reserved)    | StoragePolicy  |           18 |                    518 |
| policies[4] (reserved)    | StoragePolicy  |           18 |                    536 |
| policies[5] (reserved)    | StoragePolicy  |           18 |                    554 |
| policies[6] (reserved)    | StoragePolicy  |           18 |                    572 |
| policies[7] (reserved)    | StoragePolicy  |           18 |                    590 |
| policies[8] (reserved)    | StoragePolicy  |           18 |                    608 |
| has_auto_lock_delay_ms    | bool           |            1 |                    626 |
| auto_lock_delay_ms        | u32            |            4 |                    627 |
| reserved                  | char[169]      |          169 |                    631 |
