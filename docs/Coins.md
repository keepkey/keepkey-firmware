# BIP-44 Derivation Paths

| Coin              | Curve            | GetPublicKey           | GetAddress         | SignTx             | Derivation    | Note           |
|-------------------|------------------|------------------------|--------------------|--------------------|---------------|----------------|
| Bitcoin           | secp256k1        | `m/p'/c'/a'`           | `m/p'/c'/a'/h/i`   | `m/p'/c'/a'/h/i`   | BIP-32        | [1](#Bitcoin)  |
| Ethereum          | secp256k1        | `m/44'/60'/0'`         | `m/44'/60'/a'/0/0` | `m/44'/60'/a'/0/0` | BIP-32        | [2](#Ethereum) |

Where `p` is the [BIP-44](https://github.com/bitcoin/bips/blob/master/bip-0044.mediawiki) purpose described further in [1](#Bitcoin).

Where `c` is the Coin's [slip44 id](https://github.com/satoshilabs/slips/blob/master/slip-0044.md).

Where `a` is the Account index, starting from `0`.

Where `h` is `0` / `1` for External / Change respectively (for UTXO coins).

Where `i` is the address index, starting from `0`.

# Notes

1. <a name="Bitcoin"></a> For Bitcoin and its derivatives, `p` is decided based on:

    | p    | Type          | Input Script Type    |
    |------|---------------|----------------------|
    |   44 | Legacy        | SPENDADDRESS         |
    |   48 | Multisig      | SPENDMULTISIG        |
    |   49 | p2sh SegWit   | SPENDP2SHWITNESS     |
    |   84 | Native SegWit | SPENDWITNESS         |

Other `p` are strongly discouraged with an on-device warning. `c` must be equal
to the coin's [slip44-id](https://github.com/satoshilabs/slips/blob/master/slip-0044.md).

2. <a name="Ethereum"></a> For legacy reasons, Ethereum address derivation
paths are very non-standardized across vendors. Not much we can do about it
unfortunately, since there are lots of wallets out in the wild with funds on
them at those addresses.

## Allowed Values

For SignTx on UTXO coins, `i` must be in the range \[0, 1000000].
