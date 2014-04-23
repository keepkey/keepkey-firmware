#!/usr/bin/python
from fabric.api import *
from fabric.contrib.files import *

# Path to keepkey app directory.
KEEPKEY_PATH = os.environ['KEEPKEY']
KEEPKEY_BIN = os.path.join(KEEPKEY_PATH, 'keepkey_main.elf')
KEEPKEY_WALLET = os.path.join(KEEPKEY_PATH, 'keepkey_wallet.dat')

BITCOIND = 'bitcoind -testnet'
BITCOIND_ADDR = 

#
# The original transaction that funded the multisig address
#
INPUT_TX = 

#
# ALL KEYPAIRS are PRIVATE/PUBLIC.
#



#
# @return the public/private keypair for the keepkey
def provision_keepkey():
    #
    # Check if kk wallet file exists.  If so, just grab the required
    # key info.
    #
    if not exists(KEEPKEY_WALLET):
        local(KEEPKEY_BIN + ' --make')

    info = local(KEEPKEY_BIN + ' --show')

    keypair = info.split(' ')
    return keypair

def provision_bitcoind():
    # bitcoind -testnet dumpprivkey
    privkey = 'cSFZsVkzZMeqj43Lb3YQJGi4oJGJZR3hitHHjbpAMH7mAxhKESXE'

    # bitcoind -testnet validateaddress
    pubkey = '02b5e219df1509538bbc227e41124764766682b456d99fb2e53deb99a62b19e6bc'

    return privkey,pubkey

def main():
    kk_keypair = provision_keepkey()
    bc_keypair = provision_bitcoind()

    


if __name__ == '__main__':
    main()



