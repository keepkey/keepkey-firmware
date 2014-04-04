#include <fstream>
#include <iostream>
#include <string>

#include "utility.h"
#include "wallet.h"

namespace cd {

    BIP32Wallet::BIP32Wallet() {}
    BIP32Wallet::~BIP32Wallet() {}

    void BIP32Wallet::init_from_seed(const std::string &mnemonic) {
        /*
         * The glories of inconsistent constness.
         */
        uint8_t *tmp_seed = const_cast<uint8_t*>(reinterpret_cast<const uint8_t*>(seed.c_str()));
        hdnode_from_seed(tmp_seed, seed.length(), &hdnode);
    }

    bool BIP32Wallet::init_from_file(const std::string &filename) {
        if(!is_file(filename.c_str())) {
            return false;
        }

        std::ifstream f;
        f.open(filename.c_str(), std::ios::in | std::ios::binary );

        f >> seed;;
        f >>  hdnode.depth;
        f >> hdnode.fingerprint;
        f >> hdnode.child_num;
        f >> hdnode.chain_code;
        f >> hdnode.private_key;
        f >>hdnode.public_key;

        return true;
    }

    void BIP32Wallet::serialize(const std::string &filename) {
        std::ofstream of;
        of.open(filename.c_str(), std::ios::out | std::ios::binary | std::ios::trunc | std::ios::app);

        of << seed << std::endl;
        of << hdnode.depth << std::endl;
        of << hdnode.fingerprint << std::endl;
        of << hdnode.child_num << std::endl;
        of << hdnode.chain_code << std::endl;
        of << hdnode.private_key << std::endl;
        of << hdnode.public_key << std::endl;
    }

    void BIP32Wallet::print() {
        std::cout << "KeepKey BIP32 wallet:" << std::endl;
        std::cout << "  depth       : " <<  hdnode.depth << std::endl;
        std::cout << "  fingerprint : " <<  hdnode.fingerprint << std::endl;
        std::cout << "  child_num   : " <<  hdnode.child_num << std::endl; 
        std::cout << "  chain_code  : " << hexdump(hdnode.chain_code, sizeof(hdnode.chain_code)) << std::endl;
        std::cout << "  private_key : " << hexdump(hdnode.private_key, sizeof(hdnode.private_key)) << std::endl;
        std::cout << "  public_key  : " << hexdump(hdnode.public_key, sizeof(hdnode.public_key)) << std::endl;
    }
};

