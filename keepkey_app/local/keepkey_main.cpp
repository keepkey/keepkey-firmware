#include <cassert>
#include <cstring>
#include <iomanip>
#include <iostream>
#include <string>
#include <sstream>
#include <vector>

#include <crypto/public/crypto.h>

#include "bitcoin.h"


/*
 * Performs user prompting, etc. to make and confirm mnemonic.
 */
std::string get_mnemonic() {

    char answer = 'n';
    std::string mnemonic;

    do {
        /*
         * Generate seed and wait for user affirmation.
         */
        mnemonic = cd::make_mnemonic();

        std::cout << "\nGenerated seed: \"" <<  mnemonic << "\"" << std::endl;
        std::cout << "    Is this OK? y/n: " << std::endl;
        std::cin >> answer;
    } while (answer != 'y');

    std::cout << "mnemonic CONFIRMED." << std::endl;

    return mnemonic;
}

bool read_and_sign(std::string &tx_fn) {
    /*
    FILE* fp = fopen(tx_fn, "r");

    if(fp == NULL) {
        std::cout << "Transaction file: " << tx_fn << " not found." << std::endl;
        return false;
    }
    */
    return false;
}

std::string hexdump(std::vector<uint8_t> &v) {
    std::ostringstream ret;

    for(size_t i=0; i < v.size(); i++) {
        ret << std::hex << std::setfill('0') << std::setw(2) << v[i];
        if(i != v.size()-1) {
            ret << " ";
        }
    }

    return ret.str();
}

void print_wallet(HDNode& wallet) {
    std::cout << "Created bip32 wallet:" << std::endl;
    std::cout << "  depth       : " <<  wallet.depth << std::endl;
    std::cout << "  fingerprint : " <<  wallet.fingerprint << std::endl;
    std::cout << "  child_num   : " <<  wallet.child_num << std::endl; 
    std::vector<uint8_t> v;
    v.assign(wallet.chain_code, wallet.chain_code + sizeof(wallet.chain_code));
    /*
    std::cout << "  chain_code  : " << hexdump(std::vector<uint8_t>(wallet.chain_code)) << std::endl;
    std::cout << "  private_key : " << hexdump(wallet.private_key) << std::endl;
    std::cout << "  public_key  : " << hexdump(wallet.public_key) << std::endl;
    */
}

int main(int argc, char *argv[]) {

    std::cout << "Making seed ..." << std::endl;
    std::string mnemonic = get_mnemonic();

    /**
     * Make the bip32 wallet.
     */
    HDNode wallet = cd::make_wallet(mnemonic);
    print_wallet(wallet);

    /*
     * Read transaction from file and do it.
     */
    std::string transaction_filename("tx.txt");
    std::cout << "Reading transaction from " <<  transaction_filename << " ... " << std::endl;
    read_and_sign(transaction_filename);
    std::cout << "Transaction signed." << std::endl;

    return 0;
}
