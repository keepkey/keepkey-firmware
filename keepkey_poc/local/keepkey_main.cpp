#include <cassert>
#include <cstring>
#include <iomanip>
#include <iostream>
#include <string>
#include <sstream>
#include <vector>

#include <crypto/public/crypto.h>

#include "bitcoin.h"
#include "cd_file.h"
#include "cd_getopt.h"
#include "diag.h" 
#include "helper_macros.h"
#include "utility.h"
#include "wallet.h"

static const std::string wallet_outfilename("keepkey_wallet.dat");


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

cd::BIP32Wallet get_wallet() {

    cd::BIP32Wallet wallet;
    const std::string wallet_filename(wallet_outfilename);

    /*
     * If wallet file exists, load it, otherwise create a new one.
     */
    if(cd::is_file(wallet_filename.c_str())) {
        std::cout << "Wallet found.  Loading contents from " << wallet_filename << std::endl;
        wallet.init_from_file(wallet_filename);
    } else {
        std::cout << "No pre-existing wallet found.  Generating a new one to " << wallet_filename << std::endl;

        std::string make_seed;
        std::string mnemonic;

        while(1) {
            std::cout << "Generate seed? (y=generate, n=enter your own later)" << std::endl;
            std::cin >> make_seed;

            if(make_seed == "y") {
                std::cout << "Making seed ..." << std::endl;
                mnemonic = get_mnemonic();
                break;
            } else if(make_seed == "n") {
                std::cout << "Enter a custom seed now: ";
                std::cin >> mnemonic;
                std::cout << "Using custom seed: " << mnemonic << std::endl;
                break;
            }
        }

        wallet.init_from_seed(mnemonic);        
        wallet.serialize(wallet_filename);

        char *cwd = get_current_dir_name();
        LOG("Wallet written to : '%s/%s'\n", cwd, wallet_filename.c_str());
        free(cwd);
    }

    return wallet;
}

bool parse_commandline(int argc, char *argv[], cd::CommandLine &cl) {
    std::vector<cd::option_descriptor_t> optlist;
    cd::option_descriptor_t opts[] =
    {
        {
            "show",
            "Displays the contents of the keepkey wallet\n",
            cd::getopt_no_arg,
            cd::getopt_invalid_arg,
            false,
            cd::ArgumentValue()
        },
        {
            "make",
            "Make the initial keepkey wallet\n",
            cd::getopt_no_arg,
            cd::getopt_invalid_arg,
            false,
            cd::ArgumentValue()
        },
        {
            "sign",
            "Signs a raw bip10 transaction (tx dist proposal), as output by bitcoind.\n",
            cd::getopt_no_arg,
            cd::getopt_invalid_arg,
            false,
            cd::ArgumentValue()
        }
     };

    optlist.assign(opts, opts + ARRAY_SIZE(opts));

    AbortIfNot(cl.init(argc, argv, optlist), false, "Incorrect usage.\n");

    return true;
}

int main(int argc, char *argv[]) {
    std::cout << "KeepKey: v.1" << std::endl;

    cd::CommandLine cd;
    AbortIfNot(parse_commandline(argc, argv, cd), -1, "Failed to parse command line.\n");

    if(cd.is_arg("make")) {
        cd::BIP32Wallet wallet = get_wallet();
        wallet.serialize(wallet_outfilename);

    } else if(cd.is_arg("show")) {
        /**
         * Make the bip32 wallet.
         */
        cd::BIP32Wallet wallet = get_wallet();
        wallet.print();

    } else if(cd.is_arg("sign")) {
        cd::BIP32Wallet wallet = get_wallet();

        /*
         * Read transaction from file and do it.
         */
        std::string rawtx;
        std::cout << "Paste in raw tx:" << std::endl;
        std::cin >> rawtx;

        std::string tx_input = wallet.sign_raw_tx(rawtx);
        std::cout << "Transaction signed." << std::endl;
        std::cout << "TX_INPUT: " << tx_input << std::endl;

    } else {
        cd.print_usage();
        Abort(-1, "Unknown option.\n");
    }

    return 0;
}
