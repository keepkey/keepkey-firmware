#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iostream>
#include <string>

#include <platform.h>

#include <json.h>
#include <reader.h>
#include <writer.h>
#include "crypto/public/ecdsa.h"
#include "wallet.h"

namespace cd {

    uint8_t *fromhex(const char *str, unsigned int &num_bytes)
    {
	static uint8_t buf[128];
	uint8_t c;
	size_t i;
        num_bytes = 0;

	for (i = 0; i < strlen(str) / 2; i++) {
		c = 0;
		if (str[i*2] >= '0' && str[i*2] <= '9') c += (str[i*2] - '0') << 4;
		if (str[i*2] >= 'a' && str[i*2] <= 'f') c += (10 + str[i*2] - 'a') << 4;
		if (str[i*2+1] >= '0' && str[i*2+1] <= '9') c += (str[i*2+1] - '0');
		if (str[i*2+1] >= 'a' && str[i*2+1] <= 'f') c += (10 + str[i*2+1] - 'a');
		buf[i] = c;
                ++num_bytes;
	}
	return buf;
    }   

    char *tohex(const uint8_t *bin, size_t l)
    {
        char *buf = (char *)malloc(l * 2 + 1);
        static char digits[] = "0123456789abcdef";
        size_t i;
        for (i = 0; i < l; i++) {
            buf[i*2  ] = digits[(bin[i] >> 4) & 0xF];
            buf[i*2+1] = digits[bin[i] & 0xF];
        }
        buf[l * 2] = 0;
        return buf;
    }

    const std::string BIP32Wallet::wallet_filename("wallet.dat");

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

        std::ifstream infile(filename.c_str(), std::ios::in);
        AbortIfNot(infile.good(), false, "Failed to open wallet.\n");

        Json::Value root;
        Json::Reader reader;
        AbortIfNot(reader.parse(infile, root), false, "Failed to parse wallet file.\n");

        hdnode.depth = root["depth"].asUInt();
        hdnode.child_num = root["child_num"].asUInt();
        hdnode.fingerprint = root["fingerprint"].asUInt();
        
        unsigned int nb;
        memcpy(hdnode.chain_code, fromhex(root["chain_code"].asCString(), nb), sizeof(hdnode.chain_code));
        memcpy(hdnode.private_key, fromhex(root["private_key"].asCString(), nb), sizeof(hdnode.private_key));
        memcpy(hdnode.public_key, fromhex(root["public_key"].asCString(), nb), sizeof(hdnode.public_key));

        return true;
    }

    void BIP32Wallet::serialize(const std::string &filename) {
        std::ofstream of(filename.c_str(), std::ios::out);
        AbortIfNot(of.is_open(),, "Failed to open file to serialize : '%s'", filename.c_str());

        Json::Value out;

        out["seed"] = seed;
        out["depth"] = (unsigned int)hdnode.depth;
        out["child_num"] = (unsigned int)hdnode.child_num;
        out["fingerprint"] = (const char*)hdnode.fingerprint;
        out["chain_code"] = tohex(hdnode.chain_code, sizeof(hdnode.chain_code));
        out["private_key"] = tohex(hdnode.private_key, sizeof(hdnode.private_key));
        out["public_key"] = tohex(hdnode.public_key, sizeof(hdnode.public_key));

        of << out << std::endl;
        of.close();
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

    std::string BIP32Wallet::sign_raw_tx(const std::string &rawtx) 
    {
        /**
         * Pulled from depths of ecdsa.c. Added 1 byte sentinel because I'm
         * paranoid about overflow here.  
         *
         * TODO: size the sig array better. Source the size from the ecdsa.h file 
         * preferably.
         */
        static const unsigned int SIG_LENGTH = 64 + 1;
        uint8_t sig[SIG_LENGTH];
        memset(sig, 0, sizeof(sig));

        unsigned int rawlen=0;
        uint8_t *txbin = fromhex(rawtx.c_str(), rawlen); 
        ecdsa_sign(hdnode.private_key, txbin, rawlen, sig);

        char *hexified = tohex(sig, SIG_LENGTH-1);
        std::string ret(hexified);

        AssertIf(sig[SIG_LENGTH-1] != 0, "ecdsa failed sentinel check.\n");
        
        return ret;
    }

    bool BIP32Wallet::load()
    {
        return init_from_file(wallet_filename);
    }

    bool BIP32Wallet::store()
    {
       serialize(wallet_filename);

       return true;
    }
};


