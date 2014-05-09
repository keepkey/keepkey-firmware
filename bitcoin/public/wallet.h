#ifndef BITCOIN_WALLET_H
#define BITCOIN_WALLET_H

#include <messages.pb.h>
#include <types.pb.h>

#include <crypto.h>


namespace cd 
{

    class Wallet
    {
        public:
            Wallet();
            virtual ~Wallet();

            bool make();

            bool load();

            bool signtx(SimpleSignTx *tx);

            SimpleSignTx get_sample_tx();

        private:
            bool load_from_file();

            bool store();

            HDNode root_node;
            
            std::string mnemonic;
            
            static const uint32_t MNEMONIC_STRENGTH = 128;
            static const uint32_t SEED_SIZE = 64;

            /* 
             * The tx_version and tx_lock_time are hardcoded and derived from the
             * Trezor protocol for the simple sign.
             */
            static const uint32_t tx_version = 1;
            static const uint32_t tx_lock_time = 0;

    };
}

#endif
