#include <messages.pb.h>

#include <coins.h>
#include <transaction.h>

#include <foundation/foundation.h>
#include <crypto.h>
#include <wallet.h>

namespace cd
{

    Wallet::Wallet()
    {}

    Wallet::~Wallet()
    {}

    bool Wallet::load()
    {
        return load_from_file();
    }

    bool Wallet::make()
    {
        uint8_t seed[SEED_SIZE];

        mnemonic = mnemonic_generate(MNEMONIC_STRENGTH);
        
        mnemonic_to_seed(mnemonic.c_str(), "passphrase", seed, NULL);

        hdnode_from_seed(seed, sizeof(seed), &root_node); 

        return true;

    }

    bool Wallet::signtx(SimpleSignTx* tx)
    {

        AbortIf(tx->inputs_count < 1, false, "Tx must have at least one input.\n");
        AbortIf(tx->outputs_count < 1, false, "Tx must have at least one output.\n");
        //TODO: pin
        
        const CoinType* coin_type = NULL;
        if(tx->has_coin_name)
        {
            coin_type = coinByName(tx->coin_name);
        } else {
            /*
             * Default to bitcoin.
             */
            coin_type = coinByName("Bitcoin");
        }

        AbortIfNot(coin_type, false, "Invalid coin type.\n");

        TxRequest resp;
        memset(&resp, 0, sizeof(resp));

        int tx_size = transactionSimpleSign(coin_type, 
                                        &root_node, 
                                        tx->inputs, 
                                        tx->inputs_count, 
                                        tx->outputs, 
                                        tx->outputs_count, 
                                        tx_version, 
                                        tx_lock_time, 
                                        resp.serialized.serialized_tx.bytes);

        //TODO: Check ret for something here.  Looks like it is the sum of inputs and outputs processed.
        AbortIf(tx_size < 0, false, "Signing cancelled.\n");
        AbortIf(tx_size == 0, false, "Error signing transaction.\n");

        	size_t i, j;

	// determine change address
	uint64_t change_spend = 0;
	for (i = 0; i < tx->outputs_count; i++) {
		if (tx->outputs[i].address_n_count > 0) { // address_n set -> change address
                    AbortIf(change_spend != 0, false, "Only one change output allowed.\n");
    		    change_spend = tx->outputs[i].amount;
		}
	}

        // check origin transactions
	uint8_t prev_hashes[ pb_arraysize(SimpleSignTx, transactions) ][32];
	for (i = 0; i < tx->transactions_count; i++) {
		if (!transactionHash(&(tx->transactions[i]), prev_hashes[i])) {
			memset(prev_hashes[i], 0, 32);
		}
	}

        // calculate spendings
        uint64_t to_spend = 0;
	bool found;
	for (i = 0; i < tx->inputs_count; i++) {
		found = false;
		for (j = 0; j < tx->transactions_count; j++) {
			if (memcmp(tx->inputs[i].prev_hash.bytes, prev_hashes[j], 32) == 0) { // found prev TX
				if (tx->inputs[i].prev_index < tx->transactions[j].bin_outputs_count) {
					to_spend += tx->transactions[j].bin_outputs[tx->inputs[i].prev_index].amount;
					found = true;
					break;
				}
			}
		}
                AbortIfNot(found, false, "Invalid prevhash.\n");
	}

	uint64_t spending = 0;
	for (i = 0; i < tx->outputs_count; i++) {
		spending += tx->outputs[i].amount;
	}
        AbortIf(spending > to_spend, false, "Not enough founds: available(%d) spending(%d).\n",
                to_spend, spending);

	// last confirmation
        // TODO: Handle user cancellation.

        resp.has_request_type = true;
        resp.request_type = RequestType_TXFINISHED;
        resp.has_serialized = true;
        resp.serialized.has_serialized_tx = true;
        resp.serialized.serialized_tx.size = (uint32_t)tx_size;

        //msg_write(MessageType_MessageType_TxRequest, resp);

        return true;
    }

    SimpleSignTx Wallet::get_sample_tx()
    {
        SimpleSignTx tx;
//        tx.coin = coinByName("Bitcoin");
        /*
        tx->root 
            tx->inputs
            tx->inputs_count
            tx->outputs
            tx->output_count
            tx->version
            tx->lock_time
            tx->out
            */

        /*
         * ValidateTx
         */
        return tx;
 
    }
}

