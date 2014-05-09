#include <messages.pb.h>

#include <app.h>
#include <bitcoin.h>
#include <foundation/foundation.h>
#include <keepkey_manager.h>

namespace cd
{
    KeepkeyManager::KeepkeyManager()
    {}

    KeepkeyManager::~KeepkeyManager()
    {}

    bool KeepkeyManager::init()
    {
        AbortIfNot(Component::init("KeepkeyManager", 0), 
                false, "Failed to init.\n");

        return true;
    }

    bool KeepkeyManager::run()
    {

        enum State
        {
            INVALID,
            IDLE,
            INIT,
            PROVISION,
            SIGN
        };

        static State state = INIT;

        switch(state)
        {
            case IDLE:
                LOG("IDLE\n");
                state = SIGN;
                break;

            case INIT:
                LOG("INIT\n");

                if(wallet.load())
                {
                    state = IDLE;
                } else {
                    state = PROVISION;
                }

                state = IDLE;
                break;

            case PROVISION:
                LOG("PROVISION\n");
                /*

                std::string mnemonic = make_mnemonic();
                wallet.init_from_seed(mnemonic);
                wallet.store();
                */

                state = IDLE;
                break;

            case SIGN:
                {
                    LOG("SIGN\n");
                    SimpleSignTx tx = wallet.get_sample_tx();

                    wallet.signtx(&tx);
                    break;
                }

            default:
                Abort(false, "Invalid or unknown state: %s\n", state);
        };

        return true;
    }
};

