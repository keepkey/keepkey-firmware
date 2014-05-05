#include <app.h>
#include <platform.h>

#include "display_manager.h"
#include "wallet.h"

namespace cd
{
    DisplayManager::DisplayManager()
    {}

    DisplayManager::~DisplayManager()
    {}

    bool DisplayManager::init()
    {return true;}

    bool DisplayManager::run()
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
                break;

            case INIT:
                LOG("INIT\n");

                /*
                 * If wallet already exists, go to  idle and wait for something to do.
                 */
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
                LOG("SIGN\n");
                break;

            default:
                Abort(false, "Invalid or unknown state: %s\n", state);
        };

        return true;
    };
};

