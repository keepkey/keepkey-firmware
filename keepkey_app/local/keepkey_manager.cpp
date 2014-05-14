#include <cstring>
#include <messages.pb.h>

#include <app.h>
#include <bitcoin.h>
#include <foundation/foundation.h>
#include <keepkey_manager.h>

namespace cd
{
    KeepkeyManager::KeepkeyManager()
        : wallet()
        , reader()
        , writer()
    {}

    KeepkeyManager::~KeepkeyManager()
    {}

    bool KeepkeyManager::init()
    {
        AbortIfNot(Component::init("KeepkeyManager", 0), 
                false, "Failed to init.\n");

        AbortIfNot(reader.init(), false, "Failed to init Trezor protocol reader.\n");

        return true;
    }

    bool KeepkeyManager::send_initialize_response()
    {
        Features features;
        memset(&features, 0, sizeof(features));
        features.has_vendor = true;  strlcpy(features.vendor, "keepkey.com", sizeof(features.vendor));
        features.has_major_version = true;  features.major_version = 1;
        features.has_minor_version = true;  features.minor_version = 0;
        features.has_patch_version = true;  features.patch_version = 0;
        features.has_device_id = true;      strlcpy(features.device_id, "xxx", sizeof(features.device_id));
        features.has_pin_protection = false;
        features.has_passphrase_protection = false;
        features.has_revision = false;
        features.has_bootloader_hash = false;
        features.has_language = false;
        features.has_label = true; strlcpy(features.label, "My Keepkey #1", sizeof(features.label));
        features.has_initialized = true; features.initialized = true;

    }

    bool KeepkeyManager::run()
    {

        enum State
        {
            INVALID,
            IDLE,
            INIT,
            PROVISION,
            SIGN,
            TX_WAIT
        };

        static State state = INIT;

        uint8_t buf[1024];
        MessageType type;

        switch(state)
        {
            case IDLE:
                LOG("IDLE\n");
                state = INIT;

                if(reader.read_message(buf, sizeof(buf), type))
                {
                    if(type == MessageType_MessageType_Initialize)
                    {
                        if(send_initialize_response())
                        {
                            state = SIGN;
                        }
                    }
                }

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
            
            case TX_WAIT:
                {
                    LOG("TX_WAIT\n");
                }
                break;


            case SIGN:
                {
                    LOG("SIGN\n");
                    if(reader.read_message(buf, sizeof(buf), type))
                    {
                        if(type == MessageType_MessageType_SimpleSignTx)
                        {
                            SimpleSignTx* tx = reinterpret_cast<SimpleSignTx*>(buf);
                            wallet.signtx(tx);
                            state = IDLE;
                        }
                    }
                    break;
                }

            default:
                Abort(false, "Invalid or unknown state: %s\n", state);
        };

        return true;
    }
};

