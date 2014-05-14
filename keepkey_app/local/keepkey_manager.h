#ifndef KEEPKEY_MANAGER_H
#define KEEPKEY_MANAGER_H

#include <app.h>
#include <bitcoin.h>
#include <foundation/foundation.h>
#include <trezor_reader.h>
#include <trezor_writer.h>


namespace cd
{
    class KeepkeyManager : public Component, public Runnable
    {
        public:
            KeepkeyManager();
            virtual ~KeepkeyManager();

            bool init();

            bool run();

        private:
            Wallet wallet;

            TrezorReader reader;
            TrezorWriter writer;

            bool send_initialize_response();

    };
};

#endif

