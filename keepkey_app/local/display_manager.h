#ifndef DISPLAY_MANAGER_H
#define DISPLAY_MANAGER_H

#include <app.h>

#include "wallet.h"

namespace cd
{
    class DisplayManager : public Component, public Runnable
    {
        public:
            DisplayManager();
            virtual ~DisplayManager();

            bool init();

            bool run();

        private:

            BIP32Wallet wallet;
    };
};

#endif

