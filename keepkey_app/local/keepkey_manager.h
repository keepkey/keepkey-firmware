#ifndef KEEPKEY_MANAGER_H
#define KEEPKEY_MANAGER_H

#include <app.h>
#include <platform.h>

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

    };
};

#endif

