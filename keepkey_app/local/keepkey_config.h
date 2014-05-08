#ifndef KEEPKEY_CONFIG
#define KEEPKEY_CONFIG

#include <crypto.h>
#include <foundation/foundation.h>

class KeepkeyConfig
{
    public:
        KeepkeyConfig();
        ~KeepkeyConfig();

        /**
         * @return true on successful initialization.
         */
        bool init();

        HDNode get_root_node();

    private:

};


#endif

