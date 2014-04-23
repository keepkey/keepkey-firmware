#include <app.h>
#include <platform.h>
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
        return true;
    }
};

