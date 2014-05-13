#include <cassert>
#include <cstring>
#include <iomanip>
#include <iostream>
#include <malloc.h>
#include <string>
#include <sstream>
#include <vector>

#include <app.h>
#include <crypto.h>
#include <core.h>
#include <platform.h>

#include <display_manager.h>
#include <keepkey_manager.h>

#include "EvalKeepKeyBoard.h"


void
test_board(
        void
)
{
    EvalKeepKeyBoard* board = new EvalKeepKeyBoard();

    while(1)
    {}
}


int 
main(
        int argc, 
        char *argv[]
) 
{
    // Test the board.  This will block indefinitely.
    test_board();

    cd::App app;
    AbortIfNot(app.init("KeepKey"), false, "Failed to init KeepKey app.\n");

    cd::KeepkeyManager kkmgr;
    AbortIfNot(app.register_runnable(&kkmgr), false,
            "Failed to register %s\n", kkmgr.get_name().c_str());

    cd::DisplayManager dmgr;
    AbortIfNot(app.register_runnable(&dmgr), false,
            "Failed to register %s\n", dmgr.get_name().c_str());

    struct mallinfo mi = mallinfo();

    app.run_forever();

    Assert("Don't get here.\n");


    return 0;
}
