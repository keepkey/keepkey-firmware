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

//#include <display_manager.h>
//#include <keepkey_manager.h>

#include "KeepKeyDisplay.h"
#include "keepkey_oled_test_1.h"
#include "EvalKeepKeyBoard.h"


void
test_display(
        void
)
{
    EvalKeepKeyBoard* board = new EvalKeepKeyBoard();

    board->show_led();

    PixelBuffer* image = new PixelBuffer( 
            Pixel::A8,
            (uint32_t)image_data_keepkey_oled_test_1,
            64,
            256
    );

    PixelBuffer::transfer(
            image,
            board->display()->frame_buffer()
    );

    board->display()->frame_buffer()->taint();

    board->display()->refresh();

    while(1)
    {}
}


int main(int argc, char *argv[]) {
#if 0
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
#endif

    test_display();

    Assert("Don't get here.\n");


    return 0;
}
