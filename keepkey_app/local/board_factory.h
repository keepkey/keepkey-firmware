#ifndef BOARD_FACTORY_H
#define BOARD_FACTORY_H

#include <memory>
 
/**
 * @brief    
 */

#include <foundation/foundation.h>
#include <KeepKeyBoard.h>

namespace cd
{
    /**
     * Returns a board suitable for use on the current platform
     * and system configuration.
     *
     * @return pointer to a keepkey board isntance.  
     *
     * @note Currently, the linux platform assumes a unit test board,
     * and the stm build assuemes the real keepkey.  This function
     * could be extended to take in multiple variants.
     */
    std::shared_ptr<KeepKeyBoard> make_keepkey_board();

};

#endif
