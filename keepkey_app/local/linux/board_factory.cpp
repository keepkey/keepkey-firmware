#include <memory>

#include <foundation/foundation.h>

#include <KeepKeyBoard.h>

namespace cd
{
    std::shared_ptr<KeepKeyBoard> make_keepkey_board()
    {
        return std::make_shared<KeepKeyBoard>();
    }
};


 
