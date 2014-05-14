#include <messages.pb.h>
#include <messages.h>

#include <foundation/foundation.h>

#include <trezor_reader.h>

namespace cd 
{

    uint8_t msg_in[1024];

    TrezorReader::TrezorReader()
        : fd(-1)
    {}

    TrezorReader::~TrezorReader()
    {}
}

