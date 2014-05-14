#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include <messages.pb.h>

#include <foundation/foundation.h>

#include <trezor_reader.h>

namespace cd 
{
    const char USB_PREAMBLE[] = {'#','#'};

    struct __attribute__((__packed__)) TrezorUsbTransport
    {
        uint16_t msg_id;
        uint32_t msg_size;
    };

    struct __attribute__((__packed__)) TrezorUsbFrame
    {
        uint8_t preamble[2];
        TrezorUsbTransport header;
    };

    bool TrezorReader::init()
    {
        AssertIf(fd != -1, "Already initialized.\n");

        return true;
    }

    bool TrezorReader::read_message(uint8_t* buf, uint32_t buflen, MessageType &type)
    {
        return false;
    }

    int32_t TrezorReader::read(uint8_t* buf, uint32_t buflen)
    {
        return 0;
    }

}
