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

        const char trezor_pipe[] = "/tmp/pipe.trezor.to";
        int _fd = 0;
        AbortOnErrno((_fd = open(trezor_pipe, O_RDONLY)), 
                false, 
                "Failed to open Trezor pipe.  Make sure transport is setup by the test.\n");

        fd = _fd;
        return true;
    }

    bool TrezorReader::read_message(uint8_t* buf, uint32_t buflen, MessageType &type)
    {
        int32_t len=0;
        if((len = read(buf, buflen)) > 0)
        {
            if(len >= sizeof(TrezorUsbFrame))
            {
                TrezorUsbFrame* frame = reinterpret_cast<TrezorUsbFrame*>(buf);
                if(frame->preamble[0] != '#' || frame->preamble[0] != '#' )
                {
                    //TODO: Invalid frame counter
                    return false;  
                }

                frame->header.msg_id = __builtin_bswap16(frame->header.msg_id);
                frame->header.msg_size = __builtin_bswap16(frame->header.msg_size);

                if(frame->header.msg_id == MessageType_MessageType_Initialize
                        && frame->header.msg_size == Initialize_size)
                {
                    type = MessageType_MessageType_Initialize;
                    return true;
                } else if(frame->header.msg_id ==  MessageType_MessageType_SimpleSignTx
                    && frame->header.msg_size == SimpleSignTx_size)
                {
                    type = MessageType_MessageType_SimpleSignTx;
                    return true;
                } else {
                    // TODO: Unknown message counter.
                }

            } else {
                // TODO: Invalid length counter.
            }
        } 
        
        return false;
    }

    int32_t TrezorReader::read(uint8_t* buf, uint32_t buflen)
    {
        AssertIfNot(fd > 0, "Reader not initialized.\n");
        int rx = 0;
        AbortOnErrno((rx = ::read(fd, buf, buflen)), 0, "Failed to read from trezor pipe.\n");

        return rx;
    }

}
