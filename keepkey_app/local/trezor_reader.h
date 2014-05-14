#ifndef TREZOR_READER_H
#define TREZOR_READER_H

#include <messages.pb.h>

#include <foundation/foundation.h>

namespace cd {

    class TrezorReader
    {
        public:
            TrezorReader();
            ~TrezorReader();

            bool init();

            /**
             * TODO: Single hardcoded out function for now.  Expand this to a more
             * general messaging interface next sprint.
             */
            bool read_message(uint8_t* buf, uint32_t buflen, MessageType& type);

        private:
            int fd;
            int32_t read(uint8_t* buf, uint32_t buflen);

    };
}

#endif
