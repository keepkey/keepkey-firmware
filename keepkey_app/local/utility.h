#ifndef UTILITY_H
#define UTILITY_H

#include <string>
#include <vector>

namespace cd {

    /*
     * Terrible code that needs to be cleaned up and merged into real platform library.
     */

    /**
     * Return true if the specified file exists.
     */
    bool is_file(const char *filename);

    /*
     * Return an ascii string representing a hexdump of the vector contents.
     */
    std::string hexdump(const std::vector<uint8_t> &v);

    /**
     * Return an ascii string representing a hexdump of the buffer contents.
     */
    std::string hexdump(const void *buf, unsigned int len);

};

#endif
