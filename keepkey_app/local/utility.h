#ifndef UTILITY_H
#define UTILITY_H

#include <string>
#include <vector>

namespace cd {

    /*
     * Terrible code that needs to be cleaned up and merged into real platform library.
     */

    /*
     * Return an ascii string representing a hexdump of the vector contents.
     *
     * @param v The vector to dump as hex representation.
     * @param space Set to true to add space between each byte.
     */
    std::string hexdump(const std::vector<uint8_t> &v, bool space=false);

    /**
     * Return an ascii string representing a hexdump of the buffer contents.
     */
    std::string hexdump(const void *buf, unsigned int len, bool space=false);

};

#endif
