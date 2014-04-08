#ifndef UTILITY_H
#define UTILITY_H

#include <cstdint>
#include <cstdlib>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

#include "utility.h"

namespace cd {
    std::string hexdump(const std::vector<uint8_t> &v, bool space) {
        std::ostringstream ret;

        for(size_t i=0; i < v.size(); i++) {
            ret << std::hex << std::setfill('0') << std::setw(2) << (int)v[i];
            if(space)
            {
                if(i != v.size()-1) {
                    ret << " ";
                }
            }
        }

        return ret.str();
    }

    std::string hexdump(const void *buf, unsigned int len, bool space) {
        const uint8_t *start = reinterpret_cast<const uint8_t*>(buf);
        std::vector<unsigned char> v(start, start + len);
        return hexdump(v, space);
    }

};

#endif
