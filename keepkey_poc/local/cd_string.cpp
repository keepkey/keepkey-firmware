/**
  * @file
  *
  * $Id:$
  * @author Thomas Taranowski
  *
  * @brief General purpose string handling and parsing goes here.
  *
  */

#include <errno.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>

#include <fstream>
#include <sstream>
#include <string>

#include <diag.h>
#include <cd_string.h>

namespace cd
{

    bool split_once(const std::string &str, vec_str &tokens, char delimiter)
    {
        tokens.clear();

        if(str.length() <= 0)
        {
            return false;
        }

        size_t s = str.find_first_of(delimiter);
        if(s != std::string::npos)
        {
            tokens.push_back(str.substr(0, s));
            tokens.push_back(str.substr(s+1));
            return true;
        } else {
            tokens.push_back(str);
            return false;
        }
    }

     bool split(const std::string &str, vec_str &tokens, char delimiter)
    {
        tokens.clear();

        if(str.length() <= 0)
        {
            return false;
        }

        std::istringstream iss(str);
        std::string token;
        while(std::getline(iss, token, delimiter))
        {
            tokens.push_back(token);
        }

        return true;
    }

    bool split(const char *str, vec_str &tokens, char delimiter, size_t max_str_len)
    {
        std::string tmp_str;
        tmp_str.assign(str, max_str_len);

        return split(tmp_str, tokens, delimiter);
    }

    bool to_uint16(const std::string &str, uint16_t &u16)
    {
        u16=0;
        errno = 0;
        u16 = static_cast<uint16_t>(strtoul(str.c_str(), NULL, 0));
        AbortIf(errno || u16 > 0xffff, false, "Invalid conversion. (%s)\n", str.c_str());

        return true;
    }

    bool to_uint32(const std::string &str, uint32_t &u32)
    {
        u32 = 0;
        errno = 0;
        u32 = strtoul(str.c_str(), NULL, 0);
        AbortIf(errno, false, "Invalid conversion. (%s)\n", str.c_str());

        return true;
    }

    bool to_long(const std::string &str, long &l)
    {
        l = 0;
        errno = 0;

        l = strtol(str.c_str(), NULL, 0);

        AbortIf(errno, false, "Invalid conversion. (%s)\n", str.c_str());

        return true;
    }

    bool to_double(const std::string &str, double &d)
    {
        d = 0;
        errno = 0;

        d = strtod(str.c_str(), NULL);

        AbortIf(errno, false, "Invalid conversion. (%s)\n", str.c_str());

        return true;
    }

    bool trim_newline(char *str, uint32_t strlen)
    {
        if(str == NULL || strlen == 0)
        {
            return true;
        }

        for(uint32_t i=0; i < strlen; i++)
        {
            if(str[i] == '\r' || str[i] == '\n')
            {
                str[i] = '\0';
                break;
            }
        }

        return true;
    }

    const char* pathsep(const char *path, unsigned int num_pathelements)
    {
        if(num_pathelements == 0)
        {
            return path;
        }

        const size_t max_path_len = 4096;
        size_t len =  strnlen(path, max_path_len);
        unsigned int num_split = 0;

        if(len < max_path_len)
        {
            for(size_t i = len - 1; i >= 0; i--)
            {
                if(path[i] == '\\' || path[i] == '/')
                {
                    num_split++;
                    if(num_split >= num_pathelements)
                    {
                        return &path[i+1];
                    }

                }
            }
        }

        return path;
    }

}

