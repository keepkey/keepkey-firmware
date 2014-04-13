/**
  * @file
  *
  * $Id:$
  * @author Thomas Taranowski
  *
  * @brief Common cross platform string routines for Blue programs.
  *
  */

#ifndef CD_STRING_H
#define CD_STRING_H

#include <map>
#include <string>
#include <vector>

/**
 * Common stl string container typedefs
 */

namespace cd
{

    typedef std::vector<std::string> vec_str;

    typedef std::vector<vec_str> vec_vec_str;

    typedef std::map<std::string, std::string> map_str_str;

    /**
     * Tokenizes the input string into tokens based off the specified 
     * delimiter.
     *
     * @param[in] str The string to tokenize.
     *
     * @return true on success 
     */
    bool split(const std::string &str, vec_str &tokens, char delimiter);

    /**
     * Tokenizes the input string into tokens based off the specified 
     * delimiter.
     *
     * @param[in] str The string to tokenize.
     * @param[in,out] tokens The tokens resulting from parsing the string.
     * @param delimiter The delimiter to parse on.
     * @param max_str_len The max length of the input string, for safety.
     *
     * @return true on success 
     */
    bool split(const char *str, vec_str &tokens, char delimiter, size_t max_str_len);

    /**
     * Splits the string once on a given delimiter.  If no delimiter exists,
     * the default action is to return the original string.
     *
     * @param str The string to split
     * @param tokens The split vector, of length 1 or more.
     * @param delimiter The delimiter used for splitting the string.
     *
     * @return true on successful split.
     */
    bool split_once(const std::string &str, vec_str &tokens, char delimiter);

    /**
     * Safely convert the specified string to a unsigned 16 bit balue.
     *
     * @param str The string to convert
     * @param u16 The value is returned here on success.
     *
     * @return true on success 
     */
    bool to_uint16(const std::string &str, uint16_t &u16);

       /**
     * Safely convert the specified string to a unsigned 32 bit balue.
     *
     * @param str The string to convert
     * @param u32 The value is returned here on success.
     *
     * @return true on success 
     */
 
    bool to_uint32(const std::string &str, uint32_t &u32);
   /**
     * Safely convert the specified string to a signed long value.
     *
     * @param str The string to convert
     * @param l The value is returned here on success.
     *
     * @return true on success 
     */

    bool to_long(const std::string &str, long &l);
   /**
     * Safely convert the specified string to a double.
     *
     * @param str The string to convert
     * @param d The value is returned here on success.
     *
     * @return true on success 
     */

    bool to_double(const std::string &str, double &d);
    /**
     * Trim any newline or carriage return from the specified string.
     *
     * @param str Point to the string to trim.
     * @param strlen Length of the string.
     *
     * @return true on success
     */

    bool trim_newline(char *str, uint32_t strlen);

    /**
     * Splits a pathname starting ad the end and working back, up to the 
     * number of pat elements specified by num_pathelements.
     *
     * @param path The path to split
     * @param num_pathelements The number of path elements to attempt to retrieve.
     *
     * @return The requested subset of path elements.
     *
     * @note
     * Example: 
     *  mypath = /my/path/is.cpp
     *
     *  short_path = pathsep(mypath, 2);
     *  shortpath: Now equals "path/is.cpp"
     */
    const char* pathsep(const char *path, unsigned int num_pathelements);
};

#endif

