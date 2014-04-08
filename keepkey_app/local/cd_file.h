/**
  * @file
  *
  * $Id:$
  * @author Thomas Taranowski
  *
  * @brief platform agnostic file operations
  *
  */

#ifndef CD_FILE_H
#define CD_FILE_H

#include "cd_string.h"

namespace cd
{
    /**
     * Creates and opens a binary log file for writing data to,
     * creating it if it needs to.
     *
     * @return true on success;
     */
    bool make_log_file(int &fd, const char *filename);

    /**
     * Parses a simple whitespace/line delimited configuration file 
     * with # used as the comment character.
     *
     * @param filename The name of the file to parse.
     * @param lines The file parsed into a vector of lines parsed into vectors of strings.A
     *
     * @return true if the file exists and is readable, false on error.
     */
    bool read_configfile(const char *filename, vec_vec_str &lines);

    bool open_file(const char *filename, int &fd);
    
    /**
     * @eturn true if the specified file exists.
     */
    bool is_file(const char *filename);


};

#endif
