/**
  * @file
  *
  * $Id:$
  * @author Thomas Taranowski
  *
  * @brief Implement helper routines to aid with common file operations.
  *
  */

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <fstream>
#include <sstream>
#include <string>

#include "diag.h"
#include "cd_file.h"
#include "cd_string.h"


namespace cd
{

    bool make_log_file(int &fd, const char *filename)
    {
        fd = -1;
        /*
         * Create the logfile with read/write for me, read-only for others.
         */
        AbortOnErrno((fd = open(filename, 
                                O_RDWR | O_CREAT | O_LARGEFILE,
                                S_IRUSR | S_IWUSR |
                                S_IRGRP |
                                S_IROTH)),
                false, "Failed to open log file.\n");

        return true;
    }

    bool read_configfile(const char *filename, vec_vec_str &lines)
    {
        std::ifstream infile(filename);

        AbortIfNot(infile.good(), false, 
                "Invalid config filename (%s).\n", filename);
        lines.clear();

        std::string instr;
        std::string word;

        while(getline(infile, instr))
        {
            std::stringstream ss(instr);
            while (ss >> word)
            {
                // Handle comment character
                if(word.length() > 0 && word[0] == '#')
                {
                    break;
                }
                vec_str line_tokens;
                line_tokens.push_back(word);
                lines.push_back(line_tokens);
            }
        }

        return true;
    }

    bool open_file(const char *filename, int &fd)
    {
        fd = -1;
        /*
         * Create the logfile with read/write for me, read-only for others.
         */
        AbortOnErrno((fd = open(filename, O_RDWR | O_NOCTTY | O_NDELAY)),
                false, "Failed to open log file.\n");

        return true;
    }


};
