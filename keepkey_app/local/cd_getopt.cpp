/**
  * @file
  *
  * $Id:$
  * @author Thomas Taranowski
  *
  * @brief Implements a standardized type safe command line processing mechanism.
  *
  */

#include <getopt.h>

#include <string>
#include <vector>

#include "diag.h"

#include "cd_getopt.h"
#include "cd_string.h"

namespace cd
{

    ArgumentValue::ArgumentValue()
        : was_set(false)
    {
    }

    ArgumentValue::ArgumentValue(const std::string &strval)
        : was_set(true)
    {
        argval = strval;
    }

    ArgumentValue::ArgumentValue(const char *strval)
        :was_set(true)
    {
        argval = strval;
    }


    bool ArgumentValue::as_double(double &d)
    {
        if(was_set)
        {
            return to_double(argval, d);
        } 

        return false;
    }

    bool ArgumentValue::as_long(long &l)
    {
        if(was_set)
        {
            return to_long(argval, l);
        }

        return false;
    }

    bool ArgumentValue::as_string(std::string &str)
    {
        if(was_set)
        {
            str = argval;
            return true;
        }

        return false;
    }

    void ArgumentValue::set(const std::string &strval)
    {
        argval = strval;

        was_set = true;
    }

    bool ArgumentValue::is_set() const
    {
        return was_set;
    }

    CommandLine::CommandLine()
        : argv(NULL)
        , argc(0)
    {}

    CommandLine::~CommandLine()
    {}

    bool CommandLine::init(int argc_, 
                           char **argv_,
                           std::vector<option_descriptor_t> &optlist_)
    {
        optlist = optlist_;
        argc = argc_;
        argv = argv_;
        bool ret = true;

        if(!parse())
        {
            Error("Failed to parse command line.\n");
            ret = false;
        } 
        else if(!validate())
        {
            Error("Invalid command line.\n");
            ret = false;
        }

        if(!ret)
        {
            print_usage();
        }

        return ret;
    }

    bool CommandLine::parse()
    {
    
        /*
         * Map our option specification into gnu option format
         * for passing to getopt_long.
         *
         */
        std::vector<struct option> goptlist;

        struct option o;
        size_t i=0;
        for(i=0; i < optlist.size(); i++)
        {
            o.name = optlist[i].long_option_string.c_str();
            o.has_arg = optlist[i].argspec;
            o.flag = NULL;
            o.val = i;

            goptlist.push_back(o);
        }

        struct option nullopt = {0,0,0,0};
        goptlist.push_back(nullopt);


        int ret = 0;
        int option_index = 0;

        int argct = 0;
        while(1 && argct++ < MAX_NUM_ARGS)
        { 
            ret = ::getopt_long(argc, 
                              argv, 
                              "", 
                              &goptlist[0], 
                              &option_index);
            if(ret == -1)
            {
                break;
            } else if(ret == '?') {
                Abort(false, "Unknown or ambiguous command line option.\n");
            } else {
                /*
                 * Option found.
                 */
                AbortIfNot(ret < optlist.size(), 
                           false, 
                           "Undefined operation for getopt_long.\n");

                optlist[ret].value.set(optarg);
            }
        }

        return true;
    }

    bool CommandLine::validate()
    {
        /*
         * Verify all required options were set.
         */
        for(size_t i=0; i < optlist.size(); i++)
        {
            if(optlist[i].argspec == getopt_required_arg &&
               optlist[i].value.is_set() == false)
            {
                Abort(false, "Required argument '%s' not specified.\n",
                    optlist[i].long_option_string.c_str());
                return false;
            }
        }

        return true;
 
    }

    void CommandLine::print_usage()
    {
        /*
         * Verify all required options were set.
         */
        for(size_t i=0; i < optlist.size(); i++)
        {
            LOG("%s (%s)\n\t%s\n", optlist[i].long_option_string.c_str(),
                   optlist[i].argspec==getopt_required_arg ? "required" : "optional",
                    optlist[i].help_string.c_str());
        }
    }

    bool CommandLine::get_double_arg(std::string &argname_, double &val)
    {
        val = 0;

        for(size_t i=0; i < optlist.size(); i++)
        {
            if(optlist[i].argtype == getopt_double_arg &&
               optlist[i].long_option_string == argname_)
            {
                return optlist[i].value.as_double(val);
            }
        }
 
        return false;
    }

    bool CommandLine::get_long_arg(std::string &argname_, long &val)
    {
        val = 0;

        for(size_t i=0; i < optlist.size(); i++)
        {
            if(optlist[i].argtype == getopt_long_arg &&
               optlist[i].long_option_string == argname_)
            {
                return optlist[i].value.as_long(val);
            }
        }
 
        return false;
    }

    bool CommandLine::get_string_arg(const std::string &argname_, 
                                     std::string &argval_)
    {
        for(size_t i=0; i < optlist.size(); i++)
        {
            if(optlist[i].argtype == getopt_string_arg &&
               optlist[i].long_option_string == argname_)
            {
                return optlist[i].value.as_string(argval_);
            }
        }
        
        return false;
    }

    bool CommandLine::is_arg(const std::string argname) {
        for(size_t i=0; i < optlist.size(); i++)
        {
            if(optlist[i].long_option_string == argname) {
                if(optlist[i].value.is_set()) {
                    return true;
                } else {
                    return false;
                }
            }
        }
        
        return false;
    }
};

