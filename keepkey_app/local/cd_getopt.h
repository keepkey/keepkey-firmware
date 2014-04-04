/**
  * @file
  *
  * $Id:$
  * @author Thomas Taranowski
  *
  * @brief Command line processing helper class
  *
  */
#ifndef CD_GETOPT_H_
#define CD_GETOPT_H_

#include <string>
#include <vector>
#include <map>

namespace cd
{

    /*
     * The max argval size is defined to be the max size possible
     * for argument names and values.  It is used internally
     * to size any static arrays needed to store or manipulate the
     * arguments.
     */
    static const unsigned int MAX_ARGVAL_SIZE=512;

    /*
     * Set to the max number of command line arguments allowed.
     */
    static const unsigned int MAX_NUM_ARGS = 512;

    /*
     * For each option, make an option descriptor to describe
     * it's attributes.
     */
    enum argument_specifier_t
    {
        getopt_no_arg = 0,
        getopt_required_arg = 1,
        getopt_optional_arg = 2
    };

    /**
     * Specify the type of the option, in order to dictate the
     * type conversion that takes place when reading in the option.
     *
     * The type list should be a minimal set, meaning that, for example,
     * a float may be represented by a double without loss of precision,
     *  so no need for another type to conversion to float.  
     */
    enum argument_type_t
    {
        getopt_invalid_arg,
        getopt_double_arg,
        getopt_long_arg,
        getopt_string_arg
    };

    class ArgumentValue
    {
        public:
            ArgumentValue();

            ArgumentValue(const std::string &string_value);

            ArgumentValue(const char *string_value);

            void set(const std::string &string_value);

            bool as_double(double &d);

            bool as_long(long &l);

            bool as_string(std::string &s);

            /**
             * @return true if the value has been set.
             */
            bool is_set() const;

        private:
            bool was_set;

            std::string argval;

    };

    /**
     * An option descriptor must be created for each option
     * to be handled.
     */
    struct option_descriptor_t
    {
        /*         
         * Specify the option long form name, e.g. use "interface" 
         * for --interface=... option.
         */
        std::string             long_option_string;

        /*
         * A short help string describing the option.  May be empty.
         */
        std::string             help_string;

        /*
         * Specify whether the argument has a required argval, optional argval, 
         * or no argval at all.
         */
        argument_specifier_t    argspec;

        /*
         * Specify the type of the argument value expected.  Used for conversion
         * and type checking.
         */
        argument_type_t         argtype;

        /*
         * Set to true if it has a default value.
         */
        bool                    has_default;

        /*
         * Set to the default argument value, if it has one,
         * otherwise just leave it blank.
         */
        ArgumentValue           value;
    };



    /**
     * The CommandLine class handles processing the command line in a 
     * standardized cross platform way.  
     */
    class CommandLine
    {
        public:
            CommandLine();
            ~CommandLine();

            /**
             * Initializes the command line processor with the specified
             * option list.
             *
             * @param arglist List of known options to look for.
             *
             * @return false if it fails to parse the argument list.
             */
            bool init(int argc, 
                      char **argv, 
                      std::vector<option_descriptor_t> &optlist);

            /**
             * See if a argument of type double exists from the command line.
             *
             * @param argname The name of the argument to retrieve
             * @param val The value of the argument is returned here.
             *
             * @return true if the argument exists (or has a default).
             */
            bool get_double_arg(std::string &argname, double &val);

            /**
             * See if a argument of type long exists from the command line.
             *
             * @param argname The name of the argument to retrieve
             * @param val The value of the argument is returned here.
             *
             * @return true if the argument exists (or has a default).
             */
            bool get_long_arg(std::string &argname, long &val);

            /**
             * See if a argument of type string exists from the command line.
             *
             * @param argname The name of the argument to retrieve
             * @param val The value of the argument is returned here.
             *
             * @return true if the argument exists (or has a default).
             */
            bool get_string_arg(const std::string &argname, std::string &argval);

            /**
             * Check to see if a given argname exists.  No consideration is
             * given to the type of the argument.
             *
             * @return true if the argument exists in option list.
             */
            bool is_arg(const std::string argname);

            /**
             * Prints the command line usage spec.  Useful for incorrectly specified
             * options and such.
             */
            void print_usage();

        private:
            /**
             * Parses out the command line for later retrieval.
             *
             * @return true on successful parse.
             */
            bool parse();

            /**
             * Validate the parsed command line against invariants.
             *
             * @return true if valid.
             */
            bool validate();

            std::vector<option_descriptor_t> optlist;

            char **argv;

            int argc;
        


    };

};

#endif

