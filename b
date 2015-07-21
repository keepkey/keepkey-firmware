#!/usr/bin/python

import argparse
import os

"""
Build helper script to shortcut common build scenarions.
"""

from fabric.api import local


def proc_args():
    parser = argparse.ArgumentParser(description = 'Build helper front end tool.')
    parser.add_argument('-i',  '--invert',     help = 'Build with inverted display.', action = 'store_true')
    parser.add_argument('-dl', '--debug-link',  help = 'Build with Debug Link.', action = 'store_true')
    parser.add_argument('-mp', '--memory-protect',  help = 'Build with memory protection', action = 'store_true')
    parser.add_argument('-p',  '--project', 
                        help = 'Build specific project (bootloader, bootstrap, crypto, interface, keepkey, keepkey_board, nanopb).', 
                        action = 'store')
    parser.add_argument('-b',  '--build-type', 
                        help = 'Build specifc build type (bstrap, bldr, app).', 
                        action = 'store')
    parser.add_argument('-d',  '--debug', help = 'Build debug variant.', action = 'store_true')
    parser.add_argument('-v',  '--verbose', help = 'Build with verbose output.', action = 'store_true')
    args = parser.parse_args()

    return args

def main():

    args = proc_args()

    buildargs = ''

    if args.invert:
        buildargs += ' invert=1'
    if args.debug_link:
        buildargs += ' debug_link=1'
    if args.memory_protect:
        buildargs += ' memory_protect=1'
    if args.build_type:
        build_aliases = {'bstrap': 'bootstrap', 'bldr': 'bootloader', 'app': 'keepkey'}
        buildargs += ' project=%s' % (build_aliases[args.build_type])
    else:
        if args.project:
            buildargs += ' project=%s' % (args.project)
    if args.debug:
        buildargs += ' debug=1'
    if args.verbose:
        buildargs += ' verbose=1'

    target ='arm-none-gnu-eabi'
    local('scons ' + 'target='+target + buildargs)

if __name__ == '__main__':
    main()