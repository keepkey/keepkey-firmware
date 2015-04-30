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
    parser.add_argument('-dl', '--debuglink',  help = 'Build with Debug Link.', action = 'store_true')
    parser.add_argument('-d',  '--debug', help = 'Build debug variant.', action = 'store_true')
    parser.add_argument('-v',  '--verbose', help = 'Build with verbose output.', action = 'store_true')
    args = parser.parse_args()

    return args

def main():

    args = proc_args()

    buildargs = ''

    if args.invert:
        buildargs += ' invert=1'
    if args.debuglink:
        buildargs += ' debuglink=1'
    if args.debug:
        buildargs += ' debug=1'
    
    if args.verbose:
        buildargs += ' verbose=1'

    target ='arm-none-gnu-eabi'
    local('scons ' + 'target='+target + buildargs)

if __name__ == '__main__':
    main()